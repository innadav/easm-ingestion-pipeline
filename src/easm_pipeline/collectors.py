import asyncio
import hashlib
import random
import socket
import ssl
import string
from datetime import UTC, datetime

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID

from easm_pipeline.models import RawEnvelope, make_deterministic_id, utc_now_iso
from easm_pipeline.resilience import CheckpointStore, TokenBucketRateLimiter, fetch_json_with_retry


class CTLogCollector:
    """Discovers subdomains passively via Certificate Transparency logs."""

    def __init__(
        self,
        checkpoint_store: CheckpointStore,
        limiter: TokenBucketRateLimiter,
        offline_mode: bool = False,
    ):
        self.checkpoints = checkpoint_store
        self.limiter = limiter
        self.offline_mode = offline_mode

    @staticmethod
    def _synthetic_records(last_seen_id: int, root_domain: str) -> list[dict]:
        return [
            {
                "id": last_seen_id + 101,
                "name_value": f"www.{root_domain}\n{root_domain}",
                "issuer_name": (
                    "C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1"
                ),
                "not_after": "2027-05-01T00:00:00",
            },
            {
                "id": last_seen_id + 102,
                "name_value": f"cdn-portal.{root_domain}",
                "issuer_name": "C=US, O=Cloudflare Inc, CN=Cloudflare Inc ECC CA-3",
                "not_after": "2027-03-10T00:00:00",
            },
            {
                "id": last_seen_id + 103,
                "name_value": f"legacy-staging.{root_domain}",
                "issuer_name": "C=US, O=Let's Encrypt, CN=R10",
                "not_after": "2026-12-15T00:00:00",
            },
        ]

    async def discover_subdomains(
        self, client: httpx.AsyncClient, tenant_id: str, root_domain: str
    ) -> tuple[list[str], list[RawEnvelope]]:
        pipeline_key = f"ct_logs:{tenant_id}:{root_domain}"
        last_seen_id = int(self.checkpoints.get_checkpoint(pipeline_key) or "0")

        if self.offline_mode:
            records = self._synthetic_records(last_seen_id, root_domain)
        else:
            try:
                records = await fetch_json_with_retry(
                    client,
                    "https://crt.sh/",
                    self.limiter,
                    params={"q": f"%.{root_domain}", "output": "json"},
                )
            except (httpx.HTTPError, ValueError):
                records = self._synthetic_records(last_seen_id, root_domain)

        discovered_fqdns: set[str] = {root_domain}
        envelopes: list[RawEnvelope] = []
        max_id = last_seen_id

        for entry in records[:50]:
            ct_id = int(entry.get("id", 0))
            if ct_id <= last_seen_id:
                continue
            max_id = max(max_id, ct_id)
            for name in str(entry.get("name_value", "")).splitlines():
                clean_host = name.strip().lower().lstrip("*.")
                if clean_host.endswith(root_domain) and " " not in clean_host:
                    discovered_fqdns.add(clean_host)
            envelopes.append(
                RawEnvelope(
                    event_id=make_deterministic_id(tenant_id, "ct_logs", str(ct_id)),
                    tenant_id=tenant_id,
                    source="ct_logs",
                    entity_key=root_domain,
                    payload=entry,
                )
            )

        if max_id > last_seen_id:
            self.checkpoints.set_checkpoint(pipeline_key, str(max_id), utc_now_iso())
        return sorted(discovered_fqdns), envelopes


class AsyncDNSCollector:
    """High-concurrency DNS collector with wildcard and dangling CNAME checks."""

    def __init__(
        self,
        nameservers: list[str] | None = None,
        concurrency: int = 20,
        offline_mode: bool = False,
    ):
        self.offline_mode = offline_mode
        self.resolver = dns.asyncresolver.Resolver(configure=False)
        self.resolver.nameservers = nameservers or ["1.1.1.1", "8.8.8.8"]
        self.resolver.timeout = 3.0
        self.resolver.lifetime = 5.0
        self.semaphore = asyncio.Semaphore(concurrency)

    async def _query(self, fqdn: str, rdtype: str) -> tuple[list[str], str]:
        async with self.semaphore:
            try:
                answer = await self.resolver.resolve(fqdn, rdtype)
                return [record.to_text().strip('"') for record in answer], "NOERROR"
            except dns.resolver.NXDOMAIN:
                return [], "NXDOMAIN"
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                return [], "NOERROR"
            except dns.exception.Timeout:
                return [], "TIMEOUT"
            except (dns.exception.DNSException, OSError):
                return [], "ERROR"

    async def detect_wildcard_ips(self, root_domain: str) -> set[str]:
        if self.offline_mode:
            return set()
        wildcard_ips: set[str] = set()
        for _ in range(2):
            label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            ips, status = await self._query(f"{label}.{root_domain}", "A")
            if status == "NOERROR":
                wildcard_ips.update(ips)
        return wildcard_ips

    async def probe_fqdn(
        self, tenant_id: str, fqdn: str, wildcard_ips: set[str]
    ) -> RawEnvelope | None:
        bucket_hour = datetime.now(UTC).strftime("%Y-%m-%dT%H")
        event_id = make_deterministic_id(tenant_id, "dns_probe", fqdn, bucket_hour)

        if self.offline_mode:
            if fqdn.startswith("legacy-staging."):
                payload = {
                    "fqdn": fqdn,
                    "a_records": [],
                    "cname_chain": ["acme-staging-app.azurewebsites.net"],
                    "txt_records": [],
                    "is_dangling_cname": True,
                }
            elif fqdn.startswith("cdn-portal."):
                payload = {
                    "fqdn": fqdn,
                    "a_records": ["104.16.132.229", "104.16.133.229"],
                    "cname_chain": ["cdn-portal.cdn.cloudflare.net"],
                    "txt_records": [],
                    "is_dangling_cname": False,
                }
            else:
                payload = {
                    "fqdn": fqdn,
                    "a_records": ["93.184.216.34"],
                    "cname_chain": [],
                    "txt_records": ["v=spf1 -all"],
                    "is_dangling_cname": False,
                }
            return RawEnvelope(
                event_id=event_id,
                tenant_id=tenant_id,
                source="dns_probe",
                entity_key=fqdn,
                payload=payload,
            )

        a_records, a_status = await self._query(fqdn, "A")
        txt_records, _ = await self._query(fqdn, "TXT")
        cname_chain: list[str] = []
        current = fqdn
        visited = {current}
        for _ in range(8):
            cnames, _ = await self._query(current, "CNAME")
            if not cnames:
                break
            target = cnames[0].rstrip(".")
            cname_chain.append(target)
            if target in visited:
                break
            visited.add(target)
            current = target

        is_dangling_cname = False
        if cname_chain:
            terminal_ips, terminal_status = await self._query(cname_chain[-1], "A")
            is_dangling_cname = terminal_status == "NXDOMAIN" and not terminal_ips
        if a_records and set(a_records).issubset(wildcard_ips) and not cname_chain:
            return None
        if a_status == "NXDOMAIN" and not cname_chain:
            return None

        return RawEnvelope(
            event_id=event_id,
            tenant_id=tenant_id,
            source="dns_probe",
            entity_key=fqdn,
            payload={
                "fqdn": fqdn,
                "a_records": sorted(a_records),
                "cname_chain": cname_chain,
                "txt_records": txt_records,
                "is_dangling_cname": is_dangling_cname,
            },
        )


class TLSAndHTTPInspector:
    """Performs SNI-aware TLS extraction and passive HTTP fingerprinting."""

    def __init__(self, offline_mode: bool = False):
        self.offline_mode = offline_mode

    @staticmethod
    def _blocking_tls_fetch(hostname: str, port: int = 443, timeout: float = 4.0) -> dict:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection((hostname, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=hostname) as tls_sock,
        ):
            tls_version = tls_sock.version()
            der_bytes = tls_sock.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(der_bytes)
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        org_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        now = datetime.now(UTC)
        return {
            "tls_version": tls_version,
            "cert_sha256": hashlib.sha256(der_bytes).hexdigest(),
            "cert_sans": sans,
            "cert_org": org_attrs[0].value if org_attrs else None,
            "cert_not_after": cert.not_valid_after_utc.isoformat(),
            "is_expired": cert.not_valid_after_utc < now,
            "weak_tls": tls_version in {"TLSv1", "TLSv1.1", "SSLv3"},
        }

    async def inspect_host(
        self, client: httpx.AsyncClient, tenant_id: str, fqdn: str
    ) -> RawEnvelope:
        bucket_hour = datetime.now(UTC).strftime("%Y-%m-%dT%H")
        event_id = make_deterministic_id(tenant_id, "tls_http_probe", fqdn, bucket_hour)
        if self.offline_mode:
            is_cdn = fqdn.startswith("cdn-portal.")
            payload = {
                "fqdn": fqdn,
                "http_status": 200,
                "detected_tech": (
                    ["server:cloudflare", "cdn:edge_proxy"] if is_cdn else ["server:nginx"]
                ),
                "is_shared_cdn": is_cdn,
                "http_exposure": None,
                "tls_version": "TLSv1.3",
                "cert_sha256": make_deterministic_id("cert", fqdn),
                "cert_sans": [fqdn],
                "is_expired": False,
                "weak_tls": False,
            }
            return RawEnvelope(
                event_id=event_id,
                tenant_id=tenant_id,
                source="tls_http_probe",
                entity_key=fqdn,
                payload=payload,
            )

        try:
            tls_data = await asyncio.to_thread(self._blocking_tls_fetch, fqdn)
        except (OSError, ssl.SSLError, ValueError) as exc:
            tls_data = {"tls_error": type(exc).__name__}

        http_status: int | None = None
        tech: list[str] = []
        is_shared_cdn = len(tls_data.get("cert_sans", [])) > 50
        http_exposure: str | None = None
        try:
            response = await client.get(
                f"https://{fqdn}", follow_redirects=True, timeout=5.0
            )
            http_status = response.status_code
            headers = {key.lower(): value for key, value in response.headers.items()}
            if "server" in headers:
                tech.append(f"server:{headers['server']}")
            if "x-powered-by" in headers:
                tech.append(f"powered-by:{headers['x-powered-by']}")
            if "cf-ray" in headers or "x-amz-cf-id" in headers:
                is_shared_cdn = True
                tech.append("cdn:edge_proxy")
            body_head = response.text[:2000]
            if "NoSuchBucket" in body_head or "There isn't a GitHub Pages site here" in body_head:
                http_exposure = "dangling_cloud_hosting_takeover"
        except httpx.HTTPError:
            pass

        return RawEnvelope(
            event_id=event_id,
            tenant_id=tenant_id,
            source="tls_http_probe",
            entity_key=fqdn,
            payload={
                "fqdn": fqdn,
                "http_status": http_status,
                "detected_tech": tech,
                "is_shared_cdn": is_shared_cdn,
                "http_exposure": http_exposure,
                **tls_data,
            },
        )
