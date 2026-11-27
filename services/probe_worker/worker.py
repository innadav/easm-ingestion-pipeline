import asyncio
import hashlib
import json
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
import redis.asyncio as redis
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.structs import OffsetAndMetadata
from cryptography import x509
from shared.config import PlatformConfig
from shared.models import DiscoveryTask, RawEnvelope, make_deterministic_id, utc_now_iso
from shared.redis_limiter import DistributedTokenBucket

cfg = PlatformConfig()


class NetworkProbeEngine:
    def __init__(self, dns_limiter: DistributedTokenBucket):
        self.dns_limiter = dns_limiter
        self.resolver = dns.asyncresolver.Resolver(configure=False)
        self.resolver.nameservers = cfg.dns_nameservers
        self.resolver.timeout = 3.0
        self.resolver.lifetime = 5.0

    async def _dns_query(self, fqdn: str, rdtype: str) -> tuple[list[str], str]:
        await self.dns_limiter.acquire()
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

    async def run_dns_probe(self, task: DiscoveryTask) -> RawEnvelope:
        hour_bucket = datetime.now(UTC).strftime("%Y-%m-%dT%H")
        event_id = make_deterministic_id(task.tenant_id, "dns_probe", task.fqdn, hour_bucket)
        if cfg.offline_mode:
            if task.fqdn.startswith("staging-legacy."):
                payload = {
                    "fqdn": task.fqdn,
                    "a_records": [],
                    "cname_chain": ["acme-legacy-app.azurewebsites.net"],
                    "is_dangling_cname": True,
                }
            elif task.fqdn.startswith("cdn-edge."):
                payload = {
                    "fqdn": task.fqdn,
                    "a_records": ["104.16.132.229"],
                    "cname_chain": ["cdn-edge.cdn.cloudflare.net"],
                    "is_dangling_cname": False,
                }
            else:
                payload = {
                    "fqdn": task.fqdn,
                    "a_records": ["93.184.216.34"],
                    "cname_chain": [],
                    "is_dangling_cname": False,
                }
            return RawEnvelope(
                event_id=event_id,
                tenant_id=task.tenant_id,
                source="dns_probe",
                entity_key=task.fqdn,
                payload=payload,
            )

        a_records, _ = await self._dns_query(task.fqdn, "A")
        cname_chain: list[str] = []
        current = task.fqdn
        visited = {current}
        for _ in range(8):
            cnames, _ = await self._dns_query(current, "CNAME")
            if not cnames:
                break
            target = cnames[0].rstrip(".")
            cname_chain.append(target)
            if target in visited:
                break
            visited.add(target)
            current = target

        is_dangling = False
        if cname_chain:
            terminal_ips, terminal_status = await self._dns_query(cname_chain[-1], "A")
            is_dangling = terminal_status == "NXDOMAIN" and not terminal_ips
        return RawEnvelope(
            event_id=event_id,
            tenant_id=task.tenant_id,
            source="dns_probe",
            entity_key=task.fqdn,
            payload={
                "fqdn": task.fqdn,
                "a_records": sorted(a_records),
                "cname_chain": cname_chain,
                "is_dangling_cname": is_dangling,
            },
        )

    @staticmethod
    def _blocking_tls_scan(hostname: str) -> dict:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection((hostname, 443), timeout=4.0) as sock,
            context.wrap_socket(sock, server_hostname=hostname) as tls_sock,
        ):
            tls_version = tls_sock.version()
            der_bytes = tls_sock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der_bytes)
        try:
            san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_extension.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        return {
            "tls_version": tls_version,
            "cert_sha256": hashlib.sha256(der_bytes).hexdigest(),
            "cert_sans": sans,
            "is_expired": cert.not_valid_after_utc < datetime.now(UTC),
            "weak_tls": tls_version in {"TLSv1", "TLSv1.1", "SSLv3"},
        }

    async def run_tls_http_probe(
        self, client: httpx.AsyncClient, task: DiscoveryTask
    ) -> RawEnvelope:
        hour_bucket = datetime.now(UTC).strftime("%Y-%m-%dT%H")
        event_id = make_deterministic_id(task.tenant_id, "tls_http_probe", task.fqdn, hour_bucket)
        if cfg.offline_mode:
            is_cdn = task.fqdn.startswith("cdn-edge.")
            return RawEnvelope(
                event_id=event_id,
                tenant_id=task.tenant_id,
                source="tls_http_probe",
                entity_key=task.fqdn,
                payload={
                    "fqdn": task.fqdn,
                    "http_status": 200,
                    "detected_tech": (
                        ["server:cloudflare", "cdn:edge_proxy"] if is_cdn else ["server:nginx"]
                    ),
                    "is_shared_cdn": is_cdn,
                    "tls_version": "TLSv1.3",
                    "cert_sha256": make_deterministic_id("cert", task.fqdn),
                    "cert_sans": [task.fqdn],
                    "is_expired": False,
                    "weak_tls": False,
                },
            )

        try:
            tls_info = await asyncio.to_thread(self._blocking_tls_scan, task.fqdn)
        except (OSError, ssl.SSLError, ValueError) as error:
            tls_info = {"tls_error": type(error).__name__}
        is_shared_cdn = len(tls_info.get("cert_sans", [])) > 50
        technologies: list[str] = []
        http_status = None
        try:
            response = await client.get(f"https://{task.fqdn}", follow_redirects=True, timeout=5.0)
            http_status = response.status_code
            headers = {key.lower(): value for key, value in response.headers.items()}
            if "server" in headers:
                technologies.append(f"server:{headers['server']}")
            if "cf-ray" in headers or "x-amz-cf-id" in headers:
                is_shared_cdn = True
                technologies.append("cdn:edge_proxy")
        except httpx.HTTPError:
            pass
        return RawEnvelope(
            event_id=event_id,
            tenant_id=task.tenant_id,
            source="tls_http_probe",
            entity_key=task.fqdn,
            payload={
                "fqdn": task.fqdn,
                "http_status": http_status,
                "detected_tech": technologies,
                "is_shared_cdn": is_shared_cdn,
                **tls_info,
            },
        )


async def process_single_message(
    message: Any,
    engine: NetworkProbeEngine,
    http_client: httpx.AsyncClient,
    producer: AIOKafkaProducer,
    semaphore: asyncio.Semaphore,
) -> None:
    async with semaphore:
        try:
            task = DiscoveryTask.model_validate_json(message.value)
            dns_envelope = await engine.run_dns_probe(task)
            key = f"{task.tenant_id}:{task.fqdn}".encode()
            await producer.send_and_wait(
                cfg.topic_raw,
                value=dns_envelope.model_dump_json().encode(),
                key=key,
            )
            if dns_envelope.payload.get("a_records"):
                tls_envelope = await engine.run_tls_http_probe(http_client, task)
                await producer.send_and_wait(
                    cfg.topic_raw,
                    value=tls_envelope.model_dump_json().encode(),
                    key=key,
                )
        except Exception as error:  # noqa: BLE001 - every failed record must reach the DLQ
            dlq_payload = json.dumps(
                {
                    "error": str(error),
                    "raw_message": message.value.decode("utf-8", errors="replace"),
                    "failed_at": utc_now_iso(),
                }
            ).encode()
            await producer.send_and_wait(cfg.topic_dlq, value=dlq_payload)


async def consume_forever() -> None:
    if cfg.probe_concurrency <= 0:
        raise ValueError("PROBE_CONCURRENCY must be positive")
    redis_client = redis.from_url(cfg.redis_url, decode_responses=True)
    engine = NetworkProbeEngine(
        DistributedTokenBucket(redis_client, "dns_global", cfg.dns_rate_per_sec, cfg.dns_burst)
    )
    consumer = AIOKafkaConsumer(
        cfg.topic_tasks,
        bootstrap_servers=cfg.kafka_brokers,
        group_id="easm-probe-workers",
        auto_offset_reset="earliest",
        enable_auto_commit=False,
    )
    producer = AIOKafkaProducer(bootstrap_servers=cfg.kafka_brokers)
    await consumer.start()
    await producer.start()
    print("[probe-worker] Connected to broker and consuming tasks", flush=True)
    try:
        async with httpx.AsyncClient(verify=False) as http_client:
            semaphore = asyncio.Semaphore(cfg.probe_concurrency)
            while True:
                batches = await consumer.getmany(
                    timeout_ms=1000,
                    max_records=max(1, cfg.probe_concurrency * 4),
                )
                if not batches:
                    continue
                messages = [
                    message
                    for partition_messages in batches.values()
                    for message in partition_messages
                ]
                await asyncio.gather(
                    *[
                        process_single_message(message, engine, http_client, producer, semaphore)
                        for message in messages
                    ]
                )
                offsets = {
                    partition: OffsetAndMetadata(
                        max(message.offset for message in partition_messages) + 1,
                        "",
                    )
                    for partition, partition_messages in batches.items()
                }
                await consumer.commit(offsets=offsets)
    finally:
        await consumer.stop()
        await producer.stop()
        await redis_client.aclose()


if __name__ == "__main__":
    asyncio.run(consume_forever())
