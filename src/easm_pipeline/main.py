import argparse
import asyncio
import json
from pathlib import Path

import httpx

from easm_pipeline.collectors import AsyncDNSCollector, CTLogCollector, TLSAndHTTPInspector
from easm_pipeline.config import PipelineConfig
from easm_pipeline.models import RawEnvelope
from easm_pipeline.pipeline import MedallionPipeline
from easm_pipeline.resilience import CheckpointStore, TokenBucketRateLimiter


async def run_collection_cycle(
    tenant_id: str, seed_domain: str, config: PipelineConfig
) -> list[dict]:
    checkpoints = CheckpointStore(config.data_dir / "state.db")
    pipeline = MedallionPipeline(config.data_dir, checkpoints)
    try:
        ct_collector = CTLogCollector(
            checkpoints,
            TokenBucketRateLimiter(
                rate_per_sec=config.ct_rate_per_sec,
                capacity=config.ct_burst_capacity,
            ),
            offline_mode=config.offline_mode,
        )
        dns_collector = AsyncDNSCollector(
            nameservers=config.dns_nameservers,
            concurrency=config.dns_concurrency,
            offline_mode=config.offline_mode,
        )
        tls_http_inspector = TLSAndHTTPInspector(offline_mode=config.offline_mode)
        async with httpx.AsyncClient(verify=False) as client:
            candidate_fqdns, ct_envelopes = await ct_collector.discover_subdomains(
                client, tenant_id, seed_domain
            )
            wildcard_ips = await dns_collector.detect_wildcard_ips(seed_domain)
            dns_results = [
                envelope
                for envelope in await asyncio.gather(
                    *[
                        dns_collector.probe_fqdn(tenant_id, fqdn, wildcard_ips)
                        for fqdn in candidate_fqdns
                    ]
                )
                if envelope is not None
            ]
            live_hosts = [
                envelope.payload["fqdn"]
                for envelope in dns_results
                if envelope.payload["a_records"]
            ]
            tls_http_results = await asyncio.gather(
                *[
                    tls_http_inspector.inspect_host(client, tenant_id, fqdn)
                    for fqdn in live_hosts
                ]
            )

        envelopes: list[RawEnvelope] = [*ct_envelopes, *dns_results, *tls_http_results]
        new_bronze = pipeline.write_bronze(envelopes)
        silver = pipeline.normalize_to_silver(
            new_bronze, max_error_rate=config.max_silver_error_rate
        )
        pipeline.upsert_gold(silver)
        return pipeline.get_current_inventory(tenant_id)
    finally:
        pipeline.close()
        checkpoints.close()


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Run EASM asset discovery and medallion pipeline."
    )
    parser.add_argument("--tenant", default="tenant_acme", help="Tenant identifier")
    parser.add_argument("--domain", default="example.com", help="Seed root domain to scan")
    parser.add_argument(
        "--data-dir", default="./data", help="Output directory for medallion artifacts"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Run with deterministic offline fixtures instead of live network calls",
    )
    arguments = parser.parse_args()
    config = PipelineConfig(data_dir=Path(arguments.data_dir), offline_mode=arguments.offline)
    print(
        json.dumps(
            asyncio.run(run_collection_cycle(arguments.tenant, arguments.domain, config)),
            indent=2,
        )
    )


if __name__ == "__main__":
    cli()
