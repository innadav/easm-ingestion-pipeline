# EASM Ingestion & Entity Resolution Pipeline

An asynchronous External Attack Surface Management (EASM) collection and normalization
pipeline in Python. It harvests internet-facing signals from passive and active sources,
enforces ingestion resilience, and resolves noisy network observations into canonical
entities with temporal state tracking.

## Architecture

1. **Ingestion and resilience** — Per-provider async token-bucket rate limiting,
   full-jitter exponential backoff with `Retry-After` support, durable SQLite
   checkpoints, and event idempotency.
2. **Multi-protocol reconnaissance** — Certificate Transparency discovery, concurrent
   DNS probing with wildcard filtering and CNAME checks, and SNI-aware TLS/HTTP
   inspection.
3. **Medallion storage** — Append-only Bronze JSONL, Pydantic-validated Silver JSONL
   with a fail-loud dead-letter threshold, and SQLite Gold state with SCD Type 2
   exposure history.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Deterministic demo without external network access
easm-collect --offline

# Live discovery
easm-collect --tenant tenant_acme --domain example.com

# Validation
ruff check src tests
pytest -v
```

## Container

```bash
docker build -t easm-ingestion-pipeline .
docker run --rm easm-ingestion-pipeline
```

## Production Scaling

- Replace in-process `asyncio.gather` fan-out with Kafka or SQS tasks and autoscaled
  workers backed by a distributed rate limiter.
- Land the medallion tables in a lakehouse and incrementally sync current Gold state
  into a query-optimized serving database.
