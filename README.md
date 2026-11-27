# Real-Time EASM Ingestion Platform

An event-driven External Attack Surface Management (EASM) platform. It decouples
discovery, network probing, lakehouse processing, and operational serving across
containerized services backed by Redpanda, Redis, Delta Lake, and PostgreSQL.

## Architecture

1. **Discovery scheduler** exposes `POST /scans`, polls Certificate Transparency,
   stores durable Redis watermarks, and publishes deduplicated scan tasks.
2. **Probe workers** consume tasks as a Kafka consumer group, coordinate quotas
   through a Redis Lua token bucket, execute DNS/TLS/HTTP probes, and emit raw
   envelopes plus dead-letter records.
3. **Spark Structured Streaming** routes malformed events to the DLQ, appends
   immutable Bronze records, normalizes Silver observations, maintains Delta Gold
   state with SCD Type 2 history, and upserts PostgreSQL.
4. **Asset API** serves tenant inventories, source-specific findings, and
   graph-based blast-radius clusters from PostgreSQL.

Topics:

| Topic | Producer | Consumer | Key |
| --- | --- | --- | --- |
| `easm.discovery.tasks` | Discovery scheduler | Probe workers | `tenant_id:fqdn` |
| `easm.raw.observations` | Probe workers | Spark processor | `tenant_id:fqdn` |
| `easm.dlq.errors` | Workers / Spark | Monitoring / replay | Event key |

Graph entity resolution links FQDNs to IPs, CNAME targets, and certificate
fingerprints. Shared-CDN edges and high-degree hubs are pruned before connected
component analysis; the resulting cluster and root-cause node are stored with
each Gold asset. Findings are tracked per source so one clean probe cannot erase
an unresolved finding reported by another protocol.

## Local Kubernetes

Requires Docker, kind, and kubectl.

```bash
make up
kubectl get pods -n easm -w
```

Trigger a deterministic offline scan:

```bash
kubectl port-forward -n easm svc/discovery-scheduler 8000:8000
curl -X POST http://localhost:8000/scans \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"tenant_beta","root_domain":"corp-example.io"}'
```

Read operational state:

```bash
kubectl port-forward -n easm svc/asset-api 8080:8080
curl "http://localhost:8080/tenants/tenant_beta/assets?status=exposed"
curl "http://localhost:8080/tenants/tenant_beta/clusters"
```

Inspect streaming data and stop the cluster:

```bash
kubectl exec -n easm deploy/redpanda -- \
  rpk topic describe easm.raw.observations
make down
```

Set `OFFLINE_MODE` to `"false"` in [k8s/02-apps.yaml](k8s/02-apps.yaml) and
redeploy to enable live internet probing.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,spark]"
ruff check services tests
pytest -v
```

## Repository

```text
services/
  shared/                 Event contracts, configuration, Redis limiter
  discovery_scheduler/    CT discovery and task publishing
  probe_worker/           Kafka consumer and network probe engine
  spark_processor/        Bronze, Silver, Gold, DLQ, PostgreSQL sync
  asset_api/              Operational FastAPI service
k8s/                      Local kind infrastructure and deployments
```
