import asyncio
import random
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import httpx
import redis.asyncio as redis
from aiokafka import AIOKafkaProducer
from aiokafka.errors import KafkaError
from fastapi import FastAPI
from pydantic import BaseModel
from redis.exceptions import RedisError
from shared.config import PlatformConfig
from shared.models import DiscoveryTask, make_deterministic_id
from shared.redis_limiter import DistributedTokenBucket

cfg = PlatformConfig()
producer: AIOKafkaProducer | None = None
redis_client: redis.Redis | None = None
ct_limiter: DistributedTokenBucket | None = None


class ScanRequest(BaseModel):
    tenant_id: str
    root_domain: str


def synthetic_ct_records(last_id: int, root_domain: str) -> list[dict]:
    return [
        {"id": last_id + 1, "name_value": f"{root_domain}\nwww.{root_domain}"},
        {"id": last_id + 2, "name_value": f"cdn-edge.{root_domain}"},
        {"id": last_id + 3, "name_value": f"staging-legacy.{root_domain}"},
    ]


async def schedule_domain_discovery(tenant_id: str, root_domain: str) -> int:
    if producer is None or redis_client is None or ct_limiter is None:
        raise RuntimeError("Discovery scheduler is not initialized")
    normalized_domain = root_domain.strip().lower().rstrip(".").removeprefix("*.")
    checkpoint_key = f"easm:checkpoint:ct:{tenant_id}:{normalized_domain}"
    last_id = int(await redis_client.get(checkpoint_key) or "0")

    if cfg.offline_mode:
        records = synthetic_ct_records(last_id, normalized_domain)
    else:
        records = await _fetch_live_ct_records(normalized_domain)

    fqdns: set[str] = {normalized_domain}
    max_id = last_id
    for row in sorted(records, key=lambda record: int(record.get("id", 0))):
        ct_id = int(row.get("id", 0))
        if ct_id <= last_id:
            continue
        max_id = max(max_id, ct_id)
        for line in str(row.get("name_value", "")).splitlines():
            host = line.strip().lower().removeprefix("*.").rstrip(".")
            if (
                host == normalized_domain or host.endswith(f".{normalized_domain}")
            ) and " " not in host:
                fqdns.add(host)

    hour_bucket = datetime.now(UTC).strftime("%Y-%m-%dT%H")
    published = 0
    for fqdn in sorted(fqdns):
        dedup_key = f"easm:scheduled:{tenant_id}:{fqdn}:{hour_bucket}"
        if not await redis_client.set(dedup_key, "1", ex=3600, nx=True):
            continue
        task = DiscoveryTask(
            task_id=make_deterministic_id(tenant_id, fqdn, hour_bucket),
            tenant_id=tenant_id,
            root_domain=normalized_domain,
            fqdn=fqdn,
        )
        try:
            await producer.send_and_wait(
                cfg.topic_tasks,
                value=task.model_dump_json().encode(),
                key=f"{tenant_id}:{fqdn}".encode(),
            )
        except KafkaError:
            await redis_client.delete(dedup_key)
            raise
        published += 1

    if max_id > last_id:
        await redis_client.set(checkpoint_key, str(max_id))
    return published


async def _fetch_live_ct_records(root_domain: str) -> list[dict]:
    if ct_limiter is None:
        raise RuntimeError("CT rate limiter is not initialized")
    last_error: Exception | None = None
    async with httpx.AsyncClient(timeout=10.0) as client:
        for attempt in range(3):
            await ct_limiter.acquire()
            try:
                response = await client.get(
                    "https://crt.sh/",
                    params={"q": f"%.{root_domain}", "output": "json"},
                )
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, list):
                    raise TypeError("crt.sh response must be a JSON array")
                return payload
            except (httpx.HTTPError, TypeError, ValueError) as error:
                last_error = error
                if attempt < 2:
                    await asyncio.sleep(random.uniform(0.5, 1.5) * (2**attempt))
    raise RuntimeError("Certificate Transparency discovery failed") from last_error


async def periodic_scheduler_loop() -> None:
    while True:
        try:
            await schedule_domain_discovery("tenant_acme", "example.com")
        except (KafkaError, RedisError, RuntimeError, OSError) as error:
            print(f"[scheduler] periodic cycle error: {error}", flush=True)
        await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(_: FastAPI):
    global producer, redis_client, ct_limiter
    redis_client = redis.from_url(cfg.redis_url, decode_responses=True)
    ct_limiter = DistributedTokenBucket(redis_client, "ct_logs", cfg.ct_rate_per_sec, cfg.ct_burst)
    producer = AIOKafkaProducer(bootstrap_servers=cfg.kafka_brokers)
    await producer.start()
    background_task = asyncio.create_task(periodic_scheduler_loop())
    try:
        yield
    finally:
        background_task.cancel()
        await producer.stop()
        await redis_client.aclose()


app = FastAPI(title="EASM Discovery Scheduler", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scans")
async def trigger_scan(request: ScanRequest) -> dict:
    enqueued = await schedule_domain_discovery(request.tenant_id, request.root_domain)
    return {
        "tenant_id": request.tenant_id,
        "root_domain": request.root_domain,
        "tasks_enqueued": enqueued,
    }
