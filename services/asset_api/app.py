import json
from contextlib import asynccontextmanager

import asyncpg
from fastapi import FastAPI, Query
from shared.config import PlatformConfig

cfg = PlatformConfig()
db_pool: asyncpg.Pool | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global db_pool
    db_pool = await asyncpg.create_pool(dsn=cfg.postgres_dsn, min_size=2, max_size=10)
    async with db_pool.acquire() as connection:
        await connection.execute(
            """
            CREATE TABLE IF NOT EXISTS gold_assets (
                asset_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                fqdn TEXT NOT NULL,
                latest_ips_json TEXT NOT NULL,
                is_shared_cdn BOOLEAN NOT NULL,
                detected_tech_json TEXT NOT NULL,
                tls_version TEXT,
                cert_sha256 TEXT,
                status TEXT NOT NULL,
                exposure_type TEXT,
                validation_tier TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_gold_assets_tenant_status
                ON gold_assets (tenant_id, status);
            """
        )
    try:
        yield
    finally:
        await db_pool.close()


app = FastAPI(title="EASM Operational Asset API", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/tenants/{tenant_id}/assets")
async def list_assets(
    tenant_id: str,
    status: str | None = Query(default=None, pattern="^(clean|exposed)$"),
) -> list[dict]:
    if db_pool is None:
        raise RuntimeError("Database pool is not initialized")
    async with db_pool.acquire() as connection:
        if status:
            rows = await connection.fetch(
                """
                SELECT * FROM gold_assets
                WHERE tenant_id = $1 AND status = $2
                ORDER BY fqdn
                """,
                tenant_id,
                status,
            )
        else:
            rows = await connection.fetch(
                "SELECT * FROM gold_assets WHERE tenant_id = $1 ORDER BY fqdn",
                tenant_id,
            )
    return [
        {
            "asset_id": row["asset_id"],
            "tenant_id": row["tenant_id"],
            "fqdn": row["fqdn"],
            "ips": json.loads(row["latest_ips_json"]),
            "is_shared_cdn": row["is_shared_cdn"],
            "detected_tech": json.loads(row["detected_tech_json"]),
            "tls_version": row["tls_version"],
            "status": row["status"],
            "exposure_type": row["exposure_type"],
            "validation_tier": row["validation_tier"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
        }
        for row in rows
    ]
