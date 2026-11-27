import asyncio
import random
import sqlite3
import time
from pathlib import Path
from typing import Any

import httpx


class TokenBucketRateLimiter:
    """Async token-bucket limiter to enforce per-provider API quotas."""

    def __init__(self, rate_per_sec: float, capacity: int):
        if rate_per_sec <= 0:
            raise ValueError("rate_per_sec must be positive")
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self.rate = rate_per_sec
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.updated_at = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self.updated_at
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                self.updated_at = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait_time = (1.0 - self.tokens) / self.rate
            await asyncio.sleep(wait_time)


class CheckpointStore:
    """SQLite-backed state store for durable watermarks and idempotency keys."""

    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS checkpoints (
                pipeline_key TEXT PRIMARY KEY,
                cursor_value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS processed_events (
                event_id TEXT PRIMARY KEY,
                processed_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def get_checkpoint(self, pipeline_key: str) -> str | None:
        row = self.conn.execute(
            "SELECT cursor_value FROM checkpoints WHERE pipeline_key = ?",
            (pipeline_key,),
        ).fetchone()
        return row[0] if row else None

    def set_checkpoint(self, pipeline_key: str, cursor_value: str, updated_at: str) -> None:
        self.conn.execute(
            """
            INSERT INTO checkpoints (pipeline_key, cursor_value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(pipeline_key) DO UPDATE SET
                cursor_value = excluded.cursor_value,
                updated_at = excluded.updated_at
            """,
            (pipeline_key, cursor_value, updated_at),
        )
        self.conn.commit()

    def is_duplicate(self, event_id: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM processed_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        return row is not None

    def mark_processed(self, event_id: str, processed_at: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO processed_events (event_id, processed_at) VALUES (?, ?)",
            (event_id, processed_at),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


async def fetch_json_with_retry(
    client: httpx.AsyncClient,
    url: str,
    limiter: TokenBucketRateLimiter,
    params: dict[str, Any] | None = None,
    max_retries: int = 3,
) -> Any:
    """Fetch JSON with rate limiting, Retry-After support, and jittered backoff."""
    for attempt in range(max_retries + 1):
        await limiter.acquire()
        try:
            resp = await client.get(url, params=params, timeout=10.0)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in {400, 401, 403, 404}:
                resp.raise_for_status()
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt == max_retries:
                    resp.raise_for_status()
                retry_after = resp.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    sleep_sec = float(retry_after)
                else:
                    sleep_sec = random.uniform(0.5, (2**attempt) * 1.5)
                await asyncio.sleep(sleep_sec)
                continue
            resp.raise_for_status()
        except (httpx.TimeoutException, httpx.NetworkError):
            if attempt == max_retries:
                raise
            await asyncio.sleep(random.uniform(0.5, (2**attempt) * 1.5))
    raise RuntimeError("Retry loop exhausted unexpectedly")
