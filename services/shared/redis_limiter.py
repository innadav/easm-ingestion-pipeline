import asyncio
import time

import redis.asyncio as redis

from shared.metrics import RATE_LIMIT_WAIT

_TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local data = redis.call('HMGET', key, 'tokens', 'updated_at')
local tokens = tonumber(data[1])
local updated_at = tonumber(data[2])
if tokens == nil then
    tokens = capacity
    updated_at = now
else
    tokens = math.min(capacity, tokens + math.max(0, now - updated_at) * rate)
    updated_at = now
end
if tokens >= 1.0 then
    tokens = tokens - 1.0
    redis.call('HMSET', key, 'tokens', tokens, 'updated_at', updated_at)
    redis.call('PEXPIRE', key, 60000)
    return 0
end
redis.call('HMSET', key, 'tokens', tokens, 'updated_at', updated_at)
redis.call('PEXPIRE', key, 60000)
return math.ceil(((1.0 - tokens) / rate) * 1000)
"""


class DistributedTokenBucket:
    """Cluster-wide rate limiter backed by an atomic Redis Lua script."""

    def __init__(
        self,
        client: redis.Redis,
        bucket_name: str,
        rate_per_sec: float,
        capacity: int,
    ):
        if rate_per_sec <= 0 or capacity <= 0:
            raise ValueError("Rate and capacity must be positive")
        self.bucket_name = bucket_name
        self.key = f"easm:ratelimit:{bucket_name}"
        self.rate = rate_per_sec
        self.capacity = capacity
        self._script = client.register_script(_TOKEN_BUCKET_LUA)

    async def acquire(self) -> None:
        started = time.monotonic()
        while True:
            wait_ms = int(
                await self._script(
                    keys=[self.key],
                    args=[self.rate, self.capacity, time.time()],
                )
            )
            if wait_ms <= 0:
                RATE_LIMIT_WAIT.labels(bucket=self.bucket_name).observe(
                    time.monotonic() - started
                )
                return
            await asyncio.sleep(wait_ms / 1000.0)
