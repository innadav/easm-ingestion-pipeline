import pytest
from discovery_scheduler import app as scheduler
from probe_worker.worker import NetworkProbeEngine
from pydantic import ValidationError
from shared.models import DiscoveryTask


class NoopLimiter:
    async def acquire(self) -> None:
        return None


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def set(self, key: str, value: str, *, ex: int | None = None, nx: bool = False) -> bool:
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    async def delete(self, key: str) -> None:
        self.values.pop(key, None)


class FakeProducer:
    def __init__(self) -> None:
        self.messages: list[tuple[str, bytes, bytes]] = []

    async def send_and_wait(self, topic: str, *, value: bytes, key: bytes) -> None:
        self.messages.append((topic, value, key))


def make_task(fqdn: str) -> DiscoveryTask:
    return DiscoveryTask(
        task_id="task-1",
        tenant_id="tenant-a",
        root_domain="example.com",
        fqdn=fqdn,
    )


def test_discovery_task_normalizes_hostnames() -> None:
    task = make_task("  *.API.Example.COM. ")
    assert task.fqdn == "api.example.com"
    with pytest.raises(ValidationError):
        make_task("invalid hostname")


async def test_scheduler_publishes_each_fqdn_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_redis = FakeRedis()
    fake_producer = FakeProducer()
    monkeypatch.setattr(scheduler, "redis_client", fake_redis)
    monkeypatch.setattr(scheduler, "producer", fake_producer)
    monkeypatch.setattr(scheduler, "ct_limiter", NoopLimiter())

    first_count = await scheduler.schedule_domain_discovery("tenant-a", "example.com")
    second_count = await scheduler.schedule_domain_discovery("tenant-a", "example.com")

    assert first_count == 4
    assert second_count == 0
    assert len(fake_producer.messages) == 4
    assert all(topic == scheduler.cfg.topic_tasks for topic, _, _ in fake_producer.messages)


async def test_offline_dns_probe_flags_dangling_cname() -> None:
    envelope = await NetworkProbeEngine(NoopLimiter()).run_dns_probe(
        make_task("staging-legacy.example.com")
    )
    assert envelope.source == "dns_probe"
    assert envelope.payload["is_dangling_cname"] is True
    assert envelope.payload["a_records"] == []


async def test_offline_tls_probe_marks_shared_cdn() -> None:
    engine = NetworkProbeEngine(NoopLimiter())
    envelope = await engine.run_tls_http_probe(
        client=object(),
        task=make_task("cdn-edge.example.com"),  # type: ignore[arg-type]
    )
    assert envelope.source == "tls_http_probe"
    assert envelope.payload["is_shared_cdn"] is True
    assert envelope.payload["tls_version"] == "TLSv1.3"
