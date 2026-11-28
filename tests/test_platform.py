from dataclasses import replace

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


async def test_live_ct_failure_does_not_publish_fixtures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_redis = FakeRedis()
    fake_producer = FakeProducer()
    monkeypatch.setattr(scheduler, "cfg", replace(scheduler.cfg, offline_mode=False))
    monkeypatch.setattr(scheduler, "redis_client", fake_redis)
    monkeypatch.setattr(scheduler, "producer", fake_producer)
    monkeypatch.setattr(scheduler, "ct_limiter", NoopLimiter())

    async def fail_ct(_: str) -> list[dict]:
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(scheduler, "_fetch_live_ct_records", fail_ct)
    with pytest.raises(RuntimeError, match="provider unavailable"):
        await scheduler.schedule_domain_discovery("tenant-a", "example.com")

    assert fake_producer.messages == []
    assert "easm:checkpoint:ct:tenant-a:example.com" not in fake_redis.values


async def test_scheduler_processes_complete_ct_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_redis = FakeRedis()
    fake_producer = FakeProducer()
    monkeypatch.setattr(scheduler, "redis_client", fake_redis)
    monkeypatch.setattr(scheduler, "producer", fake_producer)
    monkeypatch.setattr(scheduler, "ct_limiter", NoopLimiter())
    monkeypatch.setattr(
        scheduler,
        "synthetic_ct_records",
        lambda _last_id, root_domain: [
            {
                "id": index,
                "name_value": f"host-{index}.{root_domain}",
            }
            for index in range(1, 102)
        ],
    )

    published = await scheduler.schedule_domain_discovery("tenant-a", "example.com")

    assert published == 102
    assert len(fake_producer.messages) == 102
    assert fake_redis.values["easm:checkpoint:ct:tenant-a:example.com"] == "101"


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


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("93.184.216.34", True),
        ("10.0.0.5", False),
        ("127.0.0.1", False),
        ("169.254.169.254", False),
        ("::1", False),
        ("not-an-ip", False),
    ],
)
def test_is_public_ip(address: str, expected: bool) -> None:
    from shared.netguard import is_public_ip

    assert is_public_ip(address) is expected


async def test_dns_servfail_is_not_reported_as_empty_answer(monkeypatch) -> None:
    import dns.resolver
    from probe_worker import worker

    class Limiter:
        async def acquire(self) -> None:
            return None

    async def fail(*_args, **_kwargs):
        raise dns.resolver.NoNameservers()

    monkeypatch.setattr(worker, "cfg", replace(worker.cfg, offline_mode=False))
    engine = worker.NetworkProbeEngine(Limiter())
    monkeypatch.setattr(engine.resolver, "resolve", fail)
    with pytest.raises(worker.ProbeUnavailableError):
        await engine.run_dns_probe(make_task("www.example.com"))


async def test_tls_probe_refuses_non_public_hosts(monkeypatch) -> None:
    from probe_worker import worker

    async def private(_host: str) -> bool:
        return False

    monkeypatch.setattr(worker, "cfg", replace(worker.cfg, offline_mode=False))
    monkeypatch.setattr(worker, "host_is_public", private)
    engine = worker.NetworkProbeEngine(None)
    envelope = await engine.run_tls_http_probe(None, make_task("internal.example.com"))
    assert envelope.payload["probe_blocked"] is True


async def test_process_single_message_records_metrics_and_publishes() -> None:
    import asyncio
    from types import SimpleNamespace

    from probe_worker import worker

    sent: list[str] = []

    class Producer:
        async def send_and_wait(self, topic: str, **_kwargs) -> None:
            sent.append(topic)

    message = SimpleNamespace(value=make_task("www.example.com").model_dump_json().encode())
    engine = worker.NetworkProbeEngine(None)
    await worker.process_single_message(
        message, engine, None, Producer(), asyncio.Semaphore(1)
    )
    assert sent and worker.cfg.topic_dlq not in sent
