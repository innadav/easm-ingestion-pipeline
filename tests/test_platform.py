import shutil
import subprocess

import pytest
from discovery_scheduler import app as scheduler
from probe_worker.worker import NetworkProbeEngine
from pydantic import ValidationError
from pyspark.sql import SparkSession
from shared.models import DiscoveryTask


@pytest.fixture(scope="session")
def spark() -> SparkSession:
    java = shutil.which("java")
    if (
        java is None
        or subprocess.run([java, "-version"], capture_output=True, check=False).returncode != 0
    ):
        pytest.skip("Java 17+ is required for Spark graph tests")
    session = (
        SparkSession.builder.master("local[2]")
        .appName("easm-platform-tests")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.shuffle.partitions", "2")
        .getOrCreate()
    )
    yield session
    session.stop()


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


def test_graph_clustering_prunes_shared_cdn_hubs(
    spark: SparkSession,
) -> None:
    from spark_processor.graph_resolution import (
        extract_infrastructure_edges,
        resolve_clusters_and_root_causes,
    )

    rows = [
        (
            "t1",
            "app1.acme.com",
            ["10.20.30.40"],
            ["internal-alb.elb.amazonaws.com"],
            None,
            False,
            "2026-11-27T10:00:00Z",
        ),
        (
            "t1",
            "app2.acme.com",
            ["10.20.30.40"],
            ["internal-alb.elb.amazonaws.com"],
            None,
            False,
            "2026-11-27T10:00:00Z",
        ),
        (
            "t1",
            "www.acme.com",
            ["104.16.132.229"],
            ["www.acme.com.cdn.cloudflare.net"],
            None,
            True,
            "2026-11-27T10:00:00Z",
        ),
    ]
    columns = [
        "tenant_id",
        "fqdn",
        "a_records",
        "cname_chain",
        "cert_sha256",
        "is_shared_cdn",
        "observed_at",
    ]
    silver_df = spark.createDataFrame(rows, columns)
    clusters = {
        row["fqdn"]: (row["cluster_id"], row["root_cause_node"])
        for row in resolve_clusters_and_root_causes(
            extract_infrastructure_edges(silver_df)
        ).collect()
    }

    assert clusters["app1.acme.com"][0] == clusters["app2.acme.com"][0]
    assert clusters["app1.acme.com"][1] == "fqdn:internal-alb.elb.amazonaws.com"
    assert "www.acme.com" not in clusters
