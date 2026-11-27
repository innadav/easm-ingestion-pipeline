import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class PlatformConfig:
    kafka_brokers: str = os.getenv("KAFKA_BROKERS", "redpanda.easm.svc.cluster.local:9092")
    topic_tasks: str = os.getenv("TOPIC_TASKS", "easm.discovery.tasks")
    topic_raw: str = os.getenv("TOPIC_RAW", "easm.raw.observations")
    topic_dlq: str = os.getenv("TOPIC_DLQ", "easm.dlq.errors")
    redis_url: str = os.getenv("REDIS_URL", "redis://redis.easm.svc.cluster.local:6379/0")
    postgres_dsn: str = os.getenv(
        "POSTGRES_DSN",
        "postgresql://easm:easm_pass@postgres.easm.svc.cluster.local:5432/easm",
    )
    postgres_jdbc_url: str = os.getenv(
        "POSTGRES_JDBC_URL",
        "jdbc:postgresql://postgres.easm.svc.cluster.local:5432/easm",
    )
    postgres_user: str = os.getenv("POSTGRES_USER", "easm")
    postgres_password: str = os.getenv("POSTGRES_PASSWORD", "easm_pass")
    lakehouse_path: str = os.getenv("LAKEHOUSE_PATH", "/mnt/lakehouse")
    ct_rate_per_sec: float = float(os.getenv("CT_RATE_PER_SEC", "2.0"))
    ct_burst: int = int(os.getenv("CT_BURST", "5"))
    dns_rate_per_sec: float = float(os.getenv("DNS_RATE_PER_SEC", "25.0"))
    dns_burst: int = int(os.getenv("DNS_BURST", "50"))
    probe_concurrency: int = int(os.getenv("PROBE_CONCURRENCY", "8"))
    dns_nameservers: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    offline_mode: bool = os.getenv("OFFLINE_MODE", "true").lower() == "true"
