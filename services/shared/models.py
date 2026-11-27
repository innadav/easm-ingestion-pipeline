import hashlib
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def make_deterministic_id(*parts: str) -> str:
    joined = ":".join(part.strip().lower() for part in parts)
    return hashlib.sha256(joined.encode()).hexdigest()[:20]


class DiscoveryTask(BaseModel):
    """Message published to the discovery task topic."""

    task_id: str
    tenant_id: str
    root_domain: str
    fqdn: str
    enqueued_at: str = Field(default_factory=utc_now_iso)

    @field_validator("fqdn", "root_domain")
    @classmethod
    def clean_hostname(cls, value: str) -> str:
        cleaned = value.strip().lower().rstrip(".").removeprefix("*.")
        if not cleaned or " " in cleaned or "." not in cleaned:
            raise ValueError(f"Invalid hostname: {value!r}")
        return cleaned


class RawEnvelope(BaseModel):
    """Immutable probe observation published to the raw topic."""

    event_id: str
    tenant_id: str
    source: Literal["dns_probe", "tls_http_probe"]
    entity_key: str
    collected_at: str = Field(default_factory=utc_now_iso)
    payload: dict[str, Any]
