import hashlib
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def make_deterministic_id(*parts: str) -> str:
    joined = ":".join(p.strip().lower() for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:20]


class RawEnvelope(BaseModel):
    """Immutable Bronze-layer wrapper around raw external collector payloads."""

    event_id: str
    tenant_id: str
    source: Literal["ct_logs", "dns_probe", "tls_http_probe"]
    entity_key: str
    collected_at: str = Field(default_factory=utc_now_iso)
    payload: dict[str, Any]


class SilverObservation(BaseModel):
    """Schema-enforced Silver record ready for cross-source entity resolution."""

    observation_id: str
    asset_id: str
    tenant_id: str
    fqdn: str
    source: str
    a_records: list[str] = Field(default_factory=list)
    cname_chain: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    tls_version: str | None = None
    cert_sha256: str | None = None
    cert_sans: list[str] = Field(default_factory=list)
    cert_not_after: str | None = None
    http_status: int | None = None
    detected_tech: list[str] = Field(default_factory=list)
    is_shared_cdn: bool = False
    exposure_type: str | None = None
    validation_tier: Literal[
        "informational", "potentially_affected", "confirmed_exploitable"
    ] = "informational"
    observed_at: str = Field(default_factory=utc_now_iso)

    @field_validator("fqdn")
    @classmethod
    def normalize_fqdn(cls, value: str) -> str:
        cleaned = value.strip().lower().rstrip(".")
        cleaned = cleaned.removeprefix("*.")
        if not cleaned or " " in cleaned or "." not in cleaned:
            raise ValueError(f"Invalid FQDN: {value!r}")
        return cleaned
