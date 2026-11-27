import json
import sqlite3
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from easm_pipeline.models import RawEnvelope, SilverObservation, make_deterministic_id, utc_now_iso
from easm_pipeline.resilience import CheckpointStore


class MedallionPipeline:
    """Handles Bronze append, Silver normalization, and Gold SCD Type 2 state."""

    def __init__(self, data_dir: Path, checkpoint_store: CheckpointStore):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.bronze_path = data_dir / "bronze_raw.jsonl"
        self.silver_path = data_dir / "silver_observations.jsonl"
        self.dlq_path = data_dir / "dlq_errors.jsonl"
        self.checkpoints = checkpoint_store
        self.gold_conn = sqlite3.connect(str(data_dir / "gold_easm.db"))
        self._init_gold_tables()

    def _init_gold_tables(self) -> None:
        self.gold_conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS gold_assets (
                asset_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                fqdn TEXT NOT NULL,
                latest_ips_json TEXT NOT NULL,
                cname_chain_json TEXT NOT NULL,
                is_shared_cdn INTEGER NOT NULL,
                detected_tech_json TEXT NOT NULL,
                tls_version TEXT,
                cert_sha256 TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS gold_exposure_history (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                fqdn TEXT NOT NULL,
                status TEXT NOT NULL,
                exposure_type TEXT,
                validation_tier TEXT NOT NULL,
                valid_from TEXT NOT NULL,
                valid_to TEXT,
                is_current INTEGER NOT NULL
            );
            """
        )
        self.gold_conn.commit()

    def write_bronze(self, envelopes: list[RawEnvelope]) -> list[RawEnvelope]:
        fresh: list[RawEnvelope] = []
        with self.bronze_path.open("a", encoding="utf-8") as handle:
            for envelope in envelopes:
                if self.checkpoints.is_duplicate(envelope.event_id):
                    continue
                handle.write(envelope.model_dump_json() + "\n")
                fresh.append(envelope)
        return fresh

    def normalize_to_silver(
        self, envelopes: list[RawEnvelope], max_error_rate: float = 0.10
    ) -> list[SilverObservation]:
        if not envelopes:
            return []
        silver_records: list[SilverObservation] = []
        dlq_count = 0
        with (
            self.silver_path.open("a", encoding="utf-8") as silver_handle,
            self.dlq_path.open("a", encoding="utf-8") as dlq_handle,
        ):
            for envelope in envelopes:
                try:
                    observation = self._map_envelope(envelope)
                    if observation is not None:
                        silver_handle.write(observation.model_dump_json() + "\n")
                        silver_records.append(observation)
                    self.checkpoints.mark_processed(envelope.event_id, utc_now_iso())
                except (ValidationError, KeyError, ValueError) as error:
                    dlq_count += 1
                    dlq_handle.write(
                        json.dumps(
                            {
                                "event_id": envelope.event_id,
                                "source": envelope.source,
                                "error": str(error),
                                "raw_payload": envelope.payload,
                                "failed_at": utc_now_iso(),
                            }
                        )
                        + "\n"
                    )

        error_rate = dlq_count / len(envelopes)
        if error_rate > max_error_rate:
            raise RuntimeError(
                f"FAIL-LOUD ALERT: Silver error rate {error_rate:.1%} exceeded "
                f"{max_error_rate:.1%}"
            )
        return silver_records

    def _map_envelope(self, envelope: RawEnvelope) -> SilverObservation | None:
        payload = envelope.payload
        if envelope.source == "ct_logs":
            return None
        fqdn = payload["fqdn"]
        asset_id = make_deterministic_id(envelope.tenant_id, fqdn)
        if envelope.source == "dns_probe":
            is_dangling = bool(payload.get("is_dangling_cname"))
            return SilverObservation(
                observation_id=envelope.event_id,
                asset_id=asset_id,
                tenant_id=envelope.tenant_id,
                fqdn=fqdn,
                source=envelope.source,
                a_records=payload.get("a_records", []),
                cname_chain=payload.get("cname_chain", []),
                txt_records=payload.get("txt_records", []),
                exposure_type="dangling_cname_takeover" if is_dangling else None,
                validation_tier=(
                    "confirmed_exploitable" if is_dangling else "informational"
                ),
                observed_at=envelope.collected_at,
            )
        if envelope.source == "tls_http_probe":
            exposure = payload.get("http_exposure")
            tier = "confirmed_exploitable" if exposure else "informational"
            if not exposure and payload.get("is_expired"):
                exposure = "expired_tls_certificate"
                tier = "confirmed_exploitable"
            elif not exposure and payload.get("weak_tls"):
                exposure = "deprecated_tls_protocol"
                tier = "potentially_affected"
            return SilverObservation(
                observation_id=envelope.event_id,
                asset_id=asset_id,
                tenant_id=envelope.tenant_id,
                fqdn=fqdn,
                source=envelope.source,
                tls_version=payload.get("tls_version"),
                cert_sha256=payload.get("cert_sha256"),
                cert_sans=payload.get("cert_sans", []),
                cert_not_after=payload.get("cert_not_after"),
                http_status=payload.get("http_status"),
                detected_tech=payload.get("detected_tech", []),
                is_shared_cdn=bool(payload.get("is_shared_cdn")),
                exposure_type=exposure,
                validation_tier=tier,
                observed_at=envelope.collected_at,
            )
        return None

    def upsert_gold(self, observations: list[SilverObservation]) -> None:
        by_asset: dict[str, list[SilverObservation]] = {}
        for observation in observations:
            by_asset.setdefault(observation.asset_id, []).append(observation)

        now = utc_now_iso()
        for asset_id, group in by_asset.items():
            sample = group[0]
            ips = sorted({ip for observation in group for ip in observation.a_records})
            cnames = next((item.cname_chain for item in group if item.cname_chain), [])
            tech = sorted(
                {item for observation in group for item in observation.detected_tech}
            )
            is_cdn = int(any(observation.is_shared_cdn for observation in group))
            tls_version = next((item.tls_version for item in group if item.tls_version), None)
            cert_fingerprint = next(
                (item.cert_sha256 for item in group if item.cert_sha256), None
            )
            self.gold_conn.execute(
                """
                INSERT INTO gold_assets (
                    asset_id, tenant_id, fqdn, latest_ips_json, cname_chain_json,
                    is_shared_cdn, detected_tech_json, tls_version, cert_sha256,
                    first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    latest_ips_json = CASE WHEN excluded.latest_ips_json != '[]'
                        THEN excluded.latest_ips_json ELSE gold_assets.latest_ips_json END,
                    cname_chain_json = CASE WHEN excluded.cname_chain_json != '[]'
                        THEN excluded.cname_chain_json ELSE gold_assets.cname_chain_json END,
                    is_shared_cdn = MAX(gold_assets.is_shared_cdn, excluded.is_shared_cdn),
                    detected_tech_json = CASE WHEN excluded.detected_tech_json != '[]'
                        THEN excluded.detected_tech_json ELSE gold_assets.detected_tech_json END,
                    tls_version = COALESCE(excluded.tls_version, gold_assets.tls_version),
                    cert_sha256 = COALESCE(excluded.cert_sha256, gold_assets.cert_sha256),
                    last_seen = excluded.last_seen
                """,
                (
                    asset_id,
                    sample.tenant_id,
                    sample.fqdn,
                    json.dumps(ips),
                    json.dumps(cnames),
                    is_cdn,
                    json.dumps(tech),
                    tls_version,
                    cert_fingerprint,
                    now,
                    now,
                ),
            )

            exposed = [item for item in group if item.exposure_type]
            new_status = "exposed" if exposed else "clean"
            new_exposure = exposed[0].exposure_type if exposed else None
            new_tier = exposed[0].validation_tier if exposed else "informational"
            current_row = self.gold_conn.execute(
                """
                SELECT history_id, status, exposure_type
                FROM gold_exposure_history
                WHERE asset_id = ? AND is_current = 1
                """,
                (asset_id,),
            ).fetchone()
            if current_row is None:
                self._insert_history(
                    asset_id, sample, new_status, new_exposure, new_tier, now
                )
            elif (current_row[1], current_row[2]) != (new_status, new_exposure):
                self.gold_conn.execute(
                    """
                    UPDATE gold_exposure_history
                    SET valid_to = ?, is_current = 0
                    WHERE history_id = ?
                    """,
                    (now, current_row[0]),
                )
                self._insert_history(
                    asset_id, sample, new_status, new_exposure, new_tier, now
                )
        self.gold_conn.commit()

    def _insert_history(
        self,
        asset_id: str,
        sample: SilverObservation,
        status: str,
        exposure_type: str | None,
        validation_tier: str,
        valid_from: str,
    ) -> None:
        self.gold_conn.execute(
            """
            INSERT INTO gold_exposure_history (
                asset_id, tenant_id, fqdn, status, exposure_type,
                validation_tier, valid_from, valid_to, is_current
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 1)
            """,
            (
                asset_id,
                sample.tenant_id,
                sample.fqdn,
                status,
                exposure_type,
                validation_tier,
                valid_from,
            ),
        )

    def get_current_inventory(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = self.gold_conn.execute(
            """
            SELECT a.fqdn, a.latest_ips_json, a.cname_chain_json, a.is_shared_cdn,
                   a.detected_tech_json, a.tls_version, h.status, h.exposure_type,
                   h.validation_tier
            FROM gold_assets a
            JOIN gold_exposure_history h
              ON a.asset_id = h.asset_id AND h.is_current = 1
            WHERE a.tenant_id = ?
            ORDER BY a.fqdn
            """,
            (tenant_id,),
        ).fetchall()
        return [
            {
                "fqdn": row[0],
                "ips": json.loads(row[1]),
                "cname_chain": json.loads(row[2]),
                "is_shared_cdn": bool(row[3]),
                "detected_tech": json.loads(row[4]),
                "tls_version": row[5],
                "status": row[6],
                "exposure_type": row[7],
                "validation_tier": row[8],
            }
            for row in rows
        ]

    def close(self) -> None:
        self.gold_conn.close()
