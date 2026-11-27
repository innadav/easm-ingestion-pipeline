from pathlib import Path

import pytest

from easm_pipeline.config import PipelineConfig
from easm_pipeline.main import run_collection_cycle
from easm_pipeline.models import RawEnvelope, SilverObservation
from easm_pipeline.pipeline import MedallionPipeline
from easm_pipeline.resilience import CheckpointStore


def test_fqdn_normalization_strips_wildcards_and_trailing_dots() -> None:
    observation = SilverObservation(
        observation_id="obs_1",
        asset_id="asset_1",
        tenant_id="tenant_a",
        fqdn="  *.API.Example.COM. ",
        source="dns_probe",
    )
    assert observation.fqdn == "api.example.com"
    with pytest.raises(ValueError):
        SilverObservation(
            observation_id="obs_2",
            asset_id="asset_2",
            tenant_id="tenant_a",
            fqdn="invalid host",
            source="dns_probe",
        )


def test_scd2_state_transitions_and_idempotency(tmp_path: Path) -> None:
    checkpoints = CheckpointStore(tmp_path / "state.db")
    pipeline = MedallionPipeline(tmp_path, checkpoints)
    exposed = RawEnvelope(
        event_id="evt_1",
        tenant_id="tenant_a",
        source="dns_probe",
        entity_key="app.example.com",
        payload={
            "fqdn": "app.example.com",
            "a_records": [],
            "cname_chain": ["app.azurewebsites.net"],
            "is_dangling_cname": True,
        },
    )
    bronze = pipeline.write_bronze([exposed])
    assert len(bronze) == 1
    pipeline.upsert_gold(pipeline.normalize_to_silver(bronze))
    assert pipeline.write_bronze([exposed]) == []

    remediated = RawEnvelope(
        event_id="evt_2",
        tenant_id="tenant_a",
        source="dns_probe",
        entity_key="app.example.com",
        payload={
            "fqdn": "app.example.com",
            "a_records": ["20.30.40.50"],
            "cname_chain": ["app.azurewebsites.net"],
            "is_dangling_cname": False,
        },
    )
    pipeline.upsert_gold(
        pipeline.normalize_to_silver(pipeline.write_bronze([remediated]))
    )
    history = pipeline.gold_conn.execute(
        """
        SELECT status, is_current, valid_to
        FROM gold_exposure_history
        ORDER BY history_id
        """
    ).fetchall()
    assert len(history) == 2
    assert history[0][0] == "exposed" and history[0][1] == 0
    assert history[0][2] is not None
    assert history[1][0] == "clean" and history[1][1] == 1
    assert history[1][2] is None
    pipeline.close()
    checkpoints.close()


def test_fail_loud_dead_letter_threshold(tmp_path: Path) -> None:
    checkpoints = CheckpointStore(tmp_path / "state.db")
    pipeline = MedallionPipeline(tmp_path, checkpoints)
    invalid = RawEnvelope(
        event_id="evt_bad",
        tenant_id="tenant_a",
        source="dns_probe",
        entity_key="broken",
        payload={"fqdn": "not a valid fqdn"},
    )
    with pytest.raises(RuntimeError, match="FAIL-LOUD ALERT"):
        pipeline.normalize_to_silver([invalid], max_error_rate=0.05)
    assert (tmp_path / "dlq_errors.jsonl").exists()
    pipeline.close()
    checkpoints.close()


async def test_offline_end_to_end_cycle(tmp_path: Path) -> None:
    inventory = await run_collection_cycle(
        "tenant_acme",
        "example.com",
        PipelineConfig(data_dir=tmp_path, offline_mode=True),
    )
    by_fqdn = {item["fqdn"]: item for item in inventory}
    assert by_fqdn["cdn-portal.example.com"]["is_shared_cdn"] is True
    assert by_fqdn["legacy-staging.example.com"]["status"] == "exposed"
    assert (
        by_fqdn["legacy-staging.example.com"]["exposure_type"]
        == "dangling_cname_takeover"
    )
    assert by_fqdn["www.example.com"]["status"] == "clean"
