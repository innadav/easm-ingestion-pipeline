from pathlib import Path

import yaml


def test_infrastructure_uses_persistent_storage() -> None:
    root = Path(__file__).parents[1]
    namespace_documents = list(yaml.safe_load_all((root / "k8s/components/local-infra/pvcs.yaml").read_text()))
    claims = {
        document["metadata"]["name"]
        for document in namespace_documents
        if document["kind"] == "PersistentVolumeClaim"
    }
    assert {"lakehouse-pvc", "redpanda-pvc", "redis-pvc", "postgres-pvc"} <= claims

    infra_documents = list(yaml.safe_load_all((root / "k8s/components/local-infra/infra.yaml").read_text()))
    deployments = {
        document["metadata"]["name"]: document
        for document in infra_documents
        if document["kind"] == "Deployment"
    }
    expected_claims = {
        "redpanda": "redpanda-pvc",
        "redis": "redis-pvc",
        "postgres": "postgres-pvc",
    }
    for deployment_name, claim_name in expected_claims.items():
        volumes = deployments[deployment_name]["spec"]["template"]["spec"]["volumes"]
        assert any(
            volume.get("persistentVolumeClaim", {}).get("claimName") == claim_name
            for volume in volumes
        )

    redis_args = deployments["redis"]["spec"]["template"]["spec"]["containers"][0]["args"]
    assert "--appendonly" in redis_args
    assert "--appendfsync" in redis_args


def test_overlays_render_and_prod_has_no_local_infra() -> None:
    import shutil
    import subprocess

    import pytest

    if shutil.which("kubectl") is None:
        pytest.skip("kubectl not available")
    root = Path(__file__).parents[1]
    rendered = {}
    for overlay in ("local", "prod"):
        output = subprocess.run(
            ["kubectl", "kustomize", f"k8s/overlays/{overlay}"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        rendered[overlay] = [doc for doc in yaml.safe_load_all(output) if doc]
    local_names = {d["metadata"]["name"] for d in rendered["local"] if d["kind"] == "Deployment"}
    prod_names = {d["metadata"]["name"] for d in rendered["prod"] if d["kind"] == "Deployment"}
    assert {"redpanda", "redis", "postgres"} <= local_names
    assert not {"redpanda", "redis", "postgres"} & prod_names
    prod_config = next(d for d in rendered["prod"] if d["kind"] == "ConfigMap")
    assert prod_config["data"]["OBSERVABILITY_MODE"] == "production"
    assert prod_config["data"]["OFFLINE_MODE"] == "false"
