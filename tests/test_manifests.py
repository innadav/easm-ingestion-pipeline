from pathlib import Path

import yaml


def test_infrastructure_uses_persistent_storage() -> None:
    root = Path(__file__).parents[1]
    namespace_documents = list(yaml.safe_load_all((root / "k8s/00-namespace.yaml").read_text()))
    claims = {
        document["metadata"]["name"]
        for document in namespace_documents
        if document["kind"] == "PersistentVolumeClaim"
    }
    assert {"lakehouse-pvc", "redpanda-pvc", "redis-pvc", "postgres-pvc"} <= claims

    infra_documents = list(yaml.safe_load_all((root / "k8s/01-infra.yaml").read_text()))
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
