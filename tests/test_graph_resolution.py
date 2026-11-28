import shutil
import subprocess

import pytest
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    ArrayType,
    BooleanType,
    StringType,
    StructField,
    StructType,
)
from spark_processor.graph_resolution import (
    extract_infrastructure_edges,
    resolve_clusters_and_root_causes,
)
from spark_processor.stream_job import _source_finding_states


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


def test_graph_clustering_prunes_shared_cdn_hubs(spark: SparkSession) -> None:
    rows = [
        (
            "t1",
            "app1.acme.com",
            ["10.20.30.40"],
            ["internal-alb.elb.amazonaws.com"],
            "shared-cert",
            ["app1.acme.com", "app2.acme.com"],
            False,
            "2026-11-27T10:00:00Z",
        ),
        (
            "t1",
            "app2.acme.com",
            ["10.20.30.40"],
            ["internal-alb.elb.amazonaws.com"],
            "shared-cert",
            ["app1.acme.com", "app2.acme.com"],
            False,
            "2026-11-27T10:00:00Z",
        ),
        (
            "t1",
            "www.acme.com",
            ["104.16.132.229"],
            ["www.acme.com.cdn.cloudflare.net"],
            None,
            [],
            True,
            "2026-11-27T10:00:00Z",
        ),
    ]
    schema = StructType(
        [
            StructField("tenant_id", StringType(), False),
            StructField("fqdn", StringType(), False),
            StructField("a_records", ArrayType(StringType()), False),
            StructField("cname_chain", ArrayType(StringType()), False),
            StructField("cert_sha256", StringType(), True),
            StructField("cert_sans", ArrayType(StringType()), False),
            StructField("is_shared_cdn", BooleanType(), False),
            StructField("observed_at", StringType(), False),
        ]
    )
    edges = extract_infrastructure_edges(spark.createDataFrame(rows, schema))
    assert edges.filter(F.col("relation") == "COVERS_SAN").count() == 2

    clusters = {
        row["fqdn"]: (row["cluster_id"], row["root_cause_node"])
        for row in resolve_clusters_and_root_causes(edges).collect()
    }
    assert clusters["app1.acme.com"][0] == clusters["app2.acme.com"][0]
    assert clusters["app1.acme.com"][1] == "fqdn:internal-alb.elb.amazonaws.com"
    assert "www.acme.com" not in clusters


def test_latest_source_observation_controls_finding_state(
    spark: SparkSession,
) -> None:
    rows = [
        (
            "event-old",
            "asset-1",
            "t1",
            "app.acme.com",
            "dns_probe",
            "dangling_cname_takeover",
            "confirmed_exploitable",
            "2026-11-28T10:00:00Z",
        ),
        (
            "event-new",
            "asset-1",
            "t1",
            "app.acme.com",
            "dns_probe",
            None,
            "informational",
            "2026-11-28T10:00:05Z",
        ),
    ]
    schema = StructType(
        [
            StructField("event_id", StringType(), False),
            StructField("asset_id", StringType(), False),
            StructField("tenant_id", StringType(), False),
            StructField("fqdn", StringType(), False),
            StructField("source", StringType(), False),
            StructField("exposure_type", StringType(), True),
            StructField("validation_tier", StringType(), False),
            StructField("observed_at", StringType(), False),
        ]
    )
    state = _source_finding_states(spark.createDataFrame(rows, schema)).collect()[0]

    assert state["has_finding"] is False
    assert state["exposure_type"] is None
    assert state["validation_tier"] == "informational"


def test_certificate_san_fanout_is_pruned(
    spark: SparkSession,
) -> None:
    sans = [f"app-{index}.acme.com" for index in range(26)]
    schema = StructType(
        [
            StructField("tenant_id", StringType(), False),
            StructField("fqdn", StringType(), False),
            StructField("a_records", ArrayType(StringType()), False),
            StructField("cname_chain", ArrayType(StringType()), False),
            StructField("cert_sha256", StringType(), True),
            StructField("cert_sans", ArrayType(StringType()), False),
            StructField("is_shared_cdn", BooleanType(), False),
            StructField("observed_at", StringType(), False),
        ]
    )
    silver = spark.createDataFrame(
        [
            (
                "t1",
                "issuer.acme.com",
                [],
                [],
                "large-cert",
                sans,
                False,
                "2026-11-28T10:00:00Z",
            )
        ],
        schema,
    )

    clusters = resolve_clusters_and_root_causes(extract_infrastructure_edges(silver))
    fqdns = {row["fqdn"] for row in clusters.collect()}
    assert fqdns == {"issuer.acme.com"}
    assert not fqdns.intersection(sans)
