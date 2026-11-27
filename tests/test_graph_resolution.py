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
