import pandas as pd
from pyspark.sql import DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import StringType, StructField, StructType

CLUSTER_OUTPUT_SCHEMA = StructType(
    [
        StructField("tenant_id", StringType(), False),
        StructField("fqdn", StringType(), False),
        StructField("cluster_id", StringType(), False),
        StructField("root_cause_node", StringType(), False),
    ]
)


def extract_infrastructure_edges(silver_df: DataFrame) -> DataFrame:
    """Extract directed infrastructure relationships from Silver observations."""
    fqdn_node = F.concat(F.lit("fqdn:"), F.col("fqdn"))
    shared_flag = F.coalesce(F.col("is_shared_cdn"), F.lit(False))
    ip_edges = (
        silver_df.filter(F.size(F.coalesce(F.col("a_records"), F.array())) > 0)
        .withColumn("a_record", F.explode("a_records"))
        .select(
            "tenant_id",
            fqdn_node.alias("src_node"),
            F.lit("RESOLVES_TO").alias("relation"),
            F.concat(F.lit("ip:"), F.col("a_record")).alias("dst_node"),
            shared_flag.alias("is_shared_infra"),
            "observed_at",
        )
    )
    cname_edges = silver_df.filter(F.size(F.coalesce(F.col("cname_chain"), F.array())) > 0).select(
        "tenant_id",
        fqdn_node.alias("src_node"),
        F.lit("CNAME_TO").alias("relation"),
        F.concat(F.lit("fqdn:"), F.element_at(F.col("cname_chain"), -1)).alias("dst_node"),
        shared_flag.alias("is_shared_infra"),
        "observed_at",
    )
    cert_edges = silver_df.filter(F.col("cert_sha256").isNotNull()).select(
        "tenant_id",
        fqdn_node.alias("src_node"),
        F.lit("PRESENTS_CERT").alias("relation"),
        F.concat(F.lit("cert:"), F.col("cert_sha256")).alias("dst_node"),
        shared_flag.alias("is_shared_infra"),
        "observed_at",
    )
    san_edges = (
        silver_df.filter(
            F.col("cert_sha256").isNotNull()
            & (F.size(F.coalesce(F.col("cert_sans"), F.array())) > 0)
        )
        .withColumn("cert_san", F.explode("cert_sans"))
        .select(
            "tenant_id",
            F.concat(F.lit("cert:"), F.col("cert_sha256")).alias("src_node"),
            F.lit("COVERS_SAN").alias("relation"),
            F.concat(
                F.lit("fqdn:"),
                F.regexp_replace(
                    F.lower(F.trim(F.col("cert_san"))),
                    r"^(\*\.)+|\.+$",
                    "",
                ),
            ).alias("dst_node"),
            shared_flag.alias("is_shared_infra"),
            "observed_at",
        )
        .filter(~F.col("dst_node").contains(" "))
    )
    return (
        ip_edges.unionByName(cname_edges)
        .unionByName(cert_edges)
        .unionByName(san_edges)
        .groupBy("tenant_id", "src_node", "relation", "dst_node")
        .agg(
            F.max("is_shared_infra").alias("is_shared_infra"),
            F.max("observed_at").alias("observed_at"),
        )
        .withColumn(
            "edge_id",
            F.substring(
                F.sha2(
                    F.concat_ws(
                        ":",
                        F.col("tenant_id"),
                        F.col("src_node"),
                        F.col("relation"),
                        F.col("dst_node"),
                    ),
                    256,
                ),
                1,
                20,
            ),
        )
    )


def resolve_clusters_and_root_causes(
    edges_df: DataFrame,
    max_hub_degree: int = 25,
) -> DataFrame:
    """Resolve connected components per tenant with deterministic labels."""
    non_shared = edges_df.filter(~F.col("is_shared_infra"))
    destination_degree = non_shared.groupBy("tenant_id", "dst_node").agg(
        F.countDistinct("src_node").alias("in_degree")
    )
    outgoing_degree = non_shared.groupBy("tenant_id", "src_node").agg(
        F.countDistinct("dst_node").alias("out_degree")
    )
    clean_edges = (
        non_shared.join(destination_degree, on=["tenant_id", "dst_node"], how="inner")
        .join(outgoing_degree, on=["tenant_id", "src_node"], how="inner")
        .filter((F.col("in_degree") <= max_hub_degree) & (F.col("out_degree") <= max_hub_degree))
        .select("tenant_id", "src_node", "relation", "dst_node")
    )

    def cluster_tenant_partition(pdf: pd.DataFrame) -> pd.DataFrame:
        if pdf.empty:
            return pd.DataFrame(columns=["tenant_id", "fqdn", "cluster_id", "root_cause_node"])

        tenant_id = str(pdf["tenant_id"].iloc[0])
        parent: dict[str, str] = {}

        def find(node: str) -> str:
            while parent[node] != node:
                parent[node] = parent[parent[node]]
                node = parent[node]
            return node

        def union(left: str, right: str) -> None:
            parent.setdefault(left, left)
            parent.setdefault(right, right)
            left_root = find(left)
            right_root = find(right)
            if left_root == right_root:
                return
            if left_root < right_root:
                parent[right_root] = left_root
            else:
                parent[left_root] = right_root

        priorities = {
            "CNAME_TO": 1,
            "PRESENTS_CERT": 2,
            "RESOLVES_TO": 3,
        }
        best_upstream: dict[str, tuple[int, str]] = {}
        for row in pdf.itertuples(index=False):
            source = str(row.src_node)
            relation = str(row.relation)
            destination = str(row.dst_node)
            union(source, destination)
            if source.startswith("fqdn:") and relation in priorities:
                candidate = (priorities[relation], destination)
                if source not in best_upstream or candidate < best_upstream[source]:
                    best_upstream[source] = candidate

        return pd.DataFrame(
            [
                (
                    tenant_id,
                    node.removeprefix("fqdn:"),
                    find(node),
                    best_upstream.get(node, (0, node))[1],
                )
                for node in parent
                if node.startswith("fqdn:")
            ],
            columns=["tenant_id", "fqdn", "cluster_id", "root_cause_node"],
        )

    return clean_edges.groupBy("tenant_id").applyInPandas(
        cluster_tenant_partition, schema=CLUSTER_OUTPUT_SCHEMA
    )
