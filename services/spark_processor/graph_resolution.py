from pyspark.sql import DataFrame
from pyspark.sql import functions as F


def extract_infrastructure_edges(silver_df: DataFrame) -> DataFrame:
    """Extract directed infrastructure relationships from Silver observations."""
    fqdn_node = F.concat(F.lit("fqdn:"), F.col("fqdn"))
    shared_flag = F.coalesce(F.col("is_shared_cdn"), F.lit(False))
    ip_edges = silver_df.filter(F.size(F.coalesce(F.col("a_records"), F.array())) > 0).select(
        "tenant_id",
        fqdn_node.alias("src_node"),
        F.lit("RESOLVES_TO").alias("relation"),
        F.concat(F.lit("ip:"), F.explode("a_records")).alias("dst_node"),
        shared_flag.alias("is_shared_infra"),
        "observed_at",
    )
    cname_edges = silver_df.filter(F.size(F.coalesce(F.col("cname_chain"), F.array())) > 0).select(
        "tenant_id",
        fqdn_node.alias("src_node"),
        F.lit("CNAME_TO").alias("relation"),
        F.concat(
            F.lit("fqdn:"),
            F.element_at(F.col("cname_chain"), -1),
        ).alias("dst_node"),
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
    return (
        ip_edges.unionByName(cname_edges)
        .unionByName(cert_edges)
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
    max_iterations: int = 6,
) -> DataFrame:
    """Resolve FQDN clusters while pruning shared and high-degree infrastructure."""
    non_shared_edges = edges_df.filter(~F.col("is_shared_infra"))
    destination_degree = non_shared_edges.groupBy("tenant_id", "dst_node").agg(
        F.countDistinct("src_node").alias("in_degree")
    )
    clean_edges = (
        non_shared_edges.join(destination_degree, on=["tenant_id", "dst_node"])
        .filter(F.col("in_degree") <= max_hub_degree)
        .select("tenant_id", "src_node", "relation", "dst_node")
    )
    undirected = clean_edges.select(
        "tenant_id", F.col("src_node").alias("u"), F.col("dst_node").alias("v")
    ).union(
        clean_edges.select("tenant_id", F.col("dst_node").alias("u"), F.col("src_node").alias("v"))
    )
    labels = undirected.select(
        "tenant_id", F.col("u").alias("node"), F.col("u").alias("label")
    ).distinct()
    for _ in range(max_iterations):
        propagated = (
            undirected.join(
                labels,
                (undirected.tenant_id == labels.tenant_id) & (undirected.u == labels.node),
            )
            .select(undirected.tenant_id, undirected.v.alias("node"), labels.label)
            .persist()
        )
        next_labels = (
            labels.union(propagated)
            .groupBy("tenant_id", "node")
            .agg(F.min("label").alias("label"))
            .persist()
        )
        changed = (
            labels.alias("old")
            .join(next_labels.alias("new"), on=["tenant_id", "node"])
            .filter(F.col("old.label") != F.col("new.label"))
            .count()
        )
        labels.unpersist()
        propagated.unpersist()
        labels = next_labels
        if changed == 0:
            break

    ranked_upstream = (
        clean_edges.filter(F.col("src_node").startswith("fqdn:"))
        .withColumn(
            "priority",
            F.when(F.col("relation") == "CNAME_TO", F.lit(1))
            .when(F.col("relation") == "PRESENTS_CERT", F.lit(2))
            .otherwise(F.lit(3)),
        )
        .groupBy("tenant_id", "src_node")
        .agg(F.min(F.struct("priority", "dst_node")).alias("best_upstream"))
        .select(
            "tenant_id",
            F.col("src_node").alias("node"),
            F.col("best_upstream.dst_node").alias("root_cause_node"),
        )
    )
    return (
        labels.filter(F.col("node").startswith("fqdn:"))
        .join(ranked_upstream, on=["tenant_id", "node"], how="left")
        .withColumn("fqdn", F.regexp_replace(F.col("node"), r"^fqdn:", ""))
        .select(
            "tenant_id",
            "fqdn",
            F.col("label").alias("cluster_id"),
            F.coalesce(F.col("root_cause_node"), F.col("node")).alias("root_cause_node"),
        )
    )
