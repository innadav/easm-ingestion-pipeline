import os

from delta.tables import DeltaTable
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    ArrayType,
    BooleanType,
    IntegerType,
    StringType,
    StructField,
    StructType,
)

from spark_processor.graph_resolution import (
    extract_infrastructure_edges,
    resolve_clusters_and_root_causes,
)

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "redpanda.easm.svc.cluster.local:9092")
TOPIC_RAW = os.getenv("TOPIC_RAW", "easm.raw.observations")
TOPIC_DLQ = os.getenv("TOPIC_DLQ", "easm.dlq.errors")
LAKEHOUSE_PATH = os.getenv("LAKEHOUSE_PATH", "/mnt/lakehouse")
PG_JDBC_URL = os.getenv(
    "POSTGRES_JDBC_URL",
    "jdbc:postgresql://postgres.easm.svc.cluster.local:5432/easm",
)
PG_USER = os.getenv("POSTGRES_USER", "easm")
PG_PASSWORD = os.getenv("POSTGRES_PASSWORD", "easm_pass")

ENVELOPE_SCHEMA = StructType(
    [
        StructField("event_id", StringType(), False),
        StructField("tenant_id", StringType(), False),
        StructField("source", StringType(), False),
        StructField("entity_key", StringType(), False),
        StructField("collected_at", StringType(), False),
        StructField(
            "payload",
            StructType(
                [
                    StructField("fqdn", StringType(), False),
                    StructField("a_records", ArrayType(StringType()), True),
                    StructField("cname_chain", ArrayType(StringType()), True),
                    StructField("is_dangling_cname", BooleanType(), True),
                    StructField("http_status", IntegerType(), True),
                    StructField("detected_tech", ArrayType(StringType()), True),
                    StructField("is_shared_cdn", BooleanType(), True),
                    StructField("tls_version", StringType(), True),
                    StructField("cert_sha256", StringType(), True),
                    StructField("cert_sans", ArrayType(StringType()), True),
                    StructField("is_expired", BooleanType(), True),
                    StructField("weak_tls", BooleanType(), True),
                ]
            ),
            False,
        ),
    ]
)


def build_spark_session() -> SparkSession:
    return (
        SparkSession.builder.appName("EASM-Realtime-Medallion-Streaming")
        .config("spark.sql.extensions", "io.delta.sql.DeltaSparkSessionExtension")
        .config(
            "spark.sql.catalog.spark_catalog",
            "org.apache.spark.sql.delta.catalog.DeltaCatalog",
        )
        .config("spark.sql.adaptive.enabled", "true")
        .config("spark.sql.adaptive.skewJoin.enabled", "true")
        .config("spark.sql.shuffle.partitions", "8")
        .getOrCreate()
    )


def _aggregate_asset_batch(silver_df: DataFrame) -> DataFrame:
    return (
        silver_df.groupBy("asset_id", "tenant_id", "fqdn")
        .agg(
            F.flatten(F.collect_set(F.coalesce(F.col("a_records"), F.array()))).alias("latest_ips"),
            F.max(F.coalesce(F.col("is_shared_cdn"), F.lit(False))).alias("is_shared_cdn"),
            F.flatten(F.collect_set(F.coalesce(F.col("detected_tech"), F.array()))).alias(
                "detected_tech"
            ),
            F.max("tls_version").alias("tls_version"),
            F.max("cert_sha256").alias("cert_sha256"),
            F.max("exposure_type").alias("exposure_type"),
            F.max(
                F.when(F.col("validation_tier") == "confirmed_exploitable", 2)
                .when(F.col("validation_tier") == "potentially_affected", 1)
                .otherwise(0)
            ).alias("validation_tier_rank"),
            F.max("observed_at").alias("last_seen"),
        )
        .withColumn(
            "status",
            F.when(F.col("exposure_type").isNotNull(), F.lit("exposed")).otherwise(F.lit("clean")),
        )
        .withColumn(
            "validation_tier",
            F.when(F.col("validation_tier_rank") == 2, F.lit("confirmed_exploitable"))
            .when(F.col("validation_tier_rank") == 1, F.lit("potentially_affected"))
            .otherwise(F.lit("informational")),
        )
    )


def _source_finding_states(silver_df: DataFrame) -> DataFrame:
    return (
        silver_df.groupBy("asset_id", "tenant_id", "fqdn", "source")
        .agg(
            F.max(F.when(F.col("exposure_type").isNotNull(), True).otherwise(False)).alias(
                "has_finding"
            ),
            F.max(
                F.when(F.col("validation_tier") == "confirmed_exploitable", 2)
                .when(F.col("validation_tier") == "potentially_affected", 1)
                .otherwise(0)
            ).alias("validation_tier_rank"),
            F.max("exposure_type").alias("exposure_type"),
            F.max("observed_at").alias("detected_at"),
        )
        .withColumn(
            "validation_tier",
            F.when(F.col("validation_tier_rank") == 2, "confirmed_exploitable")
            .when(F.col("validation_tier_rank") == 1, "potentially_affected")
            .otherwise("informational"),
        )
    )


def _merge_delta_findings(
    spark: SparkSession, source_states: DataFrame, findings_path: str
) -> DataFrame:
    current_findings = source_states.filter(F.col("has_finding")).select(
        "asset_id",
        "tenant_id",
        "source",
        "exposure_type",
        "validation_tier",
        "detected_at",
    )
    if not DeltaTable.isDeltaTable(spark, findings_path):
        current_findings.write.format("delta").mode("overwrite").save(findings_path)
        return spark.read.format("delta").load(findings_path)

    findings = DeltaTable.forPath(spark, findings_path)
    (
        findings.alias("target")
        .merge(
            source_states.alias("source"),
            "target.asset_id = source.asset_id AND target.source = source.source",
        )
        .whenMatchedDelete()
        .execute()
    )
    current_findings.write.format("delta").mode("append").save(findings_path)
    return spark.read.format("delta").load(findings_path)


def _apply_effective_findings(aggregated: DataFrame, findings: DataFrame) -> DataFrame:
    effective = (
        findings.withColumn(
            "exposure_rank",
            F.when(F.col("validation_tier") == "confirmed_exploitable", 2)
            .when(F.col("validation_tier") == "potentially_affected", 1)
            .otherwise(0),
        )
        .groupBy("asset_id")
        .agg(
            F.max(
                F.struct(
                    "exposure_rank",
                    "exposure_type",
                    "validation_tier",
                    "detected_at",
                )
            ).alias("best_finding")
        )
        .select(
            "asset_id",
            F.col("best_finding.exposure_type").alias("effective_exposure_type"),
            F.col("best_finding.validation_tier").alias("effective_validation_tier"),
        )
    )
    return (
        aggregated.drop("exposure_type", "validation_tier", "status")
        .join(effective, on="asset_id", how="left")
        .withColumn("exposure_type", F.col("effective_exposure_type"))
        .withColumn(
            "validation_tier",
            F.coalesce(F.col("effective_validation_tier"), F.lit("informational")),
        )
        .withColumn(
            "status",
            F.when(F.col("exposure_type").isNotNull(), "exposed").otherwise("clean"),
        )
        .drop("effective_exposure_type", "effective_validation_tier")
    )


def _merge_graph_attributes(aggregated: DataFrame, clusters: DataFrame) -> DataFrame:
    return (
        aggregated.join(
            clusters.select("tenant_id", "fqdn", "cluster_id", "root_cause_node"),
            on=["tenant_id", "fqdn"],
            how="left",
        )
        .withColumn("cluster_id", F.col("cluster_id").cast("string"))
        .withColumn("root_cause_node", F.col("root_cause_node").cast("string"))
    )


def _upsert_gold_assets(spark: SparkSession, aggregated: DataFrame, gold_assets_path: str) -> None:
    columns = [
        "asset_id",
        "tenant_id",
        "fqdn",
        "cluster_id",
        "root_cause_node",
        "latest_ips",
        "is_shared_cdn",
        "detected_tech",
        "tls_version",
        "cert_sha256",
        "status",
        "exposure_type",
        "validation_tier",
        "first_seen",
        "last_seen",
    ]
    if not DeltaTable.isDeltaTable(spark, gold_assets_path):
        (
            aggregated.withColumn("first_seen", F.col("last_seen"))
            .select(*columns)
            .write.format("delta")
            .mode("overwrite")
            .save(gold_assets_path)
        )
        return

    (
        DeltaTable.forPath(spark, gold_assets_path)
        .alias("target")
        .merge(aggregated.alias("source"), "target.asset_id = source.asset_id")
        .whenMatchedUpdate(
            set={
                "cluster_id": F.coalesce(F.col("source.cluster_id"), F.col("target.cluster_id")),
                "root_cause_node": F.coalesce(
                    F.col("source.root_cause_node"),
                    F.col("target.root_cause_node"),
                ),
                "latest_ips": F.when(
                    F.size("source.latest_ips") > 0, F.col("source.latest_ips")
                ).otherwise(F.col("target.latest_ips")),
                "is_shared_cdn": F.greatest(
                    F.col("target.is_shared_cdn"),
                    F.col("source.is_shared_cdn"),
                ),
                "detected_tech": F.when(
                    F.size("source.detected_tech") > 0,
                    F.col("source.detected_tech"),
                ).otherwise(F.col("target.detected_tech")),
                "tls_version": F.coalesce(F.col("source.tls_version"), F.col("target.tls_version")),
                "cert_sha256": F.coalesce(F.col("source.cert_sha256"), F.col("target.cert_sha256")),
                "status": F.col("source.status"),
                "exposure_type": F.col("source.exposure_type"),
                "validation_tier": F.col("source.validation_tier"),
                "last_seen": F.col("source.last_seen"),
            }
        )
        .whenNotMatchedInsert(
            values={
                "asset_id": F.col("source.asset_id"),
                "tenant_id": F.col("source.tenant_id"),
                "fqdn": F.col("source.fqdn"),
                "cluster_id": F.col("source.cluster_id"),
                "root_cause_node": F.col("source.root_cause_node"),
                "latest_ips": F.col("source.latest_ips"),
                "is_shared_cdn": F.col("source.is_shared_cdn"),
                "detected_tech": F.col("source.detected_tech"),
                "tls_version": F.col("source.tls_version"),
                "cert_sha256": F.col("source.cert_sha256"),
                "status": F.col("source.status"),
                "exposure_type": F.col("source.exposure_type"),
                "validation_tier": F.col("source.validation_tier"),
                "first_seen": F.col("source.last_seen"),
                "last_seen": F.col("source.last_seen"),
            }
        )
        .execute()
    )


def _upsert_delta_edges(spark: SparkSession, edges: DataFrame, edges_path: str) -> None:
    if edges.isEmpty():
        return
    if not DeltaTable.isDeltaTable(spark, edges_path):
        edges.write.format("delta").mode("overwrite").save(edges_path)
        return
    (
        DeltaTable.forPath(spark, edges_path)
        .alias("target")
        .merge(edges.alias("source"), "target.edge_id = source.edge_id")
        .whenMatchedUpdate(
            set={
                "is_shared_infra": F.col("source.is_shared_infra"),
                "observed_at": F.col("source.observed_at"),
            }
        )
        .whenNotMatchedInsertAll()
        .execute()
    )


def _append_state_changes(spark: SparkSession, aggregated: DataFrame, history_path: str) -> None:
    candidates = aggregated.select(
        "asset_id",
        "tenant_id",
        "fqdn",
        "status",
        "exposure_type",
        "validation_tier",
        F.col("last_seen").alias("valid_from"),
        F.lit(None).cast("string").alias("valid_to"),
        F.lit(True).alias("is_current"),
    )
    if not DeltaTable.isDeltaTable(spark, history_path):
        candidates.write.format("delta").mode("overwrite").save(history_path)
        return

    history = DeltaTable.forPath(spark, history_path)
    current = history.toDF().filter(F.col("is_current"))
    changes = (
        candidates.alias("source")
        .join(current.alias("target"), on="asset_id", how="left")
        .filter(
            F.col("target.asset_id").isNull()
            | (F.col("source.status") != F.col("target.status"))
            | (
                F.coalesce(F.col("source.exposure_type"), F.lit(""))
                != F.coalesce(F.col("target.exposure_type"), F.lit(""))
            )
        )
        .select("source.*")
    )
    if changes.isEmpty():
        return
    (
        history.alias("target")
        .merge(
            changes.alias("source"),
            "target.asset_id = source.asset_id AND target.is_current = true",
        )
        .whenMatchedUpdate(
            set={
                "valid_to": F.col("source.valid_from"),
                "is_current": F.lit(False),
            }
        )
        .execute()
    )
    changes.write.format("delta").mode("append").save(history_path)


def _sync_postgres(
    spark: SparkSession,
    aggregated: DataFrame,
    source_states: DataFrame,
    edges: DataFrame,
) -> None:
    postgres_frame = aggregated.select(
        "asset_id",
        "tenant_id",
        "fqdn",
        "cluster_id",
        "root_cause_node",
        F.to_json("latest_ips").alias("latest_ips_json"),
        "is_shared_cdn",
        F.to_json("detected_tech").alias("detected_tech_json"),
        "tls_version",
        "cert_sha256",
        "status",
        "exposure_type",
        "validation_tier",
        "last_seen",
    )
    (
        postgres_frame.write.format("jdbc")
        .option("url", PG_JDBC_URL)
        .option("dbtable", "gold_assets_staging")
        .option("user", PG_USER)
        .option("password", PG_PASSWORD)
        .option("driver", "org.postgresql.Driver")
        .mode("overwrite")
        .save()
    )
    findings_frame = source_states.filter(F.col("has_finding")).select(
        "asset_id",
        "tenant_id",
        "source",
        "exposure_type",
        "validation_tier",
        F.col("detected_at"),
    )
    source_state_frame = source_states.select("asset_id", "source", "has_finding")
    edge_frame = edges.select(
        "edge_id",
        "tenant_id",
        "src_node",
        "relation",
        "dst_node",
        "is_shared_infra",
        "observed_at",
    )
    for frame, table in (
        (findings_frame, "gold_asset_findings_staging"),
        (source_state_frame, "gold_asset_sources_staging"),
        (edge_frame, "gold_asset_edges_staging"),
    ):
        (
            frame.write.format("jdbc")
            .option("url", PG_JDBC_URL)
            .option("dbtable", table)
            .option("user", PG_USER)
            .option("password", PG_PASSWORD)
            .option("driver", "org.postgresql.Driver")
            .mode("overwrite")
            .save()
        )
    connection = spark._jvm.java.sql.DriverManager.getConnection(PG_JDBC_URL, PG_USER, PG_PASSWORD)
    connection.setAutoCommit(False)
    try:
        statement = connection.createStatement()
        try:
            statement.execute(
                """
                CREATE TABLE IF NOT EXISTS gold_assets (
                    asset_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    fqdn TEXT NOT NULL,
                    cluster_id TEXT,
                    root_cause_node TEXT,
                    latest_ips_json TEXT NOT NULL,
                    is_shared_cdn BOOLEAN NOT NULL,
                    detected_tech_json TEXT NOT NULL,
                    tls_version TEXT,
                    cert_sha256 TEXT,
                    status TEXT NOT NULL,
                    exposure_type TEXT,
                    validation_tier TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                )
                """
            )
            statement.execute("ALTER TABLE gold_assets ADD COLUMN IF NOT EXISTS cluster_id TEXT")
            statement.execute(
                "ALTER TABLE gold_assets ADD COLUMN IF NOT EXISTS root_cause_node TEXT"
            )
            statement.execute(
                """
                CREATE TABLE IF NOT EXISTS gold_asset_findings (
                    asset_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    exposure_type TEXT NOT NULL,
                    validation_tier TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    PRIMARY KEY (asset_id, source, exposure_type)
                );
                CREATE TABLE IF NOT EXISTS gold_asset_edges (
                    edge_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    src_node TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    dst_node TEXT NOT NULL,
                    is_shared_infra BOOLEAN NOT NULL DEFAULT FALSE,
                    observed_at TEXT NOT NULL
                )
                """
            )
            statement.execute(
                """
                DELETE FROM gold_asset_findings existing
                USING gold_asset_sources_staging incoming
                WHERE existing.asset_id = incoming.asset_id
                  AND existing.source = incoming.source;

                INSERT INTO gold_asset_findings (
                    asset_id, tenant_id, source, exposure_type,
                    validation_tier, detected_at
                )
                SELECT
                    asset_id, tenant_id, source, exposure_type,
                    validation_tier, detected_at
                FROM gold_asset_findings_staging
                ON CONFLICT (asset_id, source, exposure_type) DO UPDATE SET
                    validation_tier = EXCLUDED.validation_tier,
                    detected_at = EXCLUDED.detected_at;

                INSERT INTO gold_asset_edges (
                    edge_id, tenant_id, src_node, relation, dst_node,
                    is_shared_infra, observed_at
                )
                SELECT
                    edge_id, tenant_id, src_node, relation, dst_node,
                    is_shared_infra, observed_at
                FROM gold_asset_edges_staging
                ON CONFLICT (edge_id) DO UPDATE SET
                    is_shared_infra = EXCLUDED.is_shared_infra,
                    observed_at = EXCLUDED.observed_at
                """
            )
            statement.execute(
                """
                INSERT INTO gold_assets (
                    asset_id, tenant_id, fqdn, cluster_id, root_cause_node,
                    latest_ips_json, is_shared_cdn,
                    detected_tech_json, tls_version, cert_sha256, status,
                    exposure_type, validation_tier, first_seen, last_seen
                )
                SELECT
                    asset_id, tenant_id, fqdn, cluster_id, root_cause_node,
                    latest_ips_json, is_shared_cdn,
                    detected_tech_json, tls_version, cert_sha256, status,
                    exposure_type, validation_tier, last_seen, last_seen
                FROM gold_assets_staging
                ON CONFLICT (asset_id) DO UPDATE SET
                    cluster_id = COALESCE(EXCLUDED.cluster_id, gold_assets.cluster_id),
                    root_cause_node = COALESCE(
                        EXCLUDED.root_cause_node, gold_assets.root_cause_node
                    ),
                    latest_ips_json = CASE
                        WHEN EXCLUDED.latest_ips_json != '[]'
                        THEN EXCLUDED.latest_ips_json
                        ELSE gold_assets.latest_ips_json END,
                    is_shared_cdn = (
                        gold_assets.is_shared_cdn OR EXCLUDED.is_shared_cdn
                    ),
                    detected_tech_json = CASE
                        WHEN EXCLUDED.detected_tech_json != '[]'
                        THEN EXCLUDED.detected_tech_json
                        ELSE gold_assets.detected_tech_json END,
                    tls_version = COALESCE(
                        EXCLUDED.tls_version, gold_assets.tls_version
                    ),
                    cert_sha256 = COALESCE(
                        EXCLUDED.cert_sha256, gold_assets.cert_sha256
                    ),
                    status = EXCLUDED.status,
                    exposure_type = EXCLUDED.exposure_type,
                    validation_tier = EXCLUDED.validation_tier,
                    last_seen = EXCLUDED.last_seen
                """
            )
            statement.execute(
                """
                UPDATE gold_assets current_asset
                SET
                    status = 'exposed',
                    exposure_type = best.exposure_type,
                    validation_tier = best.validation_tier
                FROM (
                    SELECT DISTINCT ON (asset_id)
                        asset_id, exposure_type, validation_tier
                    FROM gold_asset_findings
                    ORDER BY
                        asset_id,
                        CASE validation_tier
                            WHEN 'confirmed_exploitable' THEN 2
                            WHEN 'potentially_affected' THEN 1
                            ELSE 0
                        END DESC,
                        detected_at DESC
                ) best
                WHERE current_asset.asset_id = best.asset_id
                  AND EXISTS (
                    SELECT 1 FROM gold_assets_staging incoming
                    WHERE incoming.asset_id = current_asset.asset_id
                  );

                UPDATE gold_assets current_asset
                SET
                    status = 'clean',
                    exposure_type = NULL,
                    validation_tier = 'informational'
                WHERE EXISTS (
                    SELECT 1 FROM gold_assets_staging incoming
                    WHERE incoming.asset_id = current_asset.asset_id
                ) AND NOT EXISTS (
                    SELECT 1 FROM gold_asset_findings finding
                    WHERE finding.asset_id = current_asset.asset_id
                )
                """
            )
            connection.commit()
        finally:
            statement.close()
    finally:
        connection.close()


def process_silver_microbatch(silver_df: DataFrame, batch_id: int) -> None:
    if silver_df.isEmpty():
        return
    spark = silver_df.sparkSession
    silver_path = f"{LAKEHOUSE_PATH}/silver/observations"
    gold_assets_path = f"{LAKEHOUSE_PATH}/gold/assets"
    gold_history_path = f"{LAKEHOUSE_PATH}/gold/exposure_history"
    gold_findings_path = f"{LAKEHOUSE_PATH}/gold/findings"
    gold_edges_path = f"{LAKEHOUSE_PATH}/gold/infrastructure_edges"

    silver_df.write.format("delta").mode("append").save(silver_path)
    aggregated = _aggregate_asset_batch(silver_df)
    source_states = _source_finding_states(silver_df)
    findings = _merge_delta_findings(spark, source_states, gold_findings_path)
    aggregated = _apply_effective_findings(aggregated, findings)
    edges = extract_infrastructure_edges(silver_df)
    clusters = resolve_clusters_and_root_causes(edges)
    aggregated = _merge_graph_attributes(aggregated, clusters)
    _upsert_delta_edges(spark, edges, gold_edges_path)
    _upsert_gold_assets(spark, aggregated, gold_assets_path)
    _append_state_changes(spark, aggregated, gold_history_path)
    _sync_postgres(spark, aggregated, source_states, edges)
    spark.sparkContext.setJobDescription(f"EASM micro-batch {batch_id} complete")


def _silver_stream(valid_envelopes: DataFrame) -> DataFrame:
    return (
        valid_envelopes.withColumn(
            "fqdn",
            F.regexp_replace(F.lower(F.trim(F.col("payload.fqdn"))), r"^(\*\.)+|\.+$", ""),
        )
        .withColumn(
            "asset_id",
            F.substring(
                F.sha2(F.concat_ws(":", F.col("tenant_id"), F.col("fqdn")), 256),
                1,
                20,
            ),
        )
        .withColumn("a_records", F.col("payload.a_records"))
        .withColumn("cname_chain", F.col("payload.cname_chain"))
        .withColumn("is_shared_cdn", F.col("payload.is_shared_cdn"))
        .withColumn("detected_tech", F.col("payload.detected_tech"))
        .withColumn("tls_version", F.col("payload.tls_version"))
        .withColumn("cert_sha256", F.col("payload.cert_sha256"))
        .withColumn(
            "exposure_type",
            F.when(
                F.col("payload.is_dangling_cname"),
                F.lit("dangling_cname_takeover"),
            )
            .when(F.col("payload.is_expired"), F.lit("expired_tls_certificate"))
            .when(F.col("payload.weak_tls"), F.lit("deprecated_tls_protocol"))
            .otherwise(F.lit(None).cast("string")),
        )
        .withColumn(
            "validation_tier",
            F.when(
                F.col("payload.is_dangling_cname") | F.col("payload.is_expired"),
                F.lit("confirmed_exploitable"),
            )
            .when(F.col("payload.weak_tls"), F.lit("potentially_affected"))
            .otherwise(F.lit("informational")),
        )
        .select(
            "event_id",
            "asset_id",
            "tenant_id",
            "fqdn",
            "source",
            "a_records",
            "cname_chain",
            "is_shared_cdn",
            "detected_tech",
            "tls_version",
            "cert_sha256",
            "exposure_type",
            "validation_tier",
            F.col("collected_at").alias("observed_at"),
        )
    )


def main() -> None:
    spark = build_spark_session()
    spark.sparkContext.setLogLevel("WARN")
    raw_kafka = (
        spark.readStream.format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BROKERS)
        .option("subscribe", TOPIC_RAW)
        .option("startingOffsets", "earliest")
        .option("failOnDataLoss", "false")
        .load()
    )
    parsed = raw_kafka.select(
        F.col("value").cast("string").alias("raw_json"),
        F.from_json(F.col("value").cast("string"), ENVELOPE_SCHEMA).alias("data"),
    )
    invalid_required_fields = (
        F.col("data.event_id").isNull()
        | F.col("data.tenant_id").isNull()
        | F.col("data.source").isNull()
        | F.col("data.entity_key").isNull()
        | F.col("data.collected_at").isNull()
        | F.col("data.payload.fqdn").isNull()
    )
    invalid_stream = parsed.filter(F.col("data").isNull() | invalid_required_fields).select(
        F.to_json(
            F.struct(
                F.lit("schema_parse_failure").alias("error"),
                F.col("raw_json").alias("raw_message"),
                F.current_timestamp().cast("string").alias("failed_at"),
            )
        ).alias("value")
    )
    dlq_query = (
        invalid_stream.writeStream.format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BROKERS)
        .option("topic", TOPIC_DLQ)
        .option("checkpointLocation", f"{LAKEHOUSE_PATH}/checkpoints/dlq")
        .start()
    )
    valid_envelopes = parsed.filter(F.col("data").isNotNull() & ~invalid_required_fields).select(
        "data.*"
    )
    bronze_query = (
        valid_envelopes.withColumn("ingest_date", F.to_date("collected_at"))
        .writeStream.format("delta")
        .outputMode("append")
        .partitionBy("ingest_date")
        .option("checkpointLocation", f"{LAKEHOUSE_PATH}/checkpoints/bronze")
        .start(f"{LAKEHOUSE_PATH}/bronze/observations")
    )
    gold_query = (
        _silver_stream(valid_envelopes)
        .writeStream.foreachBatch(process_silver_microbatch)
        .option(
            "checkpointLocation",
            f"{LAKEHOUSE_PATH}/checkpoints/silver_gold",
        )
        .trigger(processingTime="5 seconds")
        .start()
    )
    try:
        spark.streams.awaitAnyTermination()
    finally:
        dlq_query.stop()
        bronze_query.stop()
        gold_query.stop()


if __name__ == "__main__":
    main()
