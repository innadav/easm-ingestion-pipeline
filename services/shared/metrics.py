from prometheus_client import Counter, Histogram, start_http_server

# Labels are deliberately bounded: never use tenant_id or fqdn here.
DNS_QUERIES = Counter("easm_dns_queries_total", "DNS queries by type and status", ["rdtype", "status"])
PROBES_PROCESSED = Counter("easm_probes_total", "Probe tasks by outcome", ["outcome"])
PROBES_BLOCKED = Counter("easm_probes_blocked_total", "Probes refused by safety guards", ["reason"])
PROBE_DURATION = Histogram("easm_probe_duration_seconds", "Time to process one probe task")
RATE_LIMIT_WAIT = Histogram(
    "easm_rate_limit_wait_seconds", "Time spent waiting for rate-limit tokens", ["bucket"]
)
SCANS_REQUESTED = Counter("easm_scans_requested_total", "Scans accepted by the scheduler")
TASKS_PUBLISHED = Counter("easm_tasks_published_total", "Discovery tasks published")


def start_metrics_server(port: int) -> None:
    start_http_server(port)
