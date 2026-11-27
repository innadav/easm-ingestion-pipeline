import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class PipelineConfig:
    data_dir: Path = Path(os.getenv("EASM_DATA_DIR", "./data"))
    ct_rate_per_sec: float = float(os.getenv("EASM_CT_RATE_PER_SEC", "2.0"))
    ct_burst_capacity: int = int(os.getenv("EASM_CT_BURST", "5"))
    dns_nameservers: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    dns_concurrency: int = int(os.getenv("EASM_DNS_CONCURRENCY", "15"))
    max_silver_error_rate: float = float(os.getenv("EASM_MAX_ERROR_RATE", "0.10"))
    offline_mode: bool = False
