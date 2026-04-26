from __future__ import annotations

from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field


class CrashTaxonomy(BaseModel):
    signal_class: str = "ERROR_UNKNOWN"
    crash_site_kind: str = "unknown"
    memory_region: str = "unknown"
    control_flow_state: str = "unknown"
    discovery_depth: str = "unknown"
    input_class: str = "unknown"


class CrashRaw(BaseModel):
    path: Path
    fuzzer_instance: str
    signal: int | None = None
    discovery_time: datetime | None = None
    input_sha1: str
    size: int


class Crash(BaseModel):
    raw: CrashRaw
    duplicate_count: int = 1
    duplicate_paths: list[Path] = Field(default_factory=list)
    stack_hash: str | None = None

    cwe_distribution: dict[str, float] = Field(default_factory=dict)
    taxonomy: CrashTaxonomy = Field(default_factory=CrashTaxonomy)
    exploitability: str = "UNKNOWN"
    evidence: str = ""

    severity_score: float = 0.0
    severity_level: str = "LOW"

    backtrace: list[str] = Field(default_factory=list)
    faulting_instruction: str | None = None
    faulting_address: int | None = None
    gdb_output: str = ""

    crash_function: str | None = None
    crash_location: str | None = None

    @property
    def top_cwe(self) -> str:
        if not self.cwe_distribution:
            return "unknown"
        return max(self.cwe_distribution.items(), key=lambda kv: kv[1])[0]


class FuzzerStats(BaseModel):
    fuzzer_instance: str
    target_binary: str | None = None
    command_line: str | None = None
    start_time: datetime | None = None
    last_update: datetime | None = None
    execs_done: int = 0
    execs_per_sec: float = 0.0
    paths_total: int = 0
    unique_crashes: int = 0
    unique_hangs: int = 0
    afl_version: str | None = None
    raw: dict[str, str] = Field(default_factory=dict)


class PlotPoint(BaseModel):
    unix_time: int
    cycles_done: int = 0
    cur_path: int = 0
    paths_total: int = 0
    pending_total: int = 0
    pending_favs: int = 0
    map_size: float = 0.0
    unique_crashes: int = 0
    unique_hangs: int = 0
    max_depth: int = 0
    execs_per_sec: float = 0.0


class Report(BaseModel):
    target: str
    generated_at: datetime
    fuzzer_stats: list[FuzzerStats] = Field(default_factory=list)
    plot_points: list[PlotPoint] = Field(default_factory=list)
    crashes: list[Crash] = Field(default_factory=list)
    total_raw_crashes: int = 0

    @property
    def unique_count(self) -> int:
        return len(self.crashes)

    @property
    def critical_count(self) -> int:
        return sum(1 for c in self.crashes if c.severity_level == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for c in self.crashes if c.severity_level == "HIGH")
