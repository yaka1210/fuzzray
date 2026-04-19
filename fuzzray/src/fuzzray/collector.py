from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path

from fuzzray.models import CrashRaw, FuzzerStats, PlotPoint

SIG_RE = re.compile(r"sig[:_](\d+)", re.IGNORECASE)


def _sha1(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_fuzzer_stats(path: Path, instance: str) -> FuzzerStats:
    raw: dict[str, str] = {}
    for line in path.read_text(errors="replace").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            raw[k.strip()] = v.strip()

    def _int(key: str) -> int:
        try:
            return int(raw.get(key, "0"))
        except ValueError:
            return 0

    def _float(key: str) -> float:
        try:
            return float(raw.get(key, "0"))
        except ValueError:
            return 0.0

    def _ts(key: str) -> datetime | None:
        v = raw.get(key)
        if not v:
            return None
        try:
            return datetime.fromtimestamp(int(v))
        except (ValueError, OSError):
            return None

    return FuzzerStats(
        fuzzer_instance=instance,
        target_binary=raw.get("target_mode") or raw.get("command_line", "").split()[-1] or None,
        command_line=raw.get("command_line"),
        start_time=_ts("start_time"),
        last_update=_ts("last_update"),
        execs_done=_int("execs_done"),
        execs_per_sec=_float("execs_per_sec"),
        paths_total=_int("corpus_count") or _int("paths_total"),
        unique_crashes=_int("saved_crashes") or _int("unique_crashes"),
        unique_hangs=_int("saved_hangs") or _int("unique_hangs"),
        afl_version=raw.get("afl_version") or raw.get("fuzzer_version"),
        raw=raw,
    )


def _parse_plot_data(path: Path) -> list[PlotPoint]:
    points: list[PlotPoint] = []
    lines = path.read_text(errors="replace").splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 9:
            continue
        try:
            points.append(
                PlotPoint(
                    unix_time=int(parts[0]),
                    cycles_done=int(parts[1]) if parts[1] else 0,
                    cur_path=int(parts[2]) if parts[2] else 0,
                    paths_total=int(parts[3]) if parts[3] else 0,
                    pending_total=int(parts[4]) if parts[4] else 0,
                    pending_favs=int(parts[5]) if parts[5] else 0,
                    map_size=float(parts[6].rstrip("%")) if parts[6] else 0.0,
                    unique_crashes=int(parts[7]) if parts[7] else 0,
                    unique_hangs=int(parts[8]) if parts[8] else 0,
                    max_depth=int(parts[9]) if len(parts) > 9 and parts[9] else 0,
                    execs_per_sec=float(parts[10]) if len(parts) > 10 and parts[10] else 0.0,
                )
            )
        except ValueError:
            continue
    return points


def _parse_crash_name(name: str) -> int | None:
    m = SIG_RE.search(name)
    return int(m.group(1)) if m else None


def _iter_instances(afl_out: Path) -> list[tuple[str, Path]]:
    if (afl_out / "fuzzer_stats").exists() or (afl_out / "crashes").exists():
        return [(afl_out.name, afl_out)]
    return [(p.name, p) for p in sorted(afl_out.iterdir()) if p.is_dir()]


def collect(
    afl_out: Path,
) -> tuple[list[CrashRaw], list[FuzzerStats], list[PlotPoint]]:
    raw_crashes: list[CrashRaw] = []
    fuzzer_stats: list[FuzzerStats] = []
    plot_points: list[PlotPoint] = []

    for instance, inst_dir in _iter_instances(afl_out):
        stats_file = inst_dir / "fuzzer_stats"
        if stats_file.exists():
            fuzzer_stats.append(_parse_fuzzer_stats(stats_file, instance))

        plot_file = inst_dir / "plot_data"
        if plot_file.exists():
            plot_points.extend(_parse_plot_data(plot_file))

        crash_dir = inst_dir / "crashes"
        if not crash_dir.is_dir():
            continue
        for f in sorted(crash_dir.iterdir()):
            if not f.is_file() or f.name.startswith("README"):
                continue
            try:
                raw_crashes.append(
                    CrashRaw(
                        path=f,
                        fuzzer_instance=instance,
                        signal=_parse_crash_name(f.name),
                        discovery_time=datetime.fromtimestamp(f.stat().st_mtime),
                        input_sha1=_sha1(f),
                        size=f.stat().st_size,
                    )
                )
            except OSError:
                continue

    return raw_crashes, fuzzer_stats, plot_points
