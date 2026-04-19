from __future__ import annotations

from pathlib import Path

from fuzzray.collector import collect
from fuzzray.deduplicator import compute_stack_hash, deduplicate, deduplicate_by_stack
from fuzzray.models import Crash, CrashRaw


def _mk_crash(cwe: str = "unknown", backtrace: list[str] | None = None) -> Crash:
    raw = CrashRaw(
        path=Path("/tmp/x"),
        fuzzer_instance="f",
        signal=11,
        input_sha1="a" * 40,
        size=4,
    )
    c = Crash(raw=raw)
    if cwe != "unknown":
        c.cwe_distribution = {cwe: 0.9}
    if backtrace:
        c.backtrace = backtrace
    return c


def test_level_a_sha1_dedup(afl_out: Path) -> None:
    raw, _, _ = collect(afl_out)
    crashes = deduplicate(raw)
    assert len(crashes) == 4
    dupes = [c for c in crashes if c.duplicate_count > 1]
    assert len(dupes) == 1
    assert dupes[0].duplicate_count == 2


def test_stack_hash_is_stable() -> None:
    h1 = compute_stack_hash(["parse_header+0x20 in /bin/x", "main+0x10"])
    h2 = compute_stack_hash(["parse_header+0x40 in /bin/x", "main+0x10"])
    assert h1 == h2


def test_stack_hash_filters_noise() -> None:
    bt_noisy = [
        "__pthread_kill_implementation at pthread_kill.c:44",
        "__GI_raise at raise.c:26",
        "__GI_abort at abort.c:79",
        "__asan_report_error",
        "process at target.c:42",
        "main at target.c:100",
    ]
    bt_clean = [
        "process at target.c:42",
        "main at target.c:100",
    ]
    assert compute_stack_hash(bt_noisy) == compute_stack_hash(bt_clean)


def test_level_b_merges_same_stack(afl_out: Path) -> None:
    raw, _, _ = collect(afl_out)
    crashes = deduplicate(raw)
    for c in crashes[:2]:
        c.backtrace = ["parse_header", "main"]
    merged = deduplicate_by_stack(crashes)
    assert len(merged) == len(crashes) - 1


def test_level_b_keeps_different_cwe_same_stack() -> None:
    c1 = _mk_crash("CWE-190", ["process at x.c:39", "main"])
    c2 = _mk_crash("CWE-369", ["process at x.c:39", "main"])
    merged = deduplicate_by_stack([c1, c2])
    assert len(merged) == 2


def test_level_b_merges_same_cwe_same_stack() -> None:
    c1 = _mk_crash("CWE-190", ["process at x.c:32", "main"])
    c2 = _mk_crash("CWE-190", ["process at x.c:32", "main"])
    merged = deduplicate_by_stack([c1, c2])
    assert len(merged) == 1
    assert merged[0].duplicate_count == 2
