from __future__ import annotations

import re
from pathlib import Path

from fuzzray.classifier.cwe_rules import (
    normalize_distribution,
    signal_to_class,
    signal_to_cwe_prior,
)
from fuzzray.classifier.exploitability import assess
from fuzzray.classifier.gdb_runner import GdbResult, replay
from fuzzray.classifier.sanitizer import parse_sanitizer_output
from fuzzray.classifier.taxonomy import build_taxonomy
from fuzzray.models import Crash

_FUNC_RE = re.compile(r"\bin\s+(\w+)\s*\(")

_ALLOC_FUNCS = {"malloc", "free", "realloc", "calloc", "_int_free", "_int_malloc",
                "cfree", "__libc_free", "__libc_malloc"}
_STRING_FUNCS = {"memcpy", "memmove", "strcpy", "strncpy", "strlen", "strcat",
                 "strncat", "memset", "memcmp", "strcmp", "strncmp", "stpcpy",
                 "wmemcpy", "wcscpy"}
_IO_FUNCS = {"printf", "fprintf", "vfprintf", "sprintf", "snprintf", "vsnprintf",
             "vprintf", "fwrite", "fread", "puts", "fputs"}

_WRITE_INSN_RE = re.compile(r"mov[a-z]*\s+.+,\s*(?:DWORD|QWORD|BYTE|WORD)?\s*(?:PTR\s*)?\[", re.I)
_READ_INSN_RE = re.compile(r"mov[a-z]*\s+\w+,\s*(?:DWORD|QWORD|BYTE|WORD)?\s*(?:PTR\s*)?\[", re.I)
_DIV_INSN_RE = re.compile(r"\b[iu]?div\b", re.I)
_CALL_INSN_RE = re.compile(r"\b(?:call|jmp)\b", re.I)
_UD_INSN_RE = re.compile(r"ud[12]\s+(?:0x([0-9a-f]+))?\(", re.I)

_UBSAN_HANDLER_CWE: dict[int, tuple[str, float]] = {
    0:  ("CWE-190", 0.75),   # AddOverflow
    3:  ("CWE-369", 0.8),    # DivremOverflow
    5:  ("CWE-190", 0.7),    # FloatCastOverflow
    7:  ("CWE-190", 0.65),   # ImplicitConversion
    12: ("CWE-190", 0.75),   # MulOverflow
    13: ("CWE-190", 0.7),    # NegateOverflow
    18: ("CWE-787", 0.7),    # OutOfBounds
    19: ("CWE-476", 0.75),   # PointerOverflow (NULL + offset → null deref)
    20: ("CWE-190", 0.7),    # ShiftOutOfBounds
    21: ("CWE-190", 0.75),   # SubOverflow
    22: ("CWE-476", 0.7),    # TypeMismatch (includes null deref)
}


def _extract_top_func(backtrace: list[str]) -> str | None:
    for frame in backtrace:
        m = _FUNC_RE.search(frame)
        if m:
            return m.group(1)
    return None


def _extract_all_funcs(backtrace: list[str]) -> list[str]:
    funcs: list[str] = []
    for frame in backtrace:
        m = _FUNC_RE.search(frame)
        if m:
            funcs.append(m.group(1))
    return funcs


_GLIBC_DOUBLE_FREE_RE = re.compile(r"double free|invalid pointer|free\(\): invalid", re.I)
_GLIBC_HEAP_CORRUPT_RE = re.compile(
    r"corrupted size vs\. prev_size|invalid next size|"
    r"corrupted double-linked list|malloc_consolidate|"
    r"munmap_chunk\(\): invalid pointer",
    re.I,
)


def _gdb_heuristics(gdb: GdbResult, signal_class: str) -> dict[str, float]:
    """Derive CWE weights from GDB data when sanitizer output is absent."""
    hints: dict[str, float] = {}

    if gdb.faulting_address is not None and gdb.faulting_address < 0x1000:
        hints["CWE-476"] = 0.75

    insn = (gdb.faulting_instruction or "").lower()
    if _DIV_INSN_RE.search(insn):
        hints["CWE-369"] = 0.8

    if signal_class == "ERROR_SEGFAULT" and gdb.faulting_instruction:
        if _WRITE_INSN_RE.search(gdb.faulting_instruction):
            hints["CWE-787"] = max(hints.get("CWE-787", 0), 0.6)
        elif _READ_INSN_RE.search(gdb.faulting_instruction):
            hints["CWE-125"] = max(hints.get("CWE-125", 0), 0.6)

    if signal_class == "ERROR_FPE":
        hints["CWE-369"] = max(hints.get("CWE-369", 0), 0.7)

    all_funcs = _extract_all_funcs(gdb.backtrace)
    has_alloc = any(f in _ALLOC_FUNCS for f in all_funcs)
    has_string = any(f in _STRING_FUNCS for f in all_funcs)
    has_io = any(f in _IO_FUNCS for f in all_funcs)

    if has_alloc:
        hints["CWE-416"] = max(hints.get("CWE-416", 0), 0.5)
        hints["CWE-787"] = max(hints.get("CWE-787", 0), 0.4)
    if has_string:
        hints["CWE-787"] = max(hints.get("CWE-787", 0), 0.6)
        hints["CWE-125"] = max(hints.get("CWE-125", 0), 0.5)
    if has_io:
        hints["CWE-134"] = max(hints.get("CWE-134", 0), 0.4)

    raw = gdb.raw
    if _GLIBC_DOUBLE_FREE_RE.search(raw):
        hints["CWE-415"] = max(hints.get("CWE-415", 0), 0.85)
    if _GLIBC_HEAP_CORRUPT_RE.search(raw):
        hints["CWE-787"] = max(hints.get("CWE-787", 0), 0.7)

    if gdb.pc is not None and gdb.pc < 0x1000:
        hints["CWE-787"] = max(hints.get("CWE-787", 0), 0.6)
        hints["CWE-416"] = max(hints.get("CWE-416", 0), 0.5)

    if _CALL_INSN_RE.search(insn) and signal_class == "ERROR_SEGFAULT":
        hints["CWE-416"] = max(hints.get("CWE-416", 0), 0.5)

    if signal_class == "ERROR_ILL" and gdb.faulting_instruction:
        ud_m = _UD_INSN_RE.search(gdb.faulting_instruction)
        if ud_m:
            handler_id = int(ud_m.group(1), 16) if ud_m.group(1) else 0
            if handler_id in _UBSAN_HANDLER_CWE:
                cwe, weight = _UBSAN_HANDLER_CWE[handler_id]
                hints[cwe] = max(hints.get(cwe, 0), weight)

    if _is_stack_exhaustion(gdb):
        hints.clear()

    return hints


def _is_stack_exhaustion(gdb: GdbResult) -> bool:
    if len(gdb.backtrace) < 5:
        return False
    funcs = []
    for frame in gdb.backtrace[:10]:
        m = _FUNC_RE.search(frame)
        if m:
            funcs.append(m.group(1))
    if len(funcs) >= 5 and len(set(funcs)) <= 2:
        return True
    insn = (gdb.faulting_instruction or "").lower()
    if "call" in insn and len(gdb.backtrace) >= 8:
        return True
    return False


def classify_one(
    crash: Crash,
    target: Path | None,
    target_args: str,
    no_replay: bool,
) -> Crash:
    dist = dict(signal_to_cwe_prior(crash.raw.signal))
    signal_class = signal_to_class(crash.raw.signal)

    gdb: GdbResult | None = None
    sanitizer_region: str | None = None
    has_sanitizer = False

    if not no_replay and target is not None:
        gdb = replay(target, crash.raw.path, target_args)
        if gdb is not None:
            san_dist, sanitizer_region = parse_sanitizer_output(gdb.raw)
            if san_dist:
                has_sanitizer = True
            for k, v in san_dist.items():
                dist[k] = max(dist.get(k, 0.0), v)

            if not has_sanitizer:
                gdb_hints = _gdb_heuristics(gdb, signal_class)
                for k, v in gdb_hints.items():
                    dist[k] = max(dist.get(k, 0.0), v)

            crash.backtrace = gdb.backtrace
            crash.faulting_instruction = gdb.faulting_instruction
            crash.faulting_address = gdb.faulting_address
            crash.evidence = gdb.raw[-2000:]
            crash.gdb_output = gdb.raw

    crash.cwe_distribution = normalize_distribution(dist)
    crash.taxonomy = build_taxonomy(signal_class, gdb, sanitizer_region)
    crash.exploitability = assess(crash.taxonomy, gdb, crash.top_cwe)
    return crash


def _replay_worker(args: tuple[Path, Path, str]) -> GdbResult | None:
    target, crash_path, target_args = args
    return replay(target, crash_path, target_args)


def classify(
    crashes: list[Crash],
    target: Path | None,
    target_args: str,
    no_replay: bool,
    jobs: int = 0,
) -> list[Crash]:
    if no_replay or target is None or jobs == 1 or len(crashes) <= 1:
        for c in crashes:
            classify_one(c, target, target_args, no_replay)
        return crashes

    from concurrent.futures import ProcessPoolExecutor
    import os

    n_workers = jobs if jobs > 0 else min(os.cpu_count() or 1, len(crashes))
    work = [(target, c.raw.path, target_args) for c in crashes]

    with ProcessPoolExecutor(max_workers=n_workers) as pool:
        gdb_results = list(pool.map(_replay_worker, work))

    for crash, gdb_res in zip(crashes, gdb_results, strict=True):
        dist = dict(signal_to_cwe_prior(crash.raw.signal))
        signal_class = signal_to_class(crash.raw.signal)
        sanitizer_region: str | None = None

        if gdb_res is not None:
            san_dist, sanitizer_region = parse_sanitizer_output(gdb_res.raw)
            has_sanitizer = bool(san_dist)
            for k, v in san_dist.items():
                dist[k] = max(dist.get(k, 0.0), v)
            if not has_sanitizer:
                gdb_hints = _gdb_heuristics(gdb_res, signal_class)
                for k, v in gdb_hints.items():
                    dist[k] = max(dist.get(k, 0.0), v)
            crash.backtrace = gdb_res.backtrace
            crash.faulting_instruction = gdb_res.faulting_instruction
            crash.faulting_address = gdb_res.faulting_address
            crash.evidence = gdb_res.raw[-2000:]
            crash.gdb_output = gdb_res.raw

        crash.cwe_distribution = normalize_distribution(dist)
        crash.taxonomy = build_taxonomy(signal_class, gdb_res, sanitizer_region)
        crash.exploitability = assess(crash.taxonomy, gdb_res, crash.top_cwe)

    return crashes
