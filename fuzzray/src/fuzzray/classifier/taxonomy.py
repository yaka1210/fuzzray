from __future__ import annotations

import re

from fuzzray.classifier.gdb_runner import GdbResult
from fuzzray.models import CrashTaxonomy

_LIBC_ALLOC = {"malloc", "free", "realloc", "calloc", "_int_free", "_int_malloc",
               "__libc_free", "__libc_malloc", "cfree"}
_LIBC_STRING = {"memcpy", "memmove", "strcpy", "strncpy", "strlen", "strcat",
                "strncat", "memset", "memcmp", "strcmp", "strncmp", "stpcpy",
                "wmemcpy", "wcscpy"}
_LIBC_IO = {"vfprintf", "fprintf", "printf", "fwrite", "vsnprintf", "snprintf",
            "vprintf", "fread", "puts", "fputs"}
_NOISE_FUNCS = {"__pthread_kill", "__pthread_kill_implementation",
                "__pthread_kill_internal", "__GI_raise", "raise",
                "__GI_abort", "abort", "__libc_message", "__assert_fail",
                "__libc_start_main", "_start"}

_FUNC_RE = re.compile(r"\bin\s+([\w:]+)\s*\(")


def _extract_func(frame: str) -> str | None:
    m = _FUNC_RE.search(frame)
    return m.group(1) if m else None


def _crash_site(backtrace: list[str]) -> str:
    if not backtrace:
        return "unknown"
    for frame in backtrace:
        func = _extract_func(frame)
        if not func or func in _NOISE_FUNCS or func.startswith("__ubsan_") or func.startswith("__asan_"):
            continue
        if func in _LIBC_ALLOC:
            return "libc_alloc"
        if func in _LIBC_STRING:
            return "libc_string"
        if func in _LIBC_IO:
            return "libc_io"
        if func.startswith("_dl_") or "ld-linux" in frame:
            return "dynamic_linker"
        if func.startswith("__") and "syscall" in func:
            return "kernel_syscall"
        return "user_code"
    return "unknown"


def _memory_region(si_addr: int | None, fallback: str | None) -> str:
    if si_addr is not None:
        if si_addr < 0x1000:
            return "null_page"
        if si_addr >= 0xFFFF_8000_0000_0000:
            return "kernel_space"
    return fallback or "unknown"


def _control_flow(pc: int | None, backtrace: list[str]) -> str:
    if pc is None:
        return "unknown"
    if pc < 0x1000:
        return "ret_to_unmapped"
    if len(backtrace) > 200:
        return "stack_exhaustion"
    return "normal"


def build_taxonomy(
    signal_class: str,
    gdb: GdbResult | None,
    sanitizer_region: str | None,
) -> CrashTaxonomy:
    tx = CrashTaxonomy(signal_class=signal_class)
    if gdb is None:
        if sanitizer_region:
            tx.memory_region = sanitizer_region
        return tx
    tx.crash_site_kind = _crash_site(gdb.backtrace)
    tx.memory_region = _memory_region(gdb.faulting_address, sanitizer_region)
    tx.control_flow_state = _control_flow(gdb.pc, gdb.backtrace)
    return tx
