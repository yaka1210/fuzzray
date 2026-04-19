from __future__ import annotations

from fuzzray.classifier.gdb_runner import GdbResult
from fuzzray.models import CrashTaxonomy

_LIBC_ALLOC = {"malloc", "free", "realloc", "calloc", "_int_free", "_int_malloc"}
_LIBC_STRING = {"memcpy", "memmove", "strcpy", "strncpy", "strlen", "strcat", "memset"}
_LIBC_IO = {"vfprintf", "fprintf", "printf", "fwrite", "vsnprintf", "snprintf"}


def _crash_site(backtrace: list[str]) -> str:
    if not backtrace:
        return "unknown"
    top = backtrace[0]
    base = top.split("@")[0].split("+")[0]
    if base in _LIBC_ALLOC:
        return "libc_alloc"
    if base in _LIBC_STRING:
        return "libc_string"
    if base in _LIBC_IO:
        return "libc_io"
    if base.startswith("_dl_") or "ld-linux" in top:
        return "dynamic_linker"
    if base.startswith("__") and "syscall" in base:
        return "kernel_syscall"
    return "user_code"


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
