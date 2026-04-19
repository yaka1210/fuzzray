from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

_FRAME_RE = re.compile(r"^#\d+\s+")
_SIGNAL_RE = re.compile(r"Program received signal (SIG\w+)")
_SI_ADDR_RE = re.compile(r"si_addr\s*=\s*(0x[0-9a-f]+)", re.I)
_PC_RE = re.compile(r"(?:rip|eip|pc)\s+(0x[0-9a-f]+)", re.I)
_FAULTING_INSN_RE = re.compile(r"=>\s*0x[0-9a-f]+[^:]*:\s*(.+)")
_LOAD_ERROR_RE = re.compile(r"error while loading shared libraries|cannot open shared object")


@dataclass
class GdbResult:
    signal_name: str | None = None
    backtrace: list[str] = field(default_factory=list)
    faulting_instruction: str | None = None
    faulting_address: int | None = None
    pc: int | None = None
    stderr_tail: str = ""
    raw: str = ""


def _have_gdb() -> bool:
    return shutil.which("gdb") is not None


def _parse_gdb_output(out: str, stderr: str) -> GdbResult | None:
    res = GdbResult(raw=out, stderr_tail=stderr[-4000:])

    m = _SIGNAL_RE.search(out)
    if m:
        res.signal_name = m.group(1)

    for line in out.splitlines():
        stripped = line.strip()
        if _FRAME_RE.match(stripped):
            res.backtrace.append(stripped)
        if len(res.backtrace) >= 20:
            break

    if not res.backtrace and "No stack" in out:
        if "ERROR:" not in out and "SUMMARY:" not in out:
            return None

    pc_m = _PC_RE.search(out)
    if pc_m:
        try:
            res.pc = int(pc_m.group(1), 16)
        except ValueError:
            pass

    insn_m = _FAULTING_INSN_RE.search(out)
    if insn_m:
        res.faulting_instruction = insn_m.group(1).strip()

    si_m = _SI_ADDR_RE.search(out)
    if si_m:
        try:
            res.faulting_address = int(si_m.group(1), 16)
        except ValueError:
            pass

    return res


def _retry_without_sanitizer(
    target: Path,
    crash_file: Path,
    run_args: str,
    timeout: int,
) -> GdbResult | None:
    gdb_script = [
        "set pagination off",
        "set confirm off",
        "set print frame-arguments all",
        "set environment LD_PRELOAD=",
        "set environment ASAN_OPTIONS=",
        "set environment UBSAN_OPTIONS=",
        "set environment MSAN_OPTIONS=",
        "set environment LSAN_OPTIONS=",
        f"run {run_args}",
        "bt 20",
        "info registers",
        "x/1i $pc",
        "printf \"SI_ADDR=\"",
        "print/x $_siginfo._sifields._sigfault.si_addr",
        "quit",
    ]
    cmd = ["gdb", "--batch", "--nx", "-q"]
    for line in gdb_script:
        cmd += ["-ex", line]
    cmd += ["--args", str(target)]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    out = proc.stdout + "\n" + proc.stderr

    if _LOAD_ERROR_RE.search(out):
        return None

    return _parse_gdb_output(out, proc.stderr)


def replay(
    target: Path,
    crash_file: Path,
    target_args: str = "@@",
    timeout: int = 30,
) -> GdbResult | None:
    if not _have_gdb() or not target.exists():
        return None

    quoted_path = str(crash_file).replace("\\", "\\\\").replace('"', '\\"')
    argv_template = target_args.replace("@@", f'"{quoted_path}"')
    run_args = argv_template

    gdb_script = [
        "set pagination off",
        "set confirm off",
        "set print frame-arguments all",
        "set environment ASAN_OPTIONS=abort_on_error=1:detect_leaks=1:symbolize=1",
        f"run {run_args}",
        "bt 20",
        "info registers",
        "x/1i $pc",
        "printf \"SI_ADDR=\"",
        "print/x $_siginfo._sifields._sigfault.si_addr",
        "quit",
    ]
    cmd = ["gdb", "--batch", "--nx", "-q"]
    for line in gdb_script:
        cmd += ["-ex", line]
    cmd += ["--args", str(target)]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    out = proc.stdout + "\n" + proc.stderr

    if _LOAD_ERROR_RE.search(out):
        retry = _retry_without_sanitizer(target, crash_file, run_args, timeout)
        if retry is not None:
            return retry
        return None

    return _parse_gdb_output(out, proc.stderr)
