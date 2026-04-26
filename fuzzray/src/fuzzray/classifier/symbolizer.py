from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

_FRAME_ADDR_RE = re.compile(r"^#\d+\s+(0x[0-9a-fA-F]+)")
_NOISE_LOC_RE = re.compile(r"^\?+(:[0?]+)?$")


def _have_addr2line() -> bool:
    return shutil.which("addr2line") is not None


def symbolize(target: Path, addr: int) -> tuple[str | None, str | None]:
    """Resolve address to (function, file:line) using addr2line.

    Returns (None, None) if address can't be symbolized or addr2line is missing.
    """
    if not _have_addr2line() or not target.exists():
        return None, None

    try:
        proc = subprocess.run(
            ["addr2line", "-e", str(target), "-f", "-C", "-i", hex(addr)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None, None

    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if len(lines) < 2:
        return None, None

    func = lines[0] if lines[0] not in ("??", "optimized out") else None
    loc = lines[1] if not _NOISE_LOC_RE.match(lines[1]) else None
    if loc and ("/nptl/" in loc or "/sysdeps/" in loc or "/glibc-" in loc):
        return None, None
    return func, loc


def symbolize_backtrace(target: Path, backtrace: list[str]) -> list[str]:
    """Enrich each backtrace frame with addr2line file:line if missing."""
    if not _have_addr2line() or not target.exists() or not backtrace:
        return backtrace

    enriched: list[str] = []
    for frame in backtrace:
        if " at " in frame:
            enriched.append(frame)
            continue
        m = _FRAME_ADDR_RE.match(frame)
        if not m:
            enriched.append(frame)
            continue
        try:
            addr = int(m.group(1), 16)
        except ValueError:
            enriched.append(frame)
            continue
        _, loc = symbolize(target, addr)
        if loc:
            enriched.append(f"{frame} at {loc}")
        else:
            enriched.append(frame)
    return enriched
