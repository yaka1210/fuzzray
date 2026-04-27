from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class MinimizeResult:
    minimized_path: Path
    original_size: int
    minimized_size: int


def _have_afl_tmin() -> bool:
    return shutil.which("afl-tmin") is not None


def minimize(
    target: Path,
    crash_file: Path,
    target_args: str = "@@",
    output_dir: Path | None = None,
    timeout: int = 600,
) -> MinimizeResult | None:
    if not _have_afl_tmin() or not target.exists() or not crash_file.exists():
        return None

    original_size = crash_file.stat().st_size

    if output_dir is None:
        output_dir = Path(tempfile.gettempdir()) / "fuzzray_min"
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_stem = "".join(c if c.isalnum() or c in "-_" else "_" for c in crash_file.stem)
    out_path = output_dir / f"min_{safe_stem}_{crash_file.stat().st_ino}"

    cmd = [
        "afl-tmin",
        "-i", str(crash_file),
        "-o", str(out_path),
        "--",
        str(target),
    ]
    if "@@" in target_args:
        for arg in target_args.split():
            if arg == "@@":
                cmd.append("@@")
            else:
                cmd.append(arg)
    else:
        cmd.append("@@")

    env = {"AFL_NO_AFFINITY": "1", "AFL_SKIP_CPUFREQ": "1", "AFL_NO_UI": "1"}

    log_path = output_dir / f"{out_path.name}.log"
    try:
        with log_path.open("w") as log:
            proc = subprocess.run(
                cmd,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
                env={**__import__("os").environ, **env},
            )
    except (subprocess.TimeoutExpired, OSError):
        return None

    if not out_path.exists() or out_path.stat().st_size == 0:
        return None

    return MinimizeResult(
        minimized_path=out_path,
        original_size=original_size,
        minimized_size=out_path.stat().st_size,
    )


def hex_dump(data: bytes, max_bytes: int = 256) -> str:
    """Format bytes as classic hex dump: offset | hex | ascii."""
    chunk = data[:max_bytes]
    lines: list[str] = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        hex_part = f"{hex_part:<47}"
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{i:08x}  {hex_part}  {ascii_part}")
    if len(data) > max_bytes:
        lines.append(f"... ({len(data) - max_bytes} bytes truncated)")
    return "\n".join(lines)
