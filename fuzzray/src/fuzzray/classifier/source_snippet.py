from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_LOC_RE = re.compile(r"^(.+):(\d+)$")
_MAX_FILE_SIZE = 1_048_576
_CONTEXT_LINES = 3


@dataclass
class SourceSnippet:
    file: str
    line: int
    lines: list[tuple[int, str]]
    crash_line: int


def _resolve_path(loc_path: str, source_root: Path | None) -> Path | None:
    p = Path(loc_path)
    if p.is_absolute() and p.is_file():
        return p

    candidates: list[Path] = []
    if source_root is not None:
        candidates.append(source_root)
        candidates.append(source_root.parent)
    candidates.append(Path.cwd())

    seen: set[Path] = set()
    for root in candidates:
        if root in seen:
            continue
        seen.add(root)
        cand = root / p
        if cand.is_file():
            return cand
        cand = root / p.name
        if cand.is_file():
            return cand
    return None


def extract_snippet(
    crash_location: str | None,
    source_root: Path | None = None,
) -> SourceSnippet | None:
    if not crash_location:
        return None
    m = _LOC_RE.match(crash_location)
    if not m:
        return None
    file_part, line_part = m.group(1), int(m.group(2))

    src = _resolve_path(file_part, source_root)
    if src is None or src.stat().st_size > _MAX_FILE_SIZE:
        return None

    try:
        text = src.read_text(errors="replace").splitlines()
    except OSError:
        return None

    if line_part < 1 or line_part > len(text):
        return None

    start = max(1, line_part - _CONTEXT_LINES)
    end = min(len(text), line_part + _CONTEXT_LINES)
    lines = [(i, text[i - 1]) for i in range(start, end + 1)]

    return SourceSnippet(file=str(src), line=line_part, lines=lines, crash_line=line_part)
