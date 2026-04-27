from __future__ import annotations

import hashlib
import re

from fuzzray.models import Crash, CrashRaw

_ADDR_RE = re.compile(r"0x[0-9a-f]+", re.I)
_TOP_N_FRAMES = 5

_NOISE_PATTERNS = re.compile(
    r"__pthread_kill|__GI_raise|__GI_abort|"
    r"__asan_|__sanitizer_|__interceptor_|"
    r"__ubsan_|__msan_|__lsan_|"
    r"ScopedInErrorReport|ReportGenericError|ReportDoubleFree|"
    r"ReportAllocationSizeTooBig|ReportInvalidFree|"
    r"Allocator::|asan_malloc|printf_common|"
    r"__libc_start|_start$"
)


def deduplicate(raw_crashes: list[CrashRaw]) -> list[Crash]:
    """Level A dedup: group by SHA1 of the input bytes."""
    by_hash: dict[str, Crash] = {}
    for r in raw_crashes:
        existing = by_hash.get(r.input_sha1)
        if existing is None:
            by_hash[r.input_sha1] = Crash(raw=r, duplicate_count=1, duplicate_paths=[r.path])
        else:
            existing.duplicate_count += 1
            existing.duplicate_paths.append(r.path)
    return list(by_hash.values())


def _normalize_frame(frame: str) -> str:
    f = _ADDR_RE.sub("", frame)
    return f.split("+")[0].strip()


def _is_noise_frame(frame: str) -> bool:
    return bool(_NOISE_PATTERNS.search(frame))


def _meaningful_frames(backtrace: list[str]) -> list[str]:
    return [f for f in backtrace if not _is_noise_frame(f)]


def compute_stack_hash(backtrace: list[str]) -> str | None:
    if not backtrace:
        return None
    meaningful = _meaningful_frames(backtrace)
    if not meaningful:
        meaningful = backtrace
    frames = [_normalize_frame(f) for f in meaningful[:_TOP_N_FRAMES] if f]
    if not frames:
        return None
    return hashlib.sha1("|".join(frames).encode()).hexdigest()[:16]


def deduplicate_by_stack(crashes: list[Crash]) -> list[Crash]:
    """Level B dedup: group by normalized top-N stack hash.

    Crashes without a backtrace keep their Level A identity.
    """
    by_stack: dict[str, Crash] = {}
    untouched: list[Crash] = []
    for c in crashes:
        sh = compute_stack_hash(c.backtrace)
        if sh is None:
            untouched.append(c)
            continue
        dedup_key = f"{sh}:{c.top_cwe}"
        existing = by_stack.get(dedup_key)
        if existing is None:
            by_stack[dedup_key] = c
        else:
            existing.duplicate_count += c.duplicate_count
            existing.duplicate_paths.extend(c.duplicate_paths)
    return [*by_stack.values(), *untouched]


def deduplicate_by_location(crashes: list[Crash]) -> list[Crash]:
    """Level C dedup: collapse crashes pointing to the same code location.

    Key = (crash_location, faulting_instruction, top_cwe). Crashes without
    a resolved location keep their Level B identity.
    """
    by_loc: dict[tuple[str, str, str], Crash] = {}
    untouched: list[Crash] = []
    for c in crashes:
        if not c.crash_location:
            untouched.append(c)
            continue
        key = (c.crash_location, c.faulting_instruction or "", c.top_cwe)
        existing = by_loc.get(key)
        if existing is None:
            by_loc[key] = c
        else:
            existing.duplicate_count += c.duplicate_count
            existing.duplicate_paths.extend(c.duplicate_paths)
    return [*by_loc.values(), *untouched]
