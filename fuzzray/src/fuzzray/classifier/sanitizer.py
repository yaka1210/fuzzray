from __future__ import annotations

import re

_OVERFLOW_RE = re.compile(r"(heap|stack|global)-buffer-overflow", re.I)
_ACCESS_RE = re.compile(r"^\s*(READ|WRITE)\s+of\s+size", re.I | re.M)

_RULES: list[tuple[re.Pattern[str], str, float]] = [
    # ASan messages (use hyphens)
    (re.compile(r"heap[- ]use[- ]after[- ]free", re.I), "CWE-416", 0.97),
    (re.compile(r"stack[- ]use[- ]after[- ]return", re.I), "CWE-416", 0.9),
    (re.compile(r"(?:double[- ]free|attempting double[- ]free|double[- ]free or corruption)", re.I), "CWE-415", 0.95),
    (re.compile(r"allocation[- ]size[- ]too[- ]big", re.I), "CWE-190", 0.9),
    (re.compile(r"SEGV on unknown address 0x0*[0-9a-f]{1,3}\b", re.I), "CWE-476", 0.9),
    (re.compile(r"null[- ]deref", re.I), "CWE-476", 0.95),
    # UBSan messages — match both handler-name format (hyphens) and runtime text (spaces)
    (re.compile(r"signed[- ]integer[- ]overflow", re.I), "CWE-190", 0.95),
    (re.compile(r"unsigned[- ]integer[- ]overflow", re.I), "CWE-190", 0.9),
    (re.compile(r"shift[- ]exponent\s+\S+\s+is\s+too\s+large|shift[- ]out[- ]of[- ]bounds", re.I), "CWE-190", 0.9),
    (re.compile(r"(?:integer[- ]divide[- ]by[- ]zero|division by zero|divide by zero)", re.I), "CWE-369", 0.97),
    (re.compile(r"use[- ]of[- ]uninitialized[- ]value", re.I), "CWE-457", 0.95),
    (re.compile(r"load of misaligned|misaligned address", re.I), "CWE-457", 0.6),
    (re.compile(r"implicit conversion|conversion[- ]from[- ]type|float[- ]cast[- ]overflow", re.I), "CWE-681", 0.85),
    (re.compile(r"index\s+\S+\s+out of bounds for type", re.I), "CWE-125", 0.7),
    (re.compile(r"member access within null pointer|reference binding to null pointer|null pointer", re.I), "CWE-476", 0.85),
]

_MEMORY_REGION_RE = re.compile(
    r"(heap|stack|global|bss|mmap)[- ]", re.I
)


def parse_sanitizer_output(text: str) -> tuple[dict[str, float], str | None]:
    """Return (CWE distribution, detected memory_region) from sanitizer output."""
    if not text:
        return {}, None

    dist: dict[str, float] = {}

    if _OVERFLOW_RE.search(text):
        access_m = _ACCESS_RE.search(text)
        if access_m and access_m.group(1).upper() == "WRITE":
            dist["CWE-787"] = 0.95
        elif access_m and access_m.group(1).upper() == "READ":
            dist["CWE-125"] = 0.95
        else:
            dist["CWE-787"] = 0.7

    for pat, cwe, w in _RULES:
        if pat.search(text):
            dist[cwe] = max(dist.get(cwe, 0.0), w)

    region: str | None = None
    m = _MEMORY_REGION_RE.search(text)
    if m:
        token = m.group(1).lower()
        region = {"global": "bss"}.get(token, token)
    if "0x000000000000" in text or "address 0x0" in text:
        region = "null_page"
    return dist, region
