from __future__ import annotations

import re

_OVERFLOW_RE = re.compile(r"(heap|stack|global)-buffer-overflow", re.I)
_ACCESS_RE = re.compile(r"^\s*(READ|WRITE)\s+of\s+size", re.I | re.M)

_RULES: list[tuple[re.Pattern[str], str, float]] = [
    # =========================================================================
    # ASan (AddressSanitizer) messages
    # =========================================================================
    (re.compile(r"heap[- ]use[- ]after[- ]free", re.I), "CWE-416", 0.97),
    (re.compile(r"stack[- ]use[- ]after[- ]return", re.I), "CWE-416", 0.9),
    (re.compile(r"stack[- ]use[- ]after[- ]scope", re.I), "CWE-416", 0.9),
    (re.compile(r"(?:double[- ]free|attempting double[- ]free|double[- ]free or corruption)", re.I), "CWE-415", 0.95),
    (re.compile(r"allocation[- ]size[- ]too[- ]big|requested allocation size", re.I), "CWE-190", 0.9),
    (re.compile(r"SEGV on unknown address 0x0*[0-9a-f]{1,3}\b", re.I), "CWE-476", 0.9),
    (re.compile(r"null[- ]deref", re.I), "CWE-476", 0.95),

    # =========================================================================
    # UBSan text messages (both -fsanitize-trap and text mode covered)
    # =========================================================================
    # Integer / arithmetic overflows → CWE-190
    (re.compile(r"signed[- ]integer[- ]overflow|signed integer overflow", re.I), "CWE-190", 0.95),
    (re.compile(r"unsigned[- ]integer[- ]overflow|unsigned integer overflow", re.I), "CWE-190", 0.9),
    (re.compile(r"shift[- ]exponent\s+\S+\s+is\s+too\s+large|shift[- ]out[- ]of[- ]bounds|left shift of (?:negative value|\S+ by \S+ places)", re.I), "CWE-190", 0.9),
    (re.compile(r"negation of \S+ cannot be represented", re.I), "CWE-190", 0.9),

    # Division by zero → CWE-369
    (re.compile(r"(?:integer[- ]divide[- ]by[- ]zero|float[- ]divide[- ]by[- ]zero|division by zero|divide by zero)", re.I), "CWE-369", 0.97),

    # Type conversion → CWE-681
    (re.compile(r"implicit conversion|conversion[- ]from[- ]type|float[- ]cast[- ]overflow|is outside the range of representable values|(?:inf|nan) is outside|truncated to", re.I), "CWE-681", 0.85),

    # Out of bounds (read) → CWE-125
    (re.compile(r"index\s+\S+\s+out of bounds for type", re.I), "CWE-125", 0.8),

    # NULL pointer issues → CWE-476
    (re.compile(r"member access within null pointer|reference binding to null pointer|member call on null pointer|downcast of null pointer|null pointer passed as argument|null pointer returned from function|applying (?:non-zero offset|zero offset) to null", re.I), "CWE-476", 0.9),

    # Pointer overflow / function type mismatch → CWE-476 (best fit in our set)
    (re.compile(r"applying \S+ offset .* produced null pointer|pointer overflow|calling function .* through pointer to incorrect function type", re.I), "CWE-476", 0.85),

    # Misalignment → CWE-476 (best fit, true class CWE-704 not in our set)
    (re.compile(r"load of misaligned address|misaligned address \S+ for type", re.I), "CWE-476", 0.7),

    # MemorySanitizer-specific messages
    (re.compile(r"MemorySanitizer:\s*use[- ]of[- ]uninitialized[- ]value", re.I), "CWE-457", 0.97),
    (re.compile(r"MemorySanitizer:\s*requested allocation", re.I), "CWE-190", 0.9),

    # Uninitialized / invalid load → CWE-457
    (re.compile(r"use[- ]of[- ]uninitialized[- ]value", re.I), "CWE-457", 0.95),
    (re.compile(r"load of value \S+, which is not a valid value for type", re.I), "CWE-457", 0.85),
    (re.compile(r"variable length array bound evaluates to non-positive", re.I), "CWE-457", 0.7),
    (re.compile(r"execution reached an unreachable|reached the end of a value-returning function|passing zero to (?:ctz|clz|ffs)", re.I), "CWE-457", 0.5),

    # =========================================================================
    # UBSan handler functions in backtrace — work even without text output
    # =========================================================================
    (re.compile(r"__ubsan_handle_(?:add|sub|mul|negate)_overflow", re.I), "CWE-190", 0.85),
    (re.compile(r"__ubsan_handle_shift_out_of_bounds", re.I), "CWE-190", 0.85),
    (re.compile(r"__ubsan_handle_divrem_overflow", re.I), "CWE-369", 0.9),
    (re.compile(r"__ubsan_handle_(?:float_cast_overflow|implicit_conversion)", re.I), "CWE-681", 0.85),
    (re.compile(r"__ubsan_handle_out_of_bounds", re.I), "CWE-125", 0.75),
    (re.compile(r"__ubsan_handle_(?:nonnull_arg|nonnull_return|nullability_arg|nullability_return|pointer_overflow|type_mismatch|function_type_mismatch|dynamic_type_cache_miss)", re.I), "CWE-476", 0.7),
    (re.compile(r"__ubsan_handle_load_invalid_value|__ubsan_handle_vla_bound_not_positive|__ubsan_handle_invalid_builtin", re.I), "CWE-457", 0.75),
    (re.compile(r"__ubsan_handle_(?:builtin_unreachable|missing_return|alignment_assumption)", re.I), "CWE-457", 0.5),
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
