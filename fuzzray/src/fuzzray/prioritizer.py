from __future__ import annotations

import math

from fuzzray.models import Crash

_CWE_BASE: dict[str, int] = {
    "CWE-787": 9,
    "CWE-416": 9,
    "CWE-415": 8,
    "CWE-134": 7,
    "CWE-125": 7,
    "CWE-119": 7,
    "CWE-476": 5,
    "CWE-190": 5,
    "CWE-681": 5,
    "CWE-369": 5,
    "CWE-457": 5,
}

_EXPLOIT_MULT: dict[str, float] = {
    "EXPLOITABLE": 1.5,
    "PROBABLY_EXPLOITABLE": 1.2,
    "PROBABLY_NOT_EXPLOITABLE": 0.8,
    "UNKNOWN": 1.0,
}

ERROR_SEVERITY: dict[str, str] = {
    "ERROR_SEGFAULT": "HIGH",
    "ERROR_ABORT": "HIGH",
    "ERROR_BUSERROR": "HIGH",
    "ERROR_ILL": "MEDIUM",
    "ERROR_FPE": "MEDIUM",
    "ERROR_TIMEOUT": "LOW",
    "ERROR_UNKNOWN": "LOW",
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _compute_score(c: Crash) -> float:
    top = c.top_cwe
    if top == "unknown":
        return 0.0

    base = _CWE_BASE.get(top, 3)

    confidence = max(c.cwe_distribution.values()) if c.cwe_distribution else 0.0
    confidence_penalty = 1.0 - (1.0 - confidence) * 0.5

    exploit_mult = _EXPLOIT_MULT.get(c.exploitability, 1.0)

    freq_bonus = math.log2(c.duplicate_count + 1)

    return base * confidence_penalty * exploit_mult + freq_bonus


def _score_to_level(score: float, has_cwe: bool) -> str:
    if not has_cwe:
        return "LOW"
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def prioritize(crashes: list[Crash]) -> list[Crash]:
    for c in crashes:
        top = c.top_cwe
        has_cwe = top != "unknown"

        if has_cwe:
            c.severity_score = round(_compute_score(c), 1)
            c.severity_level = _score_to_level(c.severity_score, True)
        else:
            c.severity_score = 0.0
            c.severity_level = ERROR_SEVERITY.get(
                c.taxonomy.signal_class, "LOW"
            )

    crashes.sort(key=lambda c: (SEVERITY_ORDER.get(c.severity_level, 0), c.severity_score), reverse=True)
    return crashes
