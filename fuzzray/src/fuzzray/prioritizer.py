from __future__ import annotations

from fuzzray.models import Crash

CWE_SEVERITY: dict[str, str] = {
    "CWE-787": "CRITICAL",   # OOB Write
    "CWE-416": "CRITICAL",   # Use After Free
    "CWE-415": "HIGH",       # Double Free
    "CWE-125": "HIGH",       # OOB Read
    "CWE-119": "HIGH",       # Generic Buffer Issue
    "CWE-476": "MEDIUM",     # NULL Pointer Dereference
    "CWE-190": "MEDIUM",     # Integer Overflow
    "CWE-681": "MEDIUM",     # Type Conversion
    "CWE-369": "MEDIUM",     # Divide By Zero
    "CWE-457": "MEDIUM",     # Uninitialized Variable
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


def prioritize(crashes: list[Crash]) -> list[Crash]:
    for c in crashes:
        if c.top_cwe != "unknown":
            c.severity_level = CWE_SEVERITY.get(c.top_cwe, "MEDIUM")
        else:
            c.severity_level = ERROR_SEVERITY.get(c.taxonomy.signal_class, "LOW")

    crashes.sort(
        key=lambda c: (SEVERITY_ORDER.get(c.severity_level, 0), c.duplicate_count),
        reverse=True,
    )
    return crashes
