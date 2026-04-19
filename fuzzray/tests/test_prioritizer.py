from __future__ import annotations

from pathlib import Path

from fuzzray.models import Crash, CrashRaw, CrashTaxonomy
from fuzzray.prioritizer import prioritize


def _mk(
    cwe: str | None = None,
    signal_class: str = "ERROR_UNKNOWN",
    dup: int = 1,
    exploitability: str = "UNKNOWN",
    confidence: float = 1.0,
) -> Crash:
    raw = CrashRaw(
        path=Path("/tmp/x"),
        fuzzer_instance="f",
        signal=11,
        input_sha1="a" * 40,
        size=4,
    )
    c = Crash(raw=raw, duplicate_count=dup)
    if cwe:
        c.cwe_distribution = {cwe: confidence}
    else:
        c.cwe_distribution = {"unknown": 1.0}
    c.taxonomy = CrashTaxonomy(signal_class=signal_class)
    c.exploitability = exploitability
    return c


def test_severity_score_computed() -> None:
    c = _mk("CWE-787", exploitability="EXPLOITABLE")
    prioritize([c])
    assert c.severity_score > 0


def test_cwe787_higher_than_cwe476() -> None:
    write = _mk("CWE-787")
    null = _mk("CWE-476")
    prioritize([null, write])
    assert write.severity_score > null.severity_score


def test_exploitable_boosts_score() -> None:
    expl = _mk("CWE-787", exploitability="EXPLOITABLE")
    unknown = _mk("CWE-787", exploitability="UNKNOWN")
    prioritize([expl, unknown])
    assert expl.severity_score > unknown.severity_score


def test_duplicates_boost_score() -> None:
    many = _mk("CWE-125", dup=10)
    one = _mk("CWE-125", dup=1)
    prioritize([one, many])
    assert many.severity_score > one.severity_score


def test_low_confidence_reduces_score() -> None:
    high = _mk("CWE-787", confidence=0.95)
    low = _mk("CWE-787", confidence=0.30)
    prioritize([low, high])
    assert high.severity_score > low.severity_score


def test_critical_level_for_high_score() -> None:
    c = _mk("CWE-787", exploitability="EXPLOITABLE")
    prioritize([c])
    assert c.severity_level == "CRITICAL"


def test_medium_level_for_low_cwe() -> None:
    c = _mk("CWE-476", exploitability="PROBABLY_NOT_EXPLOITABLE")
    prioritize([c])
    assert c.severity_level == "MEDIUM"


def test_errors_without_cwe() -> None:
    segfault = _mk(signal_class="ERROR_SEGFAULT")
    timeout = _mk(signal_class="ERROR_TIMEOUT")
    prioritize([timeout, segfault])
    assert segfault.severity_level == "HIGH"
    assert timeout.severity_level == "LOW"
    assert segfault.severity_score == 0.0


def test_sort_order() -> None:
    critical = _mk("CWE-787", exploitability="EXPLOITABLE")
    medium = _mk("CWE-476")
    low = _mk(signal_class="ERROR_TIMEOUT")
    result = prioritize([low, medium, critical])
    assert result[0].severity_level == "CRITICAL"
    assert result[-1].severity_level == "LOW"
