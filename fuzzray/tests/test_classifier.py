from __future__ import annotations

from fuzzray.classifier.cwe_rules import signal_to_class, signal_to_cwe_prior
from fuzzray.classifier.sanitizer import parse_sanitizer_output
from fuzzray.classifier.exploitability import assess
from fuzzray.classifier.gdb_runner import GdbResult
from fuzzray.models import CrashTaxonomy


def test_signal_priors() -> None:
    assert signal_to_class(11) == "ERROR_SEGFAULT"
    assert signal_to_class(8) == "ERROR_FPE"
    assert "CWE-369" in signal_to_cwe_prior(8)


def test_sanitizer_heap_write() -> None:
    stderr = (
        "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef\n"
        "WRITE of size 4 at 0xdeadbeef thread T0\n"
    )
    dist, region = parse_sanitizer_output(stderr)
    assert dist.get("CWE-787", 0) > 0.9
    assert region == "heap"


def test_sanitizer_heap_read() -> None:
    text = (
        "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xbeef\n"
        "READ of size 1 at 0xbeef thread T0\n"
    )
    dist, _ = parse_sanitizer_output(text)
    assert dist.get("CWE-125", 0) > 0.9
    assert dist.get("CWE-787", 0) < dist["CWE-125"]


def test_sanitizer_no_crossline_match() -> None:
    text = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xbeef\n"
        "READ of size 1 at 0xbeef thread T0\n"
        "some other line\n"
        "allocated by thread T0 here:\n"
        "WRITE something unrelated\n"
    )
    dist, _ = parse_sanitizer_output(text)
    assert dist.get("CWE-125", 0) > 0.9


def test_sanitizer_uaf() -> None:
    dist, _ = parse_sanitizer_output("==1==ERROR: AddressSanitizer: heap-use-after-free")
    assert dist.get("CWE-416", 0) > 0.9


def test_sanitizer_double_free() -> None:
    dist, _ = parse_sanitizer_output("==1==ERROR: AddressSanitizer: attempting double-free")
    assert dist.get("CWE-415", 0) > 0.9


def test_sanitizer_divzero() -> None:
    dist, _ = parse_sanitizer_output("runtime error: integer-divide-by-zero")
    assert dist.get("CWE-369", 0) > 0.9


def test_sanitizer_null_page() -> None:
    text = "==1==ERROR: SEGV on unknown address 0x000000000000"
    dist, region = parse_sanitizer_output(text)
    assert dist.get("CWE-476", 0) > 0.8
    assert region == "null_page"


def test_exploitability_oob_write() -> None:
    taxonomy = CrashTaxonomy(
        signal_class="ERROR_SEGFAULT",
        memory_region="heap",
    )
    result = assess(taxonomy, None, "CWE-787")
    assert result in ("EXPLOITABLE", "PROBABLY_EXPLOITABLE")


def test_exploitability_null_deref() -> None:
    taxonomy = CrashTaxonomy(
        signal_class="ERROR_SEGFAULT",
        memory_region="null_page",
    )
    result = assess(taxonomy, None, "CWE-476")
    assert result in ("UNKNOWN", "PROBABLY_NOT_EXPLOITABLE")


def test_exploitability_with_gdb_pc_zero() -> None:
    taxonomy = CrashTaxonomy(signal_class="ERROR_SEGFAULT")
    gdb = GdbResult(pc=0x41, faulting_address=0x41414141)
    result = assess(taxonomy, gdb, "CWE-416")
    assert result == "EXPLOITABLE"
