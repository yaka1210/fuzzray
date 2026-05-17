from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fuzzray.classifier.engine import classify
from fuzzray.collector import collect
from fuzzray.deduplicator import deduplicate, deduplicate_by_stack
from fuzzray.models import Report
from fuzzray.prioritizer import prioritize
from fuzzray.reporter.html import render_html


def test_pipeline_renders_html(afl_out: Path, tmp_path: Path) -> None:
    raw, stats, points = collect(afl_out)
    crashes = deduplicate(raw)
    classify(crashes, target=None, target_args="@@", no_replay=True)
    crashes = deduplicate_by_stack(crashes)
    prioritize(crashes)

    report = Report(
        target="test",
        generated_at=datetime(2026, 1, 1, 12, 0, 0),
        fuzzer_stats=stats,
        plot_points=points,
        crashes=crashes,
        total_raw_crashes=len(raw),
    )
    html = render_html(report)
    out = tmp_path / "r.html"
    out.write_text(html, encoding="utf-8")

    assert "FuzzRay" in html
    assert "уникальных" in html
    assert "CWE-" in html
    assert out.stat().st_size > 1000
