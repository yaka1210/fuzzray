from __future__ import annotations

from pathlib import Path

from fuzzray.collector import collect


def test_collect_reads_crashes_and_stats(afl_out: Path) -> None:
    raw, stats, points = collect(afl_out)
    assert len(raw) == 5
    assert {r.signal for r in raw} == {11, 6, 8}
    assert len(stats) == 1
    assert stats[0].execs_done == 123456
    assert stats[0].afl_version == "++4.21c"
    assert len(points) == 3
    assert points[-1].unique_crashes == 5
