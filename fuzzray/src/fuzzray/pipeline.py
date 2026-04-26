from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.console import Console

from fuzzray.classifier.engine import classify
from fuzzray.classifier.minimizer import hex_dump, minimize
from fuzzray.collector import collect
from fuzzray.deduplicator import deduplicate, deduplicate_by_stack
from fuzzray.models import Report
from fuzzray.prioritizer import prioritize
from fuzzray.reporter.html import render_html
from fuzzray.reporter.reproducer import render as render_reproducer

console = Console()


def run_pipeline(
    *,
    afl_out: Path,
    output: Path,
    target: Path | None,
    target_args: str,
    no_replay: bool,
    jobs: int,
    do_minimize: bool = False,
    write_reproducers: bool = True,
) -> None:
    console.print(f"[bold cyan]FuzzRay[/] сканирование [yellow]{afl_out}[/]")

    raw_crashes, fuzzer_stats, plot_points = collect(afl_out)
    console.print(f"  собрано [bold]{len(raw_crashes)}[/] файлов падений")

    crashes = deduplicate(raw_crashes)
    console.print(f"  дедупликация → [bold]{len(crashes)}[/] уникальных входов")

    classify(crashes, target=target, target_args=target_args, no_replay=no_replay, jobs=jobs)
    console.print("  классификация (CWE + таксономия + эксплуатируемость)")

    crashes = deduplicate_by_stack(crashes)
    console.print(f"  дедупликация по стеку → [bold]{len(crashes)}[/] уязвимостей")

    prioritize(crashes)
    crit = sum(1 for c in crashes if c.severity_level == "CRITICAL")
    high = sum(1 for c in crashes if c.severity_level == "HIGH")
    med = sum(1 for c in crashes if c.severity_level == "MEDIUM")
    low = sum(1 for c in crashes if c.severity_level == "LOW")
    parts = []
    if crit:
        parts.append(f"[red]{crit} CRITICAL[/]")
    if high:
        parts.append(f"[yellow]{high} HIGH[/]")
    if med:
        parts.append(f"[cyan]{med} MEDIUM[/]")
    if low:
        parts.append(f"[dim]{low} LOW[/]")
    console.print(f"  приоритизация: {', '.join(parts)}")

    if do_minimize and target is not None:
        min_dir = output.parent / f"{output.stem}_minimized"
        ok = 0
        for c in crashes:
            res = minimize(target, c.raw.path, target_args, min_dir)
            if res is not None:
                c.minimized_size = res.minimized_size
                try:
                    c.minimized_hex = hex_dump(res.minimized_path.read_bytes())
                except OSError:
                    pass
                ok += 1
        console.print(f"  минимизация (afl-tmin): [bold]{ok}[/] / {len(crashes)} → {min_dir}")

    if write_reproducers:
        repro_dir = output.parent / f"{output.stem}_reproducers"
        repro_dir.mkdir(parents=True, exist_ok=True)
        for i, c in enumerate(crashes, 1):
            script = render_reproducer(c, i, target, target_args)
            c.reproducer_script = script
            sh = repro_dir / f"reproduce_{i:03d}_{c.top_cwe.replace('-', '_')}.sh"
            sh.write_text(script, encoding="utf-8")
            sh.chmod(0o755)
        console.print(f"  репродьюсеры: [bold]{len(crashes)}[/] скриптов → {repro_dir}")

    report = Report(
        target=str(target) if target else "(не указана)",
        generated_at=datetime.now(),
        fuzzer_stats=fuzzer_stats,
        plot_points=plot_points,
        crashes=crashes,
        total_raw_crashes=len(raw_crashes),
    )

    html = render_html(report)
    output.write_text(html, encoding="utf-8")
    console.print(f"[bold green]записан[/] {output}")
