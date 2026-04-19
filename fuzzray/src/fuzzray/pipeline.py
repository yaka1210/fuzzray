from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.console import Console

from fuzzray.classifier.engine import classify
from fuzzray.collector import collect
from fuzzray.deduplicator import deduplicate, deduplicate_by_stack
from fuzzray.models import Report
from fuzzray.prioritizer import prioritize
from fuzzray.reporter.html import render_html

console = Console()


def run_pipeline(
    *,
    afl_out: Path,
    output: Path,
    target: Path | None,
    target_args: str,
    no_replay: bool,
    pdf: bool,
    jobs: int,
) -> None:
    console.print(f"[bold cyan]FuzzRay[/] сканирование [yellow]{afl_out}[/]")

    raw_crashes, fuzzer_stats, plot_points = collect(afl_out)
    console.print(f"  собрано [bold]{len(raw_crashes)}[/] файлов падений")

    crashes = deduplicate(raw_crashes)
    console.print(f"  дедупликация → [bold]{len(crashes)}[/] уникальных входов")

    classify(crashes, target=target, target_args=target_args, no_replay=no_replay)
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

    if pdf:
        from fuzzray.reporter.pdf import render_pdf

        pdf_path = output.with_suffix(".pdf")
        render_pdf(html, pdf_path)
        console.print(f"[bold green]записан[/] {pdf_path}")
