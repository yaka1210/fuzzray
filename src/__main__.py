# src/__main__.py

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from models import Crash
from collector import collect_afl_data
from deduplicator import deduplicate_crashes
from classifier import classify_crashes
from prioritizer import prioritize_crashes
from reporter import generate_html_report

console = Console(highlight=True)


@click.group()
@click.version_option("0.2.0-dev", prog_name="FuzzRay")
def cli():
    """FuzzRay — анализатор результатов фаззинг-тестирования AFL++"""
    pass


@cli.command()
@click.argument(
    "afl_output_dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path)
)
@click.option("--report", "-r", default="fuzzray_report.html", help="Путь к HTML-отчёту")
@click.option("--verbose", "-v", is_flag=True, help="Подробный вывод")
@click.option("--target", "-t", type=click.Path(exists=True, file_okay=True), help="Путь к бинарнику для GDB")
def analyze(afl_output_dir: Path, report: str, verbose: bool, target: Optional[str] = None):
    """Запустить анализ директории AFL++ и создать отчёт"""
    console.rule("FuzzRay анализ", style="bold green")
    console.print(f"[bold]Директория:[/bold] {afl_output_dir}")

    if verbose:
        console.print(f"[dim]Абсолютный путь:[/dim] {afl_output_dir.resolve()}")
        if target:
            console.print(f"[dim]Target binary для GDB:[/dim] {Path(target).resolve()}")

    # 1. Сбор данных
    afl_data = collect_afl_data(afl_output_dir, verbose=verbose)

        # 2. Дедупликация
    console.print("\n[cyan]→ Двухуровневая дедупликация крашей...[/cyan]")
    unique_crashes, dedup_stats = deduplicate_crashes(
        afl_data["crashes"],
        target_bin=target
    )

    # 3. Классификация
    console.print("\n[cyan]→ Классификация крашей и хэнгов...[/cyan]")
    classified = classify_crashes(
        crashes=afl_data["crashes"],   # сюда можно передать original, если хочешь
        hangs=afl_data["hangs"],
        target_bin=target,
        parallel=True
    )

    # 4. Приоритизация — ТОЛЬКО уникальные краши!
    console.print("\n[cyan]→ Приоритизация крашей...[/cyan]")
    prioritized = prioritize_crashes(unique_crashes)   # ← важно: unique_crashes, а не classified

    # 5. Генерация отчёта
    if report:
        console.print("\n[cyan]→ Генерация HTML-отчёта...[/cyan]")
        generate_html_report(
            stats=dedup_stats,
            prioritized=prioritized,
            classified=classified,          # ← передаём весь classified
            afl_stats=afl_data.get("fuzzer_stats", {}),
            output_path=report
        )

    # Итоги
    console.print("\n[bold green]Анализ завершён.[/bold green]")
    console.print(f"Отчёт сохранён в: {report}")


if __name__ == "__main__":
    cli()