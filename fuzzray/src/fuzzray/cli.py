from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer(add_completion=False, help="FuzzRay — постпроцессор AFL++ → HTML-отчёт")


@app.command()
def main(
    afl_out: Annotated[Path, typer.Option("--afl-out", help="Выходной каталог AFL++")],
    output: Annotated[Path, typer.Option("-o", "--output", help="Путь к HTML-отчёту")] = Path(
        "fuzzray_report.html"
    ),
    target: Annotated[Path | None, typer.Option("--target", help="Целевой бинарник для gdb-воспроизведения")] = None,
    target_args: Annotated[str, typer.Option("--target-args", help="Шаблон аргументов цели, @@ = путь к входу")] = "@@",
    no_replay: Annotated[bool, typer.Option("--no-replay", help="Без gdb-воспроизведения, только статическая классификация")] = False,
    jobs: Annotated[int, typer.Option("-j", "--jobs", help="Число параллельных gdb-воспроизведений")] = 0,
) -> None:
    """Генерация HTML-отчёта FuzzRay по выходному каталогу AFL++."""
    from fuzzray.pipeline import run_pipeline

    run_pipeline(
        afl_out=afl_out,
        output=output,
        target=target,
        target_args=target_args,
        no_replay=no_replay,
        jobs=jobs,
    )


if __name__ == "__main__":
    app()
