from __future__ import annotations

from pathlib import Path


def render_pdf(html: str, output: Path) -> None:
    from weasyprint import HTML  # type: ignore[import-untyped]

    HTML(string=html).write_pdf(str(output))
