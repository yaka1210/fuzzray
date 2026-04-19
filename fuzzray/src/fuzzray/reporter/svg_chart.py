from __future__ import annotations

from fuzzray.models import PlotPoint


def render_crashes_over_time(points: list[PlotPoint], width: int = 720, height: int = 180) -> str:
    if not points:
        return '<svg width="0" height="0"></svg>'
    xs = [p.unix_time for p in points]
    ys = [p.unique_crashes for p in points]
    x_min, x_max = min(xs), max(xs)
    y_max = max(ys) or 1
    x_range = max(x_max - x_min, 1)

    pad_l, pad_r, pad_t, pad_b = 40, 10, 10, 25
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b

    def sx(x: int) -> float:
        return pad_l + (x - x_min) / x_range * plot_w

    def sy(y: int) -> float:
        return pad_t + plot_h - (y / y_max) * plot_h

    path = " ".join(
        f"{'M' if i == 0 else 'L'}{sx(x):.1f},{sy(y):.1f}"
        for i, (x, y) in enumerate(zip(xs, ys, strict=True))
    )

    gridlines = "".join(
        f'<line x1="{pad_l}" y1="{pad_t + plot_h * i / 4:.1f}" '
        f'x2="{pad_l + plot_w}" y2="{pad_t + plot_h * i / 4:.1f}" '
        f'stroke="#eee" stroke-width="1"/>'
        for i in range(5)
    )

    return (
        f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg" '
        'font-family="sans-serif" font-size="11">'
        f'<rect width="{width}" height="{height}" fill="#fff"/>'
        f"{gridlines}"
        f'<path d="{path}" fill="none" stroke="#c0392b" stroke-width="2"/>'
        f'<text x="{pad_l}" y="{pad_t - 2}" fill="#666">падений: {y_max}</text>'
        f'<text x="{pad_l}" y="{height - 5}" fill="#666">время</text>'
        "</svg>"
    )
