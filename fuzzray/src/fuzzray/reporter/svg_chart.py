from __future__ import annotations

from fuzzray.models import PlotPoint


def _fmt_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}с"
    if seconds < 3600:
        return f"{seconds // 60}м"
    h = seconds // 3600
    m = (seconds % 3600) // 60
    return f"{h}ч{m:02d}м" if m else f"{h}ч"


def render_crashes_over_time(points: list[PlotPoint], width: int = 700, height: int = 200) -> str:
    if not points:
        return ""
    xs = [p.unix_time for p in points]
    ys = [p.unique_crashes for p in points]
    x_min, x_max = min(xs), max(xs)
    y_max = max(ys) or 1
    x_range = max(x_max - x_min, 1)

    pad_l, pad_r, pad_t, pad_b = 50, 20, 20, 35
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b

    def sx(x: int) -> float:
        return pad_l + (x - x_min) / x_range * plot_w

    def sy(y: int) -> float:
        return pad_t + plot_h - (y / y_max) * plot_h

    line_pts = " ".join(
        f"{'M' if i == 0 else 'L'}{sx(x):.1f},{sy(y):.1f}"
        for i, (x, y) in enumerate(zip(xs, ys, strict=True))
    )

    area_pts = line_pts + f" L{sx(xs[-1]):.1f},{pad_t + plot_h:.1f} L{sx(xs[0]):.1f},{pad_t + plot_h:.1f} Z"

    gridlines = ""
    for i in range(5):
        y_pos = pad_t + plot_h * i / 4
        val = int(y_max * (4 - i) / 4)
        gridlines += (
            f'<line x1="{pad_l}" y1="{y_pos:.1f}" x2="{pad_l + plot_w}" y2="{y_pos:.1f}" '
            f'stroke="rgba(100,100,255,0.12)" stroke-width="1"/>'
            f'<text x="{pad_l - 8}" y="{y_pos + 4:.1f}" fill="#8899bb" '
            f'font-size="10" text-anchor="end">{val}</text>'
        )

    x_labels = ""
    n_labels = min(6, len(xs))
    for i in range(n_labels):
        idx = i * (len(xs) - 1) // max(n_labels - 1, 1)
        elapsed = xs[idx] - x_min
        x_labels += (
            f'<text x="{sx(xs[idx]):.1f}" y="{pad_t + plot_h + 18:.1f}" '
            f'fill="#8899bb" font-size="10" text-anchor="middle">{_fmt_duration(elapsed)}</text>'
        )

    dots = ""
    step = max(1, len(xs) // 20)
    for i in range(0, len(xs), step):
        dots += (
            f'<circle cx="{sx(xs[i]):.1f}" cy="{sy(ys[i]):.1f}" r="2.5" '
            f'fill="#00ddeb" opacity="0.8"/>'
        )
    if (len(xs) - 1) % step != 0:
        dots += (
            f'<circle cx="{sx(xs[-1]):.1f}" cy="{sy(ys[-1]):.1f}" r="3" '
            f'fill="#ff6ec7"/>'
        )

    return (
        f'<svg width="100%" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'font-family="system-ui, sans-serif">'
        f'<defs>'
        f'<linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0%" stop-color="#00ddeb" stop-opacity="0.3"/>'
        f'<stop offset="100%" stop-color="#00ddeb" stop-opacity="0.02"/>'
        f'</linearGradient>'
        f'<filter id="glow"><feGaussianBlur stdDeviation="2" result="g"/>'
        f'<feMerge><feMergeNode in="g"/><feMergeNode in="SourceGraphic"/></feMerge></filter>'
        f'</defs>'
        f'{gridlines}'
        f'<path d="{area_pts}" fill="url(#areaGrad)"/>'
        f'<path d="{line_pts}" fill="none" stroke="#00ddeb" stroke-width="2" '
        f'stroke-linejoin="round" filter="url(#glow)"/>'
        f'{dots}'
        f'{x_labels}'
        f'<text x="{pad_l}" y="{pad_t - 6}" fill="#8899bb" font-size="11">'
        f'уникальных крашей: {y_max}</text>'
        f'</svg>'
    )
