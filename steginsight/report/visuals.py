"""Visual artefacts for the HTML report.

Everything here returns either an inline SVG string or a base64 ``data:`` URI,
so the finished report is a single file that opens offline with no network
access and no sidecar assets. That property is deliberate: an exhibit's analysis
should not require a page to phone anywhere, and a report that is one file can
be attached to a case record without breaking.
"""

from __future__ import annotations

import base64
import io

import numpy as np
from numpy.typing import NDArray

__all__ = [
    "bit_plane_png",
    "entropy_strip_svg",
    "histogram_svg",
    "line_chart_svg",
    "lsb_composite_png",
    "thumbnail_png",
]


def _png_data_uri(array: NDArray[np.uint8]) -> str:
    from PIL import Image

    buffer = io.BytesIO()
    Image.fromarray(array).save(buffer, "PNG", optimize=True)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _downscale(array: NDArray[np.uint8], max_side: int = 512) -> NDArray[np.uint8]:
    """Reduce by integer stride.

    Deliberately *not* interpolated: resampling a bit plane averages neighbouring
    bits and destroys the very texture the analyst is looking for. Striding keeps
    every pixel it shows exactly as it was.
    """
    height, width = array.shape[:2]
    step = max(1, (max(height, width) + max_side - 1) // max_side)
    return array[::step, ::step]


def bit_plane_png(plane: NDArray[np.uint8], bit: int) -> str:
    """Render one bit plane as a black-and-white image."""
    bits = ((plane >> bit) & 1).astype(np.uint8) * 255
    return _png_data_uri(_downscale(bits))


def lsb_composite_png(planes: dict[str, NDArray[np.uint8]]) -> str | None:
    """Colour composite of the LSB of each of R, G and B.

    Showing the three channels together in colour reveals structure that any
    single plane can hide — a payload written to one channel only appears as a
    pure red, green or blue field, which is instantly recognisable.
    """
    names = [n for n in ("R", "G", "B") if n in planes]
    if len(names) != 3:
        return None
    stack = np.stack([((planes[n] & 1) * 255).astype(np.uint8) for n in names], axis=-1)
    return _png_data_uri(_downscale(stack))


def thumbnail_png(array: NDArray[np.uint8]) -> str:
    return _png_data_uri(_downscale(array, max_side=360))


def _svg_open(width: int, height: int, extra: str = "") -> str:
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg" '
        f'role="img" {extra}>'
    )


def line_chart_svg(
    values: list[float],
    *,
    height: int = 120,
    y_max: float | None = None,
    colour: str = "var(--accent)",
    fill: bool = True,
    threshold: float | None = None,
    label: str = "",
) -> str:
    """A minimal line chart with no JavaScript and no external library."""
    if not values:
        return '<p class="empty">No data.</p>'

    width = 1000
    top = float(y_max if y_max is not None else max(max(values), 1e-9))
    n = len(values)
    step = width / max(n - 1, 1)

    points = [
        f"{i * step:.2f},{height - (v / top) * (height - 8) - 4:.2f}"
        for i, v in enumerate(values)
    ]
    path = " ".join(points)

    parts = [_svg_open(width, height, f'aria-label="{label}"')]
    parts.append(
        f'<rect width="{width}" height="{height}" fill="var(--chart-bg)" rx="4"/>'
    )
    if threshold is not None:
        y = height - (threshold / top) * (height - 8) - 4
        parts.append(
            f'<line x1="0" y1="{y:.2f}" x2="{width}" y2="{y:.2f}" '
            f'stroke="var(--danger)" stroke-width="1" stroke-dasharray="6 4" opacity="0.7"/>'
        )
    if fill:
        parts.append(
            f'<polygon points="0,{height} {path} {width},{height}" '
            f'fill="{colour}" opacity="0.18"/>'
        )
    parts.append(
        f'<polyline points="{path}" fill="none" stroke="{colour}" '
        f'stroke-width="1.6" vector-effect="non-scaling-stroke"/>'
    )
    parts.append("</svg>")
    return "".join(parts)


def entropy_strip_svg(values: list[float], height: int = 26) -> str:
    """A one-dimensional heat strip of entropy across the file.

    Reads as a map of the exhibit: dense regions show as bright bands, so an
    appended encrypted blob or a high-entropy chunk is visible as a block rather
    than as a number.
    """
    if not values:
        return '<p class="empty">No data.</p>'
    width = 1000
    n = len(values)
    bar = width / n
    parts = [_svg_open(width, height, 'aria-label="Entropy map"')]
    for i, value in enumerate(values):
        t = max(0.0, min(1.0, value / 8.0))
        # Dark blue (low) through cyan to white (maximum entropy).
        r = int(255 * max(0.0, (t - 0.75) / 0.25))
        g = int(255 * min(1.0, t * 1.15))
        b = int(90 + 165 * min(1.0, t * 1.3))
        parts.append(
            f'<rect x="{i * bar:.3f}" y="0" width="{bar + 0.5:.3f}" height="{height}" '
            f'fill="rgb({r},{g},{b})"/>'
        )
    parts.append("</svg>")
    return "".join(parts)


def histogram_svg(counts: list[int], height: int = 110) -> str:
    """Byte-value histogram, 256 bars."""
    if not counts:
        return '<p class="empty">No data.</p>'
    width = 1000
    top = max(counts) or 1
    bar = width / 256
    parts = [_svg_open(width, height, 'aria-label="Byte value histogram"')]
    parts.append(f'<rect width="{width}" height="{height}" fill="var(--chart-bg)" rx="4"/>')
    for i, count in enumerate(counts[:256]):
        h = (count / top) * (height - 6)
        parts.append(
            f'<rect x="{i * bar:.3f}" y="{height - h:.2f}" width="{bar * 0.85:.3f}" '
            f'height="{h:.2f}" fill="var(--accent)"/>'
        )
    parts.append("</svg>")
    return "".join(parts)
