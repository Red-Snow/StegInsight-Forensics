"""Bridge for the browser build.

The web app runs this exact package under Pyodide (CPython compiled to
WebAssembly), so the analysis a visitor gets is the analysis the CLI gives —
same detectors, same thresholds, same evidence model. Nothing is reimplemented
in JavaScript, which is the only way a browser front-end can be trusted to agree
with the command line.

This module is the single call the front-end makes. Keeping the bridge in Python
means it is covered by the test-suite rather than being untested glue.
"""

from __future__ import annotations

import base64
from typing import Any

from .core.carrier import Carrier
from .core.evidence import DEFAULT_PRIOR
from .engine import __version__, analyse

__all__ = ["analyse_for_web", "engine_info", "triage_for_web"]

#: Bit planes rendered for the gallery. 0 is where LSB embedding lands; 1 is the
#: control that makes plane 0 interpretable; 2 confirms the image has structure.
_PLANES = (0, 1, 2)

#: Hex preview bytes per carved object, so the payload panel stays light.
_HEX_PREVIEW = 512


def engine_info() -> dict[str, Any]:
    return {"version": __version__, "prior": DEFAULT_PRIOR}


def analyse_for_web(
    name: str,
    data: bytes,
    prior: float = DEFAULT_PRIOR,
    *,
    with_visuals: bool = True,
    with_html: bool = True,
) -> dict[str, Any]:
    """Analyse one exhibit and return everything the front-end renders.

    ``data`` arrives as bytes copied from a JavaScript ``Uint8Array``.
    """
    if isinstance(data, memoryview):
        data = bytes(data)

    report = analyse(Carrier.from_bytes(bytes(data), name), prior=prior)
    payload: dict[str, Any] = report.to_dict()

    payload["visuals"] = _visuals(report) if with_visuals else {}
    payload["carved_data"] = [
        {
            "offset": obj.offset,
            "length": obj.length,
            "format": obj.format,
            "hex_preview": obj.data[:_HEX_PREVIEW].hex(),
            "base64": base64.b64encode(obj.data).decode("ascii"),
        }
        for obj in report.carved[:8]
    ]

    if with_html:
        from .report.html import render_html

        payload["html_report"] = render_html(report)

    return payload


def triage_for_web(
    files: list[tuple[str, bytes]], prior: float = DEFAULT_PRIOR
) -> list[dict[str, Any]]:
    """Rank several exhibits. Mirrors ``steginsight triage``."""
    rows: list[dict[str, Any]] = []
    for name, data in files:
        try:
            report = analyse(Carrier.from_bytes(bytes(data), name), prior=prior)
        except Exception as exc:
            rows.append({"name": name, "error": str(exc)})
            continue
        rows.append(
            {
                "name": name,
                "size": report.carrier.full_size,
                "format": report.carrier.format_name,
                "sha256": report.carrier.hashes.sha256,
                "verdict": report.assessment.verdict.value,
                "probability": round(report.assessment.probability, 4),
                "top_findings": [
                    {"id": e.id, "title": e.title, "severity": e.severity.value}
                    for e in report.evidence
                    if e.llr > 0.2
                ][:3],
            }
        )
    rows.sort(key=lambda r: r.get("probability", -1), reverse=True)
    return rows


def _visuals(report: Any) -> dict[str, Any]:
    """Bit-plane imagery, produced only for carriers where it means something."""
    if report.spatial is None:
        return {}

    try:
        import numpy as np

        from .detectors.spatial import load_planes
        from .report.visuals import bit_plane_png, lsb_composite_png, thumbnail_png
    except ImportError:  # pragma: no cover
        return {}

    loaded = load_planes(report.carrier.data)
    if loaded is None:
        return {}
    planes, _mode, _fmt, _w, _h = loaded

    usable = {k: v for k, v in planes.items() if v.ndim == 2 and v.size > 1024}
    if not usable:
        return {}

    out: dict[str, Any] = {}
    try:
        import io as _io

        from PIL import Image

        with Image.open(_io.BytesIO(report.carrier.data)) as image:
            image.load()
            out["thumbnail"] = thumbnail_png(np.asarray(image.convert("RGB")))
    except Exception:
        pass

    composite = lsb_composite_png(usable)
    if composite:
        out["lsb_composite"] = composite

    first_name, first = next(iter(usable.items()))
    out["channel"] = first_name
    out["planes"] = [{"bit": b, "src": bit_plane_png(first, b)} for b in _PLANES]
    return out
