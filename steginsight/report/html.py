"""Single-file HTML report.

The output is one self-contained document: no scripts from a CDN, no sidecar
images, no network access of any kind. It opens offline in any browser, prints
cleanly, and can be attached to a case record as a single artefact.

This is what replaces the hosted web application the project previously shipped.
The property that actually mattered there — the exhibit never leaves the
analyst's machine — is preserved and strengthened, because now there is no
upload step and no server at all.
"""

from __future__ import annotations

import html
import json
from typing import Any

from ..core.evidence import Verdict
from ..detectors.spatial import load_planes
from ..engine import AnalysisReport
from .visuals import (
    bit_plane_png,
    entropy_strip_svg,
    histogram_svg,
    line_chart_svg,
    lsb_composite_png,
    thumbnail_png,
)

__all__ = ["render_html"]

_VERDICT_CLASS = {
    Verdict.LIKELY_EMBEDDED: "v-embedded",
    Verdict.SUSPICIOUS: "v-suspicious",
    Verdict.INCONCLUSIVE: "v-inconclusive",
    Verdict.CLEAN: "v-clean",
}

_VERDICT_LABEL = {
    Verdict.LIKELY_EMBEDDED: "Likely embedded",
    Verdict.SUSPICIOUS: "Suspicious",
    Verdict.INCONCLUSIVE: "Inconclusive",
    Verdict.CLEAN: "Clean",
}


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_html(report: AnalysisReport, *, include_json: bool = True) -> str:
    carrier = report.carrier
    assessment = report.assessment
    sections: list[str] = []

    sections.append(_header(report))
    sections.append(_exhibit(report))
    sections.append(_findings(report))
    visuals = _visuals(report)
    if visuals:
        sections.append(visuals)
    sections.append(_entropy(report))
    stats = _statistics(report)
    if stats:
        sections.append(stats)
    if report.structure:
        sections.append(_structure(report))
    if report.carved:
        sections.append(_carved(report))
    if report.recommended_actions:
        sections.append(_actions(report))
    sections.append(_limitations(report))
    if include_json:
        sections.append(_raw_json(report))

    title = f"StegInsight — {carrier.path.name}"
    return _DOCUMENT.format(
        title=_e(title),
        verdict_class=_VERDICT_CLASS[assessment.verdict],
        styles=_STYLES,
        body="\n".join(sections),
        footer=(
            f"StegInsight {report.engine_version} &middot; analysed "
            f"{_e(report.analysed_at)} &middot; {report.duration_ms:.0f} ms"
        ),
    )


# --------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------


def _header(report: AnalysisReport) -> str:
    a = report.assessment
    return f"""
<header class="hero {_VERDICT_CLASS[a.verdict]}">
  <div class="hero-mark">{_e(_VERDICT_LABEL[a.verdict])}</div>
  <div class="hero-body">
    <h1>{_e(report.carrier.path.name)}</h1>
    <p class="rationale">{_e(a.rationale)}</p>
    <div class="metrics">
      <div><span class="k">Posterior</span><span class="v">{a.probability:.3f}</span></div>
      <div><span class="k">Log-odds</span><span class="v">{a.log_odds:+.2f}</span></div>
      <div><span class="k">Corroborating families</span><span class="v">{a.corroborating_families}</span></div>
    </div>
  </div>
</header>"""


def _exhibit(report: AnalysisReport) -> str:
    c = report.carrier
    rows = [
        ("File", c.path.name),
        ("Size", f"{c.full_size:,} bytes"),
        ("Format (magic bytes)", c.detected.description if c.detected else "unrecognised"),
        ("Declared type", c.declared_type or "none"),
        ("SHA-256", c.hashes.sha256),
        ("SHA-1", c.hashes.sha1),
        ("MD5", c.hashes.md5),
    ]
    if c.truncated:
        rows.append(("Analysed", f"{c.size:,} bytes (truncated for analysis)"))

    mismatch = ""
    if c.type_mismatch:
        mismatch = (
            '<p class="warn">The filename implies a different type from the content. '
            "Renaming is the simplest concealment technique there is.</p>"
        )

    body = "".join(
        f'<tr><th>{_e(k)}</th><td class="mono">{_e(v)}</td></tr>' for k, v in rows
    )
    return f"""
<section>
  <h2>Exhibit</h2>
  {mismatch}
  <table class="kv">{body}</table>
</section>"""


def _findings(report: AnalysisReport) -> str:
    if not report.evidence:
        return '<section><h2>Findings</h2><p class="empty">No detector produced an observation.</p></section>'

    cards = []
    for item in report.evidence:
        weight = item.weight()
        badge = "supports" if weight > 0.05 else ("excludes" if weight < -0.05 else "context")
        measurements = ""
        if item.measurements:
            rows = "".join(
                f"<tr><th>{_e(k)}</th><td class='mono'>{_e(_fmt(v))}</td></tr>"
                for k, v in item.measurements.items()
            )
            measurements = f"<details><summary>Measurements</summary><table class='kv small'>{rows}</table></details>"

        location = ""
        if item.offset is not None:
            span = f", length {item.length:,}" if item.length else ""
            location = f'<p class="loc mono">offset 0x{item.offset:x}{span}</p>'

        refs = ""
        if item.references:
            items = "".join(f"<li>{_e(r)}</li>" for r in item.references)
            refs = f"<details><summary>References</summary><ul class='refs'>{items}</ul></details>"

        cards.append(f"""
<article class="finding sev-{item.severity.value}">
  <div class="finding-head">
    <span class="sev">{_e(item.severity.value)}</span>
    <h3>{_e(item.title)}</h3>
    <span class="weight {badge}">{weight:+.2f}</span>
  </div>
  <p>{_e(item.detail)}</p>
  {location}
  <p class="meta mono">{_e(item.id)} &middot; {_e(item.family.value)}{
      ' &middot; ' + _e(item.technique) if item.technique else ''}</p>
  {measurements}
  {refs}
</article>""")

    return f"""
<section>
  <h2>Findings</h2>
  <p class="note">Each finding carries a base-10 log likelihood ratio: how much
  more probable the observation is if a payload is present than if the carrier is
  clean. Negative values argue against embedding. Only these numbers move the
  verdict, so every point of the score traces to a named measurement.</p>
  {''.join(cards)}
</section>"""


def _visuals(report: AnalysisReport) -> str:
    """Bit-plane imagery. The single most useful visual in image steganalysis."""
    if report.spatial is None:
        return ""
    loaded = load_planes(report.carrier.data)
    if loaded is None:
        return ""
    planes, _mode, _fmt, _w, _h = loaded
    analysable = {k: v for k, v in planes.items() if v.ndim == 2 and v.size > 1024}
    if not analysable:
        return ""

    blocks: list[str] = []

    composite = lsb_composite_png(analysable)
    if composite:
        blocks.append(f"""
<figure>
  <img src="{composite}" alt="LSB colour composite"/>
  <figcaption><strong>LSB composite (R/G/B)</strong> — the least significant bit of
  each channel shown as one colour image. Payload written to a single channel
  appears as a saturated primary; natural content appears as fine grey noise that
  still traces the image's edges.</figcaption>
</figure>""")

    captions = {
        0: (
            "<strong>Bit plane 0</strong> (least significant) — where LSB embedding "
            "lands. Natural imagery keeps visible structure even here. Uniform noise, "
            "or a band of noise with structure elsewhere, marks the payload and its "
            "extent."
        ),
        1: (
            "<strong>Bit plane 1</strong> — the control. This plane should look much "
            "like plane 0 in a clean image. If plane 0 is noise and this one still "
            "shows the picture, plane 0 was overwritten."
        ),
        2: (
            "<strong>Bit plane 2</strong> — structure should be clearly visible here "
            "in any natural image, embedded or not."
        ),
    }
    first = next(iter(analysable.values()))
    for bit in (0, 1, 2):
        blocks.append(f"""
<figure>
  <img src="{bit_plane_png(first, bit)}" alt="Bit plane {bit}"/>
  <figcaption>{captions[bit]}</figcaption>
</figure>""")

    array = report.carrier.data
    thumb = ""
    try:
        import io as _io

        import numpy as _np
        from PIL import Image as _Image

        with _Image.open(_io.BytesIO(array)) as im:
            im.load()
            thumb = f"""
<figure>
  <img src="{thumbnail_png(_np.asarray(im.convert('RGB')))}" alt="Rendered carrier"/>
  <figcaption><strong>Carrier as rendered</strong> — what a viewer displays.</figcaption>
</figure>"""
    except Exception:
        thumb = ""

    return f"""
<section>
  <h2>Bit-plane imagery</h2>
  <div class="gallery">{thumb}{''.join(blocks)}</div>
</section>"""


def _entropy(report: AnalysisReport) -> str:
    from ..core.stats import expected_random_entropy

    expected = expected_random_entropy(report.carrier.size)
    strip = entropy_strip_svg(report.entropy_values)
    curve = line_chart_svg(
        report.entropy_values, y_max=8.0, height=130, label="Entropy by offset"
    )
    hist = histogram_svg(report.histogram)
    return f"""
<section>
  <h2>Entropy and byte distribution</h2>
  <p class="note">Overall entropy is <strong>{report.entropy_overall:.4f}</strong> bits/byte.
  Uniform random data of this length would measure <strong>{expected:.4f}</strong> — the
  correct comparison, since a short sample cannot reach 8.0 even from a perfect
  random source. High entropy indicates compressed <em>or</em> encrypted content;
  the two are not separable by this measurement alone.</p>
  <div class="chart">{strip}</div>
  <p class="caption">Entropy map across the file, {report.entropy_window:,}-byte windows.</p>
  <div class="chart">{curve}</div>
  <p class="caption">Same data as a curve. A flat maximum region is compressed or encrypted data.</p>
  <div class="chart">{hist}</div>
  <p class="caption">Byte-value histogram (0&ndash;255).</p>
</section>"""


def _statistics(report: AnalysisReport) -> str:
    blocks: list[str] = []

    if report.spatial is not None:
        rows = []
        for channel in report.spatial.channels:
            rs = channel.rs.rate if channel.rs and not channel.rs.unreliable else None
            spa = channel.spa.rate if channel.spa and not channel.spa.unreliable else None
            chi = channel.chi_square.p_value if channel.chi_square else None
            gap = ""
            if len(channel.transition_rates) >= 2:
                t0, t1 = channel.transition_rates[0], channel.transition_rates[1]
                if t0 == t0 and t1 == t1:
                    gap = f"{t0 - t1:+.4f}"
            rows.append(
                f"<tr><td>{_e(channel.name)}</td>"
                f"<td class='mono'>{_pct(rs)}</td>"
                f"<td class='mono'>{_pct(spa)}</td>"
                f"<td class='mono'>{_sci(chi)}</td>"
                f"<td class='mono'>{gap or '&mdash;'}</td></tr>"
            )
        blocks.append(f"""
<h3>Spatial domain</h3>
<table class="grid">
  <thead><tr><th>Channel</th><th>RS estimate</th><th>SPA estimate</th>
  <th>&chi;&sup2; p (PoV)</th><th>Plane 0&minus;1 gap</th></tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table>
<p class="note">RS and Sample Pair Analysis estimate the <em>embedding rate</em>, not
merely its presence. They rest on different assumptions, so agreement between them
is real corroboration. Both sit around a 3&ndash;5% noise floor on natural imagery.
For the &chi;&sup2; column a value approaching 1.0 is the incriminating outcome:
the model being fitted is the embedded one.</p>""")

        if report.spatial.curve_values:
            blocks.append(
                '<div class="chart">'
                + line_chart_svg(
                    report.spatial.curve_values,
                    y_max=1.0,
                    height=120,
                    threshold=0.95,
                    label="Chi-square p-value by block",
                )
                + "</div>"
                + '<p class="caption">&chi;&sup2; p-value across successive blocks. A run near '
                "1.0 that then collapses is the signature of a payload written sequentially "
                "from the start; the collapse point indicates its length.</p>"
            )

    if report.dct is not None:
        d = report.dct
        blocks.append(f"""
<h3>DCT (transform) domain</h3>
<table class="kv">
  <tr><th>AC coefficients</th><td class="mono">{d.total_coefficients:,}</td></tr>
  <tr><th>Non-zero AC</th><td class="mono">{d.nonzero_ac:,}</td></tr>
  <tr><th>&chi;&sup2; p (coefficient PoV)</th><td class="mono">{_sci(d.chi_square_p)}</td></tr>
  <tr><th>Estimated JPEG quality</th><td class="mono">{d.quality_estimate or '&mdash;'}</td></tr>
</table>
<p class="note">These come from the quantised DCT coefficients, decoded directly from
the entropy-coded scan. JPEG steganography lives here: once an image has been
decoded to pixels the embedding traces are gone, so pixel-domain analysis of a JPEG
measures the quantiser rather than the carrier.</p>""")

    if report.audio is not None:
        a = report.audio
        blocks.append(f"""
<h3>PCM audio</h3>
<table class="kv">
  <tr><th>Sample rate</th><td class="mono">{a.frame_rate:,} Hz &middot; {a.channels} ch &middot; {a.sample_width * 8}-bit</td></tr>
  <tr><th>Duration</th><td class="mono">{a.duration_seconds:.2f} s</td></tr>
  <tr><th>LSB transition rate</th><td class="mono">{_num(a.lsb_transition_rate)}</td></tr>
  <tr><th>Silent samples</th><td class="mono">{a.silent_samples:,}</td></tr>
  <tr><th>LSB set within silence</th><td class="mono">{_num(a.silent_lsb_ratio)}</td></tr>
</table>
<p class="note">For 16-bit audio the transition rate is uninformative on its own: a
recording's noise floor, applied dither and lossy-codec artefacts all drive it to
0.5, and so does a payload. The discriminating measurement is the low bit
<em>within digital silence</em>, which is exactly zero in any genuine recording.</p>""")

    if report.text is not None:
        t = report.text
        zw = ", ".join(f"{k} &times;{v}" for k, v in t.zero_width_counts.items()) or "none"
        blocks.append(f"""
<h3>Text and Unicode</h3>
<table class="kv">
  <tr><th>Characters</th><td class="mono">{t.characters:,}</td></tr>
  <tr><th>Zero-width</th><td class="mono">{zw}</td></tr>
  <tr><th>Tag characters</th><td class="mono">{t.tag_characters:,}</td></tr>
  <tr><th>Variation selectors</th><td class="mono">{t.variation_selectors:,}</td></tr>
  <tr><th>Bidi controls</th><td class="mono">{t.bidi_controls:,}</td></tr>
</table>""")

    if not blocks:
        return ""
    return f"<section><h2>Statistics</h2>{''.join(blocks)}</section>"


def _structure(report: AnalysisReport) -> str:
    rows = []
    for node in report.structure[:200]:
        integrity = {
            "ok": '<span class="ok">ok</span>',
            "failed": '<span class="bad">FAILED</span>',
        }.get(node.integrity, '<span class="dim">&mdash;</span>')
        entropy = f"{node.entropy:.3f}" if node.entropy is not None else "&mdash;"
        rows.append(
            f"<tr><td class='mono'>{_e(node.id)}</td>"
            f"<td>{_e(node.label)}</td>"
            f"<td class='mono'>0x{node.offset:08x}</td>"
            f"<td class='mono'>{node.length:,}</td>"
            f"<td class='mono'>{entropy}</td>"
            f"<td>{integrity}</td></tr>"
        )
    return f"""
<section>
  <h2>Container structure</h2>
  <table class="grid">
    <thead><tr><th>ID</th><th>Description</th><th>Offset</th><th>Length</th>
    <th>Entropy</th><th>Integrity</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</section>"""


def _carved(report: AnalysisReport) -> str:
    blocks = []
    for obj in report.carved[:12]:
        badge = (
            '<span class="ok">verified by parsing</span>'
            if obj.verified
            else '<span class="dim">identified by magic bytes only</span>'
        )
        blocks.append(f"""
<article class="carved">
  <h3>0x{obj.offset:08x} &middot; {obj.length:,} bytes &middot; {_e(obj.format)}</h3>
  <p>{_e(obj.description)} &mdash; {badge}</p>
  <pre class="hex">{_e(_hexdump(obj.data[:256], obj.offset))}</pre>
</article>""")
    return f"""
<section>
  <h2>Recovered objects</h2>
  <p class="note">Only regions actually located in the carrier appear here. Nothing
  is reconstructed or inferred.</p>
  {''.join(blocks)}
</section>"""


def _actions(report: AnalysisReport) -> str:
    items = "".join(f"<li class='mono'>{_e(a)}</li>" for a in report.recommended_actions)
    return f"<section><h2>Recommended next steps</h2><ol class='actions'>{items}</ol></section>"


def _limitations(report: AnalysisReport) -> str:
    if not report.limitations:
        body = (
            "<p>Every applicable detector ran to completion. Note that no negative "
            "result proves absence: a short or well-encrypted payload can fall below "
            "the detection floor of every technique implemented here.</p>"
        )
    else:
        items = "".join(f"<li>{_e(note)}</li>" for note in report.limitations)
        body = f"<ul>{items}</ul>"
    return f"""
<section class="limits">
  <h2>Limitations</h2>
  <p class="note">What the analysis could not establish is part of the result.</p>
  {body}
</section>"""


def _raw_json(report: AnalysisReport) -> str:
    payload = json.dumps(report.to_dict(), indent=2, sort_keys=False)
    return f"""
<section>
  <h2>Machine-readable result</h2>
  <details>
    <summary>Full JSON</summary>
    <pre class="json">{_e(payload)}</pre>
  </details>
</section>"""


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        lines.append(f"{base + offset:08x}  {hexpart}  |{text}|")
    return "\n".join(lines)


def _fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.6g}"
    if isinstance(value, (list, dict)):
        return json.dumps(value)[:300]
    return str(value)


def _pct(value: float | None) -> str:
    return "&mdash;" if value is None else f"{value:.1%}"


def _num(value: float | None) -> str:
    if value is None or value != value:
        return "&mdash;"
    return f"{value:.5f}"


def _sci(value: float | None) -> str:
    if value is None:
        return "&mdash;"
    return f"{value:.4g}"


_STYLES = """
:root{
  --bg:#f7f8fa; --panel:#ffffff; --ink:#161a22; --muted:#5c6675; --line:#e2e6ec;
  --accent:#1f6feb; --chart-bg:#eef1f6; --danger:#c8352b; --warn:#9a6400;
  --ok:#1a7f4b; --crit-bg:#fdecea; --high-bg:#fdf1ec; --med-bg:#fdf8e8;
  --low-bg:#eef4fb; --info-bg:#f2f4f7;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#0f1319; --panel:#161b23; --ink:#e7ecf3; --muted:#95a0b0; --line:#242c37;
    --accent:#5a9bff; --chart-bg:#111721; --danger:#ff6b5e; --warn:#e0a63a;
    --ok:#4dd08a; --crit-bg:#2a1614; --high-bg:#261914; --med-bg:#241f12;
    --low-bg:#141c27; --info-bg:#171c24;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 24px 72px}
h1{font-size:26px;margin:0 0 8px;letter-spacing:-.01em}
h2{font-size:17px;margin:0 0 14px;letter-spacing:.04em;text-transform:uppercase;
  color:var(--muted);font-weight:650}
h3{font-size:15px;margin:22px 0 10px}
section{background:var(--panel);border:1px solid var(--line);border-radius:12px;
  padding:22px 24px;margin:0 0 18px}
.mono{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  font-size:12.5px}
.note{color:var(--muted);font-size:13.5px;margin:0 0 14px}
.caption{color:var(--muted);font-size:12.5px;margin:6px 0 18px}
.empty,.dim{color:var(--muted)}
.warn{color:var(--danger);font-weight:600}
.ok{color:var(--ok);font-weight:600}
.bad{color:var(--danger);font-weight:700}

.hero{display:flex;gap:22px;align-items:flex-start;background:var(--panel);
  border:1px solid var(--line);border-left-width:6px;border-radius:12px;
  padding:24px;margin:0 0 18px}
.hero-mark{font-size:12px;font-weight:750;letter-spacing:.1em;text-transform:uppercase;
  padding:8px 12px;border-radius:6px;white-space:nowrap;flex-shrink:0}
.hero-body{min-width:0}
.rationale{margin:0 0 16px;color:var(--muted);max-width:72ch}
.v-embedded{border-left-color:var(--danger)}
.v-embedded .hero-mark{background:var(--crit-bg);color:var(--danger)}
.v-suspicious{border-left-color:var(--warn)}
.v-suspicious .hero-mark{background:var(--med-bg);color:var(--warn)}
.v-inconclusive{border-left-color:var(--accent)}
.v-inconclusive .hero-mark{background:var(--low-bg);color:var(--accent)}
.v-clean{border-left-color:var(--ok)}
.v-clean .hero-mark{background:var(--info-bg);color:var(--ok)}
.metrics{display:flex;gap:28px;flex-wrap:wrap}
.metrics .k{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.07em;
  color:var(--muted)}
.metrics .v{display:block;font-size:20px;font-weight:650;
  font-family:ui-monospace,monospace}

table{border-collapse:collapse;width:100%}
.kv th{text-align:left;font-weight:550;color:var(--muted);padding:5px 16px 5px 0;
  white-space:nowrap;vertical-align:top;width:1%}
.kv td{padding:5px 0;word-break:break-all}
.kv.small th,.kv.small td{font-size:12px;padding:3px 12px 3px 0}
.grid{font-size:13.5px}
.grid th{text-align:left;border-bottom:1px solid var(--line);padding:8px 12px 8px 0;
  color:var(--muted);font-weight:600}
.grid td{border-bottom:1px solid var(--line);padding:7px 12px 7px 0}

.finding{border:1px solid var(--line);border-left-width:4px;border-radius:8px;
  padding:14px 16px;margin:0 0 12px;background:var(--info-bg)}
.finding p{margin:0 0 8px;max-width:78ch}
.finding-head{display:flex;align-items:baseline;gap:10px;margin:0 0 8px}
.finding-head h3{margin:0;flex:1;font-size:14.5px}
.sev{font-size:10px;font-weight:750;letter-spacing:.08em;text-transform:uppercase;
  padding:3px 7px;border-radius:4px;background:var(--panel)}
.weight{font-family:ui-monospace,monospace;font-size:12px;font-weight:700}
.weight.supports{color:var(--danger)}
.weight.excludes{color:var(--ok)}
.weight.context{color:var(--muted)}
.sev-critical{border-left-color:var(--danger);background:var(--crit-bg)}
.sev-high{border-left-color:var(--danger);background:var(--high-bg)}
.sev-medium{border-left-color:var(--warn);background:var(--med-bg)}
.sev-low{border-left-color:var(--accent);background:var(--low-bg)}
.sev-info{border-left-color:var(--line)}
.meta,.loc{color:var(--muted);font-size:11.5px;margin:6px 0 0}
details{margin:8px 0 0}
summary{cursor:pointer;color:var(--accent);font-size:12.5px}
.refs{margin:6px 0 0;padding-left:18px;font-size:12.5px;color:var(--muted)}

.gallery{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:18px}
figure{margin:0}
figure img{width:100%;border:1px solid var(--line);border-radius:8px;
  image-rendering:pixelated;background:var(--chart-bg);display:block}
figcaption{font-size:12.5px;color:var(--muted);margin-top:8px}
.chart{overflow-x:auto;border-radius:6px}
.carved{border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin:0 0 12px}
.carved h3{margin:0 0 6px;font-family:ui-monospace,monospace;font-size:13px}
pre.hex,pre.json{background:var(--chart-bg);border-radius:6px;padding:12px;
  overflow-x:auto;font-size:11.5px;line-height:1.5;margin:10px 0 0}
.actions{margin:0;padding-left:22px}
.actions li{margin:0 0 7px}
.limits ul{margin:0;padding-left:20px;color:var(--muted);font-size:13.5px}
.limits li{margin:0 0 8px;max-width:80ch}
footer{color:var(--muted);font-size:12px;text-align:center;padding:8px 0 0}
@media print{
  body{background:#fff}
  section,.hero{break-inside:avoid;border-color:#ccc}
  details{display:block}
  summary{display:none}
}
"""

_DOCUMENT = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{title}</title>
<style>{styles}</style>
</head>
<body>
<div class="wrap">
{body}
<footer>{footer}</footer>
</div>
</body>
</html>
"""
