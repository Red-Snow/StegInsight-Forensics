"""Terminal reporting."""

from __future__ import annotations

import os
import sys
from typing import TextIO

from ..core.evidence import Severity, Verdict
from ..engine import AnalysisReport

__all__ = ["render_text", "supports_colour", "verdict_exit_code"]


class _Palette:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text


VERDICT_STYLE = {
    Verdict.LIKELY_EMBEDDED: ("31;1", "LIKELY EMBEDDED"),
    Verdict.SUSPICIOUS: ("33;1", "SUSPICIOUS"),
    Verdict.INCONCLUSIVE: ("36;1", "INCONCLUSIVE"),
    Verdict.CLEAN: ("32;1", "CLEAN"),
}

SEVERITY_STYLE = {
    Severity.CRITICAL: ("31;1", "CRIT"),
    Severity.HIGH: ("31", "HIGH"),
    Severity.MEDIUM: ("33", "MED "),
    Severity.LOW: ("36", "LOW "),
    Severity.INFO: ("90", "INFO"),
}


def supports_colour(stream: TextIO = sys.stdout) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def verdict_exit_code(report: AnalysisReport) -> int:
    """Exit codes so the tool composes into pipelines and CI.

    0 clean, 1 inconclusive, 2 suspicious, 3 likely embedded. A triage run over
    a corpus returns the highest code it saw, so a shell script can gate on it.
    """
    return {
        Verdict.CLEAN: 0,
        Verdict.INCONCLUSIVE: 1,
        Verdict.SUSPICIOUS: 2,
        Verdict.LIKELY_EMBEDDED: 3,
    }[report.assessment.verdict]


def render_text(report: AnalysisReport, *, colour: bool, verbose: bool = False) -> str:
    c = _Palette(colour)
    out: list[str] = []
    identity = report.carrier
    assessment = report.assessment

    code, label = VERDICT_STYLE[assessment.verdict]
    out.append("")
    out.append(c(f"  {label}", code) + c(f"   p = {assessment.probability:.3f}", "1"))
    out.append("")
    out.append(_wrap(assessment.rationale, indent="  "))
    out.append("")

    out.append(c("  EXHIBIT", "1"))
    out.append(f"    file        {identity.path.name}")
    out.append(f"    size        {identity.full_size:,} bytes")
    detected = identity.detected.description if identity.detected else "unrecognised"
    out.append(f"    format      {detected}")
    if identity.type_mismatch:
        out.append(f"    {c('mismatch', '31;1')}    extension implies {identity.declared_type}")
    out.append(f"    sha256      {identity.hashes.sha256}")
    if verbose:
        out.append(f"    sha1        {identity.hashes.sha1}")
        out.append(f"    md5         {identity.hashes.md5}")
    out.append(
        f"    entropy     {report.entropy_overall:.4f} bits/byte "
        f"(uniform random would give {_expected(report):.4f})"
    )
    out.append("")

    positives = [e for e in report.evidence if e.llr > 0 or e.severity != Severity.INFO]
    negatives = [e for e in report.evidence if e.llr < 0]
    shown = report.evidence if verbose else positives

    if shown:
        out.append(c("  FINDINGS", "1"))
        for item in shown:
            sev_code, sev_label = SEVERITY_STYLE[item.severity]
            weight = item.weight()
            marker = f"{weight:+.2f}" if weight else " 0.00"
            out.append(f"    {c(sev_label, sev_code)}  {item.title}   {c(marker, '90')}")
            out.append(_wrap(item.detail, indent="          ", dim=c))
            if item.offset is not None:
                span = f" length {item.length:,}" if item.length else ""
                out.append(c(f"          at offset 0x{item.offset:x}{span}", "90"))
            out.append("")
    else:
        out.append(c("  FINDINGS", "1"))
        out.append("    none\n")

    if negatives and not verbose:
        out.append(c(f"  {len(negatives)} exculpatory finding(s) — use -v to show", "90"))
        out.append("")

    if report.carved:
        out.append(c("  RECOVERED OBJECTS", "1"))
        for obj in report.carved[:10]:
            tick = c("verified", "32") if obj.verified else c("unverified", "33")
            out.append(
                f"    0x{obj.offset:08x}  {obj.length:>10,} B  {obj.format:<10} {tick}"
            )
            out.append(_wrap(obj.description, indent="                ", dim=c))
        out.append("")

    actions = report.recommended_actions
    if actions:
        out.append(c("  NEXT STEPS", "1"))
        for action in actions[:8]:
            out.append(f"    - {action}")
        out.append("")

    if report.limitations:
        out.append(c("  LIMITATIONS", "1"))
        for note in report.limitations:
            out.append(_wrap(f"- {note}", indent="    ", dim=c))
        out.append("")

    out.append(c(f"  analysed in {report.duration_ms:.0f} ms", "90"))
    out.append("")
    return "\n".join(out)


def _expected(report: AnalysisReport) -> float:
    from ..core.stats import expected_random_entropy

    return expected_random_entropy(report.carrier.size)


def _wrap(text: str, indent: str = "", width: int = 96, dim: _Palette | None = None) -> str:
    import textwrap

    lines = textwrap.wrap(text, width=width - len(indent)) or [""]
    body = "\n".join(indent + line for line in lines)
    return dim(body, "90") if dim else body
