"""Analysis orchestration.

Chooses which detectors apply to a given exhibit, runs them, and assembles the
report. Detector selection is driven by the format identified from magic bytes,
never by the file extension.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .containers import isobmff, jpeg, pdf, png, riff, simple
from .containers.base import ContainerResult
from .containers.zip_probe import probe_zip
from .core.carrier import Carrier, CarvedObject, StructuralNode
from .core.evidence import (
    DEFAULT_PRIOR,
    Assessment,
    Evidence,
    Family,
    Severity,
    assess,
    collect_actions,
    sort_evidence,
)
from .core.signatures import MARKER_LLR, scan_file_magics, scan_tool_markers
from .core.stats import (
    byte_histogram,
    expected_random_entropy,
    printable_ratio,
    shannon_entropy,
    sliding_entropy,
)
from .detectors import audio as audio_detector
from .detectors import spatial as spatial_detector
from .detectors import text as text_detector
from .detectors import transform as transform_detector

__version__ = "2.0.0"

__all__ = ["AnalysisReport", "analyse", "analyse_path"]


@dataclass(slots=True)
class AnalysisReport:
    carrier: Carrier
    assessment: Assessment
    evidence: list[Evidence]
    structure: list[StructuralNode]
    carved: list[CarvedObject]
    entropy_overall: float
    entropy_offsets: list[int]
    entropy_values: list[float]
    entropy_window: int
    histogram: list[int]
    printable_ratio: float
    spatial: Any = None
    dct: Any = None
    audio: Any = None
    text: Any = None
    limitations: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    analysed_at: str = ""
    engine_version: str = __version__

    @property
    def recommended_actions(self) -> list[str]:
        raw = collect_actions(self.evidence)
        name = str(self.carrier.path)
        return [action.replace("{file}", name) for action in raw]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "engine_version": self.engine_version,
            "analysed_at": self.analysed_at,
            "duration_ms": round(self.duration_ms, 2),
            "exhibit": self.carrier.identity_dict(),
            "assessment": self.assessment.to_dict(),
            "evidence": [e.to_dict() for e in self.evidence],
            "entropy": {
                "overall": round(self.entropy_overall, 5),
                "expected_if_random": round(expected_random_entropy(self.carrier.size), 5),
                "window_size": self.entropy_window,
                "offsets": self.entropy_offsets,
                "values": [round(v, 4) for v in self.entropy_values],
                "printable_ratio": round(self.printable_ratio, 5),
            },
            "structure": [n.to_dict() for n in self.structure],
            "carved": [c.to_dict() for c in self.carved],
            "spatial": self.spatial.to_dict() if self.spatial else None,
            "dct": self.dct.to_dict() if self.dct else None,
            "audio": self.audio.to_dict() if self.audio else None,
            "text": self.text.to_dict() if self.text else None,
            "recommended_actions": self.recommended_actions,
            "limitations": self.limitations,
        }


def analyse_path(path: str, prior: float = DEFAULT_PRIOR) -> AnalysisReport:
    return analyse(Carrier.load(path), prior=prior)


def analyse(carrier: Carrier, prior: float = DEFAULT_PRIOR) -> AnalysisReport:
    started = time.perf_counter()
    data = carrier.data

    evidence: list[Evidence] = []
    limitations: list[str] = []

    if carrier.truncated:
        limitations.append(
            f"Exhibit is {carrier.full_size:,} bytes; analysis used the first "
            f"{carrier.size:,}. Hashes cover the whole file, but findings beyond the "
            "read limit would have been missed. Re-run with --max-bytes to widen it."
        )

    offsets, values, window = sliding_entropy(data)
    overall_entropy = shannon_entropy(data)

    evidence.extend(_type_mismatch_evidence(carrier))
    evidence.extend(_tool_marker_evidence(data))

    container = _parse_container(carrier)
    evidence.extend(container.evidence)
    limitations.extend(container.limitations)

    evidence.extend(_embedded_archive_evidence(data, container, carrier))

    spatial_profile = dct_profile = audio_profile = text_profile = None
    fmt = carrier.format_name

    if fmt == "jpeg":
        dct_profile, dct_evidence, dct_limits = transform_detector.analyse_dct(data)
        evidence.extend(dct_evidence)
        limitations.extend(dct_limits)
        _, _, spatial_limits = spatial_detector.analyse_spatial(data)
        limitations.extend(spatial_limits)
    elif fmt in {"png", "bmp", "gif", "tiff", "webp"}:
        spatial_profile, spatial_evidence, spatial_limits = spatial_detector.analyse_spatial(data)
        evidence.extend(spatial_evidence)
        limitations.extend(spatial_limits)
    elif fmt == "riff":
        audio_profile, audio_evidence, audio_limits = audio_detector.analyse_audio(data)
        evidence.extend(audio_evidence)
        limitations.extend(audio_limits)
    elif fmt in {"unknown", "rtf"} or (carrier.declared_type or "").startswith("text/"):
        text_profile, text_evidence, text_limits = text_detector.analyse_text(data)
        evidence.extend(text_evidence)
        limitations.extend(text_limits)

    # Text carriers can also arrive without a recognised container. Run the
    # Unicode checks whenever the bytes look like text, whatever the extension.
    if text_profile is None and printable_ratio(data) > 0.85 and len(data) > 32:
        text_profile, text_evidence, text_limits = text_detector.analyse_text(data)
        evidence.extend(text_evidence)
        limitations.extend(text_limits)

    if fmt == "unknown":
        limitations.append(
            "Carrier format was not recognised from its magic bytes. Only "
            "format-agnostic checks (entropy, signatures, Unicode) were applied."
        )

    assessment = assess(evidence, prior=prior)
    ordered = sort_evidence(evidence)

    return AnalysisReport(
        carrier=carrier,
        assessment=assessment,
        evidence=ordered,
        structure=container.nodes,
        carved=container.carved,
        entropy_overall=overall_entropy,
        entropy_offsets=offsets.tolist(),
        entropy_values=values.tolist(),
        entropy_window=window,
        histogram=byte_histogram(data).tolist(),
        printable_ratio=printable_ratio(data),
        spatial=spatial_profile,
        dct=dct_profile,
        audio=audio_profile,
        text=text_profile,
        limitations=limitations,
        duration_ms=(time.perf_counter() - started) * 1000.0,
        analysed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


# --------------------------------------------------------------------------
# Format-agnostic detectors
# --------------------------------------------------------------------------


def _parse_container(carrier: Carrier) -> ContainerResult:
    parsers = {
        "png": png.parse_png,
        "jpeg": jpeg.parse_jpeg,
        "riff": riff.parse_riff,
        "isobmff": isobmff.parse_isobmff,
        "pdf": pdf.parse_pdf,
        "gif": simple.parse_gif,
        "bmp": simple.parse_bmp,
    }
    parser = parsers.get(carrier.format_name)
    if parser is None:
        return ContainerResult()
    try:
        return parser(carrier.data)
    except Exception as exc:
        result = ContainerResult()
        result.limitations.append(
            f"{carrier.format_name.upper()} structural parsing failed: {exc}. "
            "Structural findings for this exhibit are incomplete."
        )
        return result


def _type_mismatch_evidence(carrier: Carrier) -> list[Evidence]:
    if not carrier.type_mismatch:
        return []
    return [
        Evidence(
            id="identity.type-mismatch",
            family=Family.STRUCTURE,
            severity=Severity.HIGH,
            title=f"File extension claims {carrier.declared_type} but content is {carrier.format_name}",
            detail=(
                f"The filename implies {carrier.declared_type}, while the magic bytes "
                f"identify the content as {carrier.detected.description if carrier.detected else 'something else'}. "
                "Renaming a file to disguise it is the simplest concealment technique there "
                "is, and it costs nothing to check. Confirm whether the mismatch is "
                "deliberate or an artefact of how the exhibit was collected."
            ),
            llr=1.4,
            confidence=0.9,
            technique="Extension masquerade",
            actions=["file '{file}' — confirm with an independent identification tool"],
            measurements={
                "declared": carrier.declared_type,
                "detected": carrier.format_name,
            },
        )
    ]


def _tool_marker_evidence(data: bytes) -> list[Evidence]:
    findings: list[Evidence] = []
    seen: set[str] = set()

    for hit in scan_tool_markers(data):
        marker = hit.marker
        if marker.tool in seen:
            continue
        seen.add(marker.tool)

        llr = MARKER_LLR[marker.reliability]
        severity = {
            "proof": Severity.CRITICAL,
            "strong": Severity.HIGH,
            "indicative": Severity.LOW,
        }[marker.reliability]

        findings.append(
            Evidence(
                id=f"signature.{marker.tool.lower().replace(' ', '-')}",
                family=Family.SIGNATURE,
                severity=severity,
                title=f"Byte marker attributable to {marker.tool} at offset 0x{hit.offset:x}",
                detail=(
                    f"The byte sequence {marker.pattern!r} appears at offset 0x{hit.offset:x}. "
                    f"{marker.note}"
                ),
                llr=llr,
                confidence=0.9 if marker.reliability != "indicative" else 0.5,
                offset=hit.offset,
                technique=f"{marker.tool} embedding",
                references=list(marker.references),
                measurements={"tool": marker.tool, "reliability": marker.reliability},
            )
        )
    return findings


def _embedded_archive_evidence(
    data: bytes, container: ContainerResult, carrier: Carrier
) -> list[Evidence]:
    """Find archives embedded *inside* the carrier, not merely appended.

    A magic number alone proves nothing — ``PK\\x03\\x04`` turns up by chance in
    compressed data. Each candidate is therefore handed to the ZIP reader, and
    only archives that actually open and list entries are reported.
    """
    findings: list[Evidence] = []

    # An exhibit that simply *is* an archive is not a polyglot. Where the file's
    # own format is the archive, the interesting fact is any mismatch with its
    # extension, which the identity detector already reports.
    if carrier.format_name.startswith("zip"):
        return findings

    trailing_start = container.logical_end if container.logical_end is not None else len(data)
    checked = 0

    for hit in scan_file_magics(data, 0, limit=64):
        if hit.magic.name != "zip":
            continue
        # Appended payloads are already covered by the trailing-region analysis.
        if hit.offset >= trailing_start:
            continue
        if checked >= 8:
            break
        checked += 1

        probe = probe_zip(data[hit.offset :])
        if probe is None or not probe.names:
            continue

        listed = ", ".join(probe.names[:6])
        more = "" if len(probe.names) <= 6 else f" (+{len(probe.names) - 6} more)"
        findings.append(
            Evidence(
                id="polyglot.embedded-zip",
                family=Family.STRUCTURE,
                severity=Severity.CRITICAL,
                title=f"A valid ZIP archive begins at offset 0x{hit.offset:x} inside the carrier",
                detail=(
                    f"The bytes at offset 0x{hit.offset:x} open as a working ZIP archive "
                    f"containing {len(probe.names)} entries: {listed}{more}. "
                    f"{'Entries are password-protected. ' if probe.encrypted else ''}"
                    "This was confirmed by parsing the central directory, not by matching a "
                    "magic number, so it is not a chance byte coincidence. A file that is "
                    "simultaneously a valid image and a valid archive is a polyglot."
                ),
                llr=2.4,
                confidence=1.0,
                offset=hit.offset,
                technique="Polyglot / embedded archive",
                actions=[
                    "unzip -l '{file}' — most ZIP readers locate the archive regardless of prefix",
                    f"dd if='{{file}}' bs=1 skip={hit.offset} of=embedded.zip",
                    "Treat password-protected entries as a lead for passphrase recovery",
                ],
                measurements={
                    "offset": hit.offset,
                    "entries": len(probe.names),
                    "names": probe.names[:32],
                    "encrypted": probe.encrypted,
                    "uncompressed_bytes": probe.total_uncompressed,
                },
            )
        )
        break  # One confirmed archive is enough; report the first.

    return findings
