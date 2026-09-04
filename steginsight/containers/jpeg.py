"""JPEG segment-level structural analysis.

Walks the marker stream properly, including the entropy-coded scan with its
0xFF00 byte stuffing and restart markers, so the true end-of-image is known
rather than guessed.

The previous engine took the *last* ``FFD9`` in the file as the end of the JPEG.
That is exactly backwards: appended payloads frequently contain an ``FFD9`` byte
pair themselves, which drags the supposed footer to the end of the file and
makes the appended data disappear from the analysis. Here the scan is followed
forward from ``SOI``, so the first structurally reached ``EOI`` is authoritative.
"""

from __future__ import annotations

import struct

from ..core.carrier import CarvedObject, StructuralNode
from ..core.evidence import Evidence, Family, Severity
from ..core.stats import shannon_entropy
from .base import ContainerResult, analyse_trailing_region, describe_region

__all__ = ["parse_jpeg"]

SOI = 0xD8
EOI = 0xD9
SOS = 0xDA

#: Markers that stand alone with no length field.
STANDALONE = {0x01, *range(0xD0, 0xD8)}

MARKER_NAMES = {
    0xC0: "SOF0 Baseline DCT",
    0xC1: "SOF1 Extended sequential",
    0xC2: "SOF2 Progressive DCT",
    0xC4: "DHT Huffman table",
    0xDB: "DQT Quantisation table",
    0xDD: "DRI Restart interval",
    0xDA: "SOS Start of scan",
    0xD9: "EOI End of image",
    0xD8: "SOI Start of image",
    0xFE: "COM Comment",
}

#: Comments longer than this are worth reporting: real encoder comments are short.
COMMENT_ALERT_BYTES = 256
#: APPn segments larger than this deserve a look; EXIF/ICC legitimately get big.
APP_ALERT_BYTES = 64 * 1024


def parse_jpeg(data: bytes) -> ContainerResult:
    result = ContainerResult()
    if len(data) < 4 or data[0] != 0xFF or data[1] != SOI:
        result.limitations.append("Not a JPEG: SOI marker absent; JPEG parser skipped.")
        return result

    result.nodes.append(StructuralNode(id="SOI", offset=0, length=2, label="Start of image"))
    offset = 2
    comments: list[tuple[int, bytes]] = []
    app_segments: list[tuple[str, int, int]] = []

    while offset + 1 < len(data):
        if data[offset] != 0xFF:
            # Resynchronise: a conforming stream always has a marker here.
            next_marker = data.find(b"\xff", offset)
            if next_marker == -1:
                break
            offset = next_marker
            continue

        # Fill bytes (0xFF padding) are legal between segments.
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            break

        marker = data[offset]
        marker_start = offset - 1
        offset += 1

        if marker == EOI:
            result.nodes.append(
                StructuralNode(id="EOI", offset=marker_start, length=2, label="End of image")
            )
            result.logical_end = marker_start + 2
            break

        if marker in STANDALONE:
            continue

        if offset + 2 > len(data):
            break
        (seg_len,) = struct.unpack_from(">H", data, offset)
        if seg_len < 2 or offset + seg_len > len(data):
            result.evidence.append(
                Evidence(
                    id="jpeg.bad-segment-length",
                    family=Family.STRUCTURE,
                    severity=Severity.MEDIUM,
                    title=f"Segment 0xFF{marker:02X} declares an impossible length",
                    detail=(
                        f"At offset 0x{marker_start:x} the segment declares {seg_len} bytes, "
                        "which does not fit within the file. The marker stream is malformed."
                    ),
                    llr=0.6,
                    confidence=0.85,
                    offset=marker_start,
                )
            )
            break

        payload = data[offset + 2 : offset + seg_len]
        name = MARKER_NAMES.get(marker, f"APP{marker - 0xE0}" if 0xE0 <= marker <= 0xEF else f"0xFF{marker:02X}")

        result.nodes.append(
            StructuralNode(
                id=f"FF{marker:02X}",
                offset=marker_start,
                length=seg_len + 2,
                label=name,
                entropy=shannon_entropy(payload) if payload else None,
            )
        )

        if marker == 0xFE:
            comments.append((marker_start, payload))
        elif 0xE0 <= marker <= 0xEF:
            app_segments.append((name, marker_start, len(payload)))

        offset += seg_len

        if marker == SOS:
            # Entropy-coded data follows; scan for the next real marker,
            # honouring 0xFF00 stuffing and RSTn restart markers.
            offset = _skip_entropy_coded(data, offset)

    if result.logical_end is None:
        result.limitations.append(
            "JPEG marker walk never reached EOI; trailing-data analysis was not performed."
        )
    else:
        result.extend(analyse_trailing_region(data, result.logical_end, format_label="JPEG"))
        _check_extra_eoi(data, result)

    _report_comments(comments, result)
    _report_app_segments(app_segments, data, result)
    return result


def _skip_entropy_coded(data: bytes, offset: int) -> int:
    """Advance past entropy-coded scan data to the next real marker."""
    n = len(data)
    while offset < n - 1:
        if data[offset] != 0xFF:
            offset += 1
            continue
        nxt = data[offset + 1]
        # 0xFF00 is a stuffed literal 0xFF; RSTn and fill bytes stay in the scan.
        if nxt == 0x00 or nxt == 0xFF or 0xD0 <= nxt <= 0xD7:
            offset += 2
            continue
        return offset
    return n


def _check_extra_eoi(data: bytes, result: ContainerResult) -> None:
    """Report additional EOI markers past the structural end of image."""
    assert result.logical_end is not None
    extra = data.count(b"\xff\xd9", result.logical_end)
    if extra:
        result.evidence.append(
            Evidence(
                id="jpeg.multiple-eoi",
                family=Family.STRUCTURE,
                severity=Severity.LOW,
                title=f"{extra} further EOI byte pair(s) occur after the end of image",
                detail=(
                    "Additional 0xFFD9 sequences appear in the trailing region. On its own "
                    "this means little — the pair occurs by chance in arbitrary data — but it "
                    "explains why naive tools that search for the *last* EOI miss appended "
                    "payloads entirely, and it can indicate a second concatenated image."
                ),
                llr=0.15,
                confidence=0.6,
                measurements={"extra_eoi_count": extra},
            )
        )


def _report_comments(comments: list[tuple[int, bytes]], result: ContainerResult) -> None:
    for offset, payload in comments:
        if len(payload) < COMMENT_ALERT_BYTES:
            continue
        fmt, description, verified = describe_region(payload)
        result.carved.append(
            CarvedObject(
                offset=offset,
                length=len(payload),
                format=fmt,
                description=f"JPEG COM segment contents: {description}",
                data=payload,
                verified=verified,
            )
        )
        result.evidence.append(
            Evidence(
                id="jpeg.large-comment",
                family=Family.METADATA,
                severity=Severity.MEDIUM,
                title=f"COM comment segment holds {len(payload):,} bytes",
                detail=(
                    f"A JPEG comment segment at offset 0x{offset:x} contains {len(payload):,} "
                    f"bytes identified as: {description}. Encoder comments are typically a "
                    "short product string. The COM segment is ignored by decoders and is a "
                    "well-known place to park data."
                ),
                llr=1.0 if verified else 0.5,
                confidence=0.9,
                offset=offset,
                length=len(payload),
                technique="COM segment payload",
                actions=["exiftool -Comment -b '{file}' — dump the comment bytes"],
                measurements={"bytes": len(payload), "identified_as": fmt},
            )
        )


def _report_app_segments(
    segments: list[tuple[str, int, int]], data: bytes, result: ContainerResult
) -> None:
    for name, offset, length in segments:
        if length < APP_ALERT_BYTES:
            continue
        payload = data[offset + 4 : offset + 4 + length]
        fmt, description, verified = describe_region(payload)
        # EXIF and ICC profiles are legitimately large; only flag when the
        # content does not look like what the segment claims to be.
        looks_standard = payload[:6] in (b"Exif\x00\x00", b"JFIF\x00") or payload[:4] == b"ICC_"
        if looks_standard and not verified:
            continue
        result.evidence.append(
            Evidence(
                id="jpeg.oversized-app-segment",
                family=Family.METADATA,
                severity=Severity.MEDIUM,
                title=f"{name} segment holds {length:,} bytes of non-standard content",
                detail=(
                    f"The {name} application segment at offset 0x{offset:x} carries "
                    f"{length:,} bytes that do not begin with a recognised profile header. "
                    f"Content identified as: {description}."
                ),
                llr=1.2 if verified else 0.5,
                confidence=0.8,
                offset=offset,
                length=length,
                technique="APPn segment payload",
                measurements={"segment": name, "bytes": length, "identified_as": fmt},
            )
        )
        result.carved.append(
            CarvedObject(
                offset=offset,
                length=length,
                format=fmt,
                description=f"{name} segment contents: {description}",
                data=payload,
                verified=verified,
            )
        )
