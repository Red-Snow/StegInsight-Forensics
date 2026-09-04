"""ISO base media file format (MP4, MOV, 3GP, HEIF) box walker.

Boxes form a strict tree with declared sizes, so an unaccounted-for region is a
structural fact rather than a guess. The two vectors that matter are ``free``
and ``skip`` boxes carrying content — they exist to be ignored — and data past
the last top-level box.
"""

from __future__ import annotations

import struct

from ..core.carrier import CarvedObject, StructuralNode
from ..core.evidence import Evidence, Family, Severity
from ..core.stats import expected_random_entropy, shannon_entropy
from .base import ContainerResult, analyse_trailing_region, describe_region

__all__ = ["parse_isobmff"]

#: Boxes whose entire purpose is to be skipped by readers.
FILLER_BOXES = {b"free", b"skip", b"wide"}

#: Containers whose children should be walked.
CONTAINER_BOXES = {
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"dinf",
    b"udta", b"moof", b"traf", b"mvex", b"meta",
}

#: Ignore filler boxes below this size; a few padding bytes are routine.
FILLER_ALERT_BYTES = 64

MAX_DEPTH = 6


def parse_isobmff(data: bytes) -> ContainerResult:
    result = ContainerResult()
    if len(data) < 12 or data[4:8] != b"ftyp":
        result.limitations.append("No 'ftyp' box at offset 4; ISO-BMFF parser skipped.")
        return result

    end = _walk(data, 0, len(data), result, depth=0)
    result.logical_end = end

    if end < len(data):
        result.extend(analyse_trailing_region(data, end, format_label="MP4"))
    return result


def _walk(
    data: bytes, start: int, limit: int, result: ContainerResult, depth: int
) -> int:
    """Walk boxes in ``data[start:limit]``; return the offset after the last one."""
    offset = start
    while offset + 8 <= limit:
        (size,) = struct.unpack_from(">I", data, offset)
        box_type = data[offset + 4 : offset + 8]

        # Box types are four printable characters. Anything else means we have
        # walked off the structure and should stop rather than invent boxes.
        if not all(0x20 <= b <= 0x7E for b in box_type):
            break

        header = 8
        if size == 1:
            if offset + 16 > limit:
                break
            (size,) = struct.unpack_from(">Q", data, offset + 8)
            header = 16
        elif size == 0:
            # Size 0 means "extends to end of file".
            size = limit - offset

        if size < header or offset + size > limit:
            result.evidence.append(
                Evidence(
                    id="mp4.bad-box-size",
                    family=Family.STRUCTURE,
                    severity=Severity.MEDIUM,
                    title=f"Box '{_safe(box_type)}' declares an impossible size",
                    detail=(
                        f"At offset 0x{offset:x} the box declares {size:,} bytes, which does "
                        "not fit inside its parent. The box tree is malformed from here on."
                    ),
                    llr=0.5,
                    confidence=0.85,
                    offset=offset,
                )
            )
            break

        payload = data[offset + header : offset + size]
        node = StructuralNode(
            id=_safe(box_type),
            offset=offset,
            length=size,
            label=_label(box_type),
            entropy=shannon_entropy(payload) if payload and len(payload) < (1 << 22) else None,
        )
        result.nodes.append(node)

        _inspect_box(box_type, payload, offset, result)

        if box_type in CONTAINER_BOXES and depth < MAX_DEPTH:
            _walk(data, offset + header, offset + size, result, depth + 1)

        offset += size

    return offset


def _inspect_box(box_type: bytes, payload: bytes, offset: int, result: ContainerResult) -> None:
    if box_type in FILLER_BOXES and len(payload) >= FILLER_ALERT_BYTES:
        non_zero = len(payload) - payload.count(0)
        if non_zero <= len(payload) * 0.05:
            return  # Ordinary zero padding.

        entropy = shannon_entropy(payload)
        fmt, description, verified = describe_region(payload)
        random_like = entropy >= expected_random_entropy(len(payload)) - 0.05

        result.evidence.append(
            Evidence(
                id="mp4.filler-box-carries-data",
                family=Family.STRUCTURE,
                severity=Severity.HIGH,
                title=f"'{_safe(box_type)}' box holds {non_zero:,} non-zero bytes",
                detail=(
                    f"A '{_safe(box_type)}' box exists so that readers can ignore it, and is "
                    f"conventionally zero-filled. This one carries {len(payload):,} bytes at "
                    f"{entropy:.3f} bits/byte "
                    f"({'indistinguishable from encrypted or compressed data' if random_like else 'structured content'}), "
                    f"identified as: {description}. The video plays identically with or "
                    "without it."
                ),
                llr=1.8 if verified else (1.3 if random_like else 0.9),
                confidence=0.92,
                offset=offset,
                length=len(payload),
                technique="Filler-box payload",
                actions=[
                    f"dd if='{{file}}' bs=1 skip={offset} count={len(payload)} of=box_payload.bin",
                    "ffprobe -show_entries format -v error '{file}' — confirm playback is unaffected",
                ],
                measurements={
                    "box": _safe(box_type),
                    "bytes": len(payload),
                    "non_zero": non_zero,
                    "entropy": round(entropy, 4),
                    "identified_as": fmt,
                },
            )
        )
        result.carved.append(
            CarvedObject(
                offset=offset,
                length=len(payload),
                format=fmt,
                description=f"contents of '{_safe(box_type)}' box: {description}",
                data=payload,
                verified=verified,
            )
        )


def _label(box_type: bytes) -> str:
    return {
        b"ftyp": "File type",
        b"moov": "Movie metadata",
        b"mdat": "Media data",
        b"free": "Free space",
        b"skip": "Skip region",
        b"wide": "Wide placeholder",
        b"udta": "User data",
        b"meta": "Metadata",
        b"trak": "Track",
        b"moof": "Movie fragment",
    }.get(box_type, "Box")


def _safe(box_type: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b <= 0x7E else f"\\x{b:02x}" for b in box_type)
