"""RIFF container analysis (WAV, AVI, WebP).

RIFF declares its own total size in the header, which gives an authoritative
logical end independent of the file's actual length. Any discrepancy between the
two is a structural fact, not a heuristic.
"""

from __future__ import annotations

import struct

from ..core.carrier import CarvedObject, StructuralNode
from ..core.evidence import Evidence, Family, Severity
from ..core.stats import expected_random_entropy, shannon_entropy
from .base import ContainerResult, analyse_trailing_region, describe_region

__all__ = ["parse_riff"]

#: Chunks that legitimately carry bulk data.
BULK_CHUNKS = {b"data", b"movi", b"VP8 ", b"VP8L", b"ALPH"}

#: A padding chunk larger than this with non-zero content is worth reporting.
PAD_ALERT_BYTES = 256


def parse_riff(data: bytes) -> ContainerResult:
    result = ContainerResult()
    if len(data) < 12 or data[:4] != b"RIFF":
        result.limitations.append("Not a RIFF container; RIFF parser skipped.")
        return result

    (declared_size,) = struct.unpack_from("<I", data, 4)
    form = data[8:12].decode("ascii", "replace")
    # RIFF size counts everything after the 8-byte header.
    declared_end = 8 + declared_size

    result.nodes.append(
        StructuralNode(
            id="RIFF",
            offset=0,
            length=min(declared_end, len(data)),
            label=f"RIFF/{form} container",
        )
    )

    offset = 12
    limit = min(declared_end, len(data))
    data_chunk: tuple[int, int] | None = None

    while offset + 8 <= limit:
        chunk_id = data[offset : offset + 4]
        (chunk_size,) = struct.unpack_from("<I", data, offset + 4)
        payload_start = offset + 8
        payload_end = min(payload_start + chunk_size, len(data))
        payload = data[payload_start:payload_end]

        result.nodes.append(
            StructuralNode(
                id=_safe(chunk_id),
                offset=offset,
                length=chunk_size + 8,
                label=_label(chunk_id),
                entropy=shannon_entropy(payload) if payload else None,
            )
        )

        if chunk_id == b"data" and data_chunk is None:
            data_chunk = (payload_start, len(payload))

        _inspect_chunk(chunk_id, payload, offset, result)

        if payload_start + chunk_size > len(data):
            result.evidence.append(
                Evidence(
                    id="riff.truncated-chunk",
                    family=Family.STRUCTURE,
                    severity=Severity.MEDIUM,
                    title=f"Chunk '{_safe(chunk_id)}' extends past end-of-file",
                    detail=(
                        f"Chunk at offset 0x{offset:x} declares {chunk_size:,} bytes but the "
                        f"file ends after {len(data) - payload_start:,}."
                    ),
                    llr=0.5,
                    confidence=0.85,
                    offset=offset,
                )
            )
            break

        # RIFF chunks are word-aligned: an odd size is followed by a pad byte.
        offset = payload_start + chunk_size + (chunk_size & 1)

    if declared_end < len(data):
        result.logical_end = declared_end
        result.extend(analyse_trailing_region(data, declared_end, format_label="RIFF"))
        result.evidence.append(
            Evidence(
                id="riff.size-mismatch",
                family=Family.STRUCTURE,
                severity=Severity.HIGH,
                title="RIFF header under-declares the file size",
                detail=(
                    f"The RIFF header declares a total size of {declared_size:,} bytes "
                    f"(ending at offset 0x{declared_end:x}), but the file is "
                    f"{len(data):,} bytes. A player reads only as far as the header says, so "
                    "the surplus travels with the file while remaining inaudible and "
                    "invisible. This is a container-level fact, not an inference."
                ),
                llr=1.6,
                confidence=1.0,
                offset=declared_end,
                length=len(data) - declared_end,
                technique="RIFF size-field concealment",
                measurements={
                    "declared_total": declared_size,
                    "actual_size": len(data),
                    "surplus": len(data) - declared_end,
                },
            )
        )
    else:
        result.logical_end = min(declared_end, len(data))

    return result


def _inspect_chunk(chunk_id: bytes, payload: bytes, offset: int, result: ContainerResult) -> None:
    # JUNK/PAD/FLLR chunks exist to align data and should be filler.
    if chunk_id in (b"JUNK", b"PAD ", b"FLLR") and len(payload) >= PAD_ALERT_BYTES:
        non_zero = len(payload) - payload.count(0)
        if non_zero > len(payload) * 0.1:
            entropy = shannon_entropy(payload)
            fmt, description, verified = describe_region(payload)
            result.evidence.append(
                Evidence(
                    id="riff.padding-carries-data",
                    family=Family.STRUCTURE,
                    severity=Severity.HIGH,
                    title=f"Padding chunk '{_safe(chunk_id)}' contains {non_zero:,} non-zero bytes",
                    detail=(
                        f"A {_safe(chunk_id)} chunk exists purely to align the stream and is "
                        f"conventionally filled with 0x00. This one holds {len(payload):,} bytes "
                        f"at {entropy:.3f} bits/byte, {non_zero:,} of them non-zero, identified "
                        f"as: {description}."
                    ),
                    llr=1.5 if verified else 1.1,
                    confidence=0.9,
                    offset=offset,
                    length=len(payload),
                    technique="Padding-chunk payload",
                    measurements={
                        "chunk": _safe(chunk_id),
                        "bytes": len(payload),
                        "non_zero": non_zero,
                        "entropy": round(entropy, 4),
                    },
                )
            )
            result.carved.append(
                CarvedObject(
                    offset=offset + 8,
                    length=len(payload),
                    format=fmt,
                    description=f"contents of {_safe(chunk_id)} padding chunk: {description}",
                    data=payload,
                    verified=verified,
                )
            )

    # LIST/INFO metadata carrying bulk content.
    if chunk_id == b"LIST" and len(payload) > 64 * 1024:
        entropy = shannon_entropy(payload)
        if entropy >= expected_random_entropy(len(payload)) - 0.1:
            result.evidence.append(
                Evidence(
                    id="riff.high-entropy-list",
                    family=Family.METADATA,
                    severity=Severity.MEDIUM,
                    title=f"LIST metadata chunk holds {len(payload):,} bytes of random-looking data",
                    detail=(
                        f"A LIST chunk normally carries short INFO strings. This one is "
                        f"{len(payload):,} bytes at {entropy:.3f} bits/byte, which is "
                        "indistinguishable from compressed or encrypted content."
                    ),
                    llr=0.8,
                    confidence=0.8,
                    offset=offset,
                    length=len(payload),
                    measurements={"bytes": len(payload), "entropy": round(entropy, 4)},
                )
            )


def _label(chunk_id: bytes) -> str:
    return {
        b"fmt ": "Format descriptor",
        b"data": "Sample data",
        b"LIST": "Metadata list",
        b"JUNK": "Alignment padding",
        b"PAD ": "Alignment padding",
        b"fact": "Fact chunk",
        b"cue ": "Cue points",
        b"movi": "AVI frame data",
        b"idx1": "AVI index",
    }.get(chunk_id, "Chunk")


def _safe(chunk_id: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b <= 0x7E else f"\\x{b:02x}" for b in chunk_id)
