"""PNG chunk-level structural analysis.

Walks the real chunk stream and validates every CRC-32, rather than searching
for the bytes ``IEND`` with ``indexOf``. That distinction matters twice over:
the literal sequence ``IEND`` occurs inside compressed ``IDAT`` data by chance,
and a payload smuggled inside an ancillary chunk is invisible to a search for
the footer.
"""

from __future__ import annotations

import struct
import zlib

from ..core.carrier import CarvedObject, StructuralNode
from ..core.evidence import Evidence, Family, Severity
from ..core.stats import expected_random_entropy, shannon_entropy
from .base import ContainerResult, analyse_trailing_region, describe_region

__all__ = ["PNG_SIGNATURE", "parse_png"]

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

#: Chunk types defined by the PNG specification (ISO/IEC 15948).
KNOWN_CHUNKS = {
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP",
    b"sBIT", b"sRGB", b"tEXt", b"zTXt", b"iTXt", b"bKGD", b"hIST", b"pHYs",
    b"sPLT", b"tIME", b"eXIf", b"acTL", b"fcTL", b"fdAT", b"cICP", b"mDCv",
    b"cLLi",
}

#: Text chunks large enough to be worth reporting as a payload vector.
TEXT_CHUNK_ALERT_BYTES = 1024


def parse_png(data: bytes) -> ContainerResult:
    result = ContainerResult()
    if not data.startswith(PNG_SIGNATURE):
        result.limitations.append("Not a PNG: signature absent; PNG parser skipped.")
        return result

    offset = len(PNG_SIGNATURE)
    crc_failures: list[tuple[str, int]] = []

    while offset + 8 <= len(data):
        (length,) = struct.unpack_from(">I", data, offset)
        ctype = data[offset + 4 : offset + 8]

        # A declared length that runs past EOF means the stream is malformed.
        if offset + 12 + length > len(data):
            result.evidence.append(
                Evidence(
                    id="png.truncated-chunk",
                    family=Family.STRUCTURE,
                    severity=Severity.MEDIUM,
                    title=f"Chunk '{_safe(ctype)}' declares a length past end-of-file",
                    detail=(
                        f"At offset 0x{offset:x} a chunk declares {length:,} bytes of payload, "
                        f"which extends beyond the {len(data):,}-byte file. The stream is "
                        "truncated or the length field has been overwritten."
                    ),
                    llr=0.6,
                    confidence=0.9,
                    offset=offset,
                    measurements={"declared_length": length, "file_size": len(data)},
                )
            )
            break

        payload = data[offset + 8 : offset + 8 + length]
        (stored_crc,) = struct.unpack_from(">I", data, offset + 8 + length)
        actual_crc = zlib.crc32(ctype + payload) & 0xFFFFFFFF
        crc_ok = stored_crc == actual_crc

        node = StructuralNode(
            id=_safe(ctype),
            offset=offset,
            length=length + 12,
            label=_chunk_label(ctype),
            entropy=shannon_entropy(payload) if length else None,
            integrity="ok" if crc_ok else "failed",
        )
        result.nodes.append(node)

        if not crc_ok:
            crc_failures.append((_safe(ctype), offset))

        _inspect_chunk(ctype, payload, offset, result)

        offset += 12 + length

        if ctype == b"IEND":
            # IEND terminates the stream. Everything past it is trailing data,
            # and must not be walked as though it were more chunks: appended
            # payloads read as chunks with absurd lengths, which the previous
            # revision reported as a malformed-chunk finding on every file that
            # simply had something appended.
            result.logical_end = offset
            _check_post_iend_chunks(data, offset, result)
            break

    if crc_failures:
        listed = ", ".join(f"{name} @ 0x{off:x}" for name, off in crc_failures[:5])
        result.evidence.append(
            Evidence(
                id="png.crc-mismatch",
                family=Family.STRUCTURE,
                severity=Severity.HIGH,
                title=f"{len(crc_failures)} chunk CRC-32 check(s) failed",
                detail=(
                    f"PNG stores a CRC-32 over every chunk's type and payload. These chunks "
                    f"do not match their stored checksum: {listed}. Encoders do not produce "
                    "bad CRCs; this indicates the chunk was modified after it was written, "
                    "either by an embedding tool or by corruption in transit."
                ),
                llr=1.4,
                confidence=0.95,
                technique="In-place chunk modification",
                actions=["pngcheck -v '{file}' — cross-check the chunk stream independently"],
                measurements={"failed_chunks": [n for n, _ in crc_failures]},
            )
        )

    if result.logical_end is None:
        result.limitations.append(
            "PNG chunk walk did not reach IEND; trailing-data analysis was not performed."
        )
        return result

    result.extend(analyse_trailing_region(data, result.logical_end, format_label="PNG"))
    return result


def _check_post_iend_chunks(data: bytes, offset: int, result: ContainerResult) -> None:
    """Report structurally valid PNG chunks appearing after IEND.

    Validity is decided by the CRC, not by the bytes merely looking chunk-shaped.
    Random appended data will occasionally present a plausible type field; it
    will not present a matching CRC-32. Requiring the checksum is what separates
    a deliberately constructed container from an ordinary appended payload.
    """
    found: list[str] = []
    cursor = offset
    while cursor + 12 <= len(data) and len(found) < 16:
        (length,) = struct.unpack_from(">I", data, cursor)
        ctype = data[cursor + 4 : cursor + 8]
        if not all(0x41 <= b <= 0x7A for b in ctype):
            break
        if cursor + 12 + length > len(data):
            break
        payload = data[cursor + 8 : cursor + 8 + length]
        (stored_crc,) = struct.unpack_from(">I", data, cursor + 8 + length)
        if (zlib.crc32(ctype + payload) & 0xFFFFFFFF) != stored_crc:
            break
        found.append(_safe(ctype))
        result.nodes.append(
            StructuralNode(
                id=_safe(ctype),
                offset=cursor,
                length=length + 12,
                label="Chunk after IEND",
                entropy=shannon_entropy(payload) if length else None,
                integrity="ok",
            )
        )
        cursor += 12 + length

    if not found:
        return

    result.logical_end = cursor
    result.evidence.append(
        Evidence(
            id="png.chunks-after-iend",
            family=Family.STRUCTURE,
            severity=Severity.CRITICAL,
            title=f"{len(found)} CRC-valid chunk(s) follow IEND",
            detail=(
                "IEND terminates a PNG stream and every conforming decoder stops there. "
                f"Additional chunks were found after it — {', '.join(found[:8])} — and each "
                "carries a correct CRC-32. Random appended bytes do not produce matching "
                "checksums, so these were written by something that understands the PNG "
                "format. This is a deliberately constructed container, not an accidental "
                "concatenation."
            ),
            llr=2.2,
            confidence=1.0,
            offset=offset,
            technique="Post-IEND chunk injection",
            measurements={"chunks": found},
        )
    )


def _inspect_chunk(ctype: bytes, payload: bytes, offset: int, result: ContainerResult) -> None:
    """Look for payloads hidden inside individual chunks."""
    name = _safe(ctype)

    # --- Non-standard chunk types -----------------------------------------
    if ctype not in KNOWN_CHUNKS and len(payload) > 0:
        ancillary = bool(ctype[0] & 0x20)  # lowercase first letter = ancillary
        fmt, description, verified = describe_region(payload)
        result.carved.append(
            CarvedObject(
                offset=offset + 8,
                length=len(payload),
                format=fmt,
                description=f"contents of non-standard PNG chunk '{name}': {description}",
                data=payload,
                verified=verified,
            )
        )
        result.evidence.append(
            Evidence(
                id="png.unknown-chunk",
                family=Family.STRUCTURE,
                severity=Severity.HIGH if len(payload) > 256 else Severity.MEDIUM,
                title=f"Non-standard chunk '{name}' carrying {len(payload):,} bytes",
                detail=(
                    f"Chunk type '{name}' is not defined by the PNG specification or the "
                    f"registered extensions. It is marked {'ancillary' if ancillary else 'critical'} "
                    f"and contains {len(payload):,} bytes identified as: {description}. "
                    "Private chunks are a legitimate extension mechanism, but they are also "
                    "the tidiest way to carry a payload inside a file that still renders."
                ),
                llr=1.3 if verified else (0.9 if len(payload) > 256 else 0.4),
                confidence=0.9,
                offset=offset,
                length=len(payload),
                technique="Private-chunk payload",
                measurements={"chunk": name, "bytes": len(payload), "identified_as": fmt},
            )
        )
        return

    # --- Text chunks -------------------------------------------------------
    if ctype in (b"tEXt", b"zTXt", b"iTXt"):
        content = payload
        if ctype == b"zTXt":
            # keyword \0 compression-method compressed-text
            sep = payload.find(b"\x00")
            if sep != -1 and len(payload) > sep + 2:
                try:
                    content = zlib.decompress(payload[sep + 2 :])
                except zlib.error:
                    content = payload

        if len(content) >= TEXT_CHUNK_ALERT_BYTES:
            fmt, description, verified = describe_region(content)
            result.carved.append(
                CarvedObject(
                    offset=offset + 8,
                    length=len(content),
                    format=fmt,
                    description=f"contents of {name} chunk: {description}",
                    data=content,
                    verified=verified,
                )
            )
            result.evidence.append(
                Evidence(
                    id="png.oversized-text-chunk",
                    family=Family.METADATA,
                    severity=Severity.MEDIUM,
                    title=f"{name} metadata chunk holds {len(content):,} bytes",
                    detail=(
                        f"A {name} chunk contains {len(content):,} bytes of data identified as: "
                        f"{description}. Text chunks normally hold short captions, authorship "
                        "or software strings. A chunk this large is a plausible carrier for "
                        "base64-encoded or compressed payload."
                    ),
                    llr=0.8 if verified else 0.45,
                    confidence=0.85,
                    offset=offset,
                    length=len(content),
                    technique="Metadata-field payload",
                    actions=["exiftool -a -G1 '{file}' — dump every metadata field verbatim"],
                    measurements={"chunk": name, "bytes": len(content), "identified_as": fmt},
                )
            )

    # --- Suspicious IDAT-adjacent padding ---------------------------------
    if ctype == b"IEND" and len(payload) > 0:
        result.evidence.append(
            Evidence(
                id="png.non-empty-iend",
                family=Family.STRUCTURE,
                severity=Severity.CRITICAL,
                title=f"IEND chunk carries {len(payload):,} bytes of payload",
                detail=(
                    "The PNG specification requires IEND to be empty. This one is not. "
                    "The data is invisible to every decoder yet travels with the file."
                ),
                llr=2.2,
                confidence=1.0,
                offset=offset,
                length=len(payload),
                technique="IEND payload smuggling",
            )
        )
        result.carved.append(
            CarvedObject(
                offset=offset + 8,
                length=len(payload),
                format=describe_region(payload)[0],
                description="contents of a non-empty IEND chunk",
                data=payload,
            )
        )


def _chunk_label(ctype: bytes) -> str:
    labels = {
        b"IHDR": "Image header",
        b"PLTE": "Palette",
        b"IDAT": "Image data",
        b"IEND": "End of stream",
        b"tEXt": "Text metadata",
        b"zTXt": "Compressed text metadata",
        b"iTXt": "International text metadata",
        b"eXIf": "EXIF metadata",
        b"pHYs": "Physical dimensions",
        b"gAMA": "Gamma",
        b"sRGB": "sRGB rendering intent",
        b"iCCP": "ICC colour profile",
        b"acTL": "APNG animation control",
        b"fcTL": "APNG frame control",
        b"fdAT": "APNG frame data",
    }
    return labels.get(ctype, "Non-standard chunk")


def _safe(ctype: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b <= 0x7E else f"\\x{b:02x}" for b in ctype)


def high_entropy_note(payload: bytes) -> bool:
    """True when a chunk payload is indistinguishable from random data."""
    return shannon_entropy(payload) >= expected_random_entropy(len(payload)) - 0.05
