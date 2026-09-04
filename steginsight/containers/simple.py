"""GIF and BMP structural analysis.

Both formats declare their own extent, so appended data is provable rather than
inferred. BMP matters disproportionately: it is uncompressed, which makes it the
classic target for naive LSB tools and the format where the spatial detectors
have their best sensitivity.
"""

from __future__ import annotations

import struct

from ..core.carrier import StructuralNode
from ..core.evidence import Evidence, Family, Severity
from .base import ContainerResult, analyse_trailing_region

__all__ = ["parse_bmp", "parse_gif"]


def parse_bmp(data: bytes) -> ContainerResult:
    result = ContainerResult()
    if len(data) < 54 or data[:2] != b"BM":
        result.limitations.append("Not a BMP; BMP parser skipped.")
        return result

    (declared_size,) = struct.unpack_from("<I", data, 2)
    (pixel_offset,) = struct.unpack_from("<I", data, 10)
    (dib_size,) = struct.unpack_from("<I", data, 14)

    result.nodes.append(
        StructuralNode(id="BITMAPFILEHEADER", offset=0, length=14, label="File header")
    )
    result.nodes.append(
        StructuralNode(id="DIB", offset=14, length=dib_size, label="DIB information header")
    )
    if pixel_offset < len(data):
        result.nodes.append(
            StructuralNode(
                id="PIXELS",
                offset=pixel_offset,
                length=max(0, min(declared_size, len(data)) - pixel_offset),
                label="Pixel array",
            )
        )

    if 0 < declared_size < len(data):
        result.logical_end = declared_size
        result.extend(analyse_trailing_region(data, declared_size, format_label="BMP"))
        result.evidence.append(
            Evidence(
                id="bmp.size-mismatch",
                family=Family.STRUCTURE,
                severity=Severity.HIGH,
                title="BMP header under-declares the file size",
                detail=(
                    f"The BITMAPFILEHEADER declares {declared_size:,} bytes but the file is "
                    f"{len(data):,}. Viewers read only the declared extent, so the surplus "
                    f"{len(data) - declared_size:,} bytes are carried invisibly."
                ),
                llr=1.6,
                confidence=1.0,
                offset=declared_size,
                length=len(data) - declared_size,
                technique="Header size-field concealment",
                measurements={"declared": declared_size, "actual": len(data)},
            )
        )
    else:
        result.logical_end = min(declared_size or len(data), len(data))

    # A pixel offset far beyond the headers leaves an unreferenced gap.
    header_end = 14 + dib_size
    if pixel_offset > header_end + 4096:
        gap = data[header_end:pixel_offset]
        non_zero = len(gap) - gap.count(0)
        if non_zero > len(gap) * 0.1:
            result.evidence.append(
                Evidence(
                    id="bmp.header-gap",
                    family=Family.STRUCTURE,
                    severity=Severity.MEDIUM,
                    title=f"{len(gap):,}-byte unreferenced gap before the pixel array",
                    detail=(
                        f"The pixel array starts at offset 0x{pixel_offset:x}, well past the "
                        f"end of the headers at 0x{header_end:x}. The intervening "
                        f"{len(gap):,} bytes ({non_zero:,} non-zero) belong to no structure "
                        "and are not rendered. A colour palette would explain a small gap; "
                        "this one is larger than any palette can be."
                    ),
                    llr=1.0,
                    confidence=0.85,
                    offset=header_end,
                    length=len(gap),
                    technique="Header-gap payload",
                    measurements={"gap_bytes": len(gap), "non_zero": non_zero},
                )
            )

    return result


def parse_gif(data: bytes) -> ContainerResult:
    result = ContainerResult()
    if len(data) < 13 or data[:3] != b"GIF":
        result.limitations.append("Not a GIF; GIF parser skipped.")
        return result

    result.nodes.append(
        StructuralNode(id="HEADER", offset=0, length=13, label="Header and logical screen")
    )

    # The GIF trailer is a single 0x3B byte at the end of the block stream.
    # Walking the block structure is what makes the terminator authoritative;
    # 0x3B occurs constantly inside LZW-compressed image data.
    end = _walk_gif_blocks(data)
    if end is None:
        result.limitations.append(
            "GIF block walk did not reach the trailer; trailing-data analysis skipped."
        )
        return result

    result.logical_end = end
    if end < len(data):
        result.extend(analyse_trailing_region(data, end, format_label="GIF"))
    return result


def _walk_gif_blocks(data: bytes) -> int | None:
    """Return the offset just past the GIF trailer, or None if unreachable."""
    flags = data[10]
    offset = 13
    if flags & 0x80:  # global colour table present
        offset += 3 * (2 ** ((flags & 0x07) + 1))

    n = len(data)
    while offset < n:
        block = data[offset]

        if block == 0x3B:  # trailer
            return offset + 1

        if block == 0x21:  # extension introducer
            if offset + 2 >= n:
                return None
            offset += 2  # introducer + label
            nxt = _skip_sub_blocks(data, offset)
            if nxt is None:
                return None
            offset = nxt
            continue

        if block == 0x2C:  # image descriptor
            if offset + 10 > n:
                return None
            local_flags = data[offset + 9]
            offset += 10
            if local_flags & 0x80:
                offset += 3 * (2 ** ((local_flags & 0x07) + 1))
            if offset >= n:
                return None
            offset += 1  # LZW minimum code size
            nxt = _skip_sub_blocks(data, offset)
            if nxt is None:
                return None
            offset = nxt
            continue

        return None  # Unrecognised block: stop rather than guess.

    return None


def _skip_sub_blocks(data: bytes, offset: int) -> int | None:
    n = len(data)
    while offset < n:
        size = data[offset]
        if size == 0:
            return offset + 1
        offset += 1 + size
    return None
