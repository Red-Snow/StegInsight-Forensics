"""Baseline JPEG entropy decoder producing *quantised DCT coefficients*.

Why this exists
---------------
Almost every serious JPEG steganography tool — JSteg, F5, OutGuess, nsF5,
J-UNIWARD, UED — operates on quantised DCT coefficients, not on pixels. Once a
JPEG has been decoded to RGB the embedding evidence has been through
dequantisation, an inverse DCT, clipping and rounding, and the statistical
traces that identify those tools are gone. Any analysis that starts from decoded
pixels is looking at the wrong signal.

Pillow will not hand over coefficients, and the usual route (``jpeglib``, or
libjpeg via a C extension) is a build-time dependency that fails on locked-down
forensic workstations. So the entropy-coded scan is decoded here directly. It is
about 200 lines and removes the dependency entirely.

Scope
-----
Baseline sequential Huffman JPEG (SOF0/SOF1) only. Progressive JPEG (SOF2)
requires successive-approximation and spectral-selection handling across
multiple scans; it is detected and reported as an explicit limitation rather
than decoded incorrectly. Arithmetic-coded JPEG is likewise out of scope.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

import numpy as np
from numpy.typing import NDArray

__all__ = ["ZIGZAG", "JpegComponent", "JpegScan", "UnsupportedJpeg", "decode_coefficients"]


class UnsupportedJpeg(Exception):
    """Raised when the file is a JPEG the coefficient decoder cannot handle."""


#: Zig-zag scan order: index i of the zig-zag sequence maps to natural position.
ZIGZAG = np.array(
    [
        0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5,
        12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
        35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
        58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
    ],
    dtype=np.intp,
)


@dataclass(slots=True)
class HuffmanTable:
    """Canonical JPEG Huffman table, stored for fast incremental decoding."""

    #: min_code[l] / max_code[l] bound the codes of length l (1..16).
    min_code: list[int] = field(default_factory=lambda: [0] * 17)
    max_code: list[int] = field(default_factory=lambda: [-1] * 17)
    #: Index into `values` of the first code of length l.
    val_ptr: list[int] = field(default_factory=lambda: [0] * 17)
    values: bytes = b""

    @classmethod
    def build(cls, counts: list[int], values: bytes) -> HuffmanTable:
        table = cls(values=values)
        code = 0
        k = 0
        for length in range(1, 17):
            table.val_ptr[length] = k
            table.min_code[length] = code
            code += counts[length - 1]
            k += counts[length - 1]
            table.max_code[length] = code - 1 if counts[length - 1] else -1
            code <<= 1
        return table


@dataclass(slots=True)
class JpegComponent:
    identifier: int
    h_sampling: int
    v_sampling: int
    quant_table_id: int
    #: Quantised coefficients, shape (blocks_v, blocks_h, 8, 8) in natural order.
    coefficients: NDArray[np.int32] | None = None

    @property
    def blocks(self) -> NDArray[np.int32]:
        if self.coefficients is None:
            raise ValueError("component was not decoded")
        c = self.coefficients
        return c.reshape(-1, 8, 8)

    def ac_coefficients(self) -> NDArray[np.int32]:
        """All AC coefficients, flattened. Excludes the DC term of each block."""
        flat = self.blocks.reshape(-1, 64)
        return flat[:, 1:].ravel()


@dataclass(slots=True)
class JpegScan:
    width: int
    height: int
    components: list[JpegComponent]
    quant_tables: dict[int, NDArray[np.int32]]
    progressive: bool = False

    @property
    def luma(self) -> JpegComponent:
        return self.components[0]


class _BitReader:
    """MSB-first bit reader over an entropy-coded segment.

    Handles the two JPEG quirks that trip naive implementations: a literal 0xFF
    byte in the stream is stuffed as 0xFF00, and restart markers (0xFFD0-D7)
    terminate the current interval rather than contributing bits.
    """

    __slots__ = ("bit_buffer", "bit_count", "data", "hit_marker", "pos")

    def __init__(self, data: bytes, pos: int) -> None:
        self.data = data
        self.pos = pos
        self.bit_buffer = 0
        self.bit_count = 0
        self.hit_marker = False

    def _fill(self) -> None:
        if self.pos >= len(self.data):
            self.hit_marker = True
            self.bit_buffer = (self.bit_buffer << 8) | 0
            self.bit_count += 8
            return

        byte = self.data[self.pos]
        self.pos += 1
        if byte == 0xFF:
            nxt = self.data[self.pos] if self.pos < len(self.data) else 0xD9
            if nxt == 0x00:
                self.pos += 1  # stuffed literal 0xFF
            else:
                # A real marker: rewind so the caller can inspect it, and feed
                # zero bits so an in-flight code terminates cleanly.
                self.pos -= 1
                self.hit_marker = True
                self.bit_buffer = (self.bit_buffer << 8) | 0
                self.bit_count += 8
                return
        self.bit_buffer = (self.bit_buffer << 8) | byte
        self.bit_count += 8

    def read_bit(self) -> int:
        if self.bit_count == 0:
            self._fill()
        self.bit_count -= 1
        return (self.bit_buffer >> self.bit_count) & 1

    def read_bits(self, n: int) -> int:
        value = 0
        for _ in range(n):
            value = (value << 1) | self.read_bit()
        return value

    def align(self) -> None:
        """Discard buffered bits, e.g. before a restart marker."""
        self.bit_count = 0
        self.bit_buffer = 0

    def decode_huffman(self, table: HuffmanTable) -> int:
        code = self.read_bit()
        for length in range(1, 17):
            if table.max_code[length] >= 0 and code <= table.max_code[length]:
                index = table.val_ptr[length] + code - table.min_code[length]
                if 0 <= index < len(table.values):
                    return table.values[index]
                raise UnsupportedJpeg("Huffman table index out of range (corrupt stream)")
            code = (code << 1) | self.read_bit()
        raise UnsupportedJpeg("Huffman code longer than 16 bits (corrupt stream)")


def _extend(value: int, length: int) -> int:
    """JPEG's signed-value extension for a `length`-bit magnitude."""
    if length == 0:
        return 0
    return value if value >= (1 << (length - 1)) else value - (1 << length) + 1


def decode_coefficients(data: bytes) -> JpegScan:
    """Decode a baseline JPEG's quantised DCT coefficients.

    :raises UnsupportedJpeg: for progressive, arithmetic-coded or malformed input.
    """
    if len(data) < 4 or data[0] != 0xFF or data[1] != 0xD8:
        raise UnsupportedJpeg("not a JPEG (no SOI marker)")

    quant: dict[int, NDArray[np.int32]] = {}
    dc_tables: dict[int, HuffmanTable] = {}
    ac_tables: dict[int, HuffmanTable] = {}
    components: list[JpegComponent] = []
    width = height = 0
    restart_interval = 0
    progressive = False

    offset = 2
    while offset + 3 < len(data):
        if data[offset] != 0xFF:
            offset += 1
            continue
        marker = data[offset + 1]
        offset += 2
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            continue
        if marker == 0xD9:
            break
        if offset + 2 > len(data):
            break
        (seg_len,) = struct.unpack_from(">H", data, offset)
        segment = data[offset + 2 : offset + seg_len]

        if marker == 0xDB:  # DQT
            i = 0
            while i < len(segment):
                pq, tq = segment[i] >> 4, segment[i] & 0x0F
                i += 1
                size = 64 * (2 if pq else 1)
                raw = segment[i : i + size]
                table_values = (
                    np.frombuffer(raw, dtype=">u2").astype(np.int32)
                    if pq
                    else np.frombuffer(raw, dtype=np.uint8).astype(np.int32)
                )
                natural = np.zeros(64, dtype=np.int32)
                natural[ZIGZAG] = table_values
                quant[tq] = natural.reshape(8, 8)
                i += size

        elif marker == 0xC4:  # DHT
            i = 0
            while i + 17 <= len(segment):
                tc, th = segment[i] >> 4, segment[i] & 0x0F
                counts = list(segment[i + 1 : i + 17])
                total = sum(counts)
                huffval = bytes(segment[i + 17 : i + 17 + total])
                table = HuffmanTable.build(counts, huffval)
                (ac_tables if tc else dc_tables)[th] = table
                i += 17 + total

        elif marker in (0xC0, 0xC1):  # SOF0 / SOF1 — baseline
            height, width = struct.unpack_from(">HH", segment, 1)
            count = segment[5]
            components = []
            for c in range(count):
                base = 6 + c * 3
                components.append(
                    JpegComponent(
                        identifier=segment[base],
                        h_sampling=segment[base + 1] >> 4,
                        v_sampling=segment[base + 1] & 0x0F,
                        quant_table_id=segment[base + 2],
                    )
                )

        elif marker == 0xC2:
            progressive = True
            raise UnsupportedJpeg(
                "progressive JPEG: coefficient decoding requires multi-scan "
                "successive approximation, which is out of scope"
            )

        elif marker in (0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            raise UnsupportedJpeg(f"unsupported SOF variant 0xFF{marker:02X}")

        elif marker == 0xCC:
            raise UnsupportedJpeg("arithmetic-coded JPEG is not supported")

        elif marker == 0xDD:  # DRI
            (restart_interval,) = struct.unpack_from(">H", segment, 0)

        elif marker == 0xDA:  # SOS
            if not components:
                raise UnsupportedJpeg("SOS encountered before SOF")
            scan_count = segment[0]
            selectors: dict[int, tuple[int, int]] = {}
            for s in range(scan_count):
                cid = segment[1 + s * 2]
                tables = segment[2 + s * 2]
                selectors[cid] = (tables >> 4, tables & 0x0F)
            _decode_scan(
                data,
                offset + seg_len,
                components,
                selectors,
                dc_tables,
                ac_tables,
                width,
                height,
                restart_interval,
            )
            return JpegScan(width, height, components, quant, progressive)

        offset += seg_len

    raise UnsupportedJpeg("no start-of-scan marker found")


def _decode_scan(
    data: bytes,
    start: int,
    components: list[JpegComponent],
    selectors: dict[int, tuple[int, int]],
    dc_tables: dict[int, HuffmanTable],
    ac_tables: dict[int, HuffmanTable],
    width: int,
    height: int,
    restart_interval: int,
) -> None:
    h_max = max(c.h_sampling for c in components)
    v_max = max(c.v_sampling for c in components)
    mcu_w, mcu_h = 8 * h_max, 8 * v_max
    mcus_x = (width + mcu_w - 1) // mcu_w
    mcus_y = (height + mcu_h - 1) // mcu_h

    for comp in components:
        comp.coefficients = np.zeros(
            (mcus_y * comp.v_sampling, mcus_x * comp.h_sampling, 8, 8), dtype=np.int32
        )

    reader = _BitReader(data, start)
    predictions = {c.identifier: 0 for c in components}
    block = np.zeros(64, dtype=np.int32)
    mcu_index = 0

    for my in range(mcus_y):
        for mx in range(mcus_x):
            if restart_interval and mcu_index and mcu_index % restart_interval == 0:
                _consume_restart(reader)
                predictions = {c.identifier: 0 for c in components}

            for comp in components:
                dc_id, ac_id = selectors.get(comp.identifier, (0, 0))
                dc_table = dc_tables.get(dc_id)
                ac_table = ac_tables.get(ac_id)
                if dc_table is None or ac_table is None:
                    raise UnsupportedJpeg("scan references an undefined Huffman table")

                for by in range(comp.v_sampling):
                    for bx in range(comp.h_sampling):
                        block[:] = 0

                        length = reader.decode_huffman(dc_table)
                        diff = _extend(reader.read_bits(length), length) if length else 0
                        predictions[comp.identifier] += diff
                        block[0] = predictions[comp.identifier]

                        k = 1
                        while k < 64:
                            symbol = reader.decode_huffman(ac_table)
                            run, size = symbol >> 4, symbol & 0x0F
                            if size == 0:
                                if run == 15:
                                    k += 16  # ZRL: sixteen zeroes
                                    continue
                                break  # EOB
                            k += run
                            if k > 63:
                                break
                            block[k] = _extend(reader.read_bits(size), size)
                            k += 1

                        natural = np.zeros(64, dtype=np.int32)
                        natural[ZIGZAG] = block
                        assert comp.coefficients is not None
                        comp.coefficients[my * comp.v_sampling + by,
                                          mx * comp.h_sampling + bx] = natural.reshape(8, 8)
            mcu_index += 1

            if reader.hit_marker and reader.pos >= len(data):
                return


def _consume_restart(reader: _BitReader) -> None:
    reader.align()
    data = reader.data
    pos = reader.pos
    # Skip to and over the next RSTn marker.
    while pos + 1 < len(data):
        if data[pos] == 0xFF and 0xD0 <= data[pos + 1] <= 0xD7:
            reader.pos = pos + 2
            reader.hit_marker = False
            return
        pos += 1
    reader.pos = len(data)


def dequantise(scan: JpegScan, component_index: int = 0) -> NDArray[np.float64]:
    """Multiply a component's coefficients by its quantisation table.

    Provided so the decoder can be validated end-to-end against an independent
    decoder in the test-suite, which is the only way to be confident that a
    hand-written entropy decoder is actually correct.
    """
    comp = scan.components[component_index]
    table = scan.quant_tables[comp.quant_table_id].astype(np.float64)
    return comp.blocks.astype(np.float64) * table
