"""Container parsers.

Each test names the concealment technique it covers. Several are regressions
against specific defects in the previous engine, called out in the docstrings so
the reason the test exists survives.
"""

from __future__ import annotations

import io
import struct
import zlib

from PIL import Image

from steginsight.containers.jpeg import parse_jpeg
from steginsight.containers.pdf import parse_pdf
from steginsight.containers.png import parse_png
from steginsight.containers.riff import parse_riff
from steginsight.containers.simple import parse_bmp, parse_gif
from steginsight.containers.zip_probe import probe_zip
from tests.factories import (
    append_payload,
    bmp_bytes,
    jpeg_bytes,
    natural_image,
    png_bytes,
    wav_bytes,
    zip_bytes,
)


def ids(result) -> set[str]:  # type: ignore[no-untyped-def]
    return {e.id for e in result.evidence}


class TestPng:
    def test_clean_png_produces_no_findings(self) -> None:
        result = parse_png(png_bytes(natural_image(seed=1)))
        assert result.evidence == []
        assert result.logical_end is not None
        assert any(n.id == "IEND" for n in result.nodes)

    def test_every_chunk_crc_is_checked(self) -> None:
        result = parse_png(png_bytes(natural_image(seed=1)))
        assert all(n.integrity == "ok" for n in result.nodes if n.id != "TRAILING")

    def test_appended_archive_is_detected_and_carved(self) -> None:
        data = append_payload(png_bytes(natural_image(seed=1)), zip_bytes())
        result = parse_png(data)
        assert "png.trailing-data" in ids(result)
        carved = [c for c in result.carved if c.format == "zip"]
        assert carved and carved[0].verified
        assert probe_zip(carved[0].data) is not None

    def test_appended_data_is_not_reported_as_a_malformed_chunk(self) -> None:
        """Regression.

        The previous walk continued past IEND and read the appended payload as
        another chunk, whose absurd declared length produced a spurious
        malformed-chunk finding on every file that simply had data appended.
        """
        data = append_payload(png_bytes(natural_image(seed=1)), zip_bytes())
        assert "png.truncated-chunk" not in ids(parse_png(data))

    def test_iend_found_by_structure_not_by_byte_search(self) -> None:
        """The literal bytes 'IEND' occur inside compressed IDAT by chance.

        Walking the chunk stream is what makes the terminator authoritative.
        """
        data = png_bytes(natural_image(seed=2))
        first_literal = data.find(b"IEND")
        result = parse_png(data)
        assert result.logical_end == len(data)
        assert result.logical_end >= first_literal

    def test_corrupted_chunk_crc_is_reported(self) -> None:
        data = bytearray(png_bytes(natural_image(seed=1)))
        # Flip a byte inside the first IDAT payload, leaving its CRC stale.
        idat = data.find(b"IDAT")
        data[idat + 10] ^= 0xFF
        result = parse_png(bytes(data))
        assert "png.crc-mismatch" in ids(result)

    def test_crc_valid_chunk_after_iend_is_proof(self) -> None:
        data = png_bytes(natural_image(seed=1))
        payload = b"hidden payload bytes" * 8
        ctype = b"stEg"
        chunk = (
            struct.pack(">I", len(payload))
            + ctype
            + payload
            + struct.pack(">I", zlib.crc32(ctype + payload) & 0xFFFFFFFF)
        )
        result = parse_png(data + chunk)
        assert "png.chunks-after-iend" in ids(result)
        strongest = max(e.llr for e in result.evidence)
        assert strongest >= 1.7  # proof tier

    def test_random_appended_bytes_are_not_called_chunks(self) -> None:
        """Only a matching CRC-32 distinguishes a crafted chunk from noise."""
        import numpy as np

        rng = np.random.default_rng(4)
        noise = rng.integers(0, 256, 4096, dtype=np.uint8).tobytes()
        result = parse_png(png_bytes(natural_image(seed=1)) + noise)
        assert "png.chunks-after-iend" not in ids(result)
        assert "png.trailing-data" in ids(result)

    def test_oversized_text_chunk_is_reported(self) -> None:
        image = Image.fromarray(natural_image(seed=1))
        from PIL import PngImagePlugin

        info = PngImagePlugin.PngInfo()
        info.add_text("Comment", "A" * 4000)
        buffer = io.BytesIO()
        image.save(buffer, "PNG", pnginfo=info)
        assert "png.oversized-text-chunk" in ids(parse_png(buffer.getvalue()))

    def test_non_png_input_is_handled(self) -> None:
        result = parse_png(b"not a png at all")
        assert result.evidence == []
        assert result.limitations


class TestJpeg:
    def test_clean_jpeg_produces_no_findings(self) -> None:
        result = parse_jpeg(jpeg_bytes(natural_image(seed=1)))
        assert not [e for e in result.evidence if e.llr > 0]
        assert result.logical_end is not None

    def test_appended_archive_is_detected(self) -> None:
        data = append_payload(jpeg_bytes(natural_image(seed=1)), zip_bytes())
        result = parse_jpeg(data)
        assert "jpeg.trailing-data" in ids(result)

    def test_eoi_located_by_forward_scan_not_last_occurrence(self) -> None:
        """Regression: the previous engine searched for the *last* FFD9.

        Appended payloads frequently contain that byte pair, which dragged the
        supposed footer to the end of file and made the appended data vanish
        from the analysis entirely.
        """
        payload = zip_bytes() + b"\xff\xd9" + b"trailing marker"
        data = append_payload(jpeg_bytes(natural_image(seed=1)), payload)
        result = parse_jpeg(data)
        assert "jpeg.trailing-data" in ids(result)
        assert result.logical_end is not None
        assert result.logical_end < len(data) - len(payload) + 16

    def test_entropy_coded_stuffing_is_handled(self) -> None:
        """0xFF00 inside scan data must not be mistaken for a marker."""
        data = jpeg_bytes(natural_image(seed=5), quality=95)
        assert b"\xff\x00" in data  # the fixture genuinely exercises this
        result = parse_jpeg(data)
        assert result.logical_end == len(data)

    def test_large_comment_segment_is_reported(self) -> None:
        data = bytearray(jpeg_bytes(natural_image(seed=1)))
        comment = b"S" * 2000
        segment = b"\xff\xfe" + struct.pack(">H", len(comment) + 2) + comment
        data[2:2] = segment  # insert straight after SOI
        assert "jpeg.large-comment" in ids(parse_jpeg(bytes(data)))

    def test_non_jpeg_input_is_handled(self) -> None:
        assert parse_jpeg(b"\x00\x01\x02").limitations


class TestRiff:
    def test_clean_wav_produces_no_findings(self) -> None:
        result = parse_riff(wav_bytes(seconds=1.0))
        assert not [e for e in result.evidence if e.llr > 0]

    def test_appended_data_beyond_declared_size_is_detected(self) -> None:
        data = append_payload(wav_bytes(seconds=1.0), zip_bytes())
        result = parse_riff(data)
        assert "riff.size-mismatch" in ids(result)
        assert "riff.trailing-data" in ids(result)

    def test_padding_chunk_carrying_data_is_detected(self) -> None:
        base = bytearray(wav_bytes(seconds=1.0))
        payload = bytes(range(256)) * 8
        junk = b"JUNK" + struct.pack("<I", len(payload)) + payload
        base[12:12] = junk
        # Correct the RIFF size field so only the JUNK content is anomalous.
        struct.pack_into("<I", base, 4, len(base) - 8)
        assert "riff.padding-carries-data" in ids(parse_riff(bytes(base)))

    def test_zero_filled_padding_is_not_reported(self) -> None:
        base = bytearray(wav_bytes(seconds=1.0))
        junk = b"JUNK" + struct.pack("<I", 2048) + bytes(2048)
        base[12:12] = junk
        struct.pack_into("<I", base, 4, len(base) - 8)
        assert "riff.padding-carries-data" not in ids(parse_riff(bytes(base)))


class TestGifAndBmp:
    def test_clean_gif(self) -> None:
        buffer = io.BytesIO()
        Image.fromarray(natural_image(seed=1)).convert("P").save(buffer, "GIF")
        result = parse_gif(buffer.getvalue())
        assert result.logical_end is not None
        assert not [e for e in result.evidence if e.llr > 0]

    def test_gif_with_appended_payload(self) -> None:
        buffer = io.BytesIO()
        Image.fromarray(natural_image(seed=1)).convert("P").save(buffer, "GIF")
        result = parse_gif(append_payload(buffer.getvalue(), zip_bytes()))
        assert "gif.trailing-data" in ids(result)

    def test_clean_bmp(self) -> None:
        result = parse_bmp(bmp_bytes(natural_image(seed=1)))
        assert not [e for e in result.evidence if e.llr > 0]

    def test_bmp_size_mismatch(self) -> None:
        result = parse_bmp(append_payload(bmp_bytes(natural_image(seed=1)), zip_bytes()))
        assert "bmp.size-mismatch" in ids(result)


class TestPdf:
    MINIMAL = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        b"xref\n0 3\n"
        b"trailer\n<< /Size 3 /Root 1 0 R >>\n"
        b"startxref\n9\n%%EOF\n"
    )

    def test_ordinary_pdf_is_not_reported_as_critical(self) -> None:
        """Regression, and the single worst false positive in the old engine.

        It matched ``/xref\\b/gi``, which also matches the ``xref`` inside
        ``startxref``. Every conforming PDF contains both, so *every PDF ever
        scanned* was reported as "CRITICAL: Redundant XRef Tables".
        """
        result = parse_pdf(self.MINIMAL)
        assert not [e for e in result.evidence if e.llr > 0]
        assert "pdf.redundant-xref" not in ids(result)

    def test_incremental_updates_are_context_not_evidence(self) -> None:
        """Any signed or annotated PDF has several %%EOF markers by design."""
        updated = self.MINIMAL + b"4 0 obj\n<< >>\nendobj\nstartxref\n20\n%%EOF\n"
        result = parse_pdf(updated)
        assert "pdf.incremental-updates" in ids(result)
        assert all(e.llr == 0.0 for e in result.evidence if e.id == "pdf.incremental-updates")

    def test_trailing_whitespace_after_eof_is_ignored(self) -> None:
        result = parse_pdf(self.MINIMAL + b"\n\r\n   \n")
        assert "pdf.trailing-data" not in ids(result)

    def test_real_appended_payload_after_eof_is_detected(self) -> None:
        result = parse_pdf(self.MINIMAL + zip_bytes())
        assert "pdf.trailing-data" in ids(result)

    def test_embedded_files_are_reported(self) -> None:
        data = self.MINIMAL.replace(b"/Type /Catalog", b"/Type /Catalog /EmbeddedFiles 5 0 R")
        assert "pdf.embedded-files" in ids(parse_pdf(data))

    def test_javascript_with_open_action_is_reported(self) -> None:
        data = self.MINIMAL.replace(b"/Type /Catalog", b"/Type /Catalog /OpenAction << /JS 1 >>")
        assert "pdf.auto-executing-javascript" in ids(parse_pdf(data))

    def test_object_streams_alone_are_not_evidence(self) -> None:
        """/ObjStm is the default in PDF 1.5+ and appears in most modern files."""
        result = parse_pdf(self.MINIMAL.replace(b"/Type /Pages", b"/Type /ObjStm"))
        assert all(e.llr == 0.0 for e in result.evidence)


class TestZipProbe:
    def test_valid_archive_is_parsed(self) -> None:
        probe = probe_zip(zip_bytes({"a.txt": "x", "b.txt": "y"}))
        assert probe is not None
        assert set(probe.names) == {"a.txt", "b.txt"}

    def test_magic_bytes_alone_are_rejected(self) -> None:
        """Four bytes prove nothing; the archive must actually open."""
        assert probe_zip(b"PK\x03\x04" + b"\x00" * 200) is None

    def test_non_zip_is_rejected(self) -> None:
        assert probe_zip(b"definitely not a zip") is None


def _box(box_type: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload) + 8) + box_type + payload


def _mp4(*boxes: bytes) -> bytes:
    return _box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2avc1mp41") + b"".join(boxes)


class TestIsoBmff:
    def test_clean_mp4_produces_no_findings(self) -> None:
        from steginsight.containers.isobmff import parse_isobmff

        data = _mp4(_box(b"free", bytes(512)), _box(b"mdat", b"\x00\x11" * 4096))
        result = parse_isobmff(data)
        assert not [e for e in result.evidence if e.llr > 0]
        assert {n.id for n in result.nodes} >= {"ftyp", "free", "mdat"}

    def test_zero_filled_free_box_is_not_flagged(self) -> None:
        """A `free` box exists to be skipped and is conventionally zero-filled."""
        from steginsight.containers.isobmff import parse_isobmff

        result = parse_isobmff(_mp4(_box(b"free", bytes(4096)), _box(b"mdat", b"\x00" * 1024)))
        assert "mp4.filler-box-carries-data" not in ids(result)

    def test_free_box_carrying_a_payload_is_detected(self) -> None:
        """The OpenPuff-style vector: a payload parked in a box readers ignore."""
        from steginsight.containers.isobmff import parse_isobmff

        result = parse_isobmff(_mp4(_box(b"free", zip_bytes()), _box(b"mdat", b"\x00" * 1024)))
        assert "mp4.filler-box-carries-data" in ids(result)
        assert result.carved

    def test_appended_data_after_the_last_box_is_detected(self) -> None:
        from steginsight.containers.isobmff import parse_isobmff

        data = _mp4(_box(b"mdat", b"\x00\x11" * 2048)) + zip_bytes()
        result = parse_isobmff(data)
        assert "mp4.trailing-data" in ids(result)

    def test_nested_container_boxes_are_walked(self) -> None:
        from steginsight.containers.isobmff import parse_isobmff

        inner = _box(b"trak", _box(b"free", zip_bytes()))
        result = parse_isobmff(_mp4(_box(b"moov", inner), _box(b"mdat", b"\x00" * 512)))
        assert "mp4.filler-box-carries-data" in ids(result)

    def test_absurd_box_size_is_reported_not_fatal(self) -> None:
        from steginsight.containers.isobmff import parse_isobmff

        data = _mp4(struct.pack(">I", 0xFFFFFF) + b"mdat" + b"\x00" * 64)
        result = parse_isobmff(data)
        assert "mp4.bad-box-size" in ids(result)

    def test_non_mp4_input_is_handled(self) -> None:
        from steginsight.containers.isobmff import parse_isobmff

        assert parse_isobmff(b"nowhere near an mp4").limitations
