"""End-to-end analysis.

These are the tests that matter most: they exercise the whole pipeline the way
an analyst does, and they assert on the *verdict* rather than on any individual
detector. Both directions are covered — clean carriers must not be flagged, and
embedded ones must be.
"""

from __future__ import annotations

import io
import json

import pytest
from PIL import Image

from steginsight import Verdict, analyse
from steginsight.core.carrier import Carrier
from tests.factories import (
    append_payload,
    bmp_bytes,
    embed_lsb,
    jpeg_bytes,
    natural_image,
    png_bytes,
    silent_intro_audio,
    wav_bytes,
    zip_bytes,
)


def run(data: bytes, name: str = "exhibit.bin"):  # type: ignore[no-untyped-def]
    return analyse(Carrier.from_bytes(data, name))


def ids(report) -> set[str]:  # type: ignore[no-untyped-def]
    return {e.id for e in report.evidence}


class TestCleanCarriers:
    """No false positives. Every one of these was a false positive previously."""

    @pytest.mark.parametrize(
        ("name", "factory"),
        [
            ("clean.png", lambda: png_bytes(natural_image(seed=51))),
            ("clean.bmp", lambda: bmp_bytes(natural_image(seed=52))),
            ("clean.jpg", lambda: jpeg_bytes(natural_image(seed=53))),
            ("clean_q70.jpg", lambda: jpeg_bytes(natural_image(seed=54), quality=70)),
            ("clean_q95.jpg", lambda: jpeg_bytes(natural_image(seed=55), quality=95)),
            ("silence.wav", lambda: silent_intro_audio(0.0)),
        ],
    )
    def test_clean_carrier_is_not_flagged(self, name: str, factory) -> None:  # type: ignore[no-untyped-def]
        report = run(factory(), name)
        assert report.assessment.verdict in (Verdict.CLEAN, Verdict.INCONCLUSIVE), (
            f"{name} was reported {report.assessment.verdict.value} "
            f"(p={report.assessment.probability:.3f}) because of "
            f"{[e.id for e in report.evidence if e.llr > 0]}"
        )
        assert report.assessment.probability < 0.5

    def test_plain_text_is_not_flagged(self) -> None:
        text = ("Ordinary notes about the quarterly review.\n" * 60).encode()
        assert run(text, "notes.txt").assessment.verdict is Verdict.CLEAN

    def test_minimal_pdf_is_not_flagged(self) -> None:
        pdf = (
            b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
            b"xref\n0 2\ntrailer\n<< /Size 2 >>\nstartxref\n9\n%%EOF\n"
        )
        assert run(pdf, "doc.pdf").assessment.verdict is Verdict.CLEAN


class TestEmbeddedCarriers:
    """No false negatives."""

    def test_appended_archive(self) -> None:
        data = append_payload(png_bytes(natural_image(seed=61)), zip_bytes())
        report = run(data, "appended.png")
        assert report.assessment.verdict is Verdict.LIKELY_EMBEDDED
        assert "png.trailing-data" in ids(report)

    @pytest.mark.parametrize("rate", [0.15, 0.3, 0.6])
    def test_lsb_embedding_in_png(self, rate: float) -> None:
        report = run(png_bytes(embed_lsb(natural_image(seed=62), rate)), "lsb.png")
        assert report.assessment.verdict is Verdict.LIKELY_EMBEDDED

    def test_lsb_embedding_in_bmp(self) -> None:
        report = run(bmp_bytes(embed_lsb(natural_image(seed=63), 0.3)), "lsb.bmp")
        assert report.assessment.verdict is Verdict.LIKELY_EMBEDDED

    def test_data_hidden_in_audio_silence(self) -> None:
        report = run(silent_intro_audio(0.5), "hidden.wav")
        assert report.assessment.verdict is Verdict.LIKELY_EMBEDDED
        assert "audio.data-in-silence" in ids(report)

    def test_zero_width_text_payload(self) -> None:
        payload = "".join(
            "​" if b == "0" else "‌"
            for b in "".join(f"{ord(c):08b}" for c in "CLASSIFIED")
        )
        report = run(f"Normal memo.{payload}\n".encode(), "memo.txt")
        assert report.assessment.probability > 0.5

    def test_appended_data_to_wav(self) -> None:
        report = run(append_payload(wav_bytes(seconds=1.0), zip_bytes()), "a.wav")
        assert report.assessment.verdict is Verdict.LIKELY_EMBEDDED

    def test_polyglot_zip_inside_carrier(self) -> None:
        """A file that is simultaneously a valid image and a valid archive."""
        archive = zip_bytes({"payload.txt": "data" * 100})
        data = append_payload(png_bytes(natural_image(seed=64)), archive)
        report = run(data, "polyglot.png")
        assert report.assessment.verdict is Verdict.LIKELY_EMBEDDED
        carved = [c for c in report.carved if c.format == "zip" and c.verified]
        assert carved, "the archive should have been carved and verified"


class TestIdentity:
    def test_hashes_are_computed(self) -> None:
        report = run(b"hello world", "x.txt")
        assert len(report.carrier.hashes.sha256) == 64
        assert len(report.carrier.hashes.sha1) == 40
        assert len(report.carrier.hashes.md5) == 32

    def test_known_hash_values(self) -> None:
        report = run(b"abc", "x.txt")
        assert report.carrier.hashes.sha256 == (
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        assert report.carrier.hashes.md5 == "900150983cd24fb0d6963f7d28e17f72"

    def test_format_detected_from_magic_not_extension(self) -> None:
        report = run(png_bytes(natural_image(seed=71)), "actually_a_png.jpg")
        assert report.carrier.format_name == "png"

    def test_extension_masquerade_is_reported(self) -> None:
        report = run(zip_bytes(), "holiday_photo.jpg")
        assert "identity.type-mismatch" in ids(report)


class TestReportContract:
    def test_json_is_serialisable_and_complete(self) -> None:
        report = run(append_payload(png_bytes(natural_image(seed=81)), zip_bytes()), "a.png")
        payload = json.loads(json.dumps(report.to_dict()))
        for key in (
            "schema_version", "engine_version", "exhibit", "assessment",
            "evidence", "entropy", "structure", "carved",
            "recommended_actions", "limitations",
        ):
            assert key in payload
        assert payload["schema_version"] == 2
        assert payload["exhibit"]["hashes"]["sha256"]

    def test_actions_have_the_real_path_substituted(self) -> None:
        report = run(append_payload(png_bytes(natural_image(seed=82)), zip_bytes()), "ex.png")
        assert report.recommended_actions
        assert not any("{file}" in action for action in report.recommended_actions)

    def test_every_finding_carries_a_traceable_measurement(self) -> None:
        report = run(png_bytes(embed_lsb(natural_image(seed=83), 0.3)), "a.png")
        for item in report.evidence:
            assert item.id and item.detail
            if item.llr > 0.5:
                assert item.measurements, f"{item.id} scores but shows no measurement"

    def test_html_report_is_self_contained(self) -> None:
        from steginsight.report.html import render_html

        report = run(png_bytes(embed_lsb(natural_image(seed=84), 0.3)), "a.png")
        html = render_html(report)
        assert "<script" not in html
        assert "https://" not in html.split("<style>")[0]
        assert "data:image/png;base64," in html

    def test_text_report_renders(self) -> None:
        from steginsight.report.text import render_text, verdict_exit_code

        report = run(png_bytes(natural_image(seed=85)), "a.png")
        rendered = render_text(report, colour=False)
        assert "EXHIBIT" in rendered and "CLEAN" in rendered
        assert verdict_exit_code(report) == 0


class TestRobustness:
    """A malformed exhibit must produce a report, never a traceback."""

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"\x00",
            b"\x89PNG\r\n\x1a\n",                       # header only
            b"\x89PNG\r\n\x1a\n" + b"\xff" * 500,       # header plus garbage
            b"\xff\xd8\xff",                            # JPEG SOI only
            b"RIFF\xff\xff\xff\xffWAVE",                # absurd declared size
            b"%PDF-1.4",                                # truncated PDF
            b"GIF89a" + b"\x00" * 20,
            b"BM" + b"\xff" * 60,
            bytes(range(256)) * 40,                      # unidentifiable binary
        ],
    )
    def test_malformed_input_does_not_raise(self, data: bytes) -> None:
        report = run(data, "malformed.bin")
        assert report.assessment.verdict in set(Verdict)
        json.dumps(report.to_dict())

    def test_truncated_image_is_handled(self) -> None:
        data = png_bytes(natural_image(seed=91))
        report = run(data[: len(data) // 2], "truncated.png")
        assert report.limitations

    def test_single_pixel_image(self) -> None:
        buffer = io.BytesIO()
        Image.new("RGB", (1, 1), (255, 0, 0)).save(buffer, "PNG")
        report = run(buffer.getvalue(), "tiny.png")
        assert report.assessment.verdict in set(Verdict)

    def test_analysis_is_deterministic(self) -> None:
        data = png_bytes(embed_lsb(natural_image(seed=92), 0.3))
        first, second = run(data, "a.png"), run(data, "a.png")
        assert first.assessment.probability == second.assessment.probability
        assert ids(first) == ids(second)

    def test_prior_moves_the_posterior(self) -> None:
        data = png_bytes(natural_image(seed=93))
        low = analyse(Carrier.from_bytes(data, "a.png"), prior=0.01)
        high = analyse(Carrier.from_bytes(data, "a.png"), prior=0.5)
        assert high.assessment.probability > low.assessment.probability
