"""Detector behaviour.

The false-negative tests matter as much as the false-positive ones: a detector
that never fires is as useless as one that always does. Where a detector is
deliberately silent, the test says so and explains why, so that a future change
that "fixes" it has to argue with the reasoning rather than just the assertion.
"""

from __future__ import annotations

import numpy as np
import pytest

from steginsight.core.estimators import rs_analysis, sample_pair_analysis
from steginsight.detectors.audio import analyse_audio
from steginsight.detectors.spatial import analyse_spatial
from steginsight.detectors.text import analyse_text
from steginsight.detectors.transform import analyse_dct
from tests.factories import (
    bmp_bytes,
    embed_lsb,
    jpeg_bytes,
    natural_image,
    png_bytes,
    silent_intro_audio,
    wav_bytes,
)


def ids(evidence) -> set[str]:  # type: ignore[no-untyped-def]
    return {e.id for e in evidence}


class TestEstimators:
    """RS and SPA estimate the embedding *rate*, not merely its presence."""

    @pytest.mark.parametrize("rate", [0.0, 0.1, 0.25, 0.5])
    def test_rs_tracks_the_true_rate(self, rate: float) -> None:
        cover = natural_image(seed=21, channels=1)
        estimate = rs_analysis(embed_lsb(cover, rate))
        assert estimate is not None and not estimate.unreliable
        # RS systematically under-reads by roughly a quarter; the tolerance
        # reflects the measured behaviour rather than an idealised one.
        assert estimate.rate == pytest.approx(rate, abs=0.13)

    @pytest.mark.parametrize("rate", [0.0, 0.1, 0.25, 0.5])
    def test_spa_tracks_the_true_rate(self, rate: float) -> None:
        cover = natural_image(seed=22, channels=1)
        estimate = sample_pair_analysis(embed_lsb(cover, rate).ravel())
        assert estimate is not None and not estimate.unreliable
        assert estimate.rate == pytest.approx(rate, abs=0.13)

    def test_clean_cover_reads_near_zero(self) -> None:
        cover = natural_image(seed=23, channels=1)
        rs = rs_analysis(cover)
        spa = sample_pair_analysis(cover.ravel())
        assert rs is not None and spa is not None
        assert rs.rate < 0.035 and spa.rate < 0.035

    def test_estimates_are_deterministic(self) -> None:
        """Reproducibility is not optional in an evidentiary context."""
        cover = embed_lsb(natural_image(seed=24, channels=1), 0.3)
        first = rs_analysis(cover)
        second = rs_analysis(cover)
        assert first is not None and second is not None
        assert first.rate == second.rate

    def test_tiny_input_returns_none(self) -> None:
        assert rs_analysis(np.zeros((4, 4), dtype=np.uint8)) is None
        assert sample_pair_analysis(np.zeros(16, dtype=np.uint8)) is None


class TestSpatialDetector:
    def test_clean_png_yields_no_positive_finding(self) -> None:
        _, evidence, _ = analyse_spatial(png_bytes(natural_image(seed=31)))
        assert not [e for e in evidence if e.llr > 0]

    def test_clean_png_states_the_negative_explicitly(self) -> None:
        """A detector that clears a file should say so, not stay silent."""
        _, evidence, _ = analyse_spatial(png_bytes(natural_image(seed=31)))
        assert "spatial.lsb-clear" in ids(evidence)

    @pytest.mark.parametrize("rate", [0.15, 0.3, 0.6])
    def test_embedding_is_detected(self, rate: float) -> None:
        data = png_bytes(embed_lsb(natural_image(seed=32), rate))
        _, evidence, _ = analyse_spatial(data)
        assert "spatial.lsb-rate-agreement" in ids(evidence)

    def test_sequential_embedding_is_localised(self) -> None:
        data = png_bytes(embed_lsb(natural_image(height=512, width=512, seed=33), 0.4))
        _, evidence, _ = analyse_spatial(data)
        finding = next(e for e in evidence if e.id == "spatial.sequential-embedding")
        assert 0.2 < finding.measurements["prefix_ratio"] < 0.6

    def test_bmp_is_analysed(self) -> None:
        _, evidence, _ = analyse_spatial(bmp_bytes(embed_lsb(natural_image(seed=34), 0.3)))
        assert "spatial.lsb-rate-agreement" in ids(evidence)

    def test_jpeg_is_refused_with_a_stated_reason(self) -> None:
        """Lossy compression overwrites the low bit planes.

        Running spatial LSB analysis on a JPEG measures the quantiser, not the
        carrier, so the detector declines and says why rather than reporting a
        meaningless number.
        """
        profile, evidence, limitations = analyse_spatial(jpeg_bytes(natural_image(seed=35)))
        assert profile is None and evidence == []
        assert any("lossy" in note for note in limitations)

    def test_non_image_input_is_ignored(self) -> None:
        profile, evidence, _ = analyse_spatial(b"not an image")
        assert profile is None and evidence == []


class TestTransformDetector:
    def test_clean_jpeg_yields_no_positive_finding(self) -> None:
        _, evidence, _ = analyse_dct(jpeg_bytes(natural_image(seed=41)))
        assert not [e for e in evidence if e.llr > 0]

    def test_clean_jpeg_reports_the_negative(self) -> None:
        _, evidence, _ = analyse_dct(jpeg_bytes(natural_image(seed=41)))
        assert "dct.chi-square-clear" in ids(evidence)

    @pytest.mark.parametrize("quality", [70, 80, 90, 95])
    def test_no_false_positive_across_quality_settings(self, quality: int) -> None:
        """The F5 detector previously fired on every quality-70 JPEG."""
        _, evidence, _ = analyse_dct(jpeg_bytes(natural_image(seed=42), quality=quality))
        assert not [e for e in evidence if e.llr > 0]

    def test_calibration_is_reported_but_never_scores(self) -> None:
        """Deliberate: the measurement could not be validated in this build."""
        _, evidence, limitations = analyse_dct(jpeg_bytes(natural_image(seed=43)))
        calibration = [e for e in evidence if e.id == "dct.calibration-measurement"]
        if calibration:
            assert calibration[0].llr == 0.0
            assert any("baseline" in note for note in limitations)

    def test_progressive_jpeg_is_reported_as_a_limitation(self) -> None:
        data = jpeg_bytes(natural_image(seed=44), progressive=True)
        profile, evidence, limitations = analyse_dct(data)
        assert profile is None and evidence == []
        assert any("progressive" in note for note in limitations)

    def test_coefficient_profile_is_populated(self) -> None:
        profile, _, _ = analyse_dct(jpeg_bytes(natural_image(seed=45)))
        assert profile is not None
        assert profile.total_coefficients > 1000
        assert profile.quality_estimate is not None


class TestAudioDetector:
    def test_clean_recording_yields_no_positive_finding(self) -> None:
        _, evidence, _ = analyse_audio(wav_bytes())
        assert not [e for e in evidence if e.llr > 0]

    def test_noisy_carrier_is_reported_inconclusive_not_clean(self) -> None:
        """The honest result for 16-bit PCM without a silent passage.

        A recording's own noise floor is indistinguishable from a payload by
        these statistics. Saying so is more useful than a fabricated verdict in
        either direction.
        """
        _, evidence, limitations = analyse_audio(wav_bytes())
        assert "audio.lsb-inconclusive" in ids(evidence)
        assert any(e.inconclusive for e in evidence)
        assert any("inconclusive" in note for note in limitations)

    def test_data_hidden_in_silence_is_detected(self) -> None:
        _, evidence, _ = analyse_audio(silent_intro_audio(embed_rate=0.5))
        assert "audio.data-in-silence" in ids(evidence)

    def test_genuine_silence_is_recognised_as_clean(self) -> None:
        _, evidence, _ = analyse_audio(silent_intro_audio(embed_rate=0.0))
        assert "audio.silence-clean" in ids(evidence)
        assert not [e for e in evidence if e.llr > 0]

    def test_silent_intro_alone_is_not_a_floor_discontinuity(self) -> None:
        """Regression: a recording that begins with a pause is not an anomaly."""
        _, evidence, _ = analyse_audio(silent_intro_audio(embed_rate=0.0))
        assert "audio.floor-discontinuity" not in ids(evidence)

    def test_non_wav_input_is_reported_as_a_limitation(self) -> None:
        profile, evidence, limitations = analyse_audio(b"not audio")
        assert profile is None and evidence == []
        assert limitations


class TestTextDetector:
    def test_ordinary_prose_yields_nothing(self) -> None:
        text = ("Meeting notes. Budget approved. Next review in April.\n" * 40).encode()
        _, evidence, _ = analyse_text(text)
        assert not [e for e in evidence if e.llr > 0]

    def test_zero_width_binary_alphabet_is_detected(self) -> None:
        payload = "".join(
            "​" if bit == "0" else "‌"
            for bit in "".join(f"{ord(c):08b}" for c in "SECRET")
        )
        _, evidence, _ = analyse_text(f"Ordinary text.{payload}\nMore text.".encode())
        assert "text.zero-width-encoding" in ids(evidence)

    def test_unicode_tag_characters_are_detected(self) -> None:
        hidden = "".join(chr(0xE0000 + ord(c)) for c in "exfiltrate this")
        _, evidence, _ = analyse_text(f"Looks harmless.{hidden}".encode())
        assert "text.unicode-tag-characters" in ids(evidence)

    def test_a_single_bom_is_not_reported(self) -> None:
        """A byte-order mark at the start of a file is entirely ordinary."""
        _, evidence, _ = analyse_text("﻿Ordinary document text here.".encode())
        assert not [e for e in evidence if e.llr > 0]

    def test_emoji_joiners_do_not_trigger_the_encoder_finding(self) -> None:
        text = ("Team \U0001f469‍\U0001f4bb shipped it \U0001f468‍\U0001f680\n" * 3)
        _, evidence, _ = analyse_text(text.encode())
        assert "text.zero-width-encoding" not in ids(evidence)

    def test_variation_selector_payload_is_detected(self) -> None:
        payload = "".join(chr(0xFE00 + (i % 16)) for i in range(40))
        _, evidence, _ = analyse_text(f"base{payload}".encode())
        assert "text.variation-selector-payload" in ids(evidence)

    def test_homoglyph_substitution_is_detected(self) -> None:
        base = "The quick brown fox jumps over the lazy dog. " * 12
        swapped = base.replace("o", "о", 6)  # a few Cyrillic o
        _, evidence, _ = analyse_text(swapped.encode())
        assert "text.homoglyph-substitution" in ids(evidence)

    def test_binary_input_is_reported_as_a_limitation(self) -> None:
        profile, evidence, limitations = analyse_text(bytes(range(256)))
        assert profile is None and evidence == []
        assert limitations
