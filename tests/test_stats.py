"""Statistical primitives.

These tests pin down the properties the detectors depend on. Several encode
bugs that were present in the previous engine, so a regression would be caught
rather than shipped.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from steginsight.core.stats import (
    bit_plane_entropy,
    bit_plane_transition_rate,
    chi_square_curve,
    chi_square_pov,
    embedded_prefix_ratio,
    expected_random_entropy,
    is_effectively_random,
    printable_ratio,
    shannon_entropy,
    sliding_entropy,
)
from tests.factories import embed_lsb, natural_image


class TestEntropy:
    def test_uniform_bytes_reach_eight_bits(self) -> None:
        data = bytes(range(256)) * 64
        assert shannon_entropy(data) == pytest.approx(8.0, abs=1e-9)

    def test_constant_data_has_zero_entropy(self) -> None:
        assert shannon_entropy(b"\x00" * 4096) == 0.0

    def test_empty_input_is_zero_not_an_error(self) -> None:
        assert shannon_entropy(b"") == 0.0

    def test_english_text_sits_around_four_bits(self) -> None:
        text = ("the quick brown fox jumps over the lazy dog. " * 200).encode()
        assert 3.5 < shannon_entropy(text) < 4.8

    def test_expected_random_entropy_is_below_eight_for_small_samples(self) -> None:
        """A short sample cannot reach 8.0 even from a perfect random source.

        The previous engine compared a 10,000-byte tail against a fixed 7.95
        threshold and reported "encrypted payload" on ordinary compressed data.
        This is the correction: the bar must move with sample size.
        """
        assert expected_random_entropy(1_000) == pytest.approx(7.82, abs=0.02)
        assert expected_random_entropy(10_000) == pytest.approx(7.982, abs=0.005)
        assert expected_random_entropy(10_000_000) > 7.999

    def test_random_data_is_recognised_as_random_at_its_own_size(self) -> None:
        rng = np.random.default_rng(0)
        for size in (2_000, 10_000, 200_000):
            data = rng.integers(0, 256, size, dtype=np.uint8).tobytes()
            entropy = shannon_entropy(data)
            assert is_effectively_random(entropy, size), (
                f"uniform random data of {size} bytes measured {entropy:.4f} but was "
                f"not recognised as random (expected {expected_random_entropy(size):.4f})"
            )

    def test_a_small_random_tail_is_not_called_maximum_entropy(self) -> None:
        """Regression: the old fixed 7.95 threshold on a 10 KB tail."""
        rng = np.random.default_rng(1)
        data = rng.integers(0, 256, 10_000, dtype=np.uint8).tobytes()
        assert shannon_entropy(data) < 7.99


class TestSlidingEntropy:
    def test_output_is_bounded_regardless_of_input_size(self) -> None:
        """The old engine emitted ~200k points for a 100 MB file and hung the UI."""
        offsets, values, window = sliding_entropy(b"\x00" * (8 << 20))
        assert len(offsets) <= 1024
        assert len(values) == len(offsets)
        assert window >= 512

    def test_locates_a_high_entropy_region(self) -> None:
        rng = np.random.default_rng(3)
        low = b"\x41" * 40_000
        high = rng.integers(0, 256, 40_000, dtype=np.uint8).tobytes()
        _offsets, values, _ = sliding_entropy(low + high + low)

        midpoint = len(values) // 3
        assert values[:midpoint].mean() < 1.0
        assert values[midpoint : 2 * midpoint].mean() > 7.0

    def test_empty_input(self) -> None:
        offsets, values, window = sliding_entropy(b"")
        assert offsets.size == 0 and values.size == 0 and window == 0


class TestChiSquarePoV:
    """Westfeld-Pfitzmann pairs-of-values attack.

    Polarity matters: a *high* p-value is the incriminating outcome, because the
    model being fitted is the embedded one.
    """

    @staticmethod
    def _natural_histogram_samples(seed: int = 0) -> np.ndarray:
        """A cover with realistic image statistics.

        The generator matters: the attack keys on adjacent histogram bins being
        *unequal* in natural content, which multi-octave imagery reproduces and
        a smooth analytic distribution does not.
        """
        return natural_image(seed=seed, channels=1).ravel()

    def test_clean_samples_give_a_low_p_value(self) -> None:
        result = chi_square_pov(self._natural_histogram_samples())
        assert result is not None
        assert result.p_value < 1e-20

    def test_lsb_replacement_drives_p_toward_one(self) -> None:
        cover = natural_image(seed=0, channels=1)
        result = chi_square_pov(embed_lsb(cover, 1.0).ravel())
        assert result is not None
        assert result.p_value > 0.95

    def test_separation_between_clean_and_embedded_is_wide(self) -> None:
        """The margin is what makes the threshold choice uncontroversial."""
        cover = natural_image(seed=4, channels=1)
        clean = chi_square_pov(cover.ravel())
        embedded = chi_square_pov(embed_lsb(cover, 1.0).ravel())
        assert clean is not None and embedded is not None
        assert clean.p_value < 1e-20 < 0.9 < embedded.p_value

    def test_smooth_histograms_are_a_known_blind_spot(self) -> None:
        """Documents a real limitation rather than pretending it away.

        A perfectly smooth histogram — a soft gradient, a heavily denoised or
        low-contrast image — has near-equal adjacent bins by construction, so it
        fits the equalised model without anything being embedded. This is why
        `detectors.spatial` gates the chi-square finding on the bit-plane
        decorrelation gap instead of reporting it alone.
        """
        rng = np.random.default_rng(0)
        smooth = np.clip(rng.normal(128, 28, 200_000), 0, 255).astype(np.uint8)
        result = chi_square_pov(smooth)
        assert result is not None
        assert result.p_value > 0.9  # a false positive, if taken at face value

    def test_too_few_samples_returns_none_rather_than_a_wrong_answer(self) -> None:
        assert chi_square_pov(np.zeros(10, dtype=np.uint8)) is None

    def test_degrees_of_freedom_track_usable_bins(self) -> None:
        result = chi_square_pov(self._natural_histogram_samples())
        assert result is not None
        assert result.degrees_of_freedom == result.usable_bins - 1


class TestChiSquareCurve:
    def test_sequential_embedding_produces_a_leading_run(self) -> None:
        cover = natural_image(height=512, width=512, seed=11, channels=1)
        _, p_values = chi_square_curve(embed_lsb(cover, 0.5).ravel())
        prefix = embedded_prefix_ratio(p_values)
        assert 0.3 < prefix < 0.7, f"expected ~0.5 leading run, got {prefix}"

    def test_clean_samples_have_no_leading_run(self) -> None:
        cover = natural_image(height=512, width=512, seed=13, channels=1)
        _, p_values = chi_square_curve(cover.ravel())
        assert embedded_prefix_ratio(p_values) < 0.05

    def test_short_input_returns_empty(self) -> None:
        offsets, values = chi_square_curve(np.zeros(100, dtype=np.uint8))
        assert offsets.size == 0 and values.size == 0


class TestBitPlanes:
    def test_random_plane_has_entropy_one(self) -> None:
        rng = np.random.default_rng(5)
        samples = rng.integers(0, 256, 100_000, dtype=np.uint8)
        assert bit_plane_entropy(samples, 0) == pytest.approx(1.0, abs=0.01)

    def test_constant_plane_has_entropy_zero(self) -> None:
        assert bit_plane_entropy(np.zeros(1000, dtype=np.uint8), 0) == 0.0

    def test_transition_rate_is_half_for_random_bits(self) -> None:
        rng = np.random.default_rng(9)
        bits = rng.integers(0, 2, (200, 200), dtype=np.uint8)
        assert bit_plane_transition_rate(bits) == pytest.approx(0.5, abs=0.02)

    def test_transition_rate_is_low_for_correlated_bits(self) -> None:
        bits = np.zeros((200, 200), dtype=np.uint8)
        bits[:, 100:] = 1  # one edge only
        assert bit_plane_transition_rate(bits) < 0.02

    def test_one_dimensional_input_is_rejected(self) -> None:
        assert math.isnan(bit_plane_transition_rate(np.zeros(100, dtype=np.uint8)))


class TestPrintableRatio:
    def test_ascii_text(self) -> None:
        assert printable_ratio(b"hello world\n") == pytest.approx(1.0)

    def test_binary(self) -> None:
        assert printable_ratio(bytes(range(0, 32)) * 10) < 0.2

    def test_empty(self) -> None:
        assert printable_ratio(b"") == 0.0
