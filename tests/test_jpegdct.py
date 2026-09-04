"""Baseline JPEG coefficient decoder.

A hand-written entropy decoder is only trustworthy if it is checked against an
independent implementation, so the central test dequantises the coefficients,
runs an inverse DCT and compares the result against libjpeg's own decode of the
same file. If the Huffman decoding, the zig-zag mapping, the DC prediction or
the sampling-factor handling were wrong, the reconstruction would diverge
wildly rather than by rounding error.
"""

from __future__ import annotations

import contextlib
import io

import numpy as np
import pytest
from PIL import Image
from scipy.fft import idctn

from steginsight.jpegdct import (
    UnsupportedJpeg,
    decode_coefficients,
    dequantise,
)
from tests.factories import jpeg_bytes, natural_image


def reconstruct_luma(data: bytes) -> np.ndarray:
    scan = decode_coefficients(data)
    component = scan.components[0]
    assert component.coefficients is not None
    blocks_v, blocks_h = component.coefficients.shape[:2]

    spatial = idctn(dequantise(scan, 0), axes=(1, 2), norm="ortho") + 128
    image = (
        spatial.reshape(blocks_v, blocks_h, 8, 8)
        .transpose(0, 2, 1, 3)
        .reshape(blocks_v * 8, blocks_h * 8)
    )
    return np.clip(image, 0, 255)[: scan.height, : scan.width]


def reference_luma(data: bytes) -> np.ndarray:
    with Image.open(io.BytesIO(data)) as image:
        return np.asarray(image.convert("YCbCr"))[:, :, 0].astype(float)


class TestDecoderCorrectness:
    @pytest.mark.parametrize(
        ("quality", "kwargs"),
        [
            (85, {"subsampling": 0}),   # 4:4:4
            (75, {}),                   # 4:2:0, the common default
            (95, {"subsampling": 0}),
            (60, {"subsampling": 2}),   # 4:2:0 explicit
        ],
    )
    def test_matches_libjpeg(self, quality: int, kwargs: dict) -> None:
        """The decisive test: our coefficients must reconstruct libjpeg's pixels."""
        data = jpeg_bytes(natural_image(height=128, width=128, seed=3), quality=quality, **kwargs)
        error = np.abs(reconstruct_luma(data) - reference_luma(data))
        # Residual is the difference between a float IDCT and libjpeg's integer
        # one, which is bounded by rounding. A decoding error would be enormous.
        assert error.mean() < 1.5, f"mean error {error.mean():.3f}"
        assert np.percentile(error, 99) < 4.0

    def test_restart_markers_are_handled(self) -> None:
        data = jpeg_bytes(
            natural_image(height=128, width=128, seed=4),
            quality=80,
            restart_marker_blocks=4,
        )
        error = np.abs(reconstruct_luma(data) - reference_luma(data))
        assert error.mean() < 1.5

    def test_grayscale(self) -> None:
        buffer = io.BytesIO()
        Image.fromarray(natural_image(height=128, width=128, seed=6)).convert("L").save(
            buffer, "JPEG", quality=80
        )
        scan = decode_coefficients(buffer.getvalue())
        assert len(scan.components) == 1
        assert scan.width == 128 and scan.height == 128

    def test_dimensions_and_component_count(self) -> None:
        scan = decode_coefficients(jpeg_bytes(natural_image(height=96, width=160, seed=1)))
        assert (scan.width, scan.height) == (160, 96)
        assert len(scan.components) == 3


class TestUnsupportedInput:
    def test_progressive_is_rejected_clearly(self) -> None:
        data = jpeg_bytes(natural_image(height=96, width=96, seed=1), progressive=True)
        with pytest.raises(UnsupportedJpeg, match="progressive"):
            decode_coefficients(data)

    def test_non_jpeg_is_rejected(self) -> None:
        with pytest.raises(UnsupportedJpeg, match="SOI"):
            decode_coefficients(b"\x00\x01\x02\x03")

    def test_truncated_jpeg_does_not_hang_or_crash(self) -> None:
        data = jpeg_bytes(natural_image(height=96, width=96, seed=1))
        # An explicit refusal is an acceptable outcome; a traceback is not.
        with contextlib.suppress(UnsupportedJpeg):
            decode_coefficients(data[: len(data) // 2])


class TestCoefficientAccess:
    def test_ac_coefficients_exclude_dc(self) -> None:
        scan = decode_coefficients(jpeg_bytes(natural_image(height=128, width=128, seed=1)))
        component = scan.luma
        blocks = component.blocks
        assert component.ac_coefficients().size == blocks.shape[0] * 63

    def test_most_ac_coefficients_are_zero(self) -> None:
        """The property every DCT-domain detector depends on."""
        scan = decode_coefficients(
            jpeg_bytes(natural_image(height=256, width=256, seed=2), quality=70)
        )
        ac = scan.luma.ac_coefficients()
        assert (ac == 0).mean() > 0.7

    def test_quantisation_tables_are_recovered(self) -> None:
        scan = decode_coefficients(jpeg_bytes(natural_image(height=128, width=128, seed=1)))
        table = scan.quant_tables[scan.luma.quant_table_id]
        assert table.shape == (8, 8)
        assert table.min() >= 1
        # Low frequencies are quantised more finely than high ones.
        assert table[0, 0] < table[7, 7]
