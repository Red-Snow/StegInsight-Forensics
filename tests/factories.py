"""Synthetic carrier construction for the test-suite.

Every fixture is generated deterministically at test time rather than committed
as a binary blob, so the tests state plainly what they are testing and a reader
can see exactly what makes a given carrier "clean" or "embedded".

The cover generator matters more than it looks. A smooth gradient with Gaussian
noise added is *not* a realistic image cover: its low bit planes are already
pure noise, so it defeats every LSB detector and simultaneously trips the
chi-square test. Real photographs have multi-scale structure, so
:func:`natural_image` builds covers from summed octaves of value noise, which
reproduces the correlated bit planes that the detectors depend on. Testing
against unrealistic covers would have validated the wrong behaviour.
"""

from __future__ import annotations

import io
import wave
import zipfile

import numpy as np
from numpy.typing import NDArray
from PIL import Image

__all__ = [
    "append_payload",
    "bmp_bytes",
    "embed_lsb",
    "jpeg_bytes",
    "natural_image",
    "png_bytes",
    "silent_intro_audio",
    "wav_bytes",
    "zip_bytes",
]


def natural_image(
    height: int = 320, width: int = 320, seed: int = 1, channels: int = 3
) -> NDArray[np.uint8]:
    """A cover with multi-scale structure, approximating natural image statistics.

    Summed octaves of value noise produce the property that matters here:
    neighbouring pixels are correlated all the way down into the low bit planes,
    exactly as in a real photograph.
    """
    rng = np.random.default_rng(seed)
    planes = []
    for c in range(channels):
        acc = np.zeros((height, width), dtype=np.float64)
        for octave in range(1, 7):
            size = 2**octave
            coarse = rng.normal(0, 1, (size, size))
            tile = np.kron(
                coarse, np.ones((height // size + 1, width // size + 1))
            )[:height, :width]
            acc += tile / octave
        acc = (acc - acc.min()) / max(np.ptp(acc), 1e-9)
        planes.append(acc * (185 + 5 * c) + 30)
    stacked = np.stack(planes, axis=-1) if channels > 1 else planes[0]
    return np.clip(stacked, 0, 255).astype(np.uint8)


def embed_lsb(
    cover: NDArray[np.uint8], rate: float, seed: int = 99
) -> NDArray[np.uint8]:
    """Replace the LSB of the leading ``rate`` fraction of samples.

    This models LSB *replacement*, which is what RS analysis, Sample Pair
    Analysis and the chi-square attack are designed to detect. Embedding
    sequentially from the start also reproduces the behaviour of tools that fill
    a carrier in order, which the chi-square curve is meant to localise.
    """
    rng = np.random.default_rng(seed)
    flat = cover.copy().ravel()
    count = int(flat.size * rate)
    if count:
        flat[:count] = (flat[:count] & 0xFE) | rng.integers(
            0, 2, count, dtype=np.uint8
        )
    return flat.reshape(cover.shape)


def png_bytes(array: NDArray[np.uint8]) -> bytes:
    buffer = io.BytesIO()
    Image.fromarray(array).save(buffer, "PNG", compress_level=6)
    return buffer.getvalue()


def bmp_bytes(array: NDArray[np.uint8]) -> bytes:
    buffer = io.BytesIO()
    Image.fromarray(array).save(buffer, "BMP")
    return buffer.getvalue()


def jpeg_bytes(array: NDArray[np.uint8], quality: int = 85, **kwargs: object) -> bytes:
    buffer = io.BytesIO()
    Image.fromarray(array).save(buffer, "JPEG", quality=quality, **kwargs)
    return buffer.getvalue()


def zip_bytes(entries: dict[str, str] | None = None) -> bytes:
    entries = entries or {"secret.txt": "exfiltrated material\n" * 40}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def append_payload(carrier: bytes, payload: bytes) -> bytes:
    return carrier + payload


def _write_wav(samples: NDArray[np.int16], rate: int = 22050) -> bytes:
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(rate)
        handle.writeframes(samples.tobytes())
    return buffer.getvalue()


def wav_bytes(
    seconds: float = 3.0,
    rate: int = 22050,
    seed: int = 5,
    noise_floor: float = 1e-3,
) -> bytes:
    """A plausible recording: harmonics, a slow envelope, and a noise floor."""
    rng = np.random.default_rng(seed)
    t = np.arange(int(rate * seconds)) / rate
    envelope = 0.4 + 0.3 * np.sin(2 * np.pi * 0.7 * t)
    signal = envelope * (
        np.sin(2 * np.pi * 220 * t)
        + 0.5 * np.sin(2 * np.pi * 440 * t + 1)
        + 0.25 * np.sin(2 * np.pi * 880 * t)
    )
    signal = signal / np.abs(signal).max() * 0.7
    signal = np.clip(signal + rng.normal(0, noise_floor, signal.size), -1, 1)
    return _write_wav((signal * 32000).astype(np.int16), rate)


def silent_intro_audio(
    embed_rate: float = 0.0,
    seconds: float = 3.0,
    rate: int = 22050,
    seed: int = 5,
) -> bytes:
    """Audio whose first third is true digital silence.

    Digital silence is the one place LSB embedding in audio is reliably
    detectable, because silence is written as exact zeros by every recorder and
    codec. ``embed_rate`` writes random low bits across the leading fraction of
    the file, which necessarily disturbs that silence.
    """
    rng = np.random.default_rng(seed)
    t = np.arange(int(rate * seconds)) / rate
    signal = 0.6 * np.sin(2 * np.pi * 330 * t) + 0.2 * np.sin(2 * np.pi * 660 * t)
    signal = np.clip(signal + rng.normal(0, 1e-3, signal.size), -1, 1)
    samples = (signal * 30000).astype(np.int16)
    samples[: samples.size // 3] = 0  # a genuinely silent introduction

    count = int(samples.size * embed_rate)
    if count:
        samples[:count] = (samples[:count] & ~1) | rng.integers(
            0, 2, count, dtype=np.int16
        )
    return _write_wav(samples, rate)
