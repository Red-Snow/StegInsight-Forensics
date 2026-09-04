"""Embedding-rate estimators for LSB replacement.

These answer a more useful question than "is something hidden here?". They
estimate *how much* is hidden, which tells the analyst whether the signal sits
above the method's noise floor (roughly 3-5% for natural imagery) and how large
a payload to expect.

Two independent methods are implemented. They rest on different assumptions, so
agreement between them is genuine corroboration rather than one measurement
counted twice.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import numpy as np
from numpy.typing import NDArray

__all__ = ["EmbeddingEstimate", "rs_analysis", "sample_pair_analysis"]

#: Deterministic seed, so repeated analyses of one exhibit agree exactly.
#: Non-reproducible output is not acceptable in an evidentiary context.
_SEED = 0x5EED


@dataclass(slots=True)
class EmbeddingEstimate:
    rate: float
    method: Literal["rs", "spa"]
    unreliable: bool = False
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "method": self.method,
            "rate": round(self.rate, 5),
            "unreliable": self.unreliable,
            "note": self.note,
        }


def _smallest_root(a: float, b: float, c: float) -> float | None:
    """Root of ax² + bx + c closest to zero, or None if there is no real root."""
    if abs(a) < 1e-12:
        if abs(b) < 1e-12:
            return None
        return -c / b
    disc = b * b - 4 * a * c
    if disc < 0:
        return None
    sq = float(np.sqrt(disc))
    r1 = (-b + sq) / (2 * a)
    r2 = (-b - sq) / (2 * a)
    return r1 if abs(r1) <= abs(r2) else r2


# --------------------------------------------------------------------------
# RS analysis
# --------------------------------------------------------------------------

_MASK = np.array([0, 1, 1, 0], dtype=bool)
_GROUP = 4


def _flip_f1(v: NDArray[np.int16]) -> NDArray[np.int16]:
    """F1: 0<->1, 2<->3, ..."""
    return v ^ 1


def _flip_f_minus1(v: NDArray[np.int16]) -> NDArray[np.int16]:
    """F-1: -1<->0, 1<->2, 3<->4, ..."""
    return ((v + 1) ^ 1) - 1


def _discriminant(groups: NDArray[np.int16]) -> NDArray[np.int64]:
    """Total absolute variation within each group of pixels."""
    result: NDArray[np.int64] = np.abs(np.diff(groups.astype(np.int32), axis=-1)).sum(axis=-1)
    return result


def _rs_counts(groups: NDArray[np.int16], negate: bool) -> tuple[int, int, int]:
    before = _discriminant(groups)

    flipped = groups.copy()
    target = flipped[:, _MASK]
    flipped[:, _MASK] = _flip_f_minus1(target) if negate else _flip_f1(target)
    after = _discriminant(flipped)

    regular = int(np.count_nonzero(after > before))
    singular = int(np.count_nonzero(after < before))
    return regular, singular, groups.shape[0]


def rs_analysis(plane: NDArray[np.uint8]) -> EmbeddingEstimate | None:
    """RS (Regular / Singular) steganalysis.

    Reference: J. Fridrich, M. Goljan, R. Du, "Reliable Detection of LSB
    Steganography in Color and Grayscale Images", ACM Workshop on Multimedia and
    Security, 2001.

    The method scores fixed groups of adjacent pixels with a smoothness
    discriminant and observes how that score moves when LSBs are flipped in one
    direction versus the other. Clean images behave asymmetrically under the two
    directions; LSB replacement drives them toward each other in a quantitatively
    predictable way, yielding the embedding rate.

    ``plane`` must be a 2-D array of one colour channel.
    """
    if plane.ndim != 2 or plane.shape[1] < _GROUP:
        return None

    width = plane.shape[1]
    usable = width - (width % _GROUP)
    groups = plane[:, :usable].reshape(-1, _GROUP).astype(np.int16)
    if groups.shape[0] < 256:
        return None

    rng = np.random.default_rng(_SEED)
    randomised = (groups & ~1) | rng.integers(0, 2, size=groups.shape, dtype=np.int16)

    rm0, sm0, total = _rs_counts(groups, negate=False)
    rn0, sn0, _ = _rs_counts(groups, negate=True)
    rm1, sm1, _ = _rs_counts(randomised, negate=False)
    rn1, sn1, _ = _rs_counts(randomised, negate=True)

    total = total or 1
    d0 = (rm0 - sm0) / total
    dn0 = (rn0 - sn0) / total
    d1 = (rm1 - sm1) / total
    dn1 = (rn1 - sn1) / total

    # 2(d1 + d0)x² + (dn0 − dn1 − d1 − 3·d0)x + (d0 − dn0) = 0
    root = _smallest_root(2 * (d1 + d0), dn0 - dn1 - d1 - 3 * d0, d0 - dn0)
    if root is None or root == 0.5:
        return EmbeddingEstimate(0.0, "rs", unreliable=True, note="no usable real root")

    rate = root / (root - 0.5)
    if not np.isfinite(rate):
        return EmbeddingEstimate(0.0, "rs", unreliable=True, note="non-finite estimate")

    return EmbeddingEstimate(float(np.clip(rate, 0.0, 1.0)), "rs")


# --------------------------------------------------------------------------
# Sample Pair Analysis
# --------------------------------------------------------------------------


def sample_pair_analysis(samples: NDArray[np.uint8], stride: int = 1) -> EmbeddingEstimate | None:
    """Sample Pair Analysis (SPA).

    Reference: S. Dumitrescu, X. Wu, Z. Wang, "Detection of LSB Steganography
    via Sample Pair Analysis", IEEE Trans. Signal Processing 51(7), 2003.

    Models LSB replacement as a finite-state machine over pairs of adjacent
    samples and solves a quadratic for the embedding rate.
    """
    flat = np.asarray(samples).ravel().astype(np.int32)
    if flat.size < 512 + stride:
        return None

    u = flat[:-stride]
    v = flat[stride:]
    pairs = int(u.size)
    if pairs == 0:
        return None

    v_even = (v & 1) == 0
    x = int(np.count_nonzero((v_even & (u < v)) | (~v_even & (u > v))))
    y = int(np.count_nonzero((v_even & (u > v)) | (~v_even & (u < v))))
    k = int(np.count_nonzero((v >> 1) == (u >> 1)))

    if k == 0:
        return EmbeddingEstimate(0.0, "spa", unreliable=True, note="degenerate pair statistics")

    beta = _smallest_root(0.5 * k, 2 * x - pairs, y - x)
    if beta is None or not np.isfinite(beta):
        return EmbeddingEstimate(0.0, "spa", unreliable=True, note="no usable real root")

    # beta estimates the fraction of samples whose LSB was *changed*. Embedding
    # a payload of length L changes ~L/2 samples, so the rate is twice beta.
    return EmbeddingEstimate(float(np.clip(beta * 2.0, 0.0, 1.0)), "spa")
