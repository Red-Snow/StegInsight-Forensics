"""Statistical primitives.

Every function here operates on *decoded samples* (pixel channel values, PCM
samples) unless its name says otherwise. Running a steganalysis statistic over
compressed container bytes measures the entropy coder, not the carrier — that
was the central error in the previous engine.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

from ._special import chi2_sf

__all__ = [
    "ChiSquareResult",
    "bit_plane_entropy",
    "bit_plane_transition_rate",
    "byte_histogram",
    "chi_square_curve",
    "chi_square_pov",
    "embedded_prefix_ratio",
    "expected_random_entropy",
    "is_effectively_random",
    "printable_ratio",
    "shannon_entropy",
    "sliding_entropy",
]


# --------------------------------------------------------------------------
# Entropy
# --------------------------------------------------------------------------


def byte_histogram(data: bytes | NDArray[np.uint8]) -> NDArray[np.int64]:
    arr = np.frombuffer(data, dtype=np.uint8) if isinstance(data, (bytes, bytearray)) else data
    return np.bincount(arr.ravel(), minlength=256).astype(np.int64)


def shannon_entropy(data: bytes | NDArray[np.uint8]) -> float:
    """Shannon entropy in bits per byte, 0..8."""
    counts = byte_histogram(data)
    total = int(counts.sum())
    if total == 0:
        return 0.0
    p = counts[counts > 0] / total
    return float(-(p * np.log2(p)).sum())


def expected_random_entropy(n: int) -> float:
    """Expected entropy of ``n`` bytes drawn uniformly at random.

    This matters. With a small sample you cannot reach 8.0 even from a perfect
    random source, because symbols you never draw cost you. The previous engine
    compared a 10,000-byte tail against a fixed 7.95 threshold — a bar that
    uniform random data clears only marginally — and so reported "encrypted
    payload" on ordinary compressed content. Detectors compare against *this*,
    not against 8.
    """
    if n <= 1:
        return 0.0
    # Expected number of distinct byte values actually observed in n draws.
    k = 256.0 * (1.0 - (1.0 - 1.0 / 256.0) ** n)
    # Miller-Madow bias correction for the plug-in entropy estimator.
    return float(8.0 - (k - 1.0) / (2.0 * n * np.log(2.0)))


def is_effectively_random(entropy: float, n: int, tolerance: float = 0.02) -> bool:
    """True when a block is statistically indistinguishable from uniform random.

    That is the signature of encrypted *or already-compressed* data. The two are
    not distinguishable by entropy alone, which is why a high-entropy finding on
    its own is never enough to reach a verdict here.
    """
    return entropy >= expected_random_entropy(n) - tolerance


def sliding_entropy(
    data: bytes, max_windows: int = 1024, min_window: int = 512
) -> tuple[NDArray[np.int64], NDArray[np.float64], int]:
    """Localised entropy curve, bounded to ``max_windows`` points.

    Window size adapts to input length so the output stays renderable regardless
    of file size. The previous engine used a fixed 1 KiB window with a 512-byte
    step, emitting ~200,000 points for a 100 MB carrier.

    Returns ``(offsets, entropies, window_size)``.
    """
    n = len(data)
    if n == 0:
        return np.empty(0, dtype=np.int64), np.empty(0, dtype=np.float64), 0

    window = max(min_window, -(-n // max_windows))
    window = min(window, n)

    arr = np.frombuffer(data, dtype=np.uint8)
    count = n // window
    if count == 0:
        return (
            np.array([0], dtype=np.int64),
            np.array([shannon_entropy(arr)], dtype=np.float64),
            window,
        )

    trimmed = arr[: count * window].reshape(count, window)

    # Vectorised per-row histogram: offset each row into its own bin range.
    offsets = (np.arange(count, dtype=np.int64) * 256)[:, None]
    flat = (trimmed.astype(np.int64) + offsets).ravel()
    counts = np.bincount(flat, minlength=count * 256).reshape(count, 256)

    p = counts / window
    logs = np.zeros_like(p)
    np.log2(p, out=logs, where=p > 0)
    entropies = -(p * logs).sum(axis=1)

    return (np.arange(count, dtype=np.int64) * window, entropies.astype(np.float64), window)


def printable_ratio(data: bytes, sample_limit: int = 1 << 20) -> float:
    if not data:
        return 0.0
    arr = np.frombuffer(data[:sample_limit], dtype=np.uint8)
    printable = ((arr >= 0x20) & (arr <= 0x7E)) | np.isin(arr, (0x09, 0x0A, 0x0D))
    return float(printable.mean())


# --------------------------------------------------------------------------
# Westfeld-Pfitzmann chi-square attack on pairs of values
# --------------------------------------------------------------------------

#: Pairs with fewer than this many samples are pooled out; they destabilise chi².
MIN_BIN_COUNT = 5


@dataclass(slots=True)
class ChiSquareResult:
    statistic: float
    degrees_of_freedom: int
    #: Goodness of fit to the *equalised* model. Values approaching 1.0 indicate
    #: LSB-replacement embedding. This polarity is the opposite of an ordinary
    #: goodness-of-fit test and is a common source of implementation error.
    p_value: float
    usable_bins: int

    def to_dict(self) -> dict[str, float | int]:
        return {
            "statistic": round(self.statistic, 4),
            "degrees_of_freedom": self.degrees_of_freedom,
            "p_value": round(self.p_value, 6),
            "usable_bins": self.usable_bins,
        }


def _chi_square_from_histogram(counts: NDArray[np.int64]) -> ChiSquareResult | None:
    even = counts[0::2].astype(np.float64)
    odd = counts[1::2].astype(np.float64)
    totals = even + odd

    usable = totals >= MIN_BIN_COUNT
    if int(usable.sum()) < 2:
        return None

    diff = even[usable] - totals[usable] / 2.0
    # Only one independent cell per pair; the partner cell contributes the same
    # squared deviation, hence the factor of two.
    statistic = float((2.0 * diff * diff / totals[usable]).sum())
    dof = int(usable.sum()) - 1
    return ChiSquareResult(
        statistic=statistic,
        degrees_of_freedom=dof,
        p_value=chi2_sf(statistic, dof),
        usable_bins=int(usable.sum()),
    )


def chi_square_pov(samples: NDArray[np.uint8]) -> ChiSquareResult | None:
    """Westfeld-Pfitzmann chi-square attack on pairs of values.

    Reference: A. Westfeld, A. Pfitzmann, "Attacks on Steganographic Systems",
    Information Hiding 1999, LNCS 1768, pp. 61-76.

    LSB *replacement* maps each sample value into its pair partner (2i <-> 2i+1)
    with probability 1/2. Over an embedded region the two members of every pair
    converge to the same frequency — an equalisation that essentially never
    occurs naturally. The test measures how well the observed histogram fits the
    hypothesis "every pair is equalised".
    """
    flat = np.asarray(samples).ravel()
    if flat.size < 256:
        return None
    return _chi_square_from_histogram(np.bincount(flat, minlength=256).astype(np.int64))


def chi_square_curve(
    samples: NDArray[np.uint8], target_points: int = 128
) -> tuple[NDArray[np.int64], NDArray[np.float64]]:
    """Run the attack over successive blocks.

    Sequentially embedded payloads fill the carrier from the start and stop,
    producing a curve that sits near p=1 and then collapses. That shape is far
    more diagnostic than any single global statistic, and it localises the
    payload for the analyst.
    """
    flat = np.asarray(samples).ravel()
    if flat.size < 4096:
        return np.empty(0, dtype=np.int64), np.empty(0, dtype=np.float64)

    block = max(2048, -(-flat.size // target_points))
    count = flat.size // block
    offsets = np.arange(count, dtype=np.int64) * block
    p_values = np.zeros(count, dtype=np.float64)

    for i in range(count):
        chunk = flat[i * block : (i + 1) * block]
        result = _chi_square_from_histogram(np.bincount(chunk, minlength=256).astype(np.int64))
        p_values[i] = result.p_value if result else 0.0

    return offsets, p_values


def embedded_prefix_ratio(
    p_values: NDArray[np.float64],
    threshold: float = 0.95,
    min_prefix_density: float = 0.8,
    max_suffix_density: float = 0.2,
) -> float:
    """Locate a step from "embedded" to "clean" and return where it falls.

    A sequentially embedded carrier gives a leading region of high p-values that
    then collapses. The obvious implementation — count the leading *consecutive*
    run — is far too brittle: measured on a half-embedded image, 59 of the 64
    embedded blocks exceeded the threshold, but a single dip at block 7 truncated
    the run to 5% and hid a 50% embedding entirely.

    So instead this finds the split point that best separates a dense region of
    high p-values from a sparse one, tolerating scattered outliers on both sides.
    Returns 0.0 when no such step exists, which is the clean case.
    """
    n = int(p_values.size)
    if n < 4:
        return 0.0

    high = (p_values >= threshold).astype(np.float64)
    cumulative = np.concatenate([[0.0], np.cumsum(high)])
    total = cumulative[-1]

    best_split = 0
    best_score = 0.0
    for split in range(1, n):
        prefix_density = cumulative[split] / split
        suffix_density = (total - cumulative[split]) / (n - split)
        if prefix_density < min_prefix_density or suffix_density > max_suffix_density:
            continue
        # Prefer the split that separates most cleanly, then the longest prefix.
        score = (prefix_density - suffix_density) + split / (2.0 * n)
        if score > best_score:
            best_score = score
            best_split = split

    return best_split / float(n)


# --------------------------------------------------------------------------
# Bit planes
# --------------------------------------------------------------------------


def bit_plane_entropy(samples: NDArray[np.uint8], plane: int) -> float:
    """Entropy in bits of a single bit plane, 0..1."""
    flat = np.asarray(samples).ravel()
    if flat.size == 0:
        return 0.0
    p = float(((flat >> plane) & 1).mean())
    if p in (0.0, 1.0):
        return 0.0
    return float(-(p * np.log2(p) + (1 - p) * np.log2(1 - p)))


def bit_plane_transition_rate(plane_bits: NDArray[np.uint8]) -> float:
    """Fraction of horizontally adjacent bits that differ, for a 2-D bit plane.

    Natural content sits well below 0.5 in the low planes because neighbouring
    pixels are correlated. Independent payload bits drive it to 0.5. This is the
    discriminator that separates "noisy because it is a photo of gravel" from
    "noisy because it is ciphertext" — an absolute entropy threshold cannot.
    """
    if plane_bits.ndim != 2 or plane_bits.shape[1] < 2:
        return float("nan")
    return float((plane_bits[:, :-1] != plane_bits[:, 1:]).mean())
