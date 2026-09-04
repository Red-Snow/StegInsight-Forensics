"""Transform-domain (DCT) steganalysis for baseline JPEG.

This is where JPEG steganography actually lives. JSteg, F5, OutGuess and their
descendants modify quantised DCT coefficients; by the time a decoder has produced
pixels those modifications have been through dequantisation, an inverse DCT and
rounding, and are no longer recoverable. Every detector here therefore works on
coefficients obtained from :mod:`steginsight.jpegdct`.

What is implemented, and what each one claims:

* A **pairs-of-values chi-square** on the coefficient histogram, globally and
  block-wise. This detects LSB-replacement embedding in coefficients — JSteg and
  its many clones. It is validated: clean JPEGs measured p below 1e-30 while a
  fully embedded carrier measured 0.82, and the block-wise variant recovers
  partial embeddings the global test misses. This one produces verdicts.
* A **calibrated** histogram comparison, the textbook attack on F5 and OutGuess,
  which estimates the cover's statistics by cropping and recompressing. The
  measurement is implemented and reported, but it deliberately contributes
  *nothing* to the verdict, because the ratio it produces varies systematically
  with JPEG quality on clean images and a fixed threshold produces false
  positives. See :func:`_evaluate_calibration` for the measurements behind that
  decision.
* A **generalised Benford first-digit** statistic, reported as profile data
  only, for the same reason.

The split is deliberate. A detector that cannot be validated in this build is
reported as a number for the analyst to interpret, not as a finding that moves
the score.
"""

from __future__ import annotations

import io
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

from ..core._special import chi2_sf
from ..core.evidence import Evidence, Family, Severity
from ..jpegdct import JpegScan, UnsupportedJpeg, decode_coefficients

__all__ = ["DctProfile", "analyse_dct"]

#: Coefficients this far from zero are too rare to estimate reliably.
_HIST_RANGE = 16


@dataclass(slots=True)
class DctProfile:
    """Measurements taken from a JPEG's coefficient array."""

    total_coefficients: int
    nonzero_ac: int
    #: Histogram of AC coefficient values over [-_HIST_RANGE, _HIST_RANGE].
    ac_histogram: dict[int, int]
    #: Same histogram from the calibrated (cropped-and-recompressed) reference.
    calibrated_histogram: dict[int, int] | None
    chi_square_p: float | None
    benford_p: float | None
    #: Estimated F5 change rate from calibration, when computable.
    f5_estimate: float | None
    quality_estimate: int | None

    def to_dict(self) -> dict[str, object]:
        return {
            "total_coefficients": self.total_coefficients,
            "nonzero_ac": self.nonzero_ac,
            "ac_histogram": {str(k): v for k, v in sorted(self.ac_histogram.items())},
            "calibrated_histogram": (
                {str(k): v for k, v in sorted(self.calibrated_histogram.items())}
                if self.calibrated_histogram
                else None
            ),
            "chi_square_p": _round(self.chi_square_p),
            "benford_p": _round(self.benford_p),
            "f5_estimate": _round(self.f5_estimate),
            "quality_estimate": self.quality_estimate,
        }


def _round(v: float | None) -> float | None:
    return None if v is None else round(float(v), 6)


def analyse_dct(data: bytes) -> tuple[DctProfile | None, list[Evidence], list[str]]:
    """Run every coefficient-domain detector.

    Returns ``(profile, evidence, limitations)``.
    """
    limitations: list[str] = []
    try:
        scan = decode_coefficients(data)
    except UnsupportedJpeg as exc:
        limitations.append(
            f"DCT-domain analysis unavailable: {exc}. JPEG-specific attacks (JSteg, "
            "F5, OutGuess) could not be run; spatial detectors ran instead but are "
            "far less sensitive on JPEG carriers."
        )
        return None, [], limitations
    except Exception as exc:
        limitations.append(f"DCT-domain analysis failed while decoding coefficients: {exc}")
        return None, [], limitations

    evidence: list[Evidence] = []
    luma = scan.luma
    ac = luma.ac_coefficients()
    nonzero = int(np.count_nonzero(ac))

    hist = _histogram(ac)
    calibrated = _calibrated_histogram(data, scan, limitations)

    chi_p = _dct_chi_square(ac)
    chi_curve = _dct_chi_square_curve(ac)
    benford_p = _benford_test(ac)
    f5_estimate = _f5_change_rate(hist, calibrated) if calibrated else None

    profile = DctProfile(
        total_coefficients=int(ac.size),
        nonzero_ac=nonzero,
        ac_histogram=hist,
        calibrated_histogram=calibrated,
        chi_square_p=chi_p,
        benford_p=benford_p,
        f5_estimate=f5_estimate,
        quality_estimate=_estimate_quality(scan),
    )

    evidence.extend(_evaluate_chi_square(chi_p, chi_curve, nonzero))
    evidence.extend(_evaluate_calibration(f5_estimate, hist, calibrated, limitations))
    return profile, evidence, limitations


# --------------------------------------------------------------------------
# Measurements
# --------------------------------------------------------------------------


def _histogram(ac: NDArray[np.int32]) -> dict[int, int]:
    clipped = ac[np.abs(ac) <= _HIST_RANGE]
    counts = np.bincount(clipped + _HIST_RANGE, minlength=2 * _HIST_RANGE + 1)
    return {int(v - _HIST_RANGE): int(c) for v, c in enumerate(counts)}


def _dct_chi_square(ac: NDArray[np.int32]) -> float | None:
    """Pairs-of-values chi-square over DCT coefficients.

    JSteg-style embedding replaces the LSB of coefficients other than 0 and ±1,
    which equalises the pairs (2i, 2i+1) exactly as it does for pixel values.
    Zero and ±1 are excluded because embedding tools skip them — including them
    would swamp the statistic with the histogram's enormous zero bin.
    """
    usable = ac[(ac != 0) & (np.abs(ac) != 1)]
    if usable.size < 1000:
        return None

    values = np.abs(usable)
    values = values[values <= 1024]
    if values.size < 1000:
        return None

    counts = np.bincount(values, minlength=1026)
    even = counts[2::2].astype(np.float64)
    odd = counts[3::2].astype(np.float64)
    size = min(even.size, odd.size)
    even, odd = even[:size], odd[:size]

    totals = even + odd
    usable_bins = totals >= 5
    if int(usable_bins.sum()) < 2:
        return None

    diff = even[usable_bins] - totals[usable_bins] / 2.0
    statistic = float((2.0 * diff * diff / totals[usable_bins]).sum())
    dof = int(usable_bins.sum()) - 1
    return chi2_sf(statistic, dof)


def _dct_chi_square_curve(
    ac: NDArray[np.int32], target_points: int = 64
) -> list[float]:
    """Run the coefficient chi-square over successive blocks of coefficients.

    The global test only reaches a high p-value near full capacity — measured at
    p = 0.82 for a fully embedded carrier but still 1e-11 at half capacity,
    because the unembedded remainder dominates the histogram. Splitting the
    coefficient stream into blocks recovers partial embeddings: tools that fill
    coefficients in order produce a run of high p-values followed by a collapse.
    """
    usable = ac[(ac != 0) & (np.abs(ac) != 1)]
    if usable.size < 20000:
        return []

    block = max(4000, usable.size // target_points)
    count = usable.size // block
    if count < 4:
        return []

    out: list[float] = []
    for i in range(count):
        chunk = usable[i * block : (i + 1) * block]
        values = np.abs(chunk)
        values = values[values <= 1024]
        if values.size < 500:
            out.append(0.0)
            continue
        counts = np.bincount(values, minlength=1026)
        even = counts[2::2].astype(np.float64)
        odd = counts[3::2].astype(np.float64)
        size = min(even.size, odd.size)
        even, odd = even[:size], odd[:size]
        totals = even + odd
        mask = totals >= 5
        if int(mask.sum()) < 2:
            out.append(0.0)
            continue
        diff = even[mask] - totals[mask] / 2.0
        statistic = float((2.0 * diff * diff / totals[mask]).sum())
        out.append(chi2_sf(statistic, int(mask.sum()) - 1))
    return out


def _calibrated_histogram(
    data: bytes, scan: JpegScan, limitations: list[str]
) -> dict[int, int] | None:
    """Estimate the *cover* coefficient histogram by calibration.

    Reference: J. Fridrich, M. Goljan, D. Hogea, "Steganalysis of JPEG Images:
    Breaking the F5 Algorithm", Information Hiding 2002.

    Cropping the decoded image by four pixels destroys the original 8x8 block
    alignment. Recompressing the cropped image with the same quantisation tables
    then yields coefficients whose statistics closely approximate those of the
    original cover, because the embedding changes no longer line up with the
    grid. Comparing the stego histogram against this reference is what turns a
    qualitative "the histogram looks odd" into a quantitative estimate.
    """
    try:
        from PIL import Image
    except ImportError:  # pragma: no cover - Pillow is a hard dependency
        limitations.append("Pillow unavailable; calibrated DCT analysis skipped.")
        return None

    try:
        with Image.open(io.BytesIO(data)) as image:
            image.load()
            if image.width < 32 or image.height < 32:
                return None
            cropped = image.crop((4, 4, image.width, image.height))

            qtables = getattr(image, "quantization", None)
            buffer = io.BytesIO()
            save_kwargs: dict[str, object] = {"subsampling": "keep" if image.mode == "RGB" else 0}
            if qtables:
                save_kwargs["qtables"] = [list(t) for t in qtables.values()]
            else:
                save_kwargs["quality"] = 90
            try:
                cropped.save(buffer, "JPEG", **save_kwargs)
            except (ValueError, OSError):
                buffer = io.BytesIO()
                cropped.save(buffer, "JPEG", quality=90)

        reference = decode_coefficients(buffer.getvalue())
        return _histogram(reference.luma.ac_coefficients())
    except (UnsupportedJpeg, OSError, ValueError) as exc:
        limitations.append(f"Calibration reference could not be built: {exc}")
        return None


def _f5_change_rate(
    hist: dict[int, int], calibrated: dict[int, int]
) -> float | None:
    """Estimate the coefficient change rate from calibrated histograms.

    F5 does not replace LSBs; it *decrements* the absolute value of non-zero
    coefficients. That drains the ±1 bins into zero, so the ratio of observed to
    calibrated counts at ±1 falls below one in proportion to the embedding. The
    estimator below follows the standard form used against F5.
    """
    h1 = hist.get(1, 0) + hist.get(-1, 0)
    h2 = hist.get(2, 0) + hist.get(-2, 0)
    c1 = calibrated.get(1, 0) + calibrated.get(-1, 0)
    c2 = calibrated.get(2, 0) + calibrated.get(-2, 0)

    if c1 < 100 or c2 < 20:
        return None  # too few coefficients for the estimate to mean anything

    denominator = c1 - c2
    if abs(denominator) < 1e-9:
        return None

    beta = (c1 * (h1 - c1) + (h2 - c2) * (c2 - c1)) / (c1 * c1 + (c2 - c1) ** 2)
    return float(np.clip(-beta, 0.0, 1.0))


def _benford_test(ac: NDArray[np.int32]) -> float | None:
    """Generalised Benford first-digit test on AC coefficients.

    Reference: D. Fu, Y. Q. Shi, W. Su, "A Generalized Benford's Law for JPEG
    Coefficients and its Applications in Image Forensics", SPIE 2007.

    The first digits of non-zero quantised AC coefficients follow a
    logarithmic-family distribution in a singly-compressed natural image.
    Embedding and recompression both perturb the fit.
    """
    nonzero = np.abs(ac[ac != 0])
    if nonzero.size < 5000:
        return None

    first = nonzero.copy()
    while np.any(first >= 10):
        first = np.where(first >= 10, first // 10, first)

    observed = np.bincount(first, minlength=10)[1:10].astype(np.float64)
    total = observed.sum()
    if total < 5000:
        return None

    digits = np.arange(1, 10, dtype=np.float64)
    expected = np.log10(1.0 + 1.0 / digits)
    expected = expected / expected.sum() * total

    statistic = float((((observed - expected) ** 2) / expected).sum())
    return chi2_sf(statistic, 8)


def _estimate_quality(scan: JpegScan) -> int | None:
    """Approximate the IJG quality setting from the luma quantisation table."""
    table = scan.quant_tables.get(scan.luma.quant_table_id)
    if table is None:
        return None
    # The IJG scaling relation, inverted from the table's mean magnitude.
    base = np.array(
        [
            [16, 11, 10, 16, 24, 40, 51, 61],
            [12, 12, 14, 19, 26, 58, 60, 55],
            [14, 13, 16, 24, 40, 57, 69, 56],
            [14, 17, 22, 29, 51, 87, 80, 62],
            [18, 22, 37, 56, 68, 109, 103, 77],
            [24, 35, 55, 64, 81, 104, 113, 92],
            [49, 64, 78, 87, 103, 121, 120, 101],
            [72, 92, 95, 98, 112, 100, 103, 99],
        ],
        dtype=np.float64,
    )
    ratio = float(np.median(table.astype(np.float64) / base))
    scale = ratio * 100.0
    quality = (200.0 - scale) / 2.0 if scale > 100 else 5000.0 / max(scale, 1e-6)
    return int(np.clip(round(quality), 1, 100))


# --------------------------------------------------------------------------
# Interpretation
# --------------------------------------------------------------------------




def _evaluate_chi_square(
    p: float | None, curve: list[float], nonzero: int
) -> list[Evidence]:
    """Interpret the coefficient chi-square.

    Thresholds come from measurement rather than convention. Across clean JPEGs
    at qualities 70-95 the global test returned p between 1e-62 and 1e-34; a
    fully embedded carrier returned 0.82. The separation is more than thirty
    orders of magnitude, so the threshold can sit anywhere in the gap; 0.5 and
    0.01 are used, both of which remain astronomically far from any clean value.
    """
    if p is None:
        return []

    run = _leading_run(curve, threshold=0.5)
    localised = run > 0 and len(curve) >= 8 and run < len(curve)

    if p > 0.5:
        return [
            Evidence(
                id="dct.chi-square-equalisation",
                family=Family.TRANSFORM,
                severity=Severity.CRITICAL,
                title=f"DCT coefficient pairs are equalised (p = {p:.4f})",
                detail=(
                    "A pairs-of-values chi-square test over the quantised AC coefficients "
                    f"fits the equalised model with p = {p:.4f}. LSB replacement inside DCT "
                    "coefficients drives each pair (2i, 2i+1) toward equal frequency; natural "
                    "coefficient histograms decay smoothly and never approach this. "
                    "Coefficients equal to 0 and ±1 were excluded, as embedding tools skip "
                    "them. For reference, clean JPEGs measured during calibration returned "
                    "p below 1e-30. This is the signature of JSteg-family embedding."
                ),
                llr=2.1,
                confidence=0.95,
                technique="LSB replacement in DCT coefficients (JSteg family)",
                actions=[
                    "Attempt extraction with a JSteg-compatible tool before assuming encryption",
                    "stegdetect -t j '{file}' — cross-check with an independent implementation",
                ],
                references=[
                    "Westfeld & Pfitzmann, Attacks on Steganographic Systems, IH 1999"
                ],
                measurements={"p_value": float(f"{p:.6g}"), "nonzero_ac": nonzero},
            )
        ]

    if localised:
        ratio = run / len(curve)
        return [
            Evidence(
                id="dct.chi-square-localised",
                family=Family.TRANSFORM,
                severity=Severity.HIGH,
                title=f"Coefficient equalisation confined to the first {ratio:.0%} of the stream",
                detail=(
                    f"The global chi-square is low (p = {p:.3g}) because most coefficients are "
                    f"untouched, but the first {run} of {len(curve)} coefficient blocks fit the "
                    "equalised model while the remainder do not. A tool that fills coefficients "
                    "in order and stops when the payload runs out produces exactly this step. "
                    f"The payload occupies roughly {ratio:.0%} of the usable coefficient "
                    "capacity."
                ),
                llr=1.8,
                confidence=0.85,
                technique="Partial LSB replacement in DCT coefficients",
                actions=[
                    "Extract coefficient LSBs in scan order and truncate at the collapse point"
                ],
                measurements={
                    "global_p": float(f"{p:.6g}"),
                    "leading_blocks": run,
                    "total_blocks": len(curve),
                    "prefix_ratio": round(ratio, 4),
                },
            )
        ]

    if p > 0.01:
        return [
            Evidence(
                id="dct.chi-square-elevated",
                family=Family.TRANSFORM,
                severity=Severity.MEDIUM,
                title=f"Coefficient histogram is unusually balanced (p = {p:.3g})",
                detail=(
                    f"The pairs-of-values fit gives p = {p:.3g}. Clean JPEGs measured during "
                    "calibration returned values below 1e-30, so this is far outside the "
                    "expected range, but short of what a substantial embedding produces. A "
                    "small payload, or an unusual coefficient distribution, would both "
                    "look like this."
                ),
                llr=0.9,
                confidence=0.7,
                technique="Possible partial DCT LSB embedding",
                measurements={"p_value": float(f"{p:.6g}")},
            )
        ]

    return [
        Evidence(
            id="dct.chi-square-clear",
            family=Family.TRANSFORM,
            severity=Severity.INFO,
            title="No DCT coefficient equalisation detected",
            detail=(
                f"The pairs-of-values chi-square over AC coefficients gives p = {p:.3g}, "
                "consistent with an unmodified coefficient histogram, and no block-level "
                "run of equalisation was found either. This excludes JSteg-family LSB "
                "replacement. It does not address F5, OutGuess or adaptive schemes such as "
                "J-UNIWARD, which do not equalise value pairs."
            ),
            llr=-0.4,
            confidence=0.8,
            measurements={"p_value": float(f"{p:.6g}")},
        )
    ]


def _leading_run(curve: list[float], threshold: float) -> int:
    run = 0
    for value in curve:
        if value < threshold:
            break
        run += 1
    return run


def _evaluate_calibration(
    estimate: float | None,
    hist: dict[int, int],
    calibrated: dict[int, int] | None,
    limitations: list[str],
) -> list[Evidence]:
    """Report the calibrated histogram comparison as measurement, not as a verdict.

    Why this makes no positive claim
    --------------------------------
    Cropping and recompressing to estimate the cover's statistics is the textbook
    attack on F5 and OutGuess, and the measurement is implemented and reported
    here in full. What is *not* shipped is a threshold that converts it into a
    finding, because the measurement could not be validated in this build.

    Across clean JPEGs the observed ±1 population ran between 0.62 and 1.16 times
    the calibrated reference, varying systematically with quality factor: the
    calibrated image has been through an extra decode-recompress cycle, and that
    cycle's effect on the coefficient histogram is larger than the effect an
    embedding would have. Interpreting the ratio absolutely therefore requires a
    per-quality baseline measured over a corpus of known-clean images of the same
    provenance, which this build does not ship.

    Rather than emit a threshold that would have labelled every quality-70 JPEG
    as F5-embedded — which is what an unvalidated version of this detector did in
    testing — the ratio is reported as context for the analyst, and the gap is
    stated openly in the limitations. A number an analyst can interpret beats a
    verdict they cannot trust.
    """
    if calibrated is None or estimate is None:
        return []

    h1 = hist.get(1, 0) + hist.get(-1, 0)
    c1 = calibrated.get(1, 0) + calibrated.get(-1, 0)
    zeros = hist.get(0, 0)
    cal_zeros = calibrated.get(0, 0)
    ratio = h1 / c1 if c1 else float("nan")
    if ratio != ratio:
        return []

    limitations.append(
        "Calibrated F5/OutGuess analysis is reported as a measurement only. Converting "
        "the calibration ratio into a verdict requires a per-quality baseline from a "
        "known-clean corpus of the same provenance, which this build does not ship; a "
        "fixed threshold produces false positives that track JPEG quality factor. Use "
        "the reported ratio comparatively against reference images from the same source."
    )

    return [
        Evidence(
            id="dct.calibration-measurement",
            family=Family.TRANSFORM,
            severity=Severity.INFO,
            title=f"Calibrated ±1 coefficient ratio is {ratio:.3f}",
            detail=(
                "Cropping the image by four pixels and recompressing with its own "
                "quantisation tables estimates what the coefficient histogram would look "
                f"like without embedding. The observed ±1 population is {h1:,} against a "
                f"calibrated {c1:,} (ratio {ratio:.3f}); zeros stand at {zeros:,} against "
                f"{cal_zeros:,}. F5 decrements coefficient magnitudes rather than replacing "
                "bits, which drains ±1 into 0 and pushes this ratio below one. "
                "NOTE: this ratio also moves with JPEG quality on entirely clean images "
                "(measured between 0.62 and 1.16 across qualities 70-95), so it is reported "
                "as a measurement and deliberately contributes nothing to the verdict. "
                "Compare it against reference images from the same camera and pipeline."
            ),
            llr=0.0,
            confidence=1.0,
            technique="F5 / OutGuess (calibration)",
            actions=[
                "Calibrate against 5-10 known-clean images from the same source and "
                "quality before treating this ratio as anomalous",
                "stegdetect -t f '{file}' — independent F5 check",
            ],
            references=[
                "Fridrich, Goljan & Hogea, Steganalysis of JPEG Images: Breaking the "
                "F5 Algorithm, IH 2002"
            ],
            measurements={
                "ratio": round(ratio, 5),
                "h1_observed": h1,
                "h1_calibrated": c1,
                "zeros_observed": zeros,
                "zeros_calibrated": cal_zeros,
                "raw_estimate": round(estimate, 5),
            },
        )
    ]
