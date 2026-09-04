"""Spatial-domain steganalysis of raster images.

Applies to formats that store samples losslessly — PNG, BMP, TIFF, and the index
plane of palette images. These detectors are deliberately *not* trusted on JPEG:
lossy compression overwrites the low bit planes wholesale, so spatial LSB
analysis of a JPEG measures the quantiser, not the carrier. That case is routed
to :mod:`steginsight.detectors.transform` instead, and the limitation is stated
in the report rather than silently ignored.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field

import numpy as np
from numpy.typing import NDArray

from ..core.estimators import EmbeddingEstimate, rs_analysis, sample_pair_analysis
from ..core.evidence import Evidence, Family, Severity
from ..core.stats import (
    ChiSquareResult,
    bit_plane_entropy,
    bit_plane_transition_rate,
    chi_square_curve,
    chi_square_pov,
    embedded_prefix_ratio,
)

__all__ = ["SpatialProfile", "analyse_spatial", "load_planes"]

#: Formats whose samples survive round-tripping. Spatial analysis is valid here.
LOSSLESS_FORMATS = {"PNG", "BMP", "TIFF", "GIF", "PPM", "TGA", "WEBP"}

#: Below this many samples the estimators' variance swamps their signal.
MIN_SAMPLES = 4096

#: Natural imagery sits well below 0.5. Above this, the plane looks like noise.
TRANSITION_ALERT = 0.485

# Thresholds below were calibrated by measurement, not chosen by feel: synthetic
# covers with natural multi-octave statistics were embedded at known rates and
# both estimators recorded. On clean covers RS returned 0.000-0.009 and SPA
# 0.000; at a true 20% rate RS returned 0.145-0.157 and SPA 0.208-0.214. RS
# systematically under-reads by roughly a quarter and SPA slightly over-reads,
# so the bands are set on the *lower* of the two.

#: Both estimators must exceed this before any positive claim is made.
ESTIMATOR_FLOOR = 0.035

#: Both must exceed this, and agree, for a high-confidence finding.
ESTIMATOR_STRONG = 0.08

#: Curve must have at least this many blocks before a prefix ratio means anything.
MIN_CURVE_POINTS = 24

#: And the leading high run must be at least this many blocks.
MIN_CURVE_RUN = 4


@dataclass(slots=True)
class ChannelProfile:
    name: str
    chi_square: ChiSquareResult | None = None
    chi_curve_prefix: float = 0.0
    rs: EmbeddingEstimate | None = None
    spa: EmbeddingEstimate | None = None
    plane_entropies: list[float] = field(default_factory=list)
    transition_rates: list[float] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "channel": self.name,
            "chi_square": self.chi_square.to_dict() if self.chi_square else None,
            "chi_curve_prefix": round(self.chi_curve_prefix, 4),
            "rs": self.rs.to_dict() if self.rs else None,
            "spa": self.spa.to_dict() if self.spa else None,
            "plane_entropies": [round(v, 5) for v in self.plane_entropies],
            "transition_rates": [
                None if r != r else round(r, 5) for r in self.transition_rates
            ],
        }


@dataclass(slots=True)
class SpatialProfile:
    width: int
    height: int
    mode: str
    image_format: str
    channels: list[ChannelProfile] = field(default_factory=list)
    #: p-value curve of the strongest channel, for plotting.
    curve_offsets: list[int] = field(default_factory=list)
    curve_values: list[float] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "width": self.width,
            "height": self.height,
            "mode": self.mode,
            "format": self.image_format,
            "channels": [c.to_dict() for c in self.channels],
            "chi_curve": {
                "offsets": self.curve_offsets,
                "p_values": [round(v, 5) for v in self.curve_values],
            },
        }


def load_planes(data: bytes) -> tuple[dict[str, NDArray[np.uint8]], str, str, int, int] | None:
    """Decode an image into per-channel 2-D uint8 planes.

    Returns ``(planes, mode, format, width, height)`` or ``None`` if the bytes
    are not a decodable image.
    """
    try:
        from PIL import Image
    except ImportError:  # pragma: no cover
        return None

    try:
        with Image.open(io.BytesIO(data)) as image:
            image.load()
            fmt = image.format or "UNKNOWN"
            mode = image.mode

            if mode == "P":
                # For palette images the payload rides in the *indices*, not in
                # RGB values that do not physically exist in the file.
                indices = np.asarray(image, dtype=np.uint8)
                planes = {"index": indices}
                palette = image.getpalette()
                if palette:
                    pal = np.asarray(palette, dtype=np.uint8)
                    usable = (pal.size // 3) * 3
                    planes["palette"] = pal[:usable].reshape(-1, 3)[:, 0][None, :]
                return planes, mode, fmt, image.width, image.height

            if mode not in ("L", "LA", "RGB", "RGBA", "CMYK", "I;16", "I"):
                array = np.asarray(image.convert("RGB"))
                mode = "RGB"
            else:
                array = np.asarray(image)
            if array.dtype != np.uint8:
                return None
            if array.ndim == 2:
                return {"L": array}, mode, fmt, image.width, image.height

            names = list(mode)
            planes = {
                names[i] if i < len(names) else f"c{i}": np.ascontiguousarray(array[:, :, i])
                for i in range(array.shape[2])
            }
            return planes, mode, fmt, image.width, image.height
    except Exception:
        return None


def analyse_spatial(data: bytes) -> tuple[SpatialProfile | None, list[Evidence], list[str]]:
    limitations: list[str] = []
    loaded = load_planes(data)
    if loaded is None:
        return None, [], limitations

    planes, mode, fmt, width, height = loaded

    if fmt.upper() not in LOSSLESS_FORMATS:
        limitations.append(
            f"Spatial LSB analysis skipped: {fmt} is lossy, so its low bit planes are "
            "products of the quantiser rather than of the original samples. "
            "Coefficient-domain analysis was used instead."
        )
        return None, [], limitations

    profile = SpatialProfile(width=width, height=height, mode=mode, image_format=fmt)
    evidence: list[Evidence] = []

    # Alpha carries no visible signal and is frequently constant; analysing a
    # constant plane yields meaningless statistics.
    analysable = {
        name: plane
        for name, plane in planes.items()
        if plane.size >= MIN_SAMPLES and name != "palette" and int(np.ptp(plane)) > 0
    }
    if not analysable:
        limitations.append(
            "No image plane had enough variation for spatial statistics "
            f"(smallest usable size is {MIN_SAMPLES:,} samples)."
        )
        return profile, [], limitations

    best_channel: ChannelProfile | None = None
    best_score = -1.0

    for name, plane in analysable.items():
        channel = ChannelProfile(name=name)
        flat = plane.ravel()

        channel.chi_square = chi_square_pov(flat)
        offsets, p_values = chi_square_curve(flat)
        channel.chi_curve_prefix = embedded_prefix_ratio(p_values)
        channel.rs = rs_analysis(plane) if plane.ndim == 2 else None
        channel.spa = sample_pair_analysis(flat)
        channel.plane_entropies = [bit_plane_entropy(flat, b) for b in range(8)]
        channel.transition_rates = [
            bit_plane_transition_rate(((plane >> b) & 1).astype(np.uint8)) for b in range(8)
        ]
        profile.channels.append(channel)

        score = max(
            channel.rs.rate if channel.rs and not channel.rs.unreliable else 0.0,
            channel.spa.rate if channel.spa and not channel.spa.unreliable else 0.0,
        )
        if score > best_score:
            best_score = score
            best_channel = channel
            profile.curve_offsets = offsets.tolist()
            profile.curve_values = p_values.tolist()

    evidence.extend(_evaluate_estimators(profile.channels))
    evidence.extend(_evaluate_chi_square(profile.channels))
    evidence.extend(_evaluate_bit_planes(profile.channels))
    if best_channel is not None:
        evidence.extend(_evaluate_sequential(best_channel, profile.curve_values))

    if mode == "P":
        limitations.append(
            "Palette image: statistics were computed over palette *indices*. Index "
            "values are arbitrary labels, not intensities, so RS and SPA are less "
            "reliable here than on true-colour images."
        )

    return profile, evidence, limitations


# --------------------------------------------------------------------------
# Interpretation
# --------------------------------------------------------------------------


def _evaluate_estimators(channels: list[ChannelProfile]) -> list[Evidence]:
    pairs: list[tuple[str, float, float]] = []
    for c in channels:
        rs = c.rs.rate if c.rs and not c.rs.unreliable else None
        spa = c.spa.rate if c.spa and not c.spa.unreliable else None
        if rs is None or spa is None:
            continue
        pairs.append((c.name, rs, spa))

    if not pairs:
        return []

    name, rs, spa = max(pairs, key=lambda p: min(p[1], p[2]))
    agreement = min(rs, spa)
    spread = abs(rs - spa)
    # Agreement is judged proportionally: a 6-point gap means something very
    # different at an estimated 10% than at an estimated 60%.
    agrees = spread < 0.5 * max(rs, spa, 1e-9)

    measurements = {
        "channel": name,
        "rs_rate": round(rs, 5),
        "spa_rate": round(spa, 5),
        "all_channels": {c: {"rs": round(r, 5), "spa": round(s, 5)} for c, r, s in pairs},
    }

    if agreement >= ESTIMATOR_STRONG and agrees:
        return [
            Evidence(
                id="spatial.lsb-rate-agreement",
                family=Family.SPATIAL,
                severity=Severity.CRITICAL,
                title=f"Two independent estimators agree on ~{agreement:.0%} LSB embedding",
                detail=(
                    f"On the {name} channel, RS analysis estimates a {rs:.1%} embedding rate "
                    f"and Sample Pair Analysis estimates {spa:.1%}. These methods rest on "
                    "different assumptions — RS on how a smoothness discriminant responds to "
                    "directional bit flips, SPA on a finite-state model of adjacent sample "
                    "pairs — so their agreement is genuine corroboration rather than one "
                    "measurement taken twice. Both sit far above the ~4% noise floor these "
                    "methods exhibit on natural imagery."
                ),
                llr=2.2,
                confidence=0.95,
                technique="LSB replacement in the spatial domain",
                actions=[
                    "zsteg -a '{file}' — enumerate LSB extraction orders (PNG/BMP)",
                    "stegseek '{file}' rockyou.txt — if a passphrase-based tool is suspected",
                    "Extract the LSB plane in row-major order and inspect the first 64 bytes "
                    "for a header or magic number",
                ],
                references=[
                    "Fridrich, Goljan & Du, Reliable Detection of LSB Steganography, 2001",
                    "Dumitrescu, Wu & Wang, Detection of LSB Steganography via Sample Pair "
                    "Analysis, IEEE TSP 2003",
                ],
                measurements=measurements,
            )
        ]

    if agreement >= ESTIMATOR_FLOOR and agrees:
        return [
            Evidence(
                id="spatial.lsb-rate-weak",
                family=Family.SPATIAL,
                severity=Severity.MEDIUM,
                title=f"Low-rate LSB signal on the {name} channel (RS {rs:.1%}, SPA {spa:.1%})",
                detail=(
                    f"Both estimators return non-zero rates ({rs:.1%} and {spa:.1%}) but the "
                    "values sit close to the noise floor these methods show on natural images, "
                    "particularly on noisy, high-ISO or heavily textured photographs. A short "
                    "payload and a grainy cover are not distinguishable at this level."
                ),
                llr=0.55,
                confidence=0.65,
                technique="Possible low-rate LSB embedding",
                actions=[
                    "Obtain a reference image from the same device and settings, and compare "
                    "its estimator output to establish this camera's baseline"
                ],
                measurements=measurements,
            )
        ]

    if spread > 0.3:
        return [
            Evidence(
                id="spatial.estimator-disagreement",
                family=Family.SPATIAL,
                severity=Severity.LOW,
                title=f"RS and SPA disagree substantially on the {name} channel",
                detail=(
                    f"RS returns {rs:.1%} while SPA returns {spa:.1%}. Disagreement of this "
                    "size usually means the image violates an assumption both models make "
                    "about natural sample statistics — saturated regions, heavy prior "
                    "denoising, or synthetic content will all do it. Neither figure should "
                    "be relied on."
                ),
                llr=0.0,
                confidence=0.8,
                inconclusive=True,
                measurements=measurements,
            )
        ]

    return [
        Evidence(
            id="spatial.lsb-clear",
            family=Family.SPATIAL,
            severity=Severity.INFO,
            title="No spatial LSB embedding detected by either estimator",
            detail=(
                f"RS analysis returns {rs:.1%} and Sample Pair Analysis {spa:.1%} on the "
                f"{name} channel, both at the noise floor. This excludes LSB replacement "
                "above roughly 5% of capacity. It does not address LSB *matching* "
                "(±1 embedding), which leaves no pair-of-values structure for these methods "
                "to find."
            ),
            llr=-0.5,
            confidence=0.85,
            measurements=measurements,
        )
    ]


def _evaluate_chi_square(channels: list[ChannelProfile]) -> list[Evidence]:
    """Interpret the global pairs-of-values test.

    Gated on the bit-plane decorrelation gap, because the chi-square test has a
    known blind spot: it fits the equalised model whenever the *cover's own*
    histogram is already smooth. A gently graded image with a little sensor
    noise produces p > 0.99 while being entirely clean — measured, not
    hypothesised. Requiring the plane-0/plane-1 gap alongside it removes that
    whole class of false positive, because a smooth histogram raises both planes
    together while embedding separates them.
    """
    candidates = [c for c in channels if c.chi_square]
    if not candidates:
        return []
    best = max(candidates, key=lambda c: c.chi_square.p_value if c.chi_square else 0.0)
    result = best.chi_square
    assert result is not None
    if result.p_value <= 0.95:
        return []

    gap = _plane_gap(best)
    corroborated = gap is not None and gap > 0.03
    gap_value = 0.0 if gap is None else gap

    if corroborated:
        return [
            Evidence(
                id="spatial.chi-square-equalisation",
                family=Family.SPATIAL,
                severity=Severity.HIGH,
                title=(
                    f"Pairs-of-values histogram is equalised on {best.name} "
                    f"(p = {result.p_value:.4f})"
                ),
                detail=(
                    "The Westfeld-Pfitzmann chi-square test fits the hypothesis that every "
                    f"value pair (2i, 2i+1) has been equalised, with p = {result.p_value:.4f} "
                    f"over {result.usable_bins} usable bins, and bit plane 0 is independently "
                    f"decorrelated from plane 1 by {gap_value:.3f}. LSB replacement produces exactly "
                    "this convergence. Note the polarity: a high p-value is the incriminating "
                    "outcome here, because the model being fitted is the *embedded* one."
                ),
                llr=1.5,
                confidence=0.9,
                technique="LSB replacement",
                measurements=result.to_dict() | {"channel": best.name, "plane_gap": round(gap_value, 5)},
            )
        ]

    return [
        Evidence(
            id="spatial.chi-square-smooth-histogram",
            family=Family.SPATIAL,
            severity=Severity.LOW,
            title=f"Value pairs are equalised on {best.name}, but the bit planes are not",
            detail=(
                f"The pairs-of-values test fits the equalised model (p = {result.p_value:.4f}), "
                "which taken alone would indicate LSB replacement. However bit plane 0 shows no "
                "decorrelation from plane 1, and embedding cannot produce one without the other. "
                "The more likely explanation is that this image's histogram is intrinsically "
                "smooth — a soft gradient, a low-contrast or heavily denoised image — which "
                "fits the equalised model without anything having been embedded. Reported for "
                "completeness rather than as support."
            ),
            llr=0.1,
            confidence=0.6,
            measurements=result.to_dict() | {"channel": best.name, "plane_gap": _opt(gap)},
        )
    ]


def _plane_gap(channel: ChannelProfile) -> float | None:
    rates = channel.transition_rates
    if len(rates) < 2:
        return None
    lsb, second = rates[0], rates[1]
    if lsb != lsb or second != second:
        return None
    return lsb - second


def _opt(value: float | None) -> float | None:
    if value is None or value != value:
        return None
    return round(value, 5)


def _evaluate_sequential(
    channel: ChannelProfile, curve: list[float]
) -> list[Evidence]:
    """Detect a payload that fills the carrier from the start and stops.

    Three conditions must hold together, because any one alone fires on noise.
    The curve must have enough blocks for a ratio to mean anything; the leading
    high run must be several blocks long rather than one lucky block; and the
    curve must actually *collapse* afterwards. A curve that is high throughout
    is not evidence of sequential embedding — it is a smooth histogram, handled
    elsewhere.
    """
    prefix = channel.chi_curve_prefix
    if len(curve) < MIN_CURVE_POINTS:
        return []

    run = round(prefix * len(curve))
    if run < MIN_CURVE_RUN or prefix < 0.05 or prefix > 0.95:
        return []

    tail = curve[run:]
    if not tail or float(np.median(tail)) > 0.5:
        return []

    return [
        Evidence(
            id="spatial.sequential-embedding",
            family=Family.SPATIAL,
            severity=Severity.HIGH if prefix > 0.15 else Severity.MEDIUM,
            title=f"Embedding signature confined to the first {prefix:.0%} of the {channel.name} plane",
            detail=(
                "Running the chi-square attack over successive blocks shows a run of "
                f"high p-values covering the leading {prefix:.1%} of the image, then a sharp "
                "collapse. Tools that fill the carrier sequentially from the start produce "
                "precisely this step. The position of the collapse indicates the payload "
                "length: roughly "
                f"{prefix:.1%} of the plane's capacity."
            ),
            llr=1.6 if prefix > 0.15 else 0.8,
            confidence=0.85,
            technique="Sequential LSB embedding",
            actions=[
                "Extract the LSB plane in row-major order and truncate at the collapse point"
            ],
            measurements={
                "prefix_ratio": round(prefix, 5),
                "channel": channel.name,
                "leading_blocks": run,
                "total_blocks": len(curve),
                "tail_median_p": round(float(np.median(tail)), 5),
            },
        )
    ]


def _evaluate_bit_planes(channels: list[ChannelProfile]) -> list[Evidence]:
    findings: list[Evidence] = []
    for channel in channels:
        rates = channel.transition_rates
        if len(rates) < 3:
            continue
        lsb, second = rates[0], rates[1]
        if lsb != lsb or second != second:
            continue

        # The discriminator is the *gap* between plane 0 and plane 1, not the
        # absolute value: a noisy photograph raises both, whereas payload bits
        # raise only the plane that carries them.
        if lsb > TRANSITION_ALERT and lsb - second > 0.06:
            findings.append(
                Evidence(
                    id="spatial.lsb-decorrelated",
                    family=Family.SPATIAL,
                    severity=Severity.HIGH,
                    title=f"{channel.name} bit plane 0 has lost its correlation with plane 1",
                    detail=(
                        f"Adjacent bits differ {lsb:.1%} of the time in bit plane 0 but only "
                        f"{second:.1%} of the time in plane 1. In natural images the low "
                        "planes are noisy yet still correlated with the planes above them, so "
                        "the two rates track each other. An independent bitstream written into "
                        "plane 0 drives it to 50% while leaving plane 1 untouched, producing "
                        "exactly this gap. A grainy cover raises both rates together and does "
                        "not create the separation."
                    ),
                    llr=1.3,
                    confidence=0.8,
                    technique="LSB embedding",
                    measurements={
                        "channel": channel.name,
                        "plane0_transition": round(lsb, 5),
                        "plane1_transition": round(second, 5),
                        "gap": round(lsb - second, 5),
                    },
                )
            )
    return findings[:2]
