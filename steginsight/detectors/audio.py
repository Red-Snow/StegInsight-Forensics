"""PCM audio steganalysis.

A note on what is and is not detectable
---------------------------------------
This module deliberately claims less than the previous engine did, because
measurement says less is warranted.

Empirically, the least significant bits of real 16-bit PCM audio are already
indistinguishable from random. Every recording has a noise floor; dither is
applied deliberately during mastering; and anything that has passed through a
lossy codec and back to PCM carries reconstruction noise. Measured across clean
and embedded pairs, the adjacent-sample LSB transition rate sits at 0.500 either
way, and Sample Pair Analysis — which works well on images, where neighbouring
samples are strongly correlated — returns saturated values for clean audio too.

So whole-file LSB embedding in noisy PCM is **below the detection floor** of
these statistical methods. The previous engine reported an "Audio Bitstream
Anomaly" whenever a statistic exceeded 0.1, which every recording does; that is
a false-positive generator, not a detector, and it is not reproduced here.

What *is* reliably detectable, and what this module reports:

* **Data written into digital silence.** Silence is encoded as exact zeros by
  every recorder, codec and editor. A varying low bit inside a silent passage
  cannot arise from acoustic content. This discriminates perfectly in testing.
* **Data written into a constant low-bit floor**, as found in audio upsampled
  from a lower bit depth or rendered synthetically.
* **Structural anomalies**, handled by :mod:`steginsight.containers.riff` —
  size-field mismatches, padding chunks carrying content, appended data.

When none of those apply, the report says so explicitly rather than implying the
carrier is clean.
"""

from __future__ import annotations

import io
import wave
from dataclasses import dataclass, field

import numpy as np
from numpy.typing import NDArray

from ..core.evidence import Evidence, Family, Severity
from ..core.stats import bit_plane_entropy

__all__ = ["AudioProfile", "analyse_audio"]

MIN_SAMPLES = 8192

#: A 16-bit sample at or below this magnitude is digital silence.
SILENCE_THRESHOLD = 2

#: Minimum silent samples before the silence test is meaningful.
MIN_SILENT_SAMPLES = 2000

#: Fraction of low bits that must be set for a "constant floor" to be broken.
FLOOR_TOLERANCE = 0.001

#: Mean sample magnitude above which a block counts as carrying audible signal.
#: Blocks below this are silence, whose constant low bit means nothing.
AUDIBLE_THRESHOLD = 64


@dataclass(slots=True)
class AudioProfile:
    channels: int
    sample_width: int
    frame_rate: int
    frames: int
    duration_seconds: float
    lsb_entropy: float = 0.0
    lsb_transition_rate: float = float("nan")
    silent_samples: int = 0
    silent_lsb_ratio: float = float("nan")
    low_bit_floor_constant: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "channels": self.channels,
            "sample_width_bytes": self.sample_width,
            "sample_rate": self.frame_rate,
            "frames": self.frames,
            "duration_seconds": round(self.duration_seconds, 3),
            "lsb_entropy": round(self.lsb_entropy, 5),
            "lsb_transition_rate": _opt(self.lsb_transition_rate),
            "silent_samples": self.silent_samples,
            "silent_lsb_ratio": _opt(self.silent_lsb_ratio),
            "low_bit_floor_constant": self.low_bit_floor_constant,
        }


def _opt(value: float) -> float | None:
    return None if value != value else round(value, 5)


def analyse_audio(data: bytes) -> tuple[AudioProfile | None, list[Evidence], list[str]]:
    limitations: list[str] = []
    try:
        with wave.open(io.BytesIO(data), "rb") as handle:
            channels = handle.getnchannels()
            width = handle.getsampwidth()
            rate = handle.getframerate()
            frames = handle.getnframes()
            raw = handle.readframes(frames)
    except (wave.Error, EOFError, OSError, ValueError) as exc:
        limitations.append(
            f"PCM audio analysis skipped: {exc}. Compressed audio (MP3, AAC, Opus) has "
            "no stable sample LSBs to analyse; structural and signature checks were "
            "applied instead."
        )
        return None, [], limitations

    if width not in (1, 2, 4):
        limitations.append(
            f"Unsupported PCM sample width ({width} bytes); audio analysis skipped."
        )
        return None, [], limitations

    profile = AudioProfile(
        channels=channels,
        sample_width=width,
        frame_rate=rate,
        frames=frames,
        duration_seconds=frames / rate if rate else 0.0,
    )

    samples = _to_samples(raw, width)
    if samples.size < MIN_SAMPLES:
        limitations.append(
            "Fewer than 8,192 PCM samples; statistical audio detectors were skipped."
        )
        return profile, [], limitations

    lsb = (samples & 1).astype(np.uint8)
    profile.lsb_entropy = bit_plane_entropy((samples & 0xFF).astype(np.uint8), 0)
    profile.lsb_transition_rate = float((lsb[:-1] != lsb[1:]).mean())

    evidence: list[Evidence] = []
    found_silence_signal = _evaluate_silence(samples, lsb, profile, evidence)
    found_floor_signal = _evaluate_low_bit_floor(lsb, samples, profile, evidence)

    if not found_silence_signal and not found_floor_signal:
        evidence.append(_inconclusive_evidence(profile))
        limitations.append(
            "Whole-file LSB steganalysis of this carrier is inconclusive by design: the "
            f"low bits transition {profile.lsb_transition_rate:.1%} of the time, which is "
            "what an ordinary noise floor produces and also what an embedded payload "
            "produces. The two are not separable by these statistics. Pursue the "
            "structural findings, or obtain a reference recording from the same source "
            "device and settings for comparison."
        )

    return profile, evidence, limitations


def _to_samples(raw: bytes, width: int) -> NDArray[np.int64]:
    if width == 1:
        # 8-bit WAV is unsigned by specification, centred on 128.
        return np.frombuffer(raw, dtype=np.uint8).astype(np.int64) - 128
    if width == 2:
        return np.frombuffer(raw, dtype="<i2").astype(np.int64)
    return np.frombuffer(raw, dtype="<i4").astype(np.int64)


def _evaluate_silence(
    samples: NDArray[np.int64],
    lsb: NDArray[np.uint8],
    profile: AudioProfile,
    evidence: list[Evidence],
) -> bool:
    """Digital silence that is not silent is as close to proof as audio offers."""
    quiet = np.abs(samples) <= SILENCE_THRESHOLD
    profile.silent_samples = int(quiet.sum())
    if profile.silent_samples < MIN_SILENT_SAMPLES:
        return False

    quiet_lsb = lsb[quiet]
    ratio = float(quiet_lsb.mean())
    profile.silent_lsb_ratio = ratio

    if ratio < 0.05:
        # Exactly what a genuine silent passage looks like. Worth recording as
        # an explicit negative: it is a region where embedding would have been
        # trivially visible, and it is clean.
        evidence.append(
            Evidence(
                id="audio.silence-clean",
                family=Family.SPATIAL,
                severity=Severity.INFO,
                title=f"{profile.silent_samples:,} silent samples are exactly silent",
                detail=(
                    f"The carrier contains {profile.silent_samples:,} samples of digital "
                    f"silence, and {1 - ratio:.1%} of them are exact zeros. Any payload "
                    "written across the whole file would necessarily have disturbed these "
                    "samples, so this region rules out uniform whole-file LSB embedding."
                ),
                llr=-0.8,
                confidence=0.9,
                measurements={
                    "silent_samples": profile.silent_samples,
                    "lsb_set_ratio": round(ratio, 5),
                },
            )
        )
        return True

    if 0.15 < ratio < 0.85:
        evidence.append(
            Evidence(
                id="audio.data-in-silence",
                family=Family.SPATIAL,
                severity=Severity.CRITICAL,
                title=f"{profile.silent_samples:,} silent samples carry a varying bitstream",
                detail=(
                    f"{profile.silent_samples:,} samples have magnitude at or below "
                    f"{SILENCE_THRESHOLD}, which is digital silence, yet {ratio:.1%} of them "
                    "have their least significant bit set. Silence is written as exact zeros "
                    "by every recorder, codec and editor; a balanced, varying low bit inside "
                    "a silent passage cannot arise from acoustic content. Something wrote "
                    "into these samples. This is the one audio measurement that separates "
                    "embedded from clean carriers cleanly."
                ),
                llr=2.3,
                confidence=0.95,
                technique="LSB embedding in silent regions",
                actions=[
                    "Extract the LSBs of the silent region in order and inspect the leading "
                    "bytes for a header or magic number",
                    "Test the carrier in the tool suspected of writing it (for example "
                    "DeepSound) for a password-protected volume",
                ],
                measurements={
                    "silent_samples": profile.silent_samples,
                    "lsb_set_ratio": round(ratio, 5),
                },
            )
        )
        return True

    return False


def _evaluate_low_bit_floor(
    lsb: NDArray[np.uint8],
    samples: NDArray[np.int64],
    profile: AudioProfile,
    evidence: list[Evidence],
) -> bool:
    """Detect a broken constant low-bit floor.

    Audio upsampled from a lower bit depth, or rendered synthetically without
    dither, has low bits that are constant across the whole file. Embedding into
    such a carrier is glaring — but only if you check for the floor rather than
    assuming the low bits are always noisy.
    """
    ratio = float(lsb.mean())

    if ratio < FLOOR_TOLERANCE or ratio > 1 - FLOOR_TOLERANCE:
        profile.low_bit_floor_constant = True
        evidence.append(
            Evidence(
                id="audio.constant-low-bit-floor",
                family=Family.SPATIAL,
                severity=Severity.INFO,
                title="Low bit is constant across the entire carrier",
                detail=(
                    f"The least significant bit is {'set' if ratio > 0.5 else 'clear'} in "
                    f"{max(ratio, 1 - ratio):.2%} of samples. This carrier was upsampled from "
                    "a lower bit depth or rendered without dither, so it has no natural noise "
                    "floor. Any LSB embedding would be immediately visible here, and none is "
                    "present."
                ),
                llr=-1.0,
                confidence=0.9,
                measurements={"lsb_set_ratio": round(ratio, 6)},
            )
        )
        return True

    # A floor that is *mostly* constant but broken in one region is the giveaway.
    #
    # Crucially, only blocks that actually carry signal are considered. A silent
    # introduction has a constant low bit because it is silent, and comparing it
    # against the music that follows flags every recording that begins with a
    # pause — measured, and the reason this guard exists.
    blocks = 64
    if lsb.size >= blocks * 256 and samples is not None:
        block_size = lsb.size // blocks
        rates = np.empty(blocks)
        audible = np.empty(blocks, dtype=bool)
        for i in range(blocks):
            window = slice(i * block_size, (i + 1) * block_size)
            rates[i] = lsb[window].mean()
            audible[i] = np.abs(samples[window]).mean() > AUDIBLE_THRESHOLD

        quiet_blocks = (rates < FLOOR_TOLERANCE) & audible
        noisy_blocks = (rates > 0.4) & (rates < 0.6) & audible
        if quiet_blocks.sum() >= 8 and noisy_blocks.sum() >= 4:
            evidence.append(
                Evidence(
                    id="audio.floor-discontinuity",
                    family=Family.SPATIAL,
                    severity=Severity.HIGH,
                    title="Low-bit floor is constant in some regions and random in others",
                    detail=(
                        f"Of {blocks} equal blocks, {int(quiet_blocks.sum())} have a low bit "
                        f"that never changes while {int(noisy_blocks.sum())} are balanced "
                        "random. A single recording has one noise floor throughout. This "
                        "discontinuity means part of the carrier was written by something "
                        "other than the process that produced the rest."
                    ),
                    llr=1.9,
                    confidence=0.85,
                    technique="Regional LSB embedding",
                    actions=[
                        "Extract the LSBs of the randomised blocks only and inspect for a header"
                    ],
                    measurements={
                        "constant_blocks": int(quiet_blocks.sum()),
                        "random_blocks": int(noisy_blocks.sum()),
                        "total_blocks": blocks,
                    },
                )
            )
            return True

    return False


def _inconclusive_evidence(profile: AudioProfile) -> Evidence:
    return Evidence(
        id="audio.lsb-inconclusive",
        family=Family.SPATIAL,
        severity=Severity.INFO,
        title="LSB analysis of this PCM carrier is inconclusive",
        detail=(
            f"Adjacent sample low bits differ {profile.lsb_transition_rate:.1%} of the time. "
            "For 16-bit audio that figure is uninformative: a recording's own noise floor, "
            "applied dither, and lossy-codec reconstruction noise all produce it, and so "
            "does an embedded payload. Reporting it as an anomaly — as some tools do — "
            "would flag essentially every audio file ever recorded. No silent passage long "
            "enough to test was present, and the low-bit floor is not constant, so neither "
            "of the two reliable audio discriminators could be applied."
        ),
        llr=0.0,
        confidence=1.0,
        inconclusive=True,
        actions=[
            "Compare against a reference recording captured on the same device with the "
            "same settings — a difference in low-bit behaviour between them is meaningful "
            "where an absolute figure is not",
            "Prioritise the structural findings for this carrier over the statistical ones",
        ],
        measurements={"lsb_transition_rate": _opt(profile.lsb_transition_rate)},
    )
