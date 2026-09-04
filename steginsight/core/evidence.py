"""Domain model for forensic observations and the verdict derived from them.

Everything a detector produces is an :class:`Evidence` record. Nothing else moves
the verdict, and every point of the final score is traceable to a specific,
named measurement.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Presentation ordering only. Does not affect scoring."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Family(str, Enum):
    """Broad detector family.

    Used to measure *independent corroboration*. Two findings from the same
    family are largely the same fact observed twice, and are damped accordingly.
    """

    STRUCTURE = "structure"        # container parsing: trailing data, bad chunks
    SIGNATURE = "signature"        # literal byte markers of tools or file types
    SPATIAL = "spatial"            # RS, SPA, chi-square, bit-plane correlation
    TRANSFORM = "transform"        # DCT / frequency-domain steganalysis
    METADATA = "metadata"          # EXIF / XMP / comment-field abuse
    LINGUISTIC = "linguistic"      # unicode, whitespace, homoglyph text stego


class Verdict(str, Enum):
    CLEAN = "clean"
    INCONCLUSIVE = "inconclusive"
    SUSPICIOUS = "suspicious"
    LIKELY_EMBEDDED = "likely-embedded"


@dataclass(slots=True)
class Evidence:
    """A single observation.

    ``llr`` is the base-10 log likelihood ratio: how much more probable this
    observation is if a payload is present than if the carrier is clean. It is
    the only field that moves the verdict.

    Calibration guide (deliberately conservative):

    ==========  ==============================================================
    ``llr``     meaning
    ==========  ==============================================================
    ``0.2``     weak nudge; clean files produce these routinely
    ``0.5``     mild support
    ``1.0``     10:1 in favour — a real anomaly
    ``1.7``     50:1 — hard structural proof, e.g. a parsed ZIP after IEND
    ``2.3``     200:1 — unambiguous, self-identifying artefact
    ==========  ==============================================================

    Negative values are exculpatory and are expected: a detector that runs,
    finds nothing, and says so is more useful than one that stays silent.
    """

    id: str
    family: Family
    severity: Severity
    title: str
    detail: str
    llr: float
    confidence: float = 1.0
    offset: int | None = None
    length: int | None = None
    technique: str | None = None
    actions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    #: Raw measurements behind the finding, for audit and report tables.
    measurements: dict[str, Any] = field(default_factory=dict)
    #: Set by a detector that ran but could not reach a usable conclusion.
    #:
    #: This is the difference between "we looked and found nothing" and "we
    #: looked and could not tell". Both leave the posterior near the prior, but
    #: only the first justifies reporting the carrier as clean. Any evidence
    #: carrying this flag floors the verdict at ``INCONCLUSIVE``, so a detector
    #: that failed can never be mistaken for a detector that cleared the file.
    inconclusive: bool = False

    def weight(self) -> float:
        """Effective contribution, before family damping."""
        return _clamp(self.llr, -PER_EVIDENCE_CAP, PER_EVIDENCE_CAP) * _clamp(
            self.confidence, 0.0, 1.0
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "family": self.family.value,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "llr": round(self.llr, 4),
            "confidence": round(self.confidence, 4),
            "offset": self.offset,
            "length": self.length,
            "technique": self.technique,
            "actions": list(self.actions),
            "references": list(self.references),
            "measurements": _jsonable(self.measurements),
            "inconclusive": self.inconclusive,
        }


@dataclass(slots=True)
class Assessment:
    verdict: Verdict
    probability: float
    log_odds: float
    corroborating_families: int
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "probability": round(self.probability, 4),
            "log_odds": round(self.log_odds, 4),
            "corroborating_families": self.corroborating_families,
            "rationale": self.rationale,
        }


# --------------------------------------------------------------------------
# Combination model
# --------------------------------------------------------------------------

#: Prior probability that an arbitrary submitted file carries a payload.
#: Deliberately low. Steganography is rare in absolute terms, and a tool that
#: starts from a coin-flip manufactures false positives. Analysts triaging an
#: already-suspicious corpus can raise it with ``--prior``.
DEFAULT_PRIOR = 0.05

#: No single observation may contribute more than this many base-10 log units.
PER_EVIDENCE_CAP = 2.5

#: Second and later findings within one family are damped by this factor each,
#: because "high entropy" and "near-maximum entropy" are not two independent
#: facts about a file.
WITHIN_FAMILY_DECAY = 0.55

#: Effective weight at which a single observation counts as hard proof, and
#: exculpatory evidence from *other* families stops being subtracted. Set at the
#: "50:1 in favour" tier — a parsed archive after an end-of-file marker, a
#: CRC-valid chunk past IEND, a varying bitstream inside digital silence.
PROOF_THRESHOLD = 1.7

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _clamp(value: float, low: float, high: float) -> float:
    if value != value:  # NaN
        return 0.0
    return max(low, min(high, value))


def probability_to_log_odds(p: float) -> float:
    p = _clamp(p, 1e-9, 1 - 1e-9)
    return math.log10(p / (1 - p))


def log_odds_to_probability(log_odds: float) -> float:
    if log_odds > 12:
        return 1 - 1e-12
    if log_odds < -12:
        return 1e-12
    return float(1.0 / (1.0 + 10.0 ** (-log_odds)))


def sort_evidence(evidence: list[Evidence]) -> list[Evidence]:
    return sorted(
        evidence,
        key=lambda e: (_SEVERITY_ORDER[e.severity], -e.weight()),
    )


def assess(evidence: list[Evidence], prior: float = DEFAULT_PRIOR) -> Assessment:
    """Combine evidence into a posterior assessment.

    Assuming rough conditional independence *between* families, the posterior
    log-odds is the prior plus the sum of the likelihood ratios. Within a family
    the strongest finding counts in full and the rest are geometrically damped.
    """
    by_family: dict[Family, list[Evidence]] = {}
    for item in evidence:
        by_family.setdefault(item.family, []).append(item)

    log_odds = probability_to_log_odds(prior)
    corroborating = 0

    # Hard structural proof cannot be argued away by a different technique
    # coming back clean. If a payload has been appended past a container's end
    # marker and the bytes parse as an archive, the fact that the *pixels* show
    # no LSB embedding says nothing about it — the two findings answer different
    # questions. Without this guard an exculpatory result in one family silently
    # discounts proof in another, which is how a confirmed polyglot ends up
    # merely "suspicious".
    has_proof = any(e.weight() >= PROOF_THRESHOLD for e in evidence)

    for items in by_family.values():
        weights = sorted((e.weight() for e in items), key=abs, reverse=True)
        family_total = sum(w * (WITHIN_FAMILY_DECAY**i) for i, w in enumerate(weights))
        if family_total > 0.15:
            corroborating += 1
        if has_proof and family_total < 0:
            continue
        log_odds += family_total

    probability = log_odds_to_probability(log_odds)
    verdict = _band(probability, corroborating, has_proof)

    # A detector that could not reach a conclusion must never be mistaken for
    # one that cleared the file. Both leave the posterior at the prior; only one
    # of them justifies the word "clean".
    unresolved = [e for e in evidence if e.inconclusive]
    if unresolved and verdict is Verdict.CLEAN:
        verdict = Verdict.INCONCLUSIVE

    return Assessment(
        verdict=verdict,
        probability=probability,
        log_odds=log_odds,
        corroborating_families=corroborating,
        rationale=_rationale(
            verdict, probability, corroborating, len(evidence), unresolved
        ),
    )


def _band(probability: float, families: int, has_proof: bool = False) -> Verdict:
    # A single proof-tier observation is sufficient on its own. A ZIP that opens
    # after an end-of-file marker, or a varying bitstream inside digital
    # silence, does not need a second technique to agree with it; demanding
    # corroboration for facts that are already conclusive just moves the
    # threshold somewhere it cannot be met.
    if has_proof and probability >= 0.80:
        return Verdict.LIKELY_EMBEDDED
    if probability >= 0.85 and families >= 2:
        return Verdict.LIKELY_EMBEDDED
    if probability >= 0.90:
        return Verdict.LIKELY_EMBEDDED
    if probability >= 0.50:
        return Verdict.SUSPICIOUS
    if probability >= 0.20:
        return Verdict.INCONCLUSIVE
    return Verdict.CLEAN


def _rationale(
    verdict: Verdict,
    probability: float,
    families: int,
    count: int,
    unresolved: list[Evidence] | None = None,
) -> str:
    pct = f"{probability * 100:.1f}%"
    if unresolved:
        titles = "; ".join(e.title for e in unresolved[:3])
        return (
            f"Posterior probability {pct}, but {len(unresolved)} detector(s) ran without "
            f"reaching a usable conclusion ({titles}). The low probability reflects an "
            "absence of positive findings, not a clean result — the measurements that "
            "would have settled it were not obtainable on this carrier. Treat this as "
            "unresolved and read the limitations section before drawing any inference."
        )
    if verdict is Verdict.LIKELY_EMBEDDED:
        noun = "family" if families == 1 else "families"
        return (
            f"Posterior probability {pct} across {families} independent evidence {noun}. "
            "The observations are difficult to explain by ordinary encoding or "
            "transport of this format."
        )
    if verdict is Verdict.SUSPICIOUS:
        return (
            f"Posterior probability {pct}. Anomalies are present but each has a plausible "
            "benign explanation; corroboration from a second technique, or a reference "
            "sample of the same provenance, is needed before drawing a conclusion."
        )
    if verdict is Verdict.INCONCLUSIVE:
        lead = "No detector produced a positive observation" if count == 0 else "Weak signals only"
        return (
            f"Posterior probability {pct}. {lead}; this is consistent with a clean carrier "
            "and does not support a finding either way."
        )
    return (
        f"Posterior probability {pct}. Structure, statistics and signatures are all "
        "consistent with an unmodified carrier. This is not proof of absence: a short "
        "or well-encrypted payload can fall below the detection floor of every "
        "technique implemented here."
    )


def collect_actions(evidence: list[Evidence]) -> list[str]:
    """Deduplicated next steps, strongest evidence first."""
    seen: set[str] = set()
    actions: list[str] = []
    for item in sort_evidence(evidence):
        for action in item.actions:
            key = action.strip().lower()
            if key in seen:
                continue
            seen.add(key)
            actions.append(action)
    return actions


def _jsonable(value: Any) -> Any:
    """Coerce NumPy scalars and arrays into plain JSON-serialisable types."""
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if hasattr(value, "item") and getattr(value, "shape", None) == ():
        return value.item()
    if hasattr(value, "tolist"):
        return value.tolist()
    if isinstance(value, float):
        return None if math.isnan(value) or math.isinf(value) else round(value, 6)
    return value
