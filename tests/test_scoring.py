"""Evidence combination.

The previous engine summed hand-picked point values and clamped at 100, which
let one aggressive detector saturate the score and made the number impossible to
defend. These tests pin the properties that replaced it.
"""

from __future__ import annotations

import pytest

from steginsight.core.evidence import (
    DEFAULT_PRIOR,
    Evidence,
    Family,
    Severity,
    Verdict,
    assess,
    collect_actions,
    log_odds_to_probability,
    probability_to_log_odds,
    sort_evidence,
)


def ev(
    llr: float,
    family: Family = Family.STRUCTURE,
    *,
    confidence: float = 1.0,
    severity: Severity = Severity.MEDIUM,
    inconclusive: bool = False,
    ident: str = "test.finding",
    actions: list[str] | None = None,
) -> Evidence:
    return Evidence(
        id=ident,
        family=family,
        severity=severity,
        title="t",
        detail="d",
        llr=llr,
        confidence=confidence,
        inconclusive=inconclusive,
        actions=actions or [],
    )


class TestLogOdds:
    def test_round_trip(self) -> None:
        for p in (0.01, 0.1, 0.5, 0.9, 0.99):
            assert log_odds_to_probability(probability_to_log_odds(p)) == pytest.approx(p)

    def test_saturates_without_overflow(self) -> None:
        assert log_odds_to_probability(1e9) < 1.0
        assert log_odds_to_probability(-1e9) > 0.0


class TestAssess:
    def test_no_evidence_returns_the_prior(self) -> None:
        result = assess([], prior=0.05)
        assert result.probability == pytest.approx(0.05, abs=1e-6)
        assert result.verdict is Verdict.CLEAN

    def test_prior_is_configurable(self) -> None:
        assert assess([], prior=0.4).probability == pytest.approx(0.4, abs=1e-6)

    def test_positive_evidence_raises_probability(self) -> None:
        assert assess([ev(1.5)]).probability > DEFAULT_PRIOR

    def test_negative_evidence_lowers_probability(self) -> None:
        assert assess([ev(-1.0)]).probability < DEFAULT_PRIOR

    def test_confidence_scales_contribution(self) -> None:
        full = assess([ev(2.0, confidence=1.0)]).log_odds
        half = assess([ev(2.0, confidence=0.5)]).log_odds
        base = assess([]).log_odds
        assert (full - base) == pytest.approx(2 * (half - base), abs=1e-9)

    def test_single_evidence_cannot_saturate_the_score(self) -> None:
        """One detector shouting cannot reach certainty on its own."""
        assert assess([ev(50.0)]).probability < 0.999

    def test_repeats_within_a_family_are_damped(self) -> None:
        """'High entropy' and 'near-maximum entropy' are not two independent facts."""
        one = assess([ev(1.0, Family.SPATIAL)]).log_odds
        three = assess(
            [ev(1.0, Family.SPATIAL), ev(1.0, Family.SPATIAL), ev(1.0, Family.SPATIAL)]
        ).log_odds
        base = assess([]).log_odds
        assert (three - base) < 3 * (one - base)

    def test_independent_families_corroborate_more_than_repeats(self) -> None:
        same = assess([ev(1.0, Family.SPATIAL), ev(1.0, Family.SPATIAL)])
        different = assess([ev(1.0, Family.SPATIAL), ev(1.0, Family.STRUCTURE)])
        assert different.probability > same.probability
        assert different.corroborating_families == 2
        assert same.corroborating_families == 1

    def test_hard_proof_is_not_offset_by_other_families(self) -> None:
        """A clean LSB result says nothing about an appended archive.

        Without this, an exculpatory finding in one family silently discounts
        proof in another and a confirmed polyglot reads as merely 'suspicious'.
        """
        proof_only = assess([ev(2.3, Family.STRUCTURE)])
        with_negative = assess([ev(2.3, Family.STRUCTURE), ev(-0.5, Family.SPATIAL)])
        assert with_negative.probability == pytest.approx(proof_only.probability)
        assert with_negative.verdict is Verdict.LIKELY_EMBEDDED

    def test_weak_positives_are_still_offset_by_negatives(self) -> None:
        """The proof guard must not disable exculpatory evidence generally."""
        weak = assess([ev(0.6, Family.STRUCTURE)])
        offset = assess([ev(0.6, Family.STRUCTURE), ev(-0.5, Family.SPATIAL)])
        assert offset.probability < weak.probability


class TestVerdictBands:
    def test_clean_when_nothing_found(self) -> None:
        assert assess([]).verdict is Verdict.CLEAN

    def test_proof_tier_evidence_alone_is_sufficient(self) -> None:
        assert assess([ev(2.3)]).verdict is Verdict.LIKELY_EMBEDDED

    def test_two_moderate_families_reach_likely(self) -> None:
        result = assess([ev(1.4, Family.SPATIAL), ev(1.4, Family.TRANSFORM)])
        assert result.verdict is Verdict.LIKELY_EMBEDDED
        assert result.corroborating_families == 2

    def test_middling_evidence_is_suspicious_not_conclusive(self) -> None:
        assert assess([ev(1.5, Family.SPATIAL)]).verdict is Verdict.SUSPICIOUS


class TestInconclusive:
    def test_a_failed_detector_is_never_reported_as_clean(self) -> None:
        """'We could not measure' must not be mistaken for 'we measured nothing'."""
        result = assess([ev(0.0, inconclusive=True)])
        assert result.verdict is Verdict.INCONCLUSIVE
        assert "not a clean result" in result.rationale

    def test_inconclusive_does_not_suppress_a_positive_verdict(self) -> None:
        result = assess([ev(2.3, Family.STRUCTURE), ev(0.0, inconclusive=True)])
        assert result.verdict is Verdict.LIKELY_EMBEDDED


class TestOrderingAndActions:
    def test_sorted_by_severity_then_weight(self) -> None:
        items = [
            ev(0.1, severity=Severity.INFO, ident="a"),
            ev(2.0, severity=Severity.CRITICAL, ident="b"),
            ev(0.5, severity=Severity.MEDIUM, ident="c"),
        ]
        assert [e.id for e in sort_evidence(items)] == ["b", "c", "a"]

    def test_actions_are_deduplicated_and_ordered(self) -> None:
        items = [
            ev(0.2, severity=Severity.LOW, actions=["run x", "run y"]),
            ev(2.0, severity=Severity.CRITICAL, actions=["run z", "run x"]),
        ]
        assert collect_actions(items) == ["run z", "run x", "run y"]

    def test_rationale_is_always_present(self) -> None:
        for evidence in ([], [ev(0.5)], [ev(2.4)], [ev(-1.0)]):
            assert len(assess(evidence).rationale) > 40
