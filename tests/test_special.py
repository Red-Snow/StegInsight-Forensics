"""Our chi-square survival function against SciPy's.

SciPy was dropped as a runtime dependency so the package can run in the browser
under Pyodide, where it is a ~15 MB WebAssembly download. The only functions
used from it were `chi2.sf`, so the trade was poor value. That makes this test
load-bearing: it is the evidence that the substitution is exact rather than
approximate. SciPy remains a *test* dependency purely to serve as the oracle.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from steginsight.core._special import chi2_sf, gamma_p, gamma_q, ln_gamma

scipy_stats = pytest.importorskip("scipy.stats")


class TestChiSquareAgainstScipy:
    @pytest.mark.parametrize("df", [1, 2, 3, 5, 10, 50, 105, 127, 255, 1000])
    def test_matches_scipy_across_the_range(self, df: int) -> None:
        statistics = np.concatenate(
            [np.linspace(0.001, 5, 40), np.linspace(5, 500, 60), [1e-6, 1e4]]
        )
        for stat in statistics:
            mine = chi2_sf(float(stat), df)
            reference = float(scipy_stats.chi2.sf(stat, df))
            if reference > 1e-300:
                assert mine == pytest.approx(reference, rel=1e-9), (
                    f"df={df} statistic={stat}: {mine} vs scipy {reference}"
                )

    def test_the_detectors_operating_points(self) -> None:
        """The specific regions the detectors actually read."""
        for df, stat in [(1, 0.2), (105, 80.3), (127, 10.0), (50, 500.0), (255, 340.6)]:
            assert chi2_sf(stat, df) == pytest.approx(
                float(scipy_stats.chi2.sf(stat, df)), rel=1e-9
            )


class TestBoundaries:
    def test_zero_statistic_is_certainty(self) -> None:
        assert chi2_sf(0.0, 5) == 1.0
        assert chi2_sf(-1.0, 5) == 1.0

    def test_invalid_degrees_of_freedom(self) -> None:
        assert math.isnan(chi2_sf(1.0, 0))

    def test_result_is_always_a_probability(self) -> None:
        for df in (1, 7, 200):
            for stat in (0.0, 0.5, 3.0, 50.0, 5000.0):
                assert 0.0 <= chi2_sf(stat, df) <= 1.0

    def test_monotonically_decreasing_in_the_statistic(self) -> None:
        previous = 1.0
        for stat in np.linspace(0.1, 200, 80):
            current = chi2_sf(float(stat), 10)
            assert current <= previous + 1e-12
            previous = current


class TestIncompleteGamma:
    def test_p_and_q_are_complementary(self) -> None:
        for a in (0.5, 1.0, 5.0, 60.0):
            for x in (0.1, 1.0, 7.0, 100.0):
                assert gamma_p(a, x) + gamma_q(a, x) == pytest.approx(1.0, abs=1e-12)

    def test_ln_gamma_matches_math_lgamma(self) -> None:
        for x in (0.1, 0.5, 1.0, 2.5, 10.0, 170.0):
            assert ln_gamma(x) == pytest.approx(math.lgamma(x), rel=1e-12)
