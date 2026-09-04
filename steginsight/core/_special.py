"""Special functions needed by the statistical detectors.

Implemented here rather than taken from SciPy for one concrete reason: it lets
the whole package run in the browser under Pyodide, where SciPy is a ~15 MB
WebAssembly download that would dominate the load time of the web app. The two
functions actually used from SciPy were both ``chi2.sf``, so carrying the whole
dependency for them was poor value.

Accuracy is verified against ``scipy.stats.chi2.sf`` in the test-suite to a
relative tolerance of 1e-10 across the full range the detectors use, so this is
a substitution rather than an approximation.

Algorithms follow Numerical Recipes (3rd ed., §6.2): a series expansion for
x < a+1 and a Lentz continued fraction otherwise, which together cover the whole
domain.
"""

from __future__ import annotations

import math

__all__ = ["chi2_sf", "gamma_p", "gamma_q", "ln_gamma"]

_EPS = 1e-15
_FPMIN = 1e-300
_MAX_ITER = 500

# Lanczos coefficients (g=7, n=9).
_LANCZOS = (
    0.99999999999980993,
    676.5203681218851,
    -1259.1392167224028,
    771.32342877765313,
    -176.61502916214059,
    12.507343278686905,
    -0.13857109526572012,
    9.9843695780195716e-6,
    1.5056327351493116e-7,
)


def ln_gamma(x: float) -> float:
    """Natural log of the gamma function."""
    if x < 0.5:
        # Reflection keeps the approximation on its accurate half-plane.
        return math.log(math.pi / abs(math.sin(math.pi * x))) - ln_gamma(1.0 - x)
    z = x - 1.0
    acc = _LANCZOS[0]
    for i in range(1, len(_LANCZOS)):
        acc += _LANCZOS[i] / (z + i)
    t = z + 7.5
    return 0.5 * math.log(2.0 * math.pi) + (z + 0.5) * math.log(t) - t + math.log(acc)


def _gamma_series(a: float, x: float) -> float:
    """Regularised lower incomplete gamma via its series expansion."""
    ap = a
    total = 1.0 / a
    delta = total
    for _ in range(_MAX_ITER):
        ap += 1.0
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * _EPS:
            break
    return total * math.exp(-x + a * math.log(x) - ln_gamma(a))


def _gamma_continued_fraction(a: float, x: float) -> float:
    """Regularised upper incomplete gamma via a Lentz continued fraction."""
    b = x + 1.0 - a
    c = 1.0 / _FPMIN
    d = 1.0 / b
    h = d
    for i in range(1, _MAX_ITER + 1):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < _FPMIN:
            d = _FPMIN
        c = b + an / c
        if abs(c) < _FPMIN:
            c = _FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _EPS:
            break
    return math.exp(-x + a * math.log(x) - ln_gamma(a)) * h


def gamma_p(a: float, x: float) -> float:
    """Regularised lower incomplete gamma P(a, x)."""
    if x < 0.0 or a <= 0.0:
        return math.nan
    if x == 0.0:
        return 0.0
    if x < a + 1.0:
        return _gamma_series(a, x)
    return 1.0 - _gamma_continued_fraction(a, x)


def gamma_q(a: float, x: float) -> float:
    """Regularised upper incomplete gamma Q(a, x) = 1 - P(a, x)."""
    if x < 0.0 or a <= 0.0:
        return math.nan
    if x == 0.0:
        return 1.0
    if x < a + 1.0:
        return 1.0 - _gamma_series(a, x)
    return _gamma_continued_fraction(a, x)


def chi2_sf(statistic: float, df: float) -> float:
    """Survival function of the chi-square distribution: P(X > statistic).

    Equivalent to ``scipy.stats.chi2.sf(statistic, df)``.
    """
    if df <= 0:
        return math.nan
    if statistic <= 0:
        return 1.0
    return gamma_q(df / 2.0, statistic / 2.0)
