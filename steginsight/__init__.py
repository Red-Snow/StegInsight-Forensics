"""StegInsight Forensics — steganalysis and carrier-integrity workbench.

Typical use::

    from steginsight import analyse_path
    report = analyse_path("evidence.png")
    print(report.assessment.verdict, report.assessment.probability)
"""

from .core.carrier import Carrier
from .core.evidence import Assessment, Evidence, Family, Severity, Verdict
from .engine import AnalysisReport, __version__, analyse, analyse_path

__all__ = [
    "AnalysisReport",
    "Assessment",
    "Carrier",
    "Evidence",
    "Family",
    "Severity",
    "Verdict",
    "__version__",
    "analyse",
    "analyse_path",
]
