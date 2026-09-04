"""PDF structural analysis.

Calibration note
----------------
The previous engine matched ``/xref\\b/gi``, which also matches the ``xref``
inside ``startxref``. Every conforming PDF contains both, so *every PDF ever
scanned* was reported as "CRITICAL: Redundant XRef Tables". It also treated more
than one ``%%EOF`` as critical, but linearised PDFs and any document that has
been annotated, form-filled or digitally signed carry several by design —
incremental update is the format's normal mode of operation, not an attack.

This parser reports those as neutral context and reserves positive likelihood
for things that genuinely require explanation: bytes after the final ``%%EOF``,
embedded file attachments, and automatically-executing actions.
"""

from __future__ import annotations

import re

from ..core.carrier import StructuralNode
from ..core.evidence import Evidence, Family, Severity
from .base import ContainerResult, analyse_trailing_region

__all__ = ["parse_pdf"]

_EOF = re.compile(rb"%%EOF")
# `xref` only when it starts a token, so `startxref` does not match.
_XREF_TABLE = re.compile(rb"(?<![A-Za-z])xref\b")
_EMBEDDED_FILE = re.compile(rb"/EmbeddedFile[s]?\b")
_JAVASCRIPT = re.compile(rb"/JavaScript\b|/JS\b")
_OPEN_ACTION = re.compile(rb"/OpenAction\b")
_LAUNCH = re.compile(rb"/Launch\b")
_OBJSTM = re.compile(rb"/ObjStm\b")
_RICH_MEDIA = re.compile(rb"/RichMedia\b|/Movie\b|/Sound\b")


def parse_pdf(data: bytes) -> ContainerResult:
    result = ContainerResult()
    if not data.startswith(b"%PDF-"):
        result.limitations.append("No %PDF- header; PDF parser skipped.")
        return result

    version = data[5:8].decode("ascii", "replace")
    result.nodes.append(
        StructuralNode(id="HEADER", offset=0, length=8, label=f"PDF {version} header")
    )

    eofs = list(_EOF.finditer(data))
    xrefs = list(_XREF_TABLE.finditer(data))
    updates = max(0, len(eofs) - 1)

    if eofs:
        last = eofs[-1]
        logical_end = last.end()
        result.nodes.append(
            StructuralNode(
                id="EOF",
                offset=last.start(),
                length=5,
                label="Final end-of-file marker",
            )
        )

        # Trailing whitespace after %%EOF is normal and must not be reported.
        remainder = data[logical_end:]
        if remainder.strip(b"\r\n \t\x00"):
            result.extend(analyse_trailing_region(data, logical_end, format_label="PDF"))
        else:
            result.logical_end = len(data)
    else:
        result.limitations.append(
            "No %%EOF marker found; the document is truncated and trailing-data "
            "analysis could not be performed."
        )

    # --- Neutral context, not evidence ------------------------------------
    if updates:
        result.evidence.append(
            Evidence(
                id="pdf.incremental-updates",
                family=Family.STRUCTURE,
                severity=Severity.INFO,
                title=f"Document contains {updates} incremental update(s)",
                detail=(
                    f"{len(eofs)} %%EOF markers and {len(xrefs)} cross-reference table(s) are "
                    "present. Incremental update is how PDF records annotations, form data and "
                    "digital signatures, so this is expected in any document that has been "
                    "edited or signed. It is recorded because earlier revisions may retain "
                    "content that the current revision hides — worth extracting if the "
                    "document's history is in question — but it is not itself an anomaly."
                ),
                llr=0.0,
                confidence=1.0,
                actions=[
                    "qpdf --qdf --object-streams=disable '{file}' expanded.pdf — expose all revisions",
                    "pdf-parser.py --stats '{file}' — enumerate objects per revision",
                ],
                measurements={"eof_markers": len(eofs), "xref_tables": len(xrefs)},
            )
        )

    if _OBJSTM.search(data):
        result.evidence.append(
            Evidence(
                id="pdf.object-streams",
                family=Family.STRUCTURE,
                severity=Severity.INFO,
                title="Document uses compressed object streams",
                detail=(
                    "/ObjStm appears in the document. Object streams are the default in "
                    "PDF 1.5 and later and are present in most modern files. They do hide "
                    "objects from naive string scanners, so decompress before searching."
                ),
                llr=0.0,
                confidence=1.0,
                actions=["qpdf --qdf --object-streams=disable '{file}' expanded.pdf"],
            )
        )

    # --- Actual payload vectors -------------------------------------------
    if _EMBEDDED_FILE.search(data):
        count = len(_EMBEDDED_FILE.findall(data))
        result.evidence.append(
            Evidence(
                id="pdf.embedded-files",
                family=Family.STRUCTURE,
                severity=Severity.HIGH,
                title=f"Document carries {count} embedded file attachment(s)",
                detail=(
                    "/EmbeddedFile entries mean arbitrary files travel inside this document. "
                    "This is a documented PDF feature used legitimately for invoices and "
                    "supporting data, and it is also the most direct way to move a payload "
                    "inside a document that opens normally. Extract and examine the "
                    "attachments individually."
                ),
                llr=1.1,
                confidence=0.95,
                technique="PDF file attachment",
                actions=[
                    "pdfdetach -saveall -o ./attachments '{file}' — extract every attachment",
                    "pdfid.py '{file}' — summarise risky structure counts",
                ],
                references=["https://blog.didierstevens.com/programs/pdf-tools/"],
                measurements={"embedded_file_entries": count},
            )
        )

    has_js = bool(_JAVASCRIPT.search(data))
    has_open_action = bool(_OPEN_ACTION.search(data))
    if has_js and has_open_action:
        result.evidence.append(
            Evidence(
                id="pdf.auto-executing-javascript",
                family=Family.STRUCTURE,
                severity=Severity.HIGH,
                title="JavaScript combined with an automatic open action",
                detail=(
                    "The document contains both JavaScript and an /OpenAction, so code runs "
                    "as soon as the file is opened in a reader that permits it. This is a "
                    "malicious-document indicator rather than a steganography one; the "
                    "distinction matters for how the exhibit should be handled — treat it as "
                    "live malware until cleared, and open it only in an isolated environment."
                ),
                llr=0.9,
                confidence=0.9,
                technique="Auto-executing script",
                actions=[
                    "pdf-parser.py --search javascript --raw '{file}' — read the script",
                    "Detonate only in an isolated VM with no network route",
                ],
            )
        )
    elif has_js:
        result.evidence.append(
            Evidence(
                id="pdf.javascript",
                family=Family.STRUCTURE,
                severity=Severity.MEDIUM,
                title="Document contains JavaScript",
                detail=(
                    "JavaScript is present but not wired to an automatic open action. Forms "
                    "and calculated fields use it legitimately. Read it before drawing a "
                    "conclusion."
                ),
                llr=0.3,
                confidence=0.85,
                actions=["pdf-parser.py --search javascript --raw '{file}'"],
            )
        )

    if _LAUNCH.search(data):
        result.evidence.append(
            Evidence(
                id="pdf.launch-action",
                family=Family.STRUCTURE,
                severity=Severity.HIGH,
                title="/Launch action present",
                detail=(
                    "A /Launch action asks the reader to execute an external program or open "
                    "an external file. Modern readers block it by default, which is precisely "
                    "why its presence is notable."
                ),
                llr=1.0,
                confidence=0.9,
                actions=["pdf-parser.py --search launch --raw '{file}'"],
            )
        )

    if _RICH_MEDIA.search(data):
        result.evidence.append(
            Evidence(
                id="pdf.rich-media",
                family=Family.STRUCTURE,
                severity=Severity.LOW,
                title="Embedded rich media object present",
                detail=(
                    "/RichMedia, /Movie or /Sound entries embed a media stream inside the "
                    "document. The media stream is itself a carrier and should be extracted "
                    "and analysed in its own right."
                ),
                llr=0.4,
                confidence=0.8,
                actions=["pdfdetach -saveall -o ./attachments '{file}'"],
            )
        )

    return result
