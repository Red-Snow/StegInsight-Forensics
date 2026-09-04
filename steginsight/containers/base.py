"""Shared plumbing for container parsers."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.carrier import CarvedObject, StructuralNode
from ..core.evidence import Evidence, Family, Severity
from ..core.signatures import scan_file_magics
from ..core.stats import expected_random_entropy, shannon_entropy

__all__ = ["ContainerResult", "analyse_trailing_region", "describe_region"]


@dataclass(slots=True)
class ContainerResult:
    """What a format parser learned about a carrier."""

    nodes: list[StructuralNode] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    carved: list[CarvedObject] = field(default_factory=list)
    #: Offset at which the container's own structure legitimately ends.
    #: ``None`` when the parser could not establish one.
    logical_end: int | None = None
    #: Notes about what the parser could *not* do, surfaced in the report.
    limitations: list[str] = field(default_factory=list)

    def extend(self, other: ContainerResult) -> None:
        self.nodes.extend(other.nodes)
        self.evidence.extend(other.evidence)
        self.carved.extend(other.carved)
        self.limitations.extend(other.limitations)


def describe_region(data: bytes) -> tuple[str, str, bool]:
    """Identify what a block of bytes appears to be.

    Returns ``(format_name, description, verified)``. ``verified`` is True only
    when the identification was confirmed by parsing the object, not merely by
    matching a magic number — a distinction that decides whether the finding is
    proof or a lead.
    """
    if not data:
        return "empty", "empty region", False

    hits = scan_file_magics(data, 0, limit=8)
    leading = [h for h in hits if h.offset == 0]
    if leading:
        magic = leading[0].magic
        # A ZIP is worth confirming properly; a real archive is unambiguous.
        if magic.name.startswith("zip"):
            from .zip_probe import probe_zip

            probe = probe_zip(data)
            if probe is not None:
                names = ", ".join(probe.names[:5])
                more = "" if len(probe.names) <= 5 else f" (+{len(probe.names) - 5} more)"
                return (
                    "zip",
                    f"valid ZIP archive containing {len(probe.names)} entr"
                    f"{'y' if len(probe.names) == 1 else 'ies'}: {names}{more}",
                    True,
                )
        return magic.name, magic.description, False

    entropy = shannon_entropy(data)
    if entropy >= expected_random_entropy(len(data)) - 0.05:
        return "random", "compressed or encrypted data of unrecognised type", False

    printable = sum(1 for b in data[:4096] if 0x20 <= b <= 0x7E or b in (9, 10, 13))
    if printable / max(1, min(len(data), 4096)) > 0.9:
        return "text", "printable text", False

    return "unknown", "unrecognised binary data", False


def analyse_trailing_region(
    data: bytes,
    logical_end: int,
    *,
    format_label: str,
    min_bytes: int = 8,
) -> ContainerResult:
    """Examine whatever follows a container's legitimate end.

    Appending a payload past the end-of-file marker is the single most common
    concealment technique, because every viewer ignores it and the carrier still
    renders. It is also the easiest to prove: the bytes are simply *there*, and
    if they parse as an archive there is nothing left to argue about.
    """
    result = ContainerResult(logical_end=logical_end)
    trailing = data[logical_end:]
    if len(trailing) < min_bytes:
        return result

    fmt, description, verified = describe_region(trailing)
    entropy = shannon_entropy(trailing)

    result.nodes.append(
        StructuralNode(
            id="TRAILING",
            offset=logical_end,
            length=len(trailing),
            label=f"Data after {format_label} end-of-stream",
            entropy=entropy,
        )
    )
    result.carved.append(
        CarvedObject(
            offset=logical_end,
            length=len(trailing),
            format=fmt,
            description=description,
            data=trailing,
            verified=verified,
        )
    )

    if verified:
        llr, severity = 2.3, Severity.CRITICAL
    elif fmt not in {"unknown", "random", "empty"}:
        llr, severity = 1.7, Severity.CRITICAL
    elif fmt == "random":
        llr, severity = 1.2, Severity.HIGH
    else:
        llr, severity = 0.9, Severity.HIGH

    result.evidence.append(
        Evidence(
            id=f"{format_label.lower()}.trailing-data",
            family=Family.STRUCTURE,
            severity=severity,
            title=f"{_human_size(len(trailing))} of data after the {format_label} end marker",
            detail=(
                f"The {format_label} stream ends at offset 0x{logical_end:x}, but the file "
                f"continues for a further {len(trailing):,} bytes. The trailing region was "
                f"identified as: {description}. Entropy of the region is {entropy:.3f} "
                f"bits/byte. Decoders ignore this region entirely, so the carrier still "
                f"renders normally."
            ),
            llr=llr,
            confidence=1.0,
            offset=logical_end,
            length=len(trailing),
            technique="Append / EOF concealment",
            actions=[
                "binwalk -e '{file}' — carve the appended object automatically",
                f"dd if='{{file}}' bs=1 skip={logical_end} of=payload.{fmt} — extract it exactly",
            ],
            references=["https://github.com/ReFirmLabs/binwalk"],
            measurements={
                "logical_end": logical_end,
                "trailing_bytes": len(trailing),
                "entropy": round(entropy, 4),
                "identified_as": fmt,
                "verified_by_parse": verified,
            },
        )
    )
    return result


def _human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} GiB"
