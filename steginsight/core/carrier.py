"""The exhibit under examination."""

from __future__ import annotations

import hashlib
import mimetypes
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .signatures import FileMagic, identify_format

__all__ = ["Carrier", "CarvedObject", "Hashes", "StructuralNode"]

#: Files above this size are analysed from a bounded sample rather than in full,
#: with the limitation recorded in the report. An analyst is better served by a
#: partial answer plus an explicit caveat than by an OOM kill.
DEFAULT_MAX_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Hashes:
    md5: str
    sha1: str
    sha256: str

    def to_dict(self) -> dict[str, str]:
        return {"md5": self.md5, "sha1": self.sha1, "sha256": self.sha256}


@dataclass(slots=True)
class StructuralNode:
    """One chunk, box or segment of the carrier's container structure."""

    id: str
    offset: int
    length: int
    label: str = ""
    entropy: float | None = None
    #: Result of the format's own integrity check (CRC-32, checksum), when it
    #: has one. ``"unchecked"`` where the format provides none.
    integrity: str = "unchecked"
    children: list[StructuralNode] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "offset": self.offset,
            "length": self.length,
            "label": self.label,
            "integrity": self.integrity,
        }
        if self.entropy is not None:
            out["entropy"] = round(self.entropy, 4)
        if self.children:
            out["children"] = [c.to_dict() for c in self.children]
        return out


@dataclass(slots=True)
class CarvedObject:
    """An embedded object recovered from the carrier.

    Only objects that were actually located are recorded. The previous engine's
    ``extractPayload`` returned the final 2 KB of any file whose tail looked
    random, presenting invented bytes as a recovered payload; nothing here
    fabricates content.
    """

    offset: int
    length: int
    format: str
    description: str
    data: bytes
    #: True when the recovered object was validated by parsing it, not merely by
    #: matching a magic number.
    verified: bool = False

    def to_dict(self, preview_bytes: int = 64) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "length": self.length,
            "format": self.format,
            "description": self.description,
            "verified": self.verified,
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "preview_hex": self.data[:preview_bytes].hex(),
        }


@dataclass(slots=True)
class Carrier:
    """A loaded exhibit plus its identity."""

    path: Path
    data: bytes
    hashes: Hashes
    #: MIME type guessed from the filename. May be absent, and may be a lie.
    declared_type: str | None
    #: Format identified from magic bytes. Authoritative.
    detected: FileMagic | None
    #: True when the exhibit was larger than the read cap and was truncated.
    truncated: bool = False
    #: Size on disk, which may exceed ``len(data)`` when truncated.
    full_size: int = 0

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def format_name(self) -> str:
        return self.detected.name if self.detected else "unknown"

    @property
    def type_mismatch(self) -> bool:
        """True when the declared type contradicts the magic bytes.

        Reported as a finding in its own right: renaming ``payload.zip`` to
        ``holiday.jpg`` is the simplest concealment technique there is, and it
        costs nothing to check.
        """
        if self.detected is None or not self.declared_type:
            return False
        family = self.declared_type.split("/", 1)[0]
        name = self.detected.name
        expected = {
            "image": {"png", "jpeg", "gif", "bmp", "tiff", "webp"},
            "audio": {"riff", "ogg", "flac", "mp3", "isobmff"},
            "video": {"isobmff", "matroska", "riff", "ogg"},
            "application": {
                "pdf", "zip", "rar", "rar5", "7z", "gzip", "bzip2", "xz",
                "sqlite", "elf", "pe", "rtf", "cab", "isobmff",
            },
            "text": set(),
        }
        allowed = expected.get(family)
        if allowed is None:
            return False
        if family == "text":
            # Any recognised binary format under a text/* declaration is a lie.
            return name not in {"unknown"}
        return name not in allowed

    @classmethod
    def load(cls, path: str | os.PathLike[str], max_bytes: int = DEFAULT_MAX_BYTES) -> Carrier:
        p = Path(path)
        full_size = p.stat().st_size
        truncated = full_size > max_bytes

        with p.open("rb") as handle:
            data = handle.read(max_bytes)

        # Hash the whole file even when the analysis sample is truncated: the
        # report must identify the exhibit, not the portion that was convenient.
        if truncated:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            with p.open("rb") as handle:
                for block in iter(lambda: handle.read(1 << 20), b""):
                    md5.update(block)
                    sha1.update(block)
                    sha256.update(block)
            hashes = Hashes(md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest())
        else:
            hashes = Hashes(
                hashlib.md5(data).hexdigest(),
                hashlib.sha1(data).hexdigest(),
                hashlib.sha256(data).hexdigest(),
            )

        declared, _ = mimetypes.guess_type(p.name)
        return cls(
            path=p,
            data=data,
            hashes=hashes,
            declared_type=declared,
            detected=identify_format(data),
            truncated=truncated,
            full_size=full_size,
        )

    @classmethod
    def from_bytes(cls, data: bytes, name: str = "memory.bin") -> Carrier:
        """Build a carrier from an in-memory buffer. Used by the test-suite."""
        declared, _ = mimetypes.guess_type(name)
        return cls(
            path=Path(name),
            data=data,
            hashes=Hashes(
                hashlib.md5(data).hexdigest(),
                hashlib.sha1(data).hexdigest(),
                hashlib.sha256(data).hexdigest(),
            ),
            declared_type=declared,
            detected=identify_format(data),
            truncated=False,
            full_size=len(data),
        )

    def identity_dict(self) -> dict[str, Any]:
        return {
            "name": self.path.name,
            "path": str(self.path),
            "size": self.full_size,
            "analysed_bytes": self.size,
            "truncated": self.truncated,
            "declared_type": self.declared_type,
            "detected_format": self.format_name,
            "detected_description": self.detected.description if self.detected else None,
            "type_mismatch": self.type_mismatch,
            "hashes": self.hashes.to_dict(),
        }
