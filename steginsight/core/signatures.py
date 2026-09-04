"""Byte-level signature database and scanner.

Design notes
------------
The previous engine lowercased 200 KB of the file and ran ``str.contains`` for
words like ``"camouflage"`` and ``"outguess"``, scoring +80 CRITICAL on a match.
A holiday photo whose EXIF caption mentions camouflage was reported as
steganography. Three things are different here:

1. Patterns are **bytes**, matched exactly, with position recorded.
2. Patterns are matched in a **single compiled regex alternation**, so the scan
   is one linear C-speed pass rather than one Python pass per pattern.
3. A signature's weight depends on *where* it was found and whether the claimed
   structure actually parses. A ZIP magic number that is followed by a valid,
   walkable central directory is proof; the same four bytes appearing inside
   compressed image data are noise.

Honesty about coverage
----------------------
Several widely-cited tools genuinely have **no** plaintext signature — steghide,
OutGuess, F5 and JPHide all encrypt the payload and embed it in coefficients or
samples, leaving nothing to string-match. The previous engine listed them anyway
and claimed detection. They are absent here by design; those tools are addressed
by the statistical and transform-domain detectors instead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

__all__ = [
    "FILE_MAGICS",
    "TOOL_MARKERS",
    "FileMagic",
    "MagicHit",
    "MarkerHit",
    "ToolMarker",
    "identify_format",
    "scan_file_magics",
    "scan_tool_markers",
]

Reliability = Literal["proof", "strong", "indicative"]


@dataclass(frozen=True, slots=True)
class FileMagic:
    """A file-format magic number."""

    name: str
    pattern: bytes
    #: Byte offset the pattern must appear at to identify the *carrier*.
    #: ``None`` means the pattern may appear anywhere (used for carving).
    offset: int | None = 0
    description: str = ""
    #: Typical file extension, for naming carved output.
    extension: str = "bin"


@dataclass(frozen=True, slots=True)
class ToolMarker:
    """A marker attributable to a specific steganography tool."""

    tool: str
    pattern: bytes
    reliability: Reliability
    note: str
    references: tuple[str, ...] = ()


# --------------------------------------------------------------------------
# File-format magic numbers
# --------------------------------------------------------------------------
# Used both to identify the carrier and to carve embedded objects. These are
# unambiguous, standardised constants — unlike tool "signatures", they are safe
# to rely on when corroborated by a successful structural parse.

FILE_MAGICS: tuple[FileMagic, ...] = (
    # Images
    FileMagic("png", b"\x89PNG\r\n\x1a\n", 0, "Portable Network Graphics", "png"),
    FileMagic("jpeg", b"\xff\xd8\xff", 0, "JPEG image", "jpg"),
    FileMagic("gif", b"GIF87a", 0, "GIF image (87a)", "gif"),
    FileMagic("gif", b"GIF89a", 0, "GIF image (89a)", "gif"),
    FileMagic("bmp", b"BM", 0, "Windows bitmap", "bmp"),
    FileMagic("tiff", b"II\x2a\x00", 0, "TIFF image (little-endian)", "tif"),
    FileMagic("tiff", b"MM\x00\x2a", 0, "TIFF image (big-endian)", "tif"),
    FileMagic("webp", b"WEBP", 8, "WebP image", "webp"),
    # Containers / media
    FileMagic("riff", b"RIFF", 0, "RIFF container (WAV/AVI/WebP)", "wav"),
    FileMagic("isobmff", b"ftyp", 4, "ISO base media file (MP4/MOV/3GP)", "mp4"),
    FileMagic("matroska", b"\x1a\x45\xdf\xa3", 0, "Matroska / WebM", "mkv"),
    FileMagic("ogg", b"OggS", 0, "Ogg container", "ogg"),
    FileMagic("flac", b"fLaC", 0, "FLAC audio", "flac"),
    FileMagic("mp3", b"ID3", 0, "MP3 with ID3v2 tag", "mp3"),
    # Documents
    FileMagic("pdf", b"%PDF-", 0, "PDF document", "pdf"),
    FileMagic("rtf", b"{\\rtf", 0, "Rich Text Format", "rtf"),
    # Archives — the payloads most often appended to a carrier
    FileMagic("zip", b"PK\x03\x04", None, "ZIP archive (local file header)", "zip"),
    FileMagic("zip-empty", b"PK\x05\x06", None, "ZIP end-of-central-directory", "zip"),
    FileMagic("rar", b"Rar!\x1a\x07\x00", None, "RAR archive (v4)", "rar"),
    FileMagic("rar5", b"Rar!\x1a\x07\x01\x00", None, "RAR archive (v5)", "rar"),
    FileMagic("7z", b"7z\xbc\xaf\x27\x1c", None, "7-Zip archive", "7z"),
    FileMagic("gzip", b"\x1f\x8b\x08", None, "gzip stream", "gz"),
    FileMagic("bzip2", b"BZh", None, "bzip2 stream", "bz2"),
    FileMagic("xz", b"\xfd7zXZ\x00", None, "XZ stream", "xz"),
    FileMagic("zstd", b"\x28\xb5\x2f\xfd", None, "Zstandard stream", "zst"),
    FileMagic("tar", b"ustar", 257, "POSIX tar archive", "tar"),
    FileMagic("cab", b"MSCF", None, "Microsoft Cabinet", "cab"),
    # Executables — an appended binary is a materially different finding
    FileMagic("elf", b"\x7fELF", None, "ELF executable", "elf"),
    FileMagic("pe", b"MZ", 0, "DOS/PE executable", "exe"),
    FileMagic("macho64", b"\xcf\xfa\xed\xfe", None, "Mach-O 64-bit", "macho"),
    FileMagic("class", b"\xca\xfe\xba\xbe", None, "Java class / Mach-O fat", "class"),
    # Crypto containers — high-value finds
    FileMagic("openssl-salted", b"Salted__", None, "OpenSSL enc(1) salted stream", "enc"),
    FileMagic("pgp", b"\x85\x02", None, "OpenPGP message packet", "pgp"),
    FileMagic("gpg-armor", b"-----BEGIN PGP", None, "ASCII-armoured PGP block", "asc"),
    FileMagic("luks", b"LUKS\xba\xbe", None, "LUKS encrypted volume", "luks"),
    FileMagic("ssh-key", b"-----BEGIN OPENSSH PRIVATE KEY", None, "OpenSSH private key", "key"),
    FileMagic("rsa-key", b"-----BEGIN RSA PRIVATE KEY", None, "PEM RSA private key", "key"),
    # Data
    FileMagic("sqlite", b"SQLite format 3\x00", None, "SQLite 3 database", "sqlite"),
    FileMagic("script-sh", b"#!/bin/sh", None, "Shell script", "sh"),
    FileMagic("script-bash", b"#!/bin/bash", None, "Bash script", "sh"),
    FileMagic("script-python", b"#!/usr/bin/env python", None, "Python script", "py"),
)


# --------------------------------------------------------------------------
# Tool markers
# --------------------------------------------------------------------------
# Only tools that genuinely leave a byte-level artefact appear here. Each entry
# carries an explicit reliability rating that feeds the likelihood ratio, and a
# note stating what is actually known. Where a claim is community-sourced rather
# than drawn from a specification, the note says so and the rating is lowered.

TOOL_MARKERS: tuple[ToolMarker, ...] = (
    ToolMarker(
        tool="DeepSound",
        pattern=b"DSCF",
        reliability="strong",
        note=(
            "DeepSound writes a 'DSCF' container header into the carrier's audio data "
            "region. Widely reproduced in casework and CTF write-ups; not drawn from a "
            "published specification, so corroborate before relying on it."
        ),
        references=("https://github.com/Jpinsoft/DeepSound",),
    ),
    ToolMarker(
        tool="OpenStego",
        pattern=b"\x00OpenStego",
        reliability="strong",
        note="OpenStego embeds its product string in the payload header of some versions.",
        references=("https://www.openstego.com/",),
    ),
    ToolMarker(
        tool="SilentEye",
        pattern=b"SilentEye",
        reliability="indicative",
        note=(
            "Literal product string. May equally originate from a filename, a comment "
            "field, or unrelated text within the carrier."
        ),
    ),
    ToolMarker(
        tool="steghide",
        pattern=b"steghide",
        reliability="indicative",
        note=(
            "steghide encrypts its payload and leaves no header, so this can only be an "
            "incidental string — a filename, a log fragment, or a comment. It is NOT "
            "evidence that steghide was used. Detection of steghide relies on the "
            "statistical detectors instead."
        ),
    ),
    ToolMarker(
        tool="Camouflage",
        pattern=b"\x20\x00\x00\x00\x43\x61\x6d\x6f\x75\x66\x6c\x61\x67\x65",
        reliability="strong",
        note="Camouflage appends a structured trailer containing its product name.",
    ),
    ToolMarker(
        tool="Invisible Secrets",
        pattern=b"Invisible Secrets",
        reliability="indicative",
        note="Literal product string; treat as a lead, not a conclusion.",
    ),
)


@dataclass(frozen=True, slots=True)
class MagicHit:
    magic: FileMagic
    offset: int


@dataclass(frozen=True, slots=True)
class MarkerHit:
    marker: ToolMarker
    offset: int


def _build_scanner(patterns: list[bytes]) -> re.Pattern[bytes]:
    """Compile one alternation so scanning is a single linear pass."""
    # Longest first, so the regex engine prefers the more specific pattern where
    # two signatures share a prefix (e.g. RAR v4 vs v5).
    ordered = sorted(set(patterns), key=len, reverse=True)
    return re.compile(b"|".join(b"(?:" + re.escape(p) + b")" for p in ordered), re.DOTALL)


_CARVE_MAGICS = tuple(m for m in FILE_MAGICS if m.offset is None)
_MAGIC_BY_PATTERN: dict[bytes, FileMagic] = {}
for _m in _CARVE_MAGICS:
    _MAGIC_BY_PATTERN.setdefault(_m.pattern, _m)

_MAGIC_SCANNER = _build_scanner(list(_MAGIC_BY_PATTERN))

_MARKER_BY_PATTERN: dict[bytes, ToolMarker] = {m.pattern: m for m in TOOL_MARKERS}
_MARKER_SCANNER = _build_scanner(list(_MARKER_BY_PATTERN))


def identify_format(data: bytes) -> FileMagic | None:
    """Identify the carrier from its magic bytes, ignoring the declared type.

    A mismatch between this and the extension or MIME type is itself a finding:
    it is the cheapest possible detection of a disguised file.
    """
    best: FileMagic | None = None
    for magic in FILE_MAGICS:
        # Formats registered for carving (offset None) can equally *be* the whole
        # file: an archive renamed to .jpg is the cheapest concealment there is,
        # and it is only caught if the archive's own magic identifies the carrier.
        offset = 0 if magic.offset is None else magic.offset
        end = offset + len(magic.pattern)
        # Prefer the longest match: "BM" must not beat a real container.
        if (
            len(data) >= end
            and data[offset:end] == magic.pattern
            and (best is None or len(magic.pattern) > len(best.pattern))
        ):
            best = magic
    return best


def scan_file_magics(data: bytes, start: int = 0, limit: int = 4096) -> list[MagicHit]:
    """Find embedded file signatures anywhere in ``data`` at or after ``start``.

    ``limit`` caps the number of hits returned. Compressed carriers produce
    incidental four-byte coincidences; the caller is responsible for deciding
    which hits are meaningful, normally by attempting to parse them.
    """
    hits: list[MagicHit] = []
    for match in _MAGIC_SCANNER.finditer(data, start):
        magic = _MAGIC_BY_PATTERN.get(match.group(0))
        if magic is None:
            continue
        hits.append(MagicHit(magic=magic, offset=match.start()))
        if len(hits) >= limit:
            break
    return hits


def scan_tool_markers(data: bytes) -> list[MarkerHit]:
    hits: list[MarkerHit] = []
    seen: set[tuple[str, int]] = set()
    for match in _MARKER_SCANNER.finditer(data):
        marker = _MARKER_BY_PATTERN.get(match.group(0))
        if marker is None:
            continue
        key = (marker.tool, match.start())
        if key in seen:
            continue
        seen.add(key)
        hits.append(MarkerHit(marker=marker, offset=match.start()))
    return hits


#: Likelihood ratio contributed by a tool marker, by reliability rating.
MARKER_LLR: dict[Reliability, float] = {
    "proof": 2.3,
    "strong": 1.5,
    "indicative": 0.35,
}
