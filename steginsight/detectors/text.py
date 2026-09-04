"""Linguistic and Unicode steganography detection.

Text carriers hide data in characters that render as nothing: zero-width joiners
and non-joiners, variation selectors, Unicode tag characters, and trailing
whitespace patterns. This class of technique has become common for watermarking
LLM output and for exfiltrating data through chat and ticketing systems, where a
payload can be pasted invisibly into an ordinary-looking message.

The tag-character block (U+E0000-U+E007F) deserves particular attention: it can
encode arbitrary ASCII invisibly, and it is the mechanism behind most prompt
injection smuggled through copy-pasted text.
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field

from ..core.evidence import Evidence, Family, Severity

__all__ = ["TextProfile", "analyse_text"]

#: Characters with no visible rendering that can carry a payload.
ZERO_WIDTH = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE / BOM",
    "᠎": "MONGOLIAN VOWEL SEPARATOR",
    "­": "SOFT HYPHEN",
}

#: Bidirectional controls. Legitimate in RTL text; abused to reorder rendering.
BIDI_CONTROLS = {
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩",
}

_TAG_RANGE = range(0xE0000, 0xE0080)
_VARIATION_SELECTORS = set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0))

_TRAILING_WS = re.compile(r"[ \t]+$", re.MULTILINE)


@dataclass(slots=True)
class TextProfile:
    characters: int
    zero_width_counts: dict[str, int] = field(default_factory=dict)
    tag_characters: int = 0
    variation_selectors: int = 0
    bidi_controls: int = 0
    trailing_whitespace_lines: int = 0
    homoglyph_scripts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "characters": self.characters,
            "zero_width_counts": self.zero_width_counts,
            "tag_characters": self.tag_characters,
            "variation_selectors": self.variation_selectors,
            "bidi_controls": self.bidi_controls,
            "trailing_whitespace_lines": self.trailing_whitespace_lines,
            "homoglyph_scripts": self.homoglyph_scripts,
        }


def analyse_text(data: bytes) -> tuple[TextProfile | None, list[Evidence], list[str]]:
    limitations: list[str] = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("utf-16")
        except (UnicodeDecodeError, UnicodeError):
            limitations.append(
                "Carrier is not valid UTF-8 or UTF-16; Unicode steganography checks skipped."
            )
            return None, [], limitations

    profile = TextProfile(characters=len(text))
    evidence: list[Evidence] = []

    counts = Counter(ch for ch in text if ch in ZERO_WIDTH)
    profile.zero_width_counts = {ZERO_WIDTH[ch]: n for ch, n in counts.items()}
    profile.tag_characters = sum(1 for ch in text if ord(ch) in _TAG_RANGE)
    profile.variation_selectors = sum(1 for ch in text if ord(ch) in _VARIATION_SELECTORS)
    profile.bidi_controls = sum(1 for ch in text if ch in BIDI_CONTROLS)
    profile.trailing_whitespace_lines = len(_TRAILING_WS.findall(text))
    profile.homoglyph_scripts = _script_mix(text)

    evidence.extend(_evaluate_tags(profile))
    evidence.extend(_evaluate_zero_width(profile, counts, text))
    evidence.extend(_evaluate_variation_selectors(profile))
    evidence.extend(_evaluate_whitespace(profile, text))
    evidence.extend(_evaluate_homoglyphs(profile))
    evidence.extend(_evaluate_bidi(profile))
    return profile, evidence, limitations


def _evaluate_tags(profile: TextProfile) -> list[Evidence]:
    if profile.tag_characters == 0:
        return []
    return [
        Evidence(
            id="text.unicode-tag-characters",
            family=Family.LINGUISTIC,
            severity=Severity.CRITICAL,
            title=f"{profile.tag_characters:,} Unicode tag characters present",
            detail=(
                "Characters from the tag block (U+E0000-U+E007F) appear in the text. These "
                "render as nothing at all and map one-to-one onto ASCII, so a run of them "
                "encodes arbitrary readable text invisibly. Their only standardised use is "
                "as language tags, deprecated since Unicode 5.1, and as emoji flag sequence "
                f"components. {profile.tag_characters:,} of them is a payload, not a flag."
            ),
            llr=2.3,
            confidence=0.95,
            technique="Unicode tag-character encoding",
            actions=[
                "Decode by subtracting 0xE0000 from each tag code point to recover ASCII",
                "If this text was pasted into an AI system or ticket, treat the decoded "
                "content as a possible prompt-injection payload",
            ],
            measurements={"tag_characters": profile.tag_characters},
        )
    ]


def _evaluate_zero_width(
    profile: TextProfile, counts: Counter[str], text: str
) -> list[Evidence]:
    total = sum(counts.values())
    if total == 0:
        return []

    # A single BOM at the start of a file is entirely ordinary.
    if total == 1 and text.startswith("﻿"):
        return []

    distinct = len(counts)
    density = total / max(1, len(text))
    listed = ", ".join(f"{name} x{n}" for name, n in profile.zero_width_counts.items())

    # Two or more distinct zero-width characters used repeatedly is a binary
    # alphabet. That is a substantially stronger signal than a stray ZWJ.
    if total >= 16 and distinct >= 2:
        capacity = total // 8
        return [
            Evidence(
                id="text.zero-width-encoding",
                family=Family.LINGUISTIC,
                severity=Severity.CRITICAL,
                title=f"{total:,} zero-width characters across {distinct} distinct code points",
                detail=(
                    f"The text contains {listed}. Using two or more distinct invisible "
                    "characters repeatedly gives a binary alphabet, which is how zero-width "
                    f"encoders carry data. At one bit per character this is roughly "
                    f"{capacity:,} bytes of capacity. Ordinary text picks up the occasional "
                    "joiner from emoji or Indic scripts, but not in alternating runs."
                ),
                llr=2.0,
                confidence=0.9,
                technique="Zero-width character encoding",
                actions=[
                    "Map the two most frequent zero-width code points to 0 and 1 and decode "
                    "the resulting bitstream as ASCII or UTF-8",
                    "python3 -c \"import sys;print(''.join(f'{ord(c):04X} ' for c in "
                    "open(sys.argv[1],encoding='utf-8').read() if ord(c)>0x2000))\" '{file}'",
                ],
                measurements={
                    "total": total,
                    "distinct": distinct,
                    "density": round(density, 6),
                    "estimated_capacity_bytes": capacity,
                },
            )
        ]

    if total >= 8:
        return [
            Evidence(
                id="text.zero-width-present",
                family=Family.LINGUISTIC,
                severity=Severity.MEDIUM,
                title=f"{total:,} zero-width characters present",
                detail=(
                    f"The text contains {listed}. Emoji sequences and Arabic or Indic script "
                    "use joiners legitimately, and copy-pasted web content often carries a few. "
                    "Only one distinct code point is repeated here, which is weaker than the "
                    "two-symbol alphabet an encoder needs."
                ),
                llr=0.5,
                confidence=0.7,
                measurements={"total": total, "distinct": distinct},
            )
        ]
    return []


def _evaluate_variation_selectors(profile: TextProfile) -> list[Evidence]:
    if profile.variation_selectors < 16:
        return []
    return [
        Evidence(
            id="text.variation-selector-payload",
            family=Family.LINGUISTIC,
            severity=Severity.HIGH,
            title=f"{profile.variation_selectors:,} variation selectors present",
            detail=(
                "Variation selectors modify how the *preceding* character renders, and there "
                "is normally at most one per base character. A long run of them encodes a "
                "byte each while remaining invisible — a technique that gained currency for "
                "hiding data inside single emoji."
            ),
            llr=1.6,
            confidence=0.85,
            technique="Variation-selector encoding",
            actions=[
                "Map selectors U+FE00-FE0F and U+E0100-E01EF back to byte values and decode"
            ],
            measurements={"variation_selectors": profile.variation_selectors},
        )
    ]


def _evaluate_whitespace(profile: TextProfile, text: str) -> list[Evidence]:
    lines = text.count("\n") + 1
    flagged = profile.trailing_whitespace_lines
    if flagged < 16 or lines < 8:
        return []
    ratio = flagged / lines
    if ratio < 0.5:
        return []

    # Distinguish "sloppy editor" from "encoded payload": an encoder produces
    # varied run lengths, whereas stray whitespace is usually a single space.
    runs = [len(m.group(0)) for m in _TRAILING_WS.finditer(text)]
    distinct_lengths = len(set(runs))
    mixed_tabs = any("\t" in m.group(0) for m in _TRAILING_WS.finditer(text))

    if distinct_lengths < 3 and not mixed_tabs:
        return []

    return [
        Evidence(
            id="text.whitespace-encoding",
            family=Family.LINGUISTIC,
            severity=Severity.HIGH,
            title=f"{flagged:,} lines end with varied trailing whitespace",
            detail=(
                f"{ratio:.0%} of lines carry trailing whitespace, in {distinct_lengths} "
                f"distinct run lengths{' and mixing tabs with spaces' if mixed_tabs else ''}. "
                "Editors that leave trailing whitespace leave it uniformly; varied runs of "
                "mixed tabs and spaces at line ends is the encoding used by SNOW and similar "
                "whitespace steganography tools."
            ),
            llr=1.4,
            confidence=0.8,
            technique="Whitespace encoding (SNOW family)",
            actions=[
                "stegsnow -C '{file}' — attempt extraction with the reference implementation",
                "cat -A '{file}' | less — render whitespace visibly for manual inspection",
            ],
            measurements={
                "lines_with_trailing_whitespace": flagged,
                "total_lines": lines,
                "distinct_run_lengths": distinct_lengths,
                "mixed_tabs": mixed_tabs,
            },
        )
    ]


def _evaluate_homoglyphs(profile: TextProfile) -> list[Evidence]:
    scripts = profile.homoglyph_scripts
    if len(scripts) < 2:
        return []
    total = sum(scripts.values())
    dominant = max(scripts, key=lambda k: scripts[k])
    minority = {k: v for k, v in scripts.items() if k != dominant}
    minority_total = sum(minority.values())
    if minority_total == 0 or total == 0:
        return []
    share = minority_total / total

    # A handful of Cyrillic letters inside otherwise Latin prose is the classic
    # homoglyph substitution. Genuinely multilingual text has a much larger share.
    if 0 < share < 0.02 and minority_total >= 4:
        listed = ", ".join(f"{k} x{v}" for k, v in sorted(minority.items(), key=lambda t: -t[1]))
        return [
            Evidence(
                id="text.homoglyph-substitution",
                family=Family.LINGUISTIC,
                severity=Severity.MEDIUM,
                title=f"Isolated non-{dominant} letters mixed into {dominant} text ({listed})",
                detail=(
                    f"The text is {1 - share:.1%} {dominant} but contains {minority_total} "
                    f"letters from other scripts: {listed}. Characters such as Cyrillic 'а' "
                    "and Greek 'ο' are visually identical to their Latin counterparts, so "
                    "substituting them encodes bits invisibly, and is also used to evade "
                    "keyword filters and to spoof domain names. A genuinely multilingual "
                    "document would show a far larger minority share than this."
                ),
                llr=1.0,
                confidence=0.75,
                technique="Homoglyph substitution",
                actions=[
                    "Normalise with unicodedata and diff against the original to list every "
                    "substituted character and its position"
                ],
                measurements={"scripts": scripts, "minority_share": round(share, 6)},
            )
        ]
    return []


def _evaluate_bidi(profile: TextProfile) -> list[Evidence]:
    if profile.bidi_controls < 4:
        return []
    return [
        Evidence(
            id="text.bidi-controls",
            family=Family.LINGUISTIC,
            severity=Severity.MEDIUM,
            title=f"{profile.bidi_controls} bidirectional control characters present",
            detail=(
                "Bidi overrides and isolates reorder how text renders without changing the "
                "underlying bytes. They are legitimate in Arabic and Hebrew content, and are "
                "also the mechanism behind 'Trojan Source' attacks, where source code reads "
                "one way to a human and another to a compiler."
            ),
            llr=0.5,
            confidence=0.7,
            technique="Bidirectional override",
            references=["https://trojansource.codes/"],
            measurements={"bidi_controls": profile.bidi_controls},
        )
    ]


def _script_mix(text: str) -> dict[str, int]:
    """Count alphabetic characters by Unicode script family."""
    counts: Counter[str] = Counter()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        script = name.split(" ")[0]
        if script in {"LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC"}:
            counts[script.capitalize()] += 1
    return dict(counts)
