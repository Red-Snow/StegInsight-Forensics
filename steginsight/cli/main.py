"""Command-line interface.

Two commands:

``scan``    examine one exhibit and report in depth
``triage``  walk a directory and rank what deserves an analyst's attention

Exit codes are meaningful so the tool composes into pipelines: 0 clean,
1 inconclusive, 2 suspicious, 3 likely embedded, 4 usage or I/O error. A triage
run returns the highest code it encountered.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

from ..core.carrier import DEFAULT_MAX_BYTES, Carrier
from ..core.evidence import DEFAULT_PRIOR, Verdict
from ..engine import __version__, analyse
from ..report.text import render_text, supports_colour, verdict_exit_code

EXIT_USAGE = 4

#: Extensions worth examining during a directory walk.
CARRIER_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp",
    ".wav", ".aiff", ".au", ".mp3", ".flac", ".ogg",
    ".mp4", ".mov", ".m4a", ".m4v", ".3gp", ".mkv", ".avi",
    ".pdf", ".txt", ".md", ".csv", ".rtf", ".html", ".htm", ".json",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="steginsight",
        description=(
            "Steganalysis and carrier-integrity workbench for digital forensics. "
            "Analyses images, audio, video containers, documents and text for "
            "concealed payloads, and reports what it could not establish as well "
            "as what it could."
        ),
        epilog=(
            "Exit codes: 0 clean, 1 inconclusive, 2 suspicious, 3 likely embedded, "
            "4 error. Exhibits are never modified, and nothing leaves this machine."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"steginsight {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyse a single exhibit in depth")
    scan.add_argument("path", type=Path, help="file to analyse")
    scan.add_argument("--json", dest="json_out", metavar="FILE", type=Path,
                      help="write the full machine-readable result to FILE ('-' for stdout)")
    scan.add_argument("--html", dest="html_out", metavar="FILE", type=Path,
                      help="write a self-contained offline HTML report to FILE")
    scan.add_argument("--extract", metavar="DIR", type=Path,
                      help="write every recovered object to DIR")
    scan.add_argument("-v", "--verbose", action="store_true",
                      help="show exculpatory and informational findings too")
    scan.add_argument("-q", "--quiet", action="store_true",
                      help="suppress the terminal report; use with --json or --html")
    _shared(scan)

    triage = sub.add_parser("triage", help="walk a directory and rank exhibits")
    triage.add_argument("path", type=Path, help="directory to walk")
    triage.add_argument("-r", "--recursive", action="store_true", help="descend into subdirectories")
    triage.add_argument("--json", dest="json_out", metavar="FILE", type=Path,
                        help="write one JSON summary per exhibit to FILE ('-' for stdout)")
    triage.add_argument("--min-verdict", choices=[v.value for v in Verdict],
                        default=Verdict.INCONCLUSIVE.value,
                        help="only list exhibits at or above this verdict (default: inconclusive)")
    triage.add_argument("--all-files", action="store_true",
                        help="examine every file, not only recognised carrier extensions")
    _shared(triage)

    return parser


def _shared(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--prior", type=float, default=DEFAULT_PRIOR, metavar="P",
        help=(
            "prior probability that a submitted file carries a payload "
            f"(default {DEFAULT_PRIOR}). Raise it when triaging an already-suspicious "
            "corpus; lower it for bulk scanning of ordinary material."
        ),
    )
    parser.add_argument(
        "--max-bytes", type=int, default=DEFAULT_MAX_BYTES, metavar="N",
        help="read at most N bytes for analysis (hashes always cover the whole file)",
    )
    parser.add_argument("--no-colour", action="store_true", help="disable ANSI colour")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not 0.0 < args.prior < 1.0:
        parser.error("--prior must be strictly between 0 and 1")

    try:
        if args.command == "scan":
            return _run_scan(args)
        return _run_triage(args)
    except FileNotFoundError as exc:
        print(f"steginsight: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except PermissionError as exc:
        print(f"steginsight: permission denied: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("\nsteginsight: interrupted", file=sys.stderr)
        return EXIT_USAGE


def _run_scan(args: argparse.Namespace) -> int:
    path: Path = args.path
    if not path.is_file():
        print(f"steginsight: not a file: {path}", file=sys.stderr)
        return EXIT_USAGE

    report = analyse(Carrier.load(path, max_bytes=args.max_bytes), prior=args.prior)

    if not args.quiet:
        colour = supports_colour() and not args.no_colour
        print(render_text(report, colour=colour, verbose=args.verbose))

    if args.json_out:
        payload = json.dumps(report.to_dict(), indent=2)
        _write(args.json_out, payload)

    if args.html_out:
        from ..report.html import render_html

        _write(args.html_out, render_html(report))
        if not args.quiet:
            print(f"  HTML report written to {args.html_out}\n")

    if args.extract:
        written = _extract(report, args.extract)
        if not args.quiet:
            if written:
                print(f"  {len(written)} object(s) written to {args.extract}")
                for name in written:
                    print(f"    {name}")
            else:
                print("  no recoverable objects were located")
            print()

    return verdict_exit_code(report)


def _run_triage(args: argparse.Namespace) -> int:
    root: Path = args.path
    if not root.is_dir():
        print(f"steginsight: not a directory: {root}", file=sys.stderr)
        return EXIT_USAGE

    order = [Verdict.CLEAN, Verdict.INCONCLUSIVE, Verdict.SUSPICIOUS, Verdict.LIKELY_EMBEDDED]
    floor = order.index(Verdict(args.min_verdict))

    results = []
    worst = 0
    for path in _walk(root, recursive=args.recursive, all_files=args.all_files):
        try:
            report = analyse(Carrier.load(path, max_bytes=args.max_bytes), prior=args.prior)
        except (OSError, ValueError) as exc:
            print(f"  ! {path}: {exc}", file=sys.stderr)
            continue
        worst = max(worst, verdict_exit_code(report))
        results.append(report)

    results.sort(key=lambda r: r.assessment.probability, reverse=True)
    listed = [r for r in results if order.index(r.assessment.verdict) >= floor]

    colour = supports_colour() and not args.no_colour
    print()
    print(f"  {len(results)} exhibit(s) examined, {len(listed)} at or above "
          f"'{args.min_verdict}'")
    print()
    if listed:
        for report in listed:
            verdict = report.assessment.verdict
            label = _colourise(verdict, colour)
            top = next((e.title for e in report.evidence if e.llr > 0.2), "")
            name = report.carrier.path.name
            print(f"  {label}  {report.assessment.probability:5.3f}  {name}")
            if top:
                print(f"           {top}")
        print()
    print("  Re-run 'steginsight scan <file>' on any exhibit for the full analysis.")
    print()

    if args.json_out:
        payload = json.dumps(
            [
                {
                    "path": str(r.carrier.path),
                    "sha256": r.carrier.hashes.sha256,
                    **r.assessment.to_dict(),
                    "top_findings": [e.id for e in r.evidence if e.llr > 0.2][:5],
                }
                for r in results
            ],
            indent=2,
        )
        _write(args.json_out, payload)

    return worst


def _walk(root: Path, *, recursive: bool, all_files: bool) -> Iterable[Path]:
    paths = sorted(root.rglob("*") if recursive else root.glob("*"))
    for path in paths:
        if not path.is_file():
            continue
        if not all_files and path.suffix.lower() not in CARRIER_SUFFIXES:
            continue
        yield path


def _extract(report, directory: Path) -> list[str]:  # type: ignore[no-untyped-def]
    directory.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for index, obj in enumerate(report.carved, start=1):
        suffix = _suffix_for(obj.format)
        name = f"{report.carrier.path.stem}_{index:02d}_0x{obj.offset:x}{suffix}"
        target = directory / name
        target.write_bytes(obj.data)
        written.append(name)
    return written


def _suffix_for(fmt: str) -> str:
    return {
        "zip": ".zip", "rar": ".rar", "rar5": ".rar", "7z": ".7z", "gzip": ".gz",
        "bzip2": ".bz2", "xz": ".xz", "pdf": ".pdf", "png": ".png", "jpeg": ".jpg",
        "gif": ".gif", "elf": ".elf", "pe": ".exe", "sqlite": ".sqlite",
        "text": ".txt", "openssl-salted": ".enc",
    }.get(fmt, ".bin")


def _colourise(verdict: Verdict, colour: bool) -> str:
    labels = {
        Verdict.LIKELY_EMBEDDED: ("EMBEDDED  ", "31;1"),
        Verdict.SUSPICIOUS: ("SUSPICIOUS", "33;1"),
        Verdict.INCONCLUSIVE: ("UNRESOLVED", "36;1"),
        Verdict.CLEAN: ("CLEAN     ", "32"),
    }
    text, code = labels[verdict]
    return f"\033[{code}m{text}\033[0m" if colour else text


def _write(target: Path, content: str) -> None:
    if str(target) == "-":
        sys.stdout.write(content + "\n")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
