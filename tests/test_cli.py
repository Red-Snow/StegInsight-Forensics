"""Command-line interface.

Exit codes are part of the contract — they are how the tool composes into
pipelines and CI — so they are tested as carefully as the analysis itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from steginsight.cli.main import main
from tests.factories import (
    append_payload,
    natural_image,
    png_bytes,
    silent_intro_audio,
    zip_bytes,
)

CLEAN = 0
INCONCLUSIVE = 1
SUSPICIOUS = 2
EMBEDDED = 3
USAGE = 4


@pytest.fixture()
def corpus(tmp_path: Path) -> Path:
    (tmp_path / "clean.png").write_bytes(png_bytes(natural_image(seed=101)))
    (tmp_path / "appended.png").write_bytes(
        append_payload(png_bytes(natural_image(seed=102)), zip_bytes())
    )
    (tmp_path / "hidden.wav").write_bytes(silent_intro_audio(0.5))
    (tmp_path / "notes.txt").write_text("Ordinary notes.\n" * 50)
    return tmp_path


class TestScan:
    def test_clean_file_exits_zero(self, corpus: Path, capsys) -> None:  # type: ignore[no-untyped-def]
        assert main(["scan", str(corpus / "clean.png"), "--no-colour"]) == CLEAN
        assert "CLEAN" in capsys.readouterr().out

    def test_embedded_file_exits_three(self, corpus: Path, capsys) -> None:  # type: ignore[no-untyped-def]
        assert main(["scan", str(corpus / "appended.png"), "--no-colour"]) == EMBEDDED
        out = capsys.readouterr().out
        assert "LIKELY EMBEDDED" in out
        assert "trailing" in out.lower()

    def test_json_output_is_valid(self, corpus: Path, tmp_path: Path) -> None:
        target = tmp_path / "out" / "result.json"
        main(["scan", str(corpus / "appended.png"), "-q", "--json", str(target)])
        payload = json.loads(target.read_text())
        assert payload["assessment"]["verdict"] == "likely-embedded"
        assert payload["exhibit"]["hashes"]["sha256"]

    def test_html_output_is_written_and_offline(self, corpus: Path, tmp_path: Path) -> None:
        target = tmp_path / "report.html"
        main(["scan", str(corpus / "appended.png"), "-q", "--html", str(target)])
        html = target.read_text()
        assert html.startswith("<!doctype html>")
        assert "<script" not in html

    def test_extract_writes_recovered_objects(self, corpus: Path, tmp_path: Path) -> None:
        out = tmp_path / "carved"
        main(["scan", str(corpus / "appended.png"), "-q", "--extract", str(out)])
        written = list(out.glob("*"))
        assert written
        # The carved object must be a genuinely working archive.
        import zipfile

        archive = next(p for p in written if p.suffix == ".zip")
        with zipfile.ZipFile(archive) as zf:
            assert zf.namelist()

    def test_verbose_shows_exculpatory_findings(self, corpus: Path, capsys) -> None:  # type: ignore[no-untyped-def]
        main(["scan", str(corpus / "clean.png"), "--no-colour", "-v"])
        assert "INFO" in capsys.readouterr().out

    def test_quiet_suppresses_the_report(self, corpus: Path, capsys) -> None:  # type: ignore[no-untyped-def]
        main(["scan", str(corpus / "clean.png"), "-q"])
        assert capsys.readouterr().out.strip() == ""

    def test_missing_file_exits_usage(self, tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
        assert main(["scan", str(tmp_path / "nope.png")]) == USAGE

    def test_directory_argument_exits_usage(self, corpus: Path) -> None:
        assert main(["scan", str(corpus)]) == USAGE

    def test_invalid_prior_is_rejected(self, corpus: Path) -> None:
        with pytest.raises(SystemExit):
            main(["scan", str(corpus / "clean.png"), "--prior", "1.5"])


class TestTriage:
    def test_returns_the_highest_verdict_seen(self, corpus: Path, capsys) -> None:  # type: ignore[no-untyped-def]
        assert main(["triage", str(corpus), "--no-colour"]) == EMBEDDED
        out = capsys.readouterr().out
        assert "appended.png" in out
        assert "hidden.wav" in out

    def test_ranks_by_probability(self, corpus: Path, capsys) -> None:  # type: ignore[no-untyped-def]
        main(["triage", str(corpus), "--no-colour"])
        lines = [line for line in capsys.readouterr().out.splitlines() if "0." in line]
        scores = [float(line.split()[1]) for line in lines if line.strip().split()[0].isupper()]
        assert scores == sorted(scores, reverse=True)

    def test_min_verdict_filters_output(self, corpus: Path, capsys) -> None:  # type: ignore[no-untyped-def]
        main(["triage", str(corpus), "--no-colour", "--min-verdict", "likely-embedded"])
        out = capsys.readouterr().out
        assert "clean.png" not in out

    def test_json_summary(self, corpus: Path, tmp_path: Path) -> None:
        target = tmp_path / "triage.json"
        main(["triage", str(corpus), "--json", str(target)])
        rows = json.loads(target.read_text())
        assert len(rows) >= 3
        assert all("sha256" in row and "verdict" in row for row in rows)

    def test_missing_directory_exits_usage(self, tmp_path: Path) -> None:
        assert main(["triage", str(tmp_path / "nowhere")]) == USAGE

    def test_recursive_walk(self, corpus: Path, tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
        nested = corpus / "sub" / "deep"
        nested.mkdir(parents=True)
        (nested / "buried.png").write_bytes(
            append_payload(png_bytes(natural_image(seed=103)), zip_bytes())
        )
        main(["triage", str(corpus), "-r", "--no-colour"])
        assert "buried.png" in capsys.readouterr().out


class TestArgumentParsing:
    def test_version(self) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0

    def test_no_command_is_an_error(self) -> None:
        with pytest.raises(SystemExit):
            main([])
