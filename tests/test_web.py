"""The browser bridge.

The web app runs this package under Pyodide, so this module is the seam between
the engine and the front-end. Keeping it in Python means it is covered here
rather than being untested JavaScript glue.
"""

from __future__ import annotations

import base64
import io
import json
import zipfile

import pytest

from steginsight.web import analyse_for_web, engine_info, triage_for_web
from tests.factories import (
    append_payload,
    embed_lsb,
    natural_image,
    png_bytes,
    silent_intro_audio,
    zip_bytes,
)


class TestEngineInfo:
    def test_reports_version_and_prior(self) -> None:
        info = engine_info()
        assert info["version"]
        assert 0 < info["prior"] < 1


class TestAnalyseForWeb:
    def test_result_is_json_serialisable(self) -> None:
        """It crosses the Pyodide bridge, so it must survive JSON."""
        result = analyse_for_web("a.png", png_bytes(natural_image(seed=1)))
        json.dumps(result)

    def test_clean_carrier(self) -> None:
        result = analyse_for_web("clean.png", png_bytes(natural_image(seed=2)))
        assert result["assessment"]["verdict"] in ("clean", "inconclusive")
        assert result["exhibit"]["hashes"]["sha256"]

    def test_embedded_carrier_and_carved_payload_round_trips(self) -> None:
        data = append_payload(png_bytes(natural_image(seed=3)), zip_bytes())
        result = analyse_for_web("embedded.png", data)

        assert result["assessment"]["verdict"] == "likely-embedded"
        assert result["carved_data"], "the appended archive should be carved"

        # The browser offers this for download, so it must be the real bytes.
        recovered = base64.b64decode(result["carved_data"][0]["base64"])
        with zipfile.ZipFile(io.BytesIO(recovered)) as archive:
            assert archive.namelist()

    def test_visuals_are_data_uris(self) -> None:
        result = analyse_for_web("lsb.png", png_bytes(embed_lsb(natural_image(seed=4), 0.3)))
        visuals = result["visuals"]
        assert visuals["planes"] and len(visuals["planes"]) == 3
        for plane in visuals["planes"]:
            assert plane["src"].startswith("data:image/png;base64,")
        assert visuals["lsb_composite"].startswith("data:image/png;base64,")

    def test_html_report_is_self_contained(self) -> None:
        result = analyse_for_web("a.png", png_bytes(natural_image(seed=5)))
        html = result["html_report"]
        assert html.startswith("<!doctype html>")
        assert "<script" not in html

    def test_visuals_can_be_skipped(self) -> None:
        result = analyse_for_web(
            "a.png", png_bytes(natural_image(seed=6)), with_visuals=False, with_html=False
        )
        assert result["visuals"] == {}
        assert "html_report" not in result

    def test_audio_carrier(self) -> None:
        result = analyse_for_web("hidden.wav", silent_intro_audio(0.5))
        assert result["assessment"]["verdict"] == "likely-embedded"
        assert result["audio"] is not None

    def test_prior_is_honoured(self) -> None:
        data = png_bytes(natural_image(seed=7))
        low = analyse_for_web("a.png", data, prior=0.01)
        high = analyse_for_web("a.png", data, prior=0.5)
        assert high["assessment"]["probability"] > low["assessment"]["probability"]

    @pytest.mark.parametrize("data", [b"", b"\x00\x01", bytes(range(256)) * 8])
    def test_malformed_input_does_not_raise(self, data: bytes) -> None:
        json.dumps(analyse_for_web("odd.bin", data))


class TestTriageForWeb:
    def test_ranks_by_probability(self) -> None:
        rows = triage_for_web(
            [
                ("clean.png", png_bytes(natural_image(seed=8))),
                ("embedded.png", append_payload(png_bytes(natural_image(seed=8)), zip_bytes())),
            ]
        )
        assert rows[0]["name"] == "embedded.png"
        assert rows[0]["probability"] > rows[-1]["probability"]
        json.dumps(rows)

    def test_one_bad_file_does_not_stop_the_batch(self) -> None:
        rows = triage_for_web(
            [("bad.png", b"\xff" * 10), ("good.png", png_bytes(natural_image(seed=9)))]
        )
        assert len(rows) == 2
