# Changelog

## 2.0.0

Ground-up rewrite. The engine is now a Python library and CLI; the browser
application has been removed.

### Why the rewrite

The v1 analysis engine produced confident verdicts it could not substantiate. A
full account is in [`docs/AUDIT.md`](docs/AUDIT.md); the most consequential
items were a chi-square "test" computed over compressed container bytes rather
than decoded samples, thresholds that flagged roughly a third of clean
compressed files as critical, a regex that reported *every* PDF as critical, a
payload extractor that returned the last 2 KB of any high-entropy file as a
"recovered payload", and a dictionary-attack feature that displayed a progress
animation and then returned a hardcoded password.

### Why Python

Browsers expose only post-IDCT pixels. That makes DCT-domain analysis
impossible in a browser, and DCT is where essentially all modern JPEG
steganography lives (JSteg, F5, OutGuess, nsF5, J-UNIWARD). Python also brings
NumPy/SciPy and is what the surrounding DFIR toolchain is written in.

The property that made the web version worth having — exhibits never leaving
the analyst's machine — is preserved and strengthened: there is no upload step,
no server, and no network call at any point.

### Added

- Baseline JPEG entropy decoder recovering quantised DCT coefficients, with no
  libjpeg binding required; validated against libjpeg in the test-suite.
- DCT-domain steganalysis: pairs-of-values chi-square, globally and block-wise.
- RS analysis and Sample Pair Analysis, both estimating the embedding *rate*.
- Structural parsers with integrity validation for PNG (CRC-32 per chunk),
  JPEG, RIFF/WAV, ISO-BMFF/MP4, GIF, BMP and PDF.
- Payload carving with parse-level verification of candidate archives.
- MD5/SHA-1/SHA-256 exhibit hashing for chain of custody.
- Unicode steganography detection: zero-width encodings, Unicode tag
  characters, variation selectors, whitespace encodings, homoglyphs, bidi.
- Calibrated evidence model: per-finding log likelihood ratios combined into
  posterior log-odds, with within-family damping and an explicit prior.
- An `inconclusive` verdict, so "could not measure" is never reported as
  "clean".
- `scan` and `triage` CLI commands with meaningful exit codes.
- Self-contained offline HTML reports, and JSON output for pipelines.
- 200+ tests, ruff lint, CI across Python 3.10–3.13 on Linux, macOS, Windows.

### Removed

- The simulated dictionary attack, which fabricated results.
- Entropy-tail "payload extraction", which fabricated payloads.
- Tool signatures for steghide, OutGuess, F5 and JPHide, which encrypt their
  payloads and leave nothing to string-match; these tools never could have been
  detected that way.
- Build-time injection of `GEMINI_API_KEY` into the client bundle, and the
  transmission of exhibit bytes to a third-party API.

### Security

- **If a Gemini API key was ever present in a v1 GitHub Pages build, revoke
  it.** `define` performs literal text substitution, so the key was embedded in
  the published bundle and readable by any visitor. Rewriting history does not
  help.
