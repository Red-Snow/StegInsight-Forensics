# StegInsight Forensics

**Steganalysis and carrier-integrity workbench for digital forensics practitioners.**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab.svg)](https://www.python.org/)
[![Tests](https://github.com/Red-Snow/StegInsight-Forensics/actions/workflows/ci.yml/badge.svg)](https://github.com/Red-Snow/StegInsight-Forensics/actions/workflows/ci.yml)

**▶ Try it in your browser — no install:
[red-snow.github.io/StegInsight-Forensics](https://red-snow.github.io/StegInsight-Forensics/)**
The full engine is compiled to WebAssembly and runs inside the page, so your files are never
uploaded anywhere.

StegInsight examines images, audio, video containers, documents and text for concealed
payloads. It reports a calibrated probability with every contributing measurement shown,
recovers embedded objects that are actually present, and states plainly what it could
**not** establish.

That last part is the design principle. A steganalysis tool that reports confident
verdicts it cannot substantiate is worse than no tool at all, because its output looks
like evidence. Where a technique is below the detection floor, StegInsight says so.

```console
$ steginsight scan evidence.png

  LIKELY EMBEDDED   p = 0.913

  Posterior probability 91.3% across 1 independent evidence family. The observations are
  difficult to explain by ordinary encoding or transport of this format.

  EXHIBIT
    file        evidence.png
    size        29,320 bytes
    format      Portable Network Graphics
    sha256      18f332158c66dc1e7008ca285880541864d0e032c98a5fa49e2ca10306f5c058
    entropy     7.9505 bits/byte (uniform random would give 7.9937)

  FINDINGS
    CRIT  149 B of data after the PNG end marker   +2.30
          The PNG stream ends at offset 0x71f3, but the file continues for a further 149
          bytes. The trailing region was identified as: valid ZIP archive containing 1
          entry: secret.txt. Entropy of the region is 4.489 bits/byte. Decoders ignore
          this region entirely, so the carrier still renders normally.
          at offset 0x71f3 length 149

  RECOVERED OBJECTS
    0x000071f3         149 B  zip        verified
                valid ZIP archive containing 1 entry: secret.txt

  NEXT STEPS
    - binwalk -e 'evidence.png' — carve the appended object automatically
    - dd if='evidence.png' bs=1 skip=29171 of=payload.zip — extract it exactly
```

---

## Use it in the browser

<https://red-snow.github.io/StegInsight-Forensics/>

Drag a file in and you get the same analysis the CLI gives — the identical Python package,
compiled to WebAssembly via Pyodide, running locally in the tab. Not a reimplementation: the
wheel the page installs is built from this repository's source on every push, so the live app
cannot drift from the code here.

Everything the CLI does is there: the verdict with its evidence, bit-plane imagery, entropy and
χ² charts, container structure, recovered payloads with a hex view, and downloadable HTML/JSON
reports. Drop several files at once to triage them together.

**Nothing is uploaded.** There is no server and no upload endpoint. Open DevTools → Network:
after the engine loads, dropping a file produces no requests at all. The trade is a one-time
~20 MB engine download, cached afterwards.

## Install

```bash
git clone https://github.com/Red-Snow/StegInsight-Forensics.git
cd StegInsight-Forensics
pip install -e .
```

Requires Python 3.10+, NumPy, SciPy and Pillow. Nothing else, and no network access at
any point — exhibits are never uploaded anywhere.

## Use

```bash
steginsight scan evidence.jpg                     # one exhibit, in depth
steginsight scan evidence.jpg -v                  # include exculpatory findings
steginsight scan evidence.jpg --html report.html  # offline single-file report
steginsight scan evidence.jpg --json result.json  # machine-readable
steginsight scan evidence.jpg --extract ./carved  # write out recovered objects

steginsight triage ./seized_media -r              # rank a whole corpus
steginsight triage ./seized_media --json out.json --min-verdict suspicious
```

Exit codes compose into pipelines: `0` clean, `1` inconclusive, `2` suspicious,
`3` likely embedded, `4` error. `triage` returns the highest it saw.

As a library:

```python
from steginsight import analyse_path

report = analyse_path("evidence.png")
print(report.assessment.verdict, report.assessment.probability)
for finding in report.evidence:
    print(f"{finding.llr:+.2f}  {finding.id}  {finding.title}")
```

---

## What it detects

### Structural — container parsing, not byte searching

Full chunk/segment/box walkers with integrity validation for **PNG** (CRC-32 on every
chunk), **JPEG** (marker stream including entropy-coded scan with byte stuffing and
restart markers), **RIFF/WAV**, **ISO-BMFF/MP4**, **GIF**, **BMP** and **PDF**.

This catches appended payloads past an end-of-file marker, data smuggled in `free`/`skip`
boxes and `JUNK` padding chunks, private PNG chunks, oversized metadata fields, header
size-field mismatches, CRC failures from in-place modification, and polyglots. A
candidate archive is **opened and its central directory walked** before it is reported —
matching four magic bytes proves nothing, since `PK\x03\x04` occurs by chance in any
compressed stream.

### Spatial — LSB steganalysis of lossless imagery

**RS analysis** (Fridrich, Goljan & Du 2001) and **Sample Pair Analysis** (Dumitrescu, Wu
& Wang 2003) both estimate the *embedding rate*, not merely its presence. They rest on
different assumptions, so agreement between them is real corroboration. Alongside them:
the **Westfeld–Pfitzmann chi-square** attack, run globally and block-wise so a payload
that fills the carrier and stops is localised, and **bit-plane correlation**, which
separates "noisy because it is a photo of gravel" from "noisy because it is ciphertext".

### Transform — DCT-domain steganalysis of JPEG

**This is where JPEG steganography actually lives.** JSteg, F5, OutGuess and their
descendants modify quantised DCT coefficients; once an image has been decoded to pixels
those traces are gone, so pixel-domain analysis of a JPEG measures the quantiser rather
than the carrier.

StegInsight ships its own **baseline JPEG entropy decoder** (`steginsight/jpegdct.py`,
~250 lines, no libjpeg binding required) that recovers quantised coefficients directly
from the scan. It is validated in the test-suite by dequantising, running an inverse DCT
and comparing against libjpeg's own decode of the same file.

### In the browser

The same package runs under Pyodide. `steginsight/web.py` is the only bridge, and it is covered
by the test-suite rather than being untested JavaScript glue. SciPy was dropped as a runtime
dependency for this — the two functions used from it were both `chi2.sf`, now implemented in
`core/_special.py` and verified against SciPy to a relative tolerance of 1e-9, which removes a
~15 MB WebAssembly download.

### Audio, text and identity

PCM analysis centred on the measurements that actually discriminate (see *Known limits*).
Unicode steganography: zero-width encodings, **Unicode tag characters** (the mechanism
behind most invisible prompt-injection payloads), variation-selector encodings, SNOW-style
whitespace, homoglyph substitution and bidi overrides. Plus MD5/SHA-1/SHA-256 for chain of
custody, and format identification from magic bytes so a renamed file is caught.

---

## How the verdict is reached

Every detector emits an `Evidence` record carrying a **base-10 log likelihood ratio** —
how much more probable that observation is if a payload is present than if the carrier is
clean. Nothing else moves the score, so every point of it traces to a named measurement
you can inspect.

Ratios combine as posterior log-odds from a deliberately low prior (5%; steganography is
rare in absolute terms, and a tool that starts from a coin flip manufactures false
positives). Findings within one evidence family are geometrically damped, because "high
entropy" and "near-maximum entropy" are not two independent facts. Findings across
independent families corroborate.

Two rules keep the arithmetic honest:

- **Proof is not diluted.** A clean LSB result says nothing about an appended archive —
  they answer different questions. Once one observation reaches the proof tier,
  exculpatory findings from other families stop being subtracted.
- **"Could not measure" is never reported as "clean."** A detector that runs without
  reaching a conclusion floors the verdict at *inconclusive*, and the report says which
  detector and why.

Set `--prior` to match your context: raise it when triaging an already-suspicious corpus,
lower it for bulk scanning of ordinary material.

---

## Known limits

Stated up front, because knowing where a tool is blind is part of using it.

| Area | Status |
|---|---|
| **Whole-file LSB in noisy PCM audio** | **Not detectable.** Measured across clean/embedded pairs, the LSB transition rate is 0.500 either way: every recording has a noise floor, dither is applied deliberately, and lossy round-trips add reconstruction noise. StegInsight reports *inconclusive* instead of guessing. What it **does** detect reliably is data written into **digital silence**, which discriminates perfectly, and a broken constant low-bit floor. |
| **F5 / OutGuess via calibration** | **Measured but not scored.** Cropping and recompressing to estimate cover statistics is implemented and reported, but the ratio varies systematically with JPEG quality on clean images (0.62–1.16 across Q70–Q95). A fixed threshold labelled every Q70 JPEG as F5-embedded in testing, so no threshold ships. Use the reported ratio comparatively against reference images from the same source. |
| **Progressive JPEG** | Coefficient decoding is baseline-sequential only. Progressive files are detected and reported as a limitation rather than decoded incorrectly. |
| **Adaptive schemes (J-UNIWARD, HUGO, WOW)** | Not addressed. These minimise a distortion function and defeat every classical statistic here; detecting them needs rich-model features and a trained classifier. |
| **LSB matching (±1 embedding)** | Not addressed by RS/SPA/chi-square, which key on pair-of-values structure that ±1 embedding does not create. |
| **Smooth-histogram images** | The chi-square attack fits the equalised model on intrinsically smooth histograms. Gated on bit-plane decorrelation to suppress it; the test-suite documents the case. |

No negative result proves absence. A short or well-encrypted payload can fall below the
detection floor of every technique implemented here.

---

## Development

```bash
pip install -e ".[dev]"
pytest            # 200+ tests
ruff check .
pytest --cov=steginsight
```

Fixtures are generated deterministically at test time rather than committed as binaries,
so each test states what makes its carrier clean or embedded. The cover generator uses
multi-octave value noise: a smooth gradient with Gaussian noise added is *not* a realistic
image cover, because its low bit planes are already pure noise, and testing against one
validates the wrong behaviour.

---

## About version 2

Version 2 is a ground-up rewrite. The previous revision was a browser application whose
analysis engine had defects that produced confident but incorrect verdicts — a chi-square
"test" computed over compressed container bytes rather than decoded samples, thresholds
that flagged roughly a third of all clean files, a regex that reported *every* PDF as
critical, and a dictionary-attack feature that returned a hardcoded password. It also
inlined a Gemini API key into the published client bundle.

[`docs/AUDIT.md`](docs/AUDIT.md) documents each defect and what replaced it. Many of them
now have a named regression test.

The move from TypeScript to Python was driven by one hard constraint: browsers expose only
post-IDCT pixels, so no browser-based tool can perform DCT-domain analysis, and that rules
out most of the actual state of the art for JPEG. The property that made the web version
valuable — exhibits never leaving the analyst's machine — is preserved and strengthened,
since there is now no upload step and no server at all. The visual side survives as the
self-contained `--html` report, which opens offline in any browser.

## Author

**Farman Khan (Red-Snow)** — [GitHub](https://github.com/Red-Snow)

## Licence

Apache 2.0. See [LICENSE](./LICENSE).
