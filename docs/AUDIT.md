# Audit of the v1 engine

This records the defects found in the pre-2.0 codebase (`src/lib/stegUtils.ts` and
`src/App.tsx`) and what replaced each one. It exists so the reasoning behind v2's design
survives, and so the regression tests have something to point at.

Findings are ordered by how badly they would mislead an analyst.

---

## 1. Fabricated forensic results

### 1.1 The dictionary attack returned a hardcoded password

`App.tsx`:

```ts
const handleDictionaryAttack = async () => {
    const passwords = ['password123', 'admin', 'qwerty', /* ... */];
    for (let i = 0; i < 20; i++) {
       const word = passwords[Math.floor(Math.random() * passwords.length)] + ...;
       setCrackAttempt(`Testing key: ${word} ...`);
       await new Promise(r => setTimeout(r, 100));   // simulated delay
    }
    setCrackAttempt("Match found!");
    setCrackedPassword("steganography_key_123");     // hardcoded
}
```

No cryptographic operation took place. The UI displayed a progress animation and then
asserted a recovered password. For a tool addressed to forensic practitioners this is the
most serious possible defect: the output is indistinguishable from a real result.

**v2:** removed entirely. StegInsight performs no password recovery and instead emits the
exact `stegseek` invocation for the analyst to run themselves.

### 1.2 `extractPayload` invented payloads

```ts
// If no explicit footer found but likelihood was high, check for high-entropy tails
if (calculateEntropy(bytes.slice(-2048)) > 7.9) {
    return bytes.slice(-2048);
}
```

Any file whose last 2 KB looked random — which includes essentially every compressed
file — yielded a 2 KB "recovered payload" that was simply the tail of the carrier. The
UI presented it in a hex viewer with a download button.

**v2:** `CarvedObject` records only regions actually located by a parser, each carrying
its offset, length, SHA-256 and whether it was **verified by parsing** rather than merely
magic-matched. Nothing is reconstructed or inferred.
*Tests:* `test_containers.py::TestPng::test_appended_archive_is_detected_and_carved`,
`TestZipProbe::test_magic_bytes_alone_are_rejected`.

---

## 2. Statistics that were wrong, not merely weak

### 2.1 The chi-square test measured the wrong thing

```ts
function performChiSquared(bytes: Uint8Array): number {
  const freqs = [0, 0];
  for (let i = 0; i < bytes.length; i++) freqs[bytes[i] & 1]++;
  ...
}
```

This counts LSB parity over **raw file bytes**. For PNG, JPEG or MP4 those bytes are
DEFLATE or entropy-coder output and are already near-random, so the statistic describes
the compressor, not the carrier.

The genuine Westfeld–Pfitzmann attack operates on **decoded sample values** over
pairs-of-values histograms.

**v2:** `core/stats.chi_square_pov` implements the real test on decoded samples, plus a
block-wise variant that localises sequential embedding. Measured separation on realistic
covers: clean `p ≈ 1e-96` to `1e-143`, fully embedded `p = 1.0000`.

### 2.2 Thresholds inverted with respect to sample size

```ts
if (chiStat < 0.2) {
  findings.push({ type: 'critical', message: 'Unnatural LSB Uniformity ...' });
  likelihood += 45;
} else if (!isVideoOrAudio && chiStat > 6.63) { ... likelihood += 30; }
```

For a genuine χ²(1) variate, `P(X < 0.2) ≈ 0.345`. **Roughly one clean compressed file in
three received a CRITICAL "cryptographic masking" finding worth +45.** At the other end,
χ² grows with N, so `> 6.63` fires on almost any large file. Both branches were
false-positive generators.

**v2:** p-values from the proper distribution, thresholds set from measured separation
between clean and embedded populations, and the chi-square finding gated on independent
bit-plane decorrelation.

### 2.3 Fixed entropy thresholds ignored sample size

```ts
const tail = bytes.slice(-10000);
if (calculateEntropy(tail) > 7.95) { /* CRITICAL, +60 */ }
```

Uniform random data of 10,000 bytes measures ≈ 7.982, not 8.0 — unseen symbols cost you.
A 7.95 bar is cleared by ordinary compressed content.

**v2:** `expected_random_entropy(n)` supplies the size-aware expectation and
`is_effectively_random()` compares against it. The report shows both numbers side by side.
*Test:* `test_stats.py::TestEntropy::test_expected_random_entropy_is_below_eight_for_small_samples`.

### 2.4 The audio detector flagged every WAV in existence

```ts
const chiSq = performChiSquared(lsbBytes);
if (chiSq > 0.1) { /* 'Audio Bitstream Anomaly', +30 */ }
```

A threshold of 0.1 on that statistic is met by every real recording. It was also labelled
`p=` in the UI while being a raw statistic, not a p-value.

**v2:** measurement showed that whole-file LSB embedding in noisy PCM is *not separable*
by these methods — clean and embedded both give a transition rate of 0.500. The detector
now reports **inconclusive** and says why, and detects the cases that do discriminate:
data in digital silence (perfect separation in testing) and a broken constant low-bit
floor. See `detectors/audio.py`.

### 2.5 High entropy on compressed images treated as evidence

`analyzeImageAdvanced` warned at entropy > 7.95 across the whole byte range, which is
normal for any compressed image, adding +20 to nearly every JPEG and PNG.

**v2:** entropy is context in the report, never evidence on its own. High entropy
indicates compressed *or* encrypted content and the two are not separable by that
measurement — the report says so.

---

## 3. Every PDF was reported as critical

```ts
const xrefMatches = [...text.matchAll(/xref\b/gi)];
if (xrefMatches.length > 1) {
   findings.push({ type: 'critical', message: 'Redundant XRef Tables' });
   score += 35;
}
```

`/xref\b/` also matches the `xref` inside `startxref`. Every conforming PDF contains both,
so **every PDF ever scanned** produced a CRITICAL finding. `/ObjStm` (the default since
PDF 1.5) added +10 more, and `%%EOF` count > 1 added +50 — but incremental update is how
PDF records annotations, form data and signatures, so any signed document tripped it.

**v2:** `(?<![A-Za-z])xref\b` with a lookbehind; incremental updates and object streams
reported as **neutral context at `llr = 0.0`**; positive weight reserved for embedded file
attachments, auto-executing JavaScript, `/Launch` actions and real data after the final
`%%EOF` (with trailing whitespace correctly ignored).
*Tests:* `test_containers.py::TestPdf` — six cases.

---

## 4. Tool "detection" by substring search

```ts
const combined = (headSample + tailSample).toLowerCase();
const signatures: [string, string][] = [
  ['outguess', ...], ['camouflage', ...], ['steghide', ...], ...
];
for (const [sig, name] of signatures) {
  if (combined.includes(sig)) { /* CRITICAL, +80 */ }
}
```

Three problems. A holiday photo whose EXIF caption mentions *camouflage* scored +80
CRITICAL. Concatenating head and tail created an artificial boundary that could
manufacture matches. And most of the listed tools — steghide, OutGuess, F5, JPHide —
**encrypt their payloads and leave no plaintext signature at all**, so the entries could
never have worked as claimed.

**v2:** `core/signatures.py` matches exact **byte** patterns via one compiled alternation,
records offsets, and carries an explicit reliability rating per marker that feeds the
likelihood ratio. Tools with no real signature are absent by design, with the reasoning in
the module docstring; they are addressed by the statistical detectors instead. A marker
that can only be incidental (a filename, a log fragment) is rated `indicative` and
contributes 0.35, not 2.3.

---

## 5. Structural parsing by byte search

### 5.1 PNG located `IEND` with `indexOf`

`findSequence(bytes, PNG_FOOTER)` returns the **first** occurrence of `IEND`, which occurs
by chance inside compressed IDAT data.

### 5.2 JPEG located `EOI` with a backwards search

```ts
footerPos = findLastSequence(bytes, JPEG_FOOTER);   // last FFD9
```

Exactly backwards. Appended payloads frequently contain `FF D9`, which dragged the
supposed footer to the end of the file and made the appended data **disappear from the
analysis entirely** — the detection failed precisely in the case it existed for.

**v2:** real chunk and marker walkers. PNG validates CRC-32 on every chunk; JPEG follows
the marker stream forward through the entropy-coded scan, honouring `FF00` byte stuffing
and restart markers. Data past IEND is reported as trailing data, and *additional
CRC-valid chunks* past IEND are reported separately as proof, since random bytes do not
produce matching checksums.
*Tests:* `TestPng::test_iend_found_by_structure_not_by_byte_search`,
`TestJpeg::test_eoi_located_by_forward_scan_not_last_occurrence`.

### 5.3 Appended data misreported as a malformed chunk

The v1 walk continued past IEND and read the appended payload as another chunk, whose
absurd declared length produced a spurious structural finding on every file that simply
had something appended.

**v2:** the walk terminates at IEND; post-IEND content is handled by dedicated logic.
*Test:* `TestPng::test_appended_data_is_not_reported_as_a_malformed_chunk`.

---

## 6. Scoring model

```ts
likelihood += 65;  likelihood += 80;  likelihood += 45;   // ...
likelihood = Math.min(100, Math.max(0, likelihood));
```

Unbounded addition clamped at 100. A single aggressive detector saturated the score on its
own; two weak findings outranked one strong one; correlated findings were counted as
independent; and the resulting number could not be defended, since no part of it traced to
a specific measurement.

**v2:** calibrated base-10 log likelihood ratios combined into posterior log-odds from an
explicit prior, with within-family damping, a per-evidence cap, a proof tier that resists
dilution by unrelated exculpatory findings, and an *inconclusive* state that prevents "we
could not measure" being reported as "clean". See `core/evidence.py`.
*Tests:* `test_scoring.py` — 21 cases.

---

## 7. Security

### 7.1 API key published in the client bundle

`vite.config.ts`:

```ts
define: {
  'process.env.GEMINI_API_KEY': JSON.stringify(env.GEMINI_API_KEY),
},
```

`define` performs literal text substitution at build time. Any key present when the
GitHub Pages site was built was embedded in the published JavaScript and readable by every
visitor.

**v2:** no build-time secrets exist. There is no bundler and no hosted deployment.

> **If a real key was ever used in a v1 build, revoke it.** Rewriting history does not
> help — the bundle was public.

### 7.2 Exhibit bytes sent to a third party

`performAIAnalysis` transmitted the first and last 1 KB of every analysed file, as hex, to
the Gemini API. For an evidential exhibit that is an uncontrolled disclosure, and it was
not surfaced in the UI.

**v2:** analysis is entirely local. The tool makes no network requests.

---

## 8. Engineering

| Issue | v2 |
|---|---|
| Uncapped sliding entropy — a fixed 1 KiB window with 512-byte step emits ~200,000 points for a 100 MB file and hangs the tab | Adaptive window bounded to 1,024 points; vectorised in NumPy. *Test:* `test_output_is_bounded_regardless_of_input_size` |
| Whole file loaded via `arrayBuffer()` with no size guard | `Carrier.load(max_bytes=...)`; hashes still cover the whole file and truncation is reported as a limitation |
| All analysis on the UI thread | CLI process; no UI to block |
| `strict` off, no lint, no tests | `strict` mypy config, ruff, 200+ tests, CI |
| `express`, `dotenv`, `tsx` as runtime deps of a static SPA; `vite` in both dependency sets | Three runtime dependencies: NumPy, SciPy, Pillow |
| `generateAudioSpectrogram` drew a waveform, not a spectrogram | Removed rather than mislabelled |
| `generateRawLsbVisual` mapped only the first 65,536 bytes — mostly file header | Per-channel bit planes and an RGB LSB composite of the actual decoded image |
| `extractVideoFrame` set `currentTime` before metadata load and had no timeout, so the promise could never settle | N/A — no browser media APIs |
| Non-deterministic output | Seeded estimators; *test:* `test_analysis_is_deterministic` |

---

## Retained from v1

The good idea in v1 was that **evidence never leaves the analyst's machine**. v2 keeps it
and strengthens it: there is no upload step, no server, and no network call at any point.
The visual analysis that justified the browser UI survives as the `--html` report — one
self-contained file, no scripts, no external references, which opens offline in any
browser and prints cleanly into a case record.
