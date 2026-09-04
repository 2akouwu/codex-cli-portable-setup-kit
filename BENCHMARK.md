# Benchmark: does the verifier catch a real hallucination, safely?

**Replicate it yourself** (needs capstone + lief: `pip install "reverify[full]"`):

```bash
python benchmarks/prologue_prior.py --per-dir 40 --json my-run.json --fail-on-false-verified
```

It runs on your platform's own system binaries (Windows System32/SysWOW64, Linux
`/usr/bin` + multiarch `/usr/lib`, macOS `/bin` + `/usr/bin`), samples them
deterministically (sorted, fixed stride), and writes a record with the SHA-256 of every
file tested, every verdict, and the tool versions — so two people can compare runs file by
file. **CI runs exactly this on Linux, Windows and macOS on every push and fails the build
if a single wrong claim is VERIFIED**; each run's record is attached as an artifact
(`benchmark-<os>`) and the summary appears on the run page. Reference records are
committed under [`benchmarks/results/`](benchmarks/results/).

## What it measures

A language model asked what a function's entry prologue looks like tends to answer the
textbook frame-pointer prologue `push rbp ; mov rbp, rsp`. This benchmark applies that
prior **blind** — it never reads the disassembly itself — to real binaries and measures,
purely through reverify's verifier:

| metric | meaning |
|---|---|
| **prior wrong** | how often the model's textbook prologue is a hallucination on this corpus |
| **false VERIFIED** | how often a *wrong* claim was accepted — the safety failure, must be 0 |
| **true bytes after 1 round** | the loop re-states the mnemonics the verifier reported, reaching the true bytes |
| **95% upper bound** | Wilson interval on the false-VERIFIED rate: what "0 of N" does and does not prove |

## Results

### Windows 11, x86_64 + x86 (71 binaries, reference record)

Record: [`benchmarks/results/windows-x86_64-2026-09-04.json`](benchmarks/results/windows-x86_64-2026-09-04.json)
(reverify 0.10.0, Python 3.14, capstone + lief).

```
binaries tested                 : 71  (inconclusive, not counted: 0)
prior wrong (hallucination rate): 69/71 = 97%
false VERIFIED (must be 0)       : 0   (95% upper bound on the rate: 5.1%)
true bytes after 1 feedback round: 71/71 = 100%
```

Two of the 71 DLLs really do open with `push ; mov` and were *correctly* VERIFIED — the
metric is not rigged to make the prior look bad. The other 69 open with the x64 shadow-space
save (`mov [rsp+8], rbx ; push rdi ; sub rsp, N`) or the x86 hot-patch stub
(`mov edi, edi ; push ebp`), the verifier refuted every one, and it never once marked a wrong
claim VERIFIED.

### CI, three platforms (GitHub-hosted runners, not the author's machine)

Produced by [CI run 33871442164](https://github.com/2akouwu/reverify/actions/runs/33871442164)
on each runner's own system binaries; the full records (every file's SHA-256, every verdict)
are committed under `benchmarks/results/ci-*.json` and attached to every run as artifacts.

| platform (runner) | formats | tested | prior wrong | **false VERIFIED** | 95% upper bound | true bytes after 1 round |
|---|---|---|---|---|---|---|
| Linux x86_64 (ubuntu-latest) | ELF | 40 | 40 | **0** | 8.8% | 40/40 |
| macOS (macos-latest, universal binaries, x86_64 slice) | Mach-O | 77 | 77 | **0** | 4.8% | 77/77 |
| Windows Server (windows-latest) | PE x86 + x86_64 | 68 | 68 | **0** | 5.3% | 68/68 |

Across the reference run, the three CI runs and the third-party aarch64 run below: **275
binaries, 4 formats/architectures, 0 false VERIFIED** (pooled 95% upper bound about 1.4%).
The gate is the same everywhere: one false VERIFIED fails the build. Known gap: for the
*universal* system binaries on the arm64 macOS runner, lief still judges the x86_64 slice
(slice selection by host CPU is in place but has not taken effect on the runner yet — under
investigation); AArch64 Mach-O code **is** exercised through the compiled corpus below,
which is built natively for arm64 on that runner.

## A corpus anyone can rebuild: the prior is right exactly when it should be

`benchmarks/corpus/` holds two small C libraries; CI compiles them on each platform with
the compilers it has (gcc, clang, MSVC) at -O0 and -O2 and records toolchain versions, flags
and hashes in a manifest (`results/ci-corpus-manifest-*.json`). The prologue prior is then
applied to every **exported function** (`--probe exports`). This is the control that shows
the benchmark measures reality rather than always refuting
([CI run 33874141359](https://github.com/2akouwu/reverify/actions/runs/33874141359)):

| platform | build | functions | prior right | prior wrong | false VERIFIED |
|---|---|---|---|---|---|
| Linux x86_64 | gcc 13.3 -O0 (frame pointer kept) | 9 | **9** | 0 | 0 |
| Linux x86_64 | gcc 13.3 -O2 (frame pointer omitted) | 9 | 0 | 9 | 0 |
| Linux x86_64 | clang 18 -O0 / -O2 | 9 / 9 | **9** / 0 | 0 / 9 | 0 |
| Windows x86_64 | MinGW gcc -O0 / -O2 | 9 / 9 | **9** / 0 | 0 / 9 | 0 |
| Windows x86_64 | MSVC 19 /Od and /O2 (never uses `push rbp; mov rbp, rsp`) | 9 / 9 | 0 / 0 | 9 / 9 | 0 |
| macOS arm64 | Apple clang 21 -O0 / -O2 (AArch64 prologues) | 9 / 9 | 0 / 0 | 9 / 9 | 0 |

The textbook prologue is **verified** exactly where compilers really emit it (-O0 with frame
pointers on x86_64) and **refuted** where they don't (optimised x86_64, MSVC, AArch64) —
and no wrong claim was accepted anywhere. The matrix benchmark on the same corpus: 0 false
VERIFIED of 206 known-false claims across the three platforms, 0 known-true claims missed.

## The verifier as a classifier: known-true vs known-false claims of every kind

`benchmarks/verifier_matrix.py` is the balanced counterpart to the prior probe: for every
binary and every claim kind it builds one claim that is *known true* (from the bytes or the
parsed tables) and one that is *known false* (a controlled mutation that provably does not
hold), and tallies a confusion matrix per kind. Two gates: **false VERIFIED must be 0** for
every kind, and a known-true byte-level or structural claim must **never** be refuted.
*Unknown* (INCONCLUSIVE) is reported separately and never counted as a pass.

Windows 11 reference record, 50 binaries, engines installed
([`results/matrix-windows-x86_64-2026-09-04.json`](benchmarks/results/matrix-windows-x86_64-2026-09-04.json)):

| kind | n | TP | FN | unk(true) | **FP** | TN | unk(false) |
|---|---|---|---|---|---|---|---|
| bytes_at | 50 | 50 | 0 | 0 | **0** | 50 | 0 |
| u32_at | 50 | 50 | 0 | 0 | **0** | 50 | 0 |
| u64_at | 50 | 50 | 0 | 0 | **0** | 50 | 0 |
| string_present | 50 | 50 | 0 | 0 | **0** | 50 | 0 |
| pattern_present | 39 | 39 | 0 | 0 | **0** | 39 | 0 |
| section_present | 50 | 50 | 0 | 0 | **0** | 50 | 0 |
| import_present | 45 | 45 | 0 | 0 | **0** | 45 | 0 |
| export_present | 48 | 48 | 0 | 0 | **0** | 48 | 0 |
| instructions | 45 | 45 | 0 | 0 | **0** | 45 | 0 |
| function_at | 48 | 48 | 0 | 0 | **0** | 0 | 48 |

**0 false VERIFIED of 475 known-false claims** (95% upper bound 0.8%), 0 missed known-true
claims. The `function_at` false claims are *unknown*, not refuted, because no analysis
engine was installed for that run — the honest answer; with angr they are refuted. CI runs
this matrix in **every** job (three platforms, Python 3.9 and 3.13, with and without the
engines); each record is an artifact (`matrix-<os>-py<ver>-<deps>`). From CI run
33874141359 on each runner's system binaries, engines installed (records under
`results/ci-matrix-*.json`):

| platform | binaries | known-false claims | **false VERIFIED** | 95% upper bound | known-true missed |
|---|---|---|---|---|---|
| Linux x86_64 | 50 | 654 | **0** | 0.6% | 0 |
| Windows Server x86/x86_64 | 50 | 461 | **0** | 0.8% | 0 |
| macOS arm64 | 46 | 417 | **0** | 0.9% | 0 |

Pooled with the reference run: **0 false VERIFIED of 2,007 known-false claims** across four
platforms (95% upper bound about 0.2%).

### Third-party replication: aarch64 Linux ELF (Jetson)

Reported in [#5](https://github.com/2akouwu/reverify/pull/5) by @IMGillusion — 19 aarch64
ELFs from `/usr/bin`:

```
prior wrong (hallucination rate): 19/19 = 100%
false VERIFIED (must be 0)       : 0
true bytes after 1 feedback round: 19/19 = 100%
```

The x86 textbook prior is a weak probe on ARM64 — it is *expected* to be wrong, because
aarch64 entry points open with `sub sp, sp, #N` / `mov x29, sp`. The load-bearing number is
the **zero false-VERIFIED**: the soundness guarantee holds across architectures. Producing
this run surfaced a real bug (arm64 was routed to the x86_64 decoder), fixed in v0.9.1 —
which is what replication is for.

## Reading it honestly

- The meaningful result is the false-VERIFIED row, and the honest way to read "0 of N" is
  the upper bound: 0/71 means the rate is below about 5% with 95% confidence, not that it is
  zero. The bound tightens only with more binaries; CI adds two platforms per push and the
  `--per-dir` knob widens the sample. The zero-false-accept property is the verifier's
  soundness, tested independently (`tests/test_oracle.py`, `test_differential.py`, the
  nightly fuzz) and confirmed here in the field.
- "Prior wrong" is specific to **entry-point** prologues, which are CRT/DLL startup stubs
  with characteristic non-textbook shapes. Random internal functions would give a different
  rate; this is one clean probe of one well-known prior, not a survey of all hallucinations.
- "True bytes after 1 round" shows the feedback loop converging, but round 2 restates what
  the tool reported — in the scored `reconstruct` loop that restatement is echo-detected and
  carries no information weight. It proves the loop reaches ground truth; it is not the
  model independently reasoning.
- Binaries whose entry the verifier cannot judge (no engines, unknown format) are reported
  as *inconclusive* and excluded from every rate — never silently dropped and never counted
  as a pass.

The model in the worked example ([EXAMPLE.md](EXAMPLE.md)) was Claude, plugged in as the
injected proposer — no API key, no specific model. The benchmark itself needs no model at
all: the prior is fixed, so anyone can run it.
