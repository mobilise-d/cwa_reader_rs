# Packet-batched reader

Status: implementation, user-requested simplicity/performance follow-up. Base a686c45c4f362ed73aa404d16799e0cd2bf9cf98.
PR https://github.com/mobilise-d/cwa_reader_rs/pull/7 remains the delivery PR.
All previously reviewed history is immutable; use normal new commits.

COMPACTION CONTINUITY: Re-read implement-code-change and the task-defining artifacts before continuing after compaction or session restoration.

## Accepted design

Replace the old full-data reader path completely. One shared engine in cwa-core
serves native Python, bytes and standalone browser File streaming. Batches own a
configurable number of 512-byte data packets, not rows. Preload the owned range
plus one physical packet on either side by default, clipped to real file bounds.
Overlap is configurable. If valid interpolation/timestamp context is unavailable
inside the preload, fail explicitly with InsufficientContext; no automatic refill
or fallback legacy engine in v1. Distinguish preload boundaries from actual EOF.
A failed batch must not emit provisional output. Already-delivered batches remain
valid if a subsequent batch fails.

Cubic interpolation uses four original neighboring samples, not recursive output.
Independent batches share the global sampling grid and recording/cut origin;
exclusive output ownership prevents gaps/duplicates at boundaries. Preserve
packet timestamp continuity, channel-presence/NaN semantics, float32 values,
integer timestamps, cuts, fixed offsets, linear edges and CSV behavior.
Native Python existing calls remain compatible; new keyword tuning controls may
be added for packet batch/overlap sizes. No multiprocessing, threads or worker pool.

Metadata still manually reads only the necessary bytes, retaining PR #8 boundary
lookup. Do not force metadata through a large read-ahead buffer. Structure source
access separately so synchronous Read+Seek and async browser File.slice can each
preload ranges and invoke synchronous batch decoding. Existing full-read APIs
collect batches; CSV and incremental browser consumers use the same engine.
Sampling consistency reports still inspect all packet metadata and should avoid
one filesystem/browser call per 512-byte packet during their full scan.

User clarification: packet times are ALWAYS ordered. This is the supported format
contract. Replace the old full-file seconds-cut timing scan with estimated seek:
use first valid sample origin and sampling rate/sample count to estimate a packet,
probe timing, and correct by one or more pages according to the time error until
the exact start/end packets are located. Keep a narrowing bracket/progress rule
for poor estimates, varying packet sample counts and non-data pages. Do not build
a file-wide index or fall back to full scans for hypothetical clock resets.
Preserve exact cut origin, timestamp correction, end exclusion and context.
Unvisited packets outside the selected region are not validated by a seconds cut;
full sampling reports remain the operation that inspects all packet metadata.
This replaces the earlier conservative seconds-planning implementation direction.
Prove narrow early/middle/late cuts use few bytes/requests on the real multiday
recording, with parity against the preserved baseline.


## Ownership and review units

1. Core agent owns crates/cwa-core, Python adapters, relevant native tests and
   manifests. Baseline/golden outputs first; agree range/decoder interface with
   browser agent. Commit coherent structural and behavioral slices after focused
   Rust/native parity tests. Remove obsolete full-decode paths and dead APIs.
2. Standalone agent owns wasm, standalone docs/CI. Integrate byte and File batch
   interfaces, backpressure/cancellation, fixed-overlap errors, browser tests and
   standalone batch-size measurements. Commit after actual browser proof.
3. Xeus agent owns benchmark tooling, Xeus recipe/runtime/CI/docs and performance
   report. Find real multiday recordings through downstream checkout below;
   preserve baseline binaries/receipts, measure native and real browser WORKERFS
   with controls for downstream cache. Commit reproducible tools and aggregate
   measurements, never private recordings or participant-derived values.
4. Parent owns this plan, README/PR integration, cross-slice acceptance, packaging,
   final review/CI/artifact delivery. No published packages or merging PRs.

User-authorized test seams: core batch interface, existing Python interface,
standalone bytes/File interface and actual Xeus worker. Use behavioral red/green
for new batch/error behavior; existing checks for structural moves. Important
proof: independent batch concatenation matches pre-refactor oracle across batch
sizes, including exact timestamps and raw data, documented interpolation tolerance,
NaNs, absent/mixed channels, cuts, offsets and CSV. Check rare insufficient-context
cases explicitly; input packet alignment and truncated sectors remain validated.

## Benchmarks and external data

Read-only downstream /home/arne/.t3/worktrees/mobgap/t3code-fa914513 contains
WORKERFS bridge.js and native/browser probes. Its current workaround is one shared
aligned 1 MiB cache for .cwa files, leaving 512-byte logical Rust calls intact.
Locate multiday recordings there or in its referenced local data paths. Keep raw
recordings, private paths and per-participant outputs out of committed artifacts.
Measure baseline vs new reader, several packet batch sizes (initial candidates
64,256,1024,2048,8192), native and actual Wasm filesystem access. Include raw and
resampled reads, representative early/middle/late cuts, and full-file bounded
batch consumption where available. Do not allocate huge DataFrames merely to
prove throughput; distinguish full collector memory from bounded decoding.
Record input size/duration/channel layout, exact source/tool versions, repeats,
read calls/bytes, timings, output size and memory metric definitions. Establish a
measured default, report unsupported sizes/overlap failures and limitations.

User cleanup requirement: show historical benchmark comparisons before removing
their repository tooling. Preserve receipts outside the repository. Before the PR
is ready, remove benchmarks/tests for obsolete solutions, including the downstream
WORKERFS cache, and baseline-comparison modes. Retain useful current-reader
batch-size measurements and correctness tests. Do not retain a legacy reader just
to provide a benchmark comparator. No merge is authorized.

## Completion gates

- One production packet-batch data engine, old reader path removed.
- Targeted metadata reads and native API behavior retained.
- Rust/native/browser parity and meaningful batch/context tests pass.
- Native wheel and sdist packaging still includes core, excludes fixtures.
- Actual Xeus build/browser parity and WORKERFS performance evidence.
- Standalone File batching reads bounded slices without whole-file staging.
- Reproducible native/Wasm batch-size benchmark with real multiday recording.
- Historical benchmark results shown; obsolete comparison/cache tooling removed.
- Per-commit reviews closed; final range review from exact base above, no rewrite.
- Branch pushed, PR updated/linked, CI artifacts checked; no publication.

## Verification progress

Core replacement 327f2b6 removes the old decode path. Browser constructor
integration was corrected in e57b5c0. Ordered seconds seeking landed in a310cfa;
2126651 fixes true-start linear context and 53d5ed1 compacts empty timing runs.
The 31 preserved pre-refactor output manifests match exactly. At 53d5ed1,
22 Rust tests and 128 native Python tests pass; a wheel built from the sdist
passes all 128 tests in a clean environment. Packaging includes the core and
excludes recording fixtures. Local receipt:
/tmp/cwa-batch-package-acceptance/results.json.

Historical native/Xeus cache benchmark results were shown to the user.
3f43b57 removes the cache comparison mode, implementation and cache-specific tests.
Historical receipts remain outside the repository. Current-reader measurements,
standalone File adapter final integration, Xeus final artifact, final changeset
review and final CI/artifact inspection remain outstanding. A measured native
full-CSV regression is under investigation and must be reported or resolved.

Core source is complete through 8375b9b; standalone integration through 84891bb.
Final core has 23 Rust tests and 128 native tests passing, including a fresh
sdist-built installed wheel. Standalone has 14 browser tests and 12 private
native cut/CSV comparisons passing. Final clean Xeus artifact at 8375b9b passed
25 direct comparisons, 128 Python tests in the worker and recovered CSV parity.
All implementation reviews through 84891bb are closed. History stays immutable;
no fixup/squash commits remain. Final whole-range review may proceed while the
last quiet benchmark runs and measured-results documentation finish. These must
still be delivered before completion.

Standalone quiet full-recording medians at 256 packets: raw 5.5834 s, 60 Hz
10.3982 s; committed Wasm capacity 4.375 MiB, output discarded. Five sizes
64/256/1024/2048/8192 were measured with three repeats. Real input is 436,792,320
bytes. Native CSV follow-up quiet pair: old 16.895 s, new 17.431 s; this is one
pair, not a three-repeat median. The shared CSV schema pass decodes batches.
Do not report the earlier contended CSV timings as a regression measurement.

CI at 84891bb passed native and Xeus. Xeus artifact was downloaded and package/
module checksums and fixture exclusion verified under /tmp/cwa-batch-final-ci.
Its synthetic PR-merge source da3e343 has parents main53830c8 and 84891bb.
Final standalone CI/artifact check, remaining benchmark report, final review,
updated PR and completion receipt remain pending.

Latest requested measurement: compare the actual native Python read_cwa_file
DataFrame interface against the preserved unbatched reader for the complete real
recording and representative 24-hour seconds cuts. Streaming count/discard, CSV
and short-window numbers are not substitutes. Use isolated sequential processes,
same options/input, report rows/output parity, reader timing and peak RSS. Keep
historical comparison scripts and receipts outside the repository; do not restore
obsolete benchmark modes. These results must be shown to the user.

## Simplicity and native overhead follow-up

The user explicitly requested two GPT-6.1-sol high-reasoning agents: one to review
duplicated paths/passes and complexity from poorly fitting interfaces, another to
reduce batching overhead toward the old native full-read performance. Existing
agents are reused: Xeus agent is the read-only simplicity reviewer, core agent
owns profiling and implementation. They coordinate overlapping findings; parent
owns integration. Standalone agent remains available for adapter changes.

Baseline actual Python full DataFrame: old unbatched a686c45 median 1.3046 s,
pre-optimization batched 8375b9b median 1.5871 s. First/middle/last 24-hour cuts
were old 0.7360/0.7473/0.7198 s versus batched 0.4476/0.3909/0.3908 s. Read-phase
peak RSS was about 1510 MiB full, 441 MiB daily. Three isolated sequential runs
per case, same real recording/options, all 36 outputs identical. Historical
scripts/receipts stay outside the repository. Keep the useful current-reader
full/day benchmark.

Ranked profiling hypotheses: temporary staging and batch-to-collector copies;
fresh allocations and per-row capacity checks; repeated packet metadata and
per-sample setup. Measure before changing one mechanism at a time. Preserve one
engine, bounded independent batches, overlap/error semantics, global cubic grid,
ordered seconds cuts, native Python behavior, and no multiprocessing. Seek a
simpler interface as well as lower cost; do not restore the old reader or add
speculative abstractions. Finish and commit coherent changes with focused parity
checks, then repeat actual full/day Python measurements. Check native/Wasm output
parity and bounded-memory behavior after material changes. Report remaining
tradeoffs honestly.

Final review14240 covered a686c45..d029904 and found a short zero-overlap cut
context bug. Normal correction02e4d10 and browser regression3ddf079 address it;
24 Rust/128 Python/15 standalone tests pass at that point. A related one-sample
context error found by the correction review is being fixed before performance
work. Preserve all reviewed history and correction commits. After the new
user-requested optimization/simplicity work, review its new range from d029904;
this is new scope, not a repeat review merely for14240 corrections.
