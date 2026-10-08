# Packet-batched reader

Status: implementation. Base a686c45c4f362ed73aa404d16799e0cd2bf9cf98.
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

## Completion gates

- One production packet-batch data engine, old reader path removed.
- Targeted metadata reads and native API behavior retained.
- Rust/native/browser parity and meaningful batch/context tests pass.
- Native wheel and sdist packaging still includes core, excludes fixtures.
- Actual Xeus build/browser parity and WORKERFS performance evidence.
- Standalone File batching reads bounded slices without whole-file staging.
- Reproducible native/Wasm batch-size benchmark with real multiday recording.
- Per-commit reviews closed; final range review from exact base above, no rewrite.
- Branch pushed, PR updated/linked, CI artifacts checked; no publication.
