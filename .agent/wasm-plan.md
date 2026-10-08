# Browser builds and parser separation

COMPACTION CONTINUITY: Re-read implement-code-change and the task-defining artifacts before continuing after compaction or session restoration.

## Contract and ownership

Base: 026ddf9edca6aaf28a4318dc3023d3d98f886056. Worktree initially clean.
This thread owns cwa_reader_rs; another agent owns the downstream mobgap runtime.
The user requested GPT-6.1-Sol agents at medium/high reasoning with parent supervision.
Core, standalone and Xeus workers used high reasoning; parent owns integration and delivery.
Draft PR: https://github.com/mobilise-d/cwa_reader_rs/pull/7, linked to this thread.

The user requests a shared Rust parser independent of Python bridging, a standalone
browser header bundle, and a real Xeus Python extension. Preserve all six existing
Python exports, signatures, errors, DataFrame channels/dtypes, timestamps, cuts,
fixed timezone offsets, resampling and CSV. This task-specific compatibility
requirement overrides the repository's permissive pre-1.0 policy. Do not publish
packages. Preserve third-party fixture exclusions from distributable artifacts.

Xeus requirements: wasm32-unknown-emscripten side module with proper CPython import
suffix/initializer and dylink metadata, local emscripten-wasm32 conda installation,
pinned forge recipe/toolchain and resolved package metadata, separate CI/artifacts,
real browser worker import/file read/CSV recovery, native parity, measured timing
and memory. Compilation alone is not acceptance. Source revision, checksums and
compiler versions must accompany artifacts; do not infer target ABI from host Python.

Initial runtime: CPython3.13.1 h_2efca29_11_cp313, python_abi3.13 9_cp313,
Emscripten ABI4.0.9 h267e887_9, NumPy2.4.6 py313hcf5bae3_0,
pandas3.0.6 np23py313h124dbc7_0, xeus-python0.19.0 py313he5686da_3.
Channels: https://repo.prefix.dev/emscripten-forge-4x and conda-forge.
Optional downstream reference /tmp/mobgap-wasm/runtime was inspected read-only;
reproduction does not require it. Downstream Numba/mobgap integration remains
separate, needing participant metadata and a suitable real gyro recording.

Local file selection does not upload or persist the recording. Standalone reads
only a File slice. The pinned Xeus runtime lacks WORKERFS: the tested bridge
copies bytes into transient MEMFS. A lazy read-only local File filesystem adapter
is feasible but not implemented. Do not claim zero-copy or all-day scalability.
Full DataFrame results allocate the selected samples. Standalone sample decoding
is optional future work; the delivered browser export parses headers only.

## Review units and verification

Every slice requires focused verification and its own commit before the next.
Completed pre-curation units:
1. a4ccfef separates Python adapters and Python-free Rust core. Native5 Rust and
   122 Python tests passed; no-default core build excludes PyO3/NumPy.
2. 5cfce54 adds header bytes and Read/Seek input plus reader timing scans.
   Default/no-default7 Rust tests and native122 Python tests passed.
3. 18f9459 + fixup6497119 checks u64 offsets, usize allocation counts, counters
   and fallible capacity growth. Boundary tests avoid large allocations.
   Default/no-default8 Rust tests, native122 and Rust1.90 wasm32 core check pass.
4. 4c457e2 + fixupadcf341 delivers standalone wasm-bindgen header adapter,
   browser File example, docs and separate CI. Rust1.90/wasm-bindgen0.2.129.
   Three Chromium tests pass against native; ten repeated binding generations
   produce identical Wasm. Header fields preserve raw naive timestamps/nulls;
   malformed/truncated input and recovery tested. No data-timing scan is implied.
5. 8e91890 delivers pinned Xeus recipe, local conda artifact, file bridge,
   browser/native comparison, docs and separate CI.25 direct cases and all122
   existing tests pass in an actual Xeus worker. Fresh output directory tested.
6. Parent integration documents browser entry points and acceptance evidence.

Per-commit reviews14157,14158,14159,14160,14161,14162,14163,14165 passed or were
corrected, commented and closed. Both fixups must be autosquashed before final review.
No final whole-stack review has started yet. No feature_ready panel is configured;
use a single whole-range review from the exact base above after curation.

Native baseline: cargo5 tests and Python122 tests passed. Default uv selected
Python3.14 and attempted to compile locked pandas2.3.2; stopped that attempt and
used Python3.13 in /tmp/cwa-reader-native-313. Native packaged-wheel verification
in a separate clean Python3.13 environment passes all122 tests and explicit
reference/API/cut/resample/timezone/CSV smoke. Wheel and sdist contain no fixture
or generated recording. Receipt: /tmp/cwa-native-package-acceptance/results.json.
Native CI matrix and standalone browser CI passed at the earlier pushed head;
verify final head's checks separately.

Xeus parity covers exact integer-nanosecond timestamps, index dtype/timezone,
shape/column presence, raw values exactly, interpolation within1e-6, NaN versus
zero and absent channels, nonzero9-axis and mixed layouts, packed variants,
full/block/seconds reads, supported resampling, fixed positive/negative/fractional
offsets, metadata/reports, exceptions and recovered CSV hashes. Existing122 tests
also check full-slice consistency/end-exclusive cuts, missing times, selected
channels and C-reference comparisons. Only C CSV timestamp comparison retains
its existing millisecond tolerance. Artifact uploads exclude fixtures, raw native
comparison arrays, recovered CSV and the full test runtime.

## Artifacts and remaining delivery gates

- Standalone local bundle: wasm/pkg; metrics: wasm/test-results/header-metrics.json.
  Final pin0.2.129 produces77KiB Wasm; measured1.1ms header read/18.6ms1000parses,
  linear memory1,179,648B unchanged. Measurements are machine-specific.
- Xeus local artifact: /tmp/cwa-xeus/channel/emscripten-wasm32/cwa_reader_rs-0.4.0-h7223423_0.tar.bz2.
  Manifest/runtime resolution: /tmp/cwa-xeus/{artifact-manifest,runtime-packages}.json.
  Report: /tmp/cwa-xeus/results/browser-report.json. Fixture305,664B ->71,400x6
  DataFrame2,284,800B. Warm median2.45ms in final headless run; committed heap
  139,198,464B before/after, not a peak live-allocation measurement.
- Build metadata must be refreshed against the clean curated source revision.
- Remaining: commit integration docs; curate fixups with backup ref; fresh final
  verification; whole-range review; preserve any corrections as normal commits;
  push/update PR, check CI and artifact availability, confirm PR registration.
