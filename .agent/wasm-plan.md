# Browser builds and parser separation

Status: complete. This document records the accepted contract and validation receipt.

## Contract and ownership

Base: 026ddf9edca6aaf28a4318dc3023d3d98f886056. Worktree initially clean.
This thread owns cwa_reader_rs; another agent owns the downstream mobgap runtime.
The user requested GPT-6.1-Sol agents at medium/high reasoning with parent supervision.
Core, standalone and Xeus workers used high reasoning; parent owns integration and delivery.
Pull request: https://github.com/mobilise-d/cwa_reader_rs/pull/7, linked to this thread.

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
1. a4ccfef separates Python adapters and Python-free Rust core. Native 5 Rust and
   122 Python tests passed; no-default core build excludes PyO3/NumPy.
2. 5cfce54 adds header bytes and Read/Seek input plus reader timing scans.
   Default/no-default 7 Rust tests and native 122 Python tests passed.
3. 18f9459 + fixup6497119 checks u64 offsets, usize allocation counts, counters
   and fallible capacity growth. Boundary tests avoid large allocations.
   Default/no-default 8 Rust tests, native 122 and Rust 1.90 wasm32 core check pass.
4. 4c457e2 + fixupadcf341 delivers standalone wasm-bindgen header adapter,
   browser File example, docs and separate CI. Rust 1.90/wasm-bindgen0.2.129.
   Three Chromium tests pass against native; ten repeated binding generations
   produce identical Wasm. Header fields preserve raw naive timestamps/nulls;
   malformed/truncated input and recovery tested. No data-timing scan is implied.
5. 8e91890 delivers pinned Xeus recipe, local conda artifact, file bridge,
   browser/native comparison, docs and separate CI.25 direct cases and all 122
   existing tests pass in an actual Xeus worker. Fresh output directory tested.
6. Parent integration documents browser entry points and acceptance evidence.

Per-commit reviews14157,14158,14159,14160,14161,14162,14163,14165 passed or were
corrected, commented and closed. Both fixups were autosquashed before final review; backup ref
backup/wasm-before-curation-20261008 preserves the original stack.
Final whole-range review14168 passed without findings and is closed. No
feature_ready panel was configured, so the review used panel none from the exact
base above. Reviewed head: cf757434cb2c0c09e8945a598a44a3d3baff6c52.
No code corrections followed the final review; the remaining commit records this receipt.

Native baseline: cargo5 tests and Python 122 tests passed. Default uv selected
Python3.14 and attempted to compile locked pandas2.3.2; stopped that attempt and
used Python3.13 in /tmp/cwa-reader-native-313. Native packaged-wheel verification
in a separate clean Python3.13 environment passes all 122 tests and explicit
reference/API/cut/resample/timezone/CSV smoke. Wheel and sdist contain no fixture
or generated recording. Receipt: /tmp/cwa-native-package-acceptance/results.json.
Native CI, standalone browser CI and Xeus browser CI all passed at reviewed
head cf75743. The final receipt changes documentation only.

Xeus parity covers exact integer-nanosecond timestamps, index dtype/timezone,
shape/column presence, raw values exactly, interpolation within 1e-6, NaN versus
zero and absent channels, nonzero 9-axis and mixed layouts, packed variants,
full/block/seconds reads, supported resampling, fixed positive/negative/fractional
offsets, metadata/reports, exceptions and recovered CSV hashes. Existing 122 tests
also check full-slice consistency/end-exclusive cuts, missing times, selected
channels and C-reference comparisons. Only C CSV timestamp comparison retains
its existing millisecond tolerance. Artifact uploads exclude fixtures, raw native
comparison arrays, recovered CSV and the full test runtime.

## Final artifacts and delivery

- Standalone local bundle: wasm/pkg; metrics: wasm/test-results/header-metrics.json.
  Final pin 0.2.129 produces 78,087-byte Wasm; measured 0.6ms header read/17.6 ms for 1,000 parses,
  linear memory1,179,648B unchanged. Measurements are machine-specific.
- Xeus local artifact: /tmp/cwa-xeus/channel/emscripten-wasm32/cwa_reader_rs-0.4.0-h7223423_0.tar.bz2.
  Manifest/runtime resolution: /tmp/cwa-xeus/{artifact-manifest,runtime-packages}.json.
  Report: /tmp/cwa-xeus/results/browser-report.json. Fixture305,664B ->71,400x6
  DataFrame2,284,800B. Warm median2.45ms in final headless run; committed heap
  139,198,464B before/after, not a peak live-allocation measurement.
- Both browser artifacts were rebuilt from clean cf75743; source_dirty=false.
  Standalone SHA256: feef0ea0404087bfd15fec450272bc650f76cd3246601926ae73b94b98a47c12.
  Local Xeus package SHA256: 87b0ea60dc459871227e4879eea12b83c416123a28114af35b34d384d6b1706f.
- CI runs37772181856(native),37772181929(standalone),37772181745(Xeus) passed.
  Uploaded standalone-browser-wasm, standalone-browser-test-results and
  xeus-wasm-python313-emscripten409 artifacts were verified available.
- Curated six-commit implementation: a4ccfef,5cfce54,89b311c,2ea709e,2a7f82a,cf75743.
  The final receipt is a normal additional documentation commit, preserving the
  reviewed stack. Branch pushed; PR7 linked to thread. No package publication.
- Review14164 was a duplicate passing Xeus review, also inspected and closed;
  documentation review14167 passed and closed. No unresolved implementation reviews.
- Standalone full-sample export, lazy Xeus File mounting and downstream mobgap
  preset validation remain the explicit limits above, not unfinished delivery gates.
