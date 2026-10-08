# Browser builds and parser separation

Status: main-branch merge resolved after PR #8 merged upstream; commit review and
PR delivery remain. The previous browser delivery and reviewed history remain intact.

COMPACTION CONTINUITY: Re-read implement-code-change and the task-defining artifacts before continuing after compaction or session restoration.

## Main-branch merge

Origin main 53830c8 now contains PR #8's original path-based metadata optimization.
Merge it normally, preserve b50bb9a's Read+Seek adaptation in cwa-core, remove the
obsolete src/header.rs conflict, and retain one README metadata description.
Verification/commit gate: existing 13 Rust and 122 native Python tests, formatting,
no unresolved conflicts or duplicate parser, and temporary boundary parity checks.
Review and close the merge commit; parent owns push and PR status verification.
Merge resolution leaves all Rust/Python source and manifests identical to 4dc074b.
The existing 13 Rust and 122 native Python tests pass, formatting/diff checks pass,
and temporary 201-case boundary parity plus sparse-input I/O checks pass again.
No new buffering implementation is authorized by this housekeeping task.

## Final follow-up verification

Reviewed head be6f7ed13447e7faa4096f7ce0c3f7e9af284f97; exact follow-up range
f731c97801c9b48208582b26aab7b9021a1e891f..be6f7ed. Final review 14184 passed
without findings and is closed. All implementation reviews are resolved and closed.
No reviewed commit was rewritten and no code corrections followed final review.

- Native: 13 Rust tests; 122 source and 122 installed-wheel tests; fresh isolated
  sdist build/install/reference smoke. Receipt /tmp/cwa-core-package-acceptance/results.json;
  artifacts /tmp/cwa-pr8-package-acceptance/artifacts. No fixture redistribution.
- Standalone: clean be6f7ed, eight Chromium tests / 31 recording cases pass.
  wasm/pkg contains the installable local bundle; Wasm 261,584 bytes, SHA256
  009fb36261d1b1b14178d1ea02396d559c56d426f0114c2973b049df8c81bec2.
  Ten binding generations identical. Real fixture 305,664 bytes -> 71,400x6,
  8.4 ms read, 2,284,800 output-array bytes. Committed linear memory grows from
  1,114,112 to 6,422,528 bytes after read/CSV. This is not peak memory.
- Xeus: clean be6f7ed, 25 direct parity comparisons and 122 pytest tests pass.
  CSV recovery matches native. Local conda artifact 167,408 bytes, SHA256
  5468685fbf1157f9bec33bafd64f237ecaa17d4ce9bdddac6723968094f7ad7b.
  Warm read median 2.7 ms; first read 11.2 ms. DataFrame/index 2,284,800 bytes;
  committed heap 139,198,464 bytes unchanged, not a peak measurement.
  Artifact/manifest/runtime/report under /tmp/cwa-xeus.
- Final CI workflows passed: native 37777038905, standalone 37777039073,
  Xeus 37777038869. Downloaded artifacts verified under /tmp/cwa-final-ci.
  CI records its clean GitHub PR merge checkout c11fc73a230f18681de82c204f39a1c61837c748;
  standalone reports eight passing tests; Xeus reports success and 122 tests.
  CI package checksum verified and archive has no fixture/CSV files.
- PR #7 includes attributed adaptation of PR #8. Both linked to this thread;
  no package publication or PR merge. Final receipt is documentation only.

## Follow-up contract

Follow-up base: f731c97801c9b48208582b26aab7b9021a1e891f.
The previous delivery exposed only header parsing in Wasm and left seconds-cut
planning, resampling and CSV tied to paths. The user rejected that limitation.
Complete byte-backed access for header metadata, full metadata/timing scan,
sampling consistency report, full/block/seconds sample reads, resampling, channel
flags, fixed offsets and CSV output. Generic Read+Seek/Write implementations must
serve both path adapters and Cursor-backed bytes; no temporary file is needed.
Parsing and report calculations belong in the Rust core, not Python or JS bridges.
Preserve the native Python signatures and results. Keep header-only preview efficient;
1,024 is the header length, not a cap on recording input. Browser output must preserve
i64 timestamp precision, f32 columns, NaNs and absent-channel semantics.
Do not claim that full-buffer byte input is lazy or constant-memory streaming.

The user explicitly approved extracting `crates/cwa-core` after discussing the
same-crate optional-Python design. The core must have no Python or JavaScript
bridge dependencies. Root Python package and standalone Wasm adapter both depend
on it. Keep local source builds, native wheel/sdist packaging, Xeus recipe source
staging and standalone builds working without publishing the core crate.

Completed follow-up commits: 8863c7b and a74feec. Generic reader operations and
shared CwaReader pass 13 Rust tests with/without Python, 122 native Python tests,
and wasm32 compilation. Reviews 14171/14172 passed and are closed.

New explicit request: integrate https://github.com/mobilise-d/cwa_reader_rs/pull/8
at source d1bd1f4510d5feeede21d14a0ae5ccca3938b90b. Port boundary lookup to generic
Read+Seek in cwa-core after extraction. read_metadata searches first packet and
last packet/predecessor; sampling_consistency_report retains its full scan and
real sample count. Encountered malformed/truncated packets still error; unvisited
interior corruption is intentionally not detected by metadata lookup. Preserve
raw timestamps and continuity correction. Keep PR attribution in integration
commit and PR description. Existing tests plus temporary boundary/I/O checks
respect the source PR's explicit decision against new permanent coverage.

Extraction a010ee0 passes 13 Rust tests, pure-core dependency/wasm checks,
122 native tests and 122 installed-wheel tests. Sdist includes core source and
license, excludes fixtures/binaries, and builds/installs in an isolated target.
Packaging receipt: /tmp/cwa-core-package-acceptance/results.json.

PR #8 port b50bb9a retains original source/author attribution. Validation: 13 Rust and 122 native Python tests pass, plus Rust 1.90
wasm32 core check. Temporary checks match 201 boundary cases against full scans,
including sample offsets, gaps/backward clocks, empty/skipped packets and the real
fixture. A sparse 536,870,912-byte seekable input reads 2,560 bytes for metadata.
Visited malformed boundaries and partial sectors error; unvisited interior
corruption is skipped as explicitly requested by PR #8.

Current review units, each with focused checks and a normal commit gate:
1. Core worker: remove remaining filesystem dependencies from operations; add
   meaningful in-memory/path parity; run default/no-default Rust and native tests.
2. Standalone worker: expose all operations to JS bytes, demonstrate beyond-header
   processing and CSV, validate actual browser/native parity; update own docs/CI.
3. Core worker: extract crates/cwa-core, update Python imports/workspace and
   prove Rust/native tests plus wheel/sdist inclusion and installation.
4. Standalone worker: switch to direct cwa-core dependency and rerun browser parity.
5. Xeus worker: update staging/build assumptions and run actual-worker regression
   against the separate crate.
6. Parent: docs/PR integration, source/packaging checks, per-commit review closure,
   fresh browser artifacts, final review of this follow-up range and delivery.
Previous reviewed commits remain immutable. No amend/autosquash/rebase into them.
Standalone full-byte expansion f191065 passes seven Chromium tests and 31
native recording cases. Direct cwa-core integration passes those tests again.
Browser timestamps/raw recorded sensors compare exactly; computed light differs
by at most one float32 ULP, and resampling uses 1e-6 tolerance. Review 14174 found
an example worker-failure handling bug, corrected in ee2fae4 with a regression
test. Eight browser tests now pass; reviews 14174 and 14181 are closed.
Xeus receipts include nested core source hashes in f24d5d1; reviews 14179/14180
passed and closed. Extraction review 14178 is resolved by that receipt update.
All earlier artifacts and validation below are historical until refreshed.


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

Local file selection does not upload or persist the recording. Standalone header preview reads only a File slice; full operations read the
selected File into bytes and run in a worker. The pinned Xeus runtime lacks WORKERFS: the tested bridge
copies bytes into transient MEMFS. A lazy read-only local File filesystem adapter
is feasible but not implemented. Do not claim zero-copy or all-day scalability.
Full DataFrame results allocate the selected samples. Standalone sample decoding is now required by the follow-up above. The initial
delivery described below exposed headers only.

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

## Previous delivery artifacts and evidence

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
- Lazy Xeus File mounting and downstream mobgap preset validation remain outside
  this follow-up. Standalone full-sample export is now required.
