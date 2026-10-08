# Native and Xeus reader benchmarks

These tools run against an explicitly installed reader, so the pre-batch wheel and
new wheel can be compared without rebuilding the old implementation. Keep real
recordings and full JSON reports outside this repository. Use dataset aliases in
reports shared with reviewers.

A native invocation runs one case in a fresh Python process:

```sh
/path/to/reader-env/bin/python tools/benchmarks/native.py /private/recording.cwa \
  --case middle --resample-hz 60 --batch-packets 256
```

Omit `--batch-packets` when testing the old reader. Cases are `metadata`, `report`,
`csv-sink`, `early`, `middle` and `late`. Window cases select 60 seconds relative
to the first valid sample. Full-file raw CSV uses `/dev/null`; it includes decoding,
timestamps and text formatting but never retains a full DataFrame. `report` scans
packet timing only. They measure different work and must be labelled separately.
NumPy and pandas imports occur outside operation timing. The native maximum RSS
includes interpreter/import costs and is a process peak.

Prepare the Xeus output with `tools/wasm/build-xeus.sh`, `parity.py` and
`prepare-runtime.py` as documented in [the Xeus build guide](../../docs/xeus-wasm.md).
Install Playwright in the runner environment and its Chromium browser. Supply a
runtime adaptation of the official Emscripten WORKERFS backend compatible with the
runtime. The downstream demo's `runtime/workerfs/workerfs.js` is one such adapter;
its provenance and Emscripten MIT license stay with that source. This benchmark
does not modify or package the downstream runtime.

```sh
/path/to/browser-env/bin/python tools/benchmarks/xeus.py /tmp/cwa-wasm \
  /private/recording.cwa /path/to/workerfs.js \
  --report /tmp/cwa-bench/direct.json --cache-bytes 0 --repeats 3
/path/to/browser-env/bin/python tools/benchmarks/xeus.py /tmp/cwa-wasm \
  /private/recording.cwa /path/to/workerfs.js \
  --report /tmp/cwa-bench/cached.json --cache-bytes 1048576 --repeats 3
```

The browser selects a local File and structured-clones its handle through Xeus's
worker RPC. WORKERFS reads File slices on demand. No full-file `arrayBuffer`,
base64 conversion or MEMFS staging is used. `--cache-bytes 1048576` enables a single
shared aligned cache with the downstream bridge's read-ahead algorithm. Logical
counters measure Rust filesystem calls; physical counters measure
`FileReaderSync.readAsArrayBuffer` calls and returned bytes. Each case remounts the
File and clears the cache. The kernel stays alive, including its grown allocator. Local OS file caches are
not cleared; results are warm-storage measurements, not cold-disk latency.
The wasm committed heap size is an allocation capacity, not live or peak memory.
The optional cache is a JavaScript allocation outside that heap.

Use `--cases early,middle,late --resample-hz 60` for resampled windows;
`--cases csv-sink --repeats 1` for bounded full-file output. Sweep
`--batch-packets` over 64, 256, 1024, 2048 and 8192 once a package with tuning controls
is installed. A reader error stops the run instead of falling back to another engine.
A case exceeding `--timeout-seconds` records a lower bound and stops the run.
Reader time covers only the operation. Metadata and end-to-end time are also
recorded; end-to-end time includes metadata, conversion and output fingerprinting.
The old reader collects full resampled CSV output in memory. Benchmark its full
CSV sink only without resampling; full resampled bounded output requires the new
batch writer.
Value hashes are exact checks for raw output; resampling comparisons require the
separate numeric parity tests and their documented floating-point tolerance.

Check the counter implementation with `node tools/benchmarks/workerfs-meter.test.mjs`.
