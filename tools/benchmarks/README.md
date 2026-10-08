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
File and clears the cache. Each workload releases its frame and arrays before returning. The kernel stays
alive, including its grown allocator. Local OS file caches are
not cleared; results are warm-storage measurements, not cold-disk latency.
The wasm committed heap size is an allocation capacity, not live or peak memory.
The optional cache is a JavaScript allocation outside that heap.

Use `--cases early,middle,late --resample-hz 60` for resampled windows;
`--cases csv-sink --repeats 1` for bounded full-file output. Sweep
`--batch-packets` over 64, 256, 1024, 2048 and 8192 once a package with tuning controls
is installed. A reader error stops the run instead of falling back to another engine.
A case exceeding `--timeout-seconds` records a bound on the entire kernel
execution and stops the run. It does not claim a reader-only timing bound.
Reader time covers only the operation. Metadata and end-to-end time are also
recorded; end-to-end time includes metadata, conversion and output fingerprinting.
The old reader collects full resampled CSV output in memory. Benchmark its full
CSV sink only without resampling; full resampled bounded output requires the new
batch writer.
Value hashes are exact checks for raw output; resampling comparisons require the
separate numeric parity tests and their documented floating-point tolerance.

Check the counter implementation with `node tools/benchmarks/workerfs-meter.test.mjs`.

For native filesystem counts, run a separate instrumented case with strace. Its
slow elapsed time must not enter the normal timing table. `-s 0` suppresses input
and output values; `-P` restricts the log to the supplied recording and sink.

```sh
strace -s 0 -e trace=read,lseek,write -P /private/recording.cwa -P /dev/null \
  -o /tmp/cwa-bench/native.strace \
  /path/to/reader-env/bin/python tools/benchmarks/native.py \
  /private/recording.cwa --case csv-sink --batch-packets 256
python tools/benchmarks/native-syscalls.py /tmp/cwa-bench/native.strace
```

These are kernel read/write syscall counts, including short-read retry and EOF
probes. They do not measure physical disk reads; the OS cache remains enabled.
The parser handles the single-process `read`, `write` and `lseek` trace above.

The Linux Rust runner measures full decode without DataFrame collection or CSV
formatting. It immediately drops each decoded batch and counts bytes from actual
`File::read` calls separately from session range requests. Its peak RSS includes
all parser allocations; input buffer capacity and largest returned batch are
reported separately. It has an isolated Cargo workspace and pinned dependency
lock, so building the benchmark does not alter the Python package workspace.

```sh
CARGO_TARGET_DIR=/tmp/cwa-bench/native-core-target cargo build --release --locked \
  --manifest-path tools/benchmarks/native-core/Cargo.toml
/tmp/cwa-bench/native-core-target/release/cwa-native-benchmark \
  /private/recording.cwa 256 full
/tmp/cwa-bench/native-core-target/release/cwa-native-benchmark \
  /private/recording.cwa 256 middle 60
```

Use the same packet grid and three fresh process runs per case. Window cases use
60-second cuts, including their seconds-locator requests. The small boundary metadata
read used to choose window positions occurs outside timing and counters. Full
cases include the session header request. Files stay in the warm OS cache. There
is no equivalent pre-batch bounded decoded-array interface; the old full CSV sink
and sampling report must be labelled as separate workloads.
