# Standalone browser reader

`wasm/` builds a browser module directly from the shared `crates/cwa-core` crate.
The core has no Python dependencies; `python/` contains the Python extension.
It uses `wasm32-unknown-unknown`, Rust 1.90.0 and wasm-bindgen 0.2.129. This bundle
is independent of the [Xeus Python extension](../recipes/xeus/README.md) and its
Emscripten ABI. Shared [reader behavior](../docs/reader-behavior.md),
[timestamp rules](../docs/timestamps.md) and [validation](../docs/validation.md)
apply to both distributions.

## Build and run locally

Install Rust with rustup and Node.js 24. From the source checkout:

```sh
rustup toolchain install 1.90.0 --profile minimal --component rustfmt --target wasm32-unknown-unknown
cargo +1.90.0 install wasm-bindgen-cli --version 0.2.129 --locked
./wasm/build.sh
cd wasm
npm ci
npm run dev
```

Open `http://127.0.0.1:5287`. File selection reads the first 1,024 bytes for a
header preview. The buttons scan actual timing, decode the complete recording,
or download CSV. Sample decoding and CSV input use packet batches in a module
worker. Metadata seeks to sample boundaries; the sampling report scans bounded
input ranges. A CSV download retains the complete output. No recording bytes are sent to a server or written to a virtual filesystem.

The generated JS, Wasm, type declarations, license and checksum/compiler manifest
are in `wasm/pkg/`. Serve them with your application; the `.wasm` content type
should be `application/wasm`. Rust and npm dependency locks live in
`wasm/Cargo.lock` and `wasm/package-lock.json`. The root Cargo workspace excludes
`wasm/`, so its pinned build and lock stay independent of the Python/Emscripten
toolchains.

## Install the precompiled npm package

`./wasm/build.sh` also creates `wasm/dist/mobilise-d-cwa-reader-VERSION.tgz`.
The version comes from the Python Cargo package, currently 0.5.0. Download the
`standalone-browser-npm` CI artifact or build locally, then install the tarball
in your application:

```sh
npm install /path/to/mobilise-d-cwa-reader-0.5.0.tgz
```

```js
import { readMetadataFromFile, readCwaFileBatches } from '@mobilise-d/cwa-reader';
import init, { blocks } from '@mobilise-d/cwa-reader/bytes';

await init(); // The synchronous cut helpers require main-thread Wasm initialization.
const metadata = await readMetadataFromFile(fileHandle); // Or File/Blob.
for await (const samples of readCwaFileBatches(fileHandle, { cut: blocks(3, 10) })) {
  await consumeSamples(samples);
}
```

The package root exports the File facade; `/bytes` exports the synchronous byte
API and cut helpers. The tarball includes compiled Wasm, worker/JS modules,
TypeScript declarations, license, README and build metadata. Consumers need no
Rust compiler, installation scripts or runtime npm dependencies. The package
name is a provisional local scope; this workflow does not publish to a registry.
`wasm/dist/npm-pack.json` records the archive inventory, integrity and SHA-256.

## Source layout and deployment

| Directory | Purpose |
| --- | --- |
| `wasm/src/` | Rust adapter over the shared core. |
| `wasm/js/` | Handwritten File facade, declarations, worker and package README. |
| `wasm/scripts/` | Package generation, local server, installed-consumer test and benchmark. |
| `wasm/tests/` | Browser parity tests and minimal npm consumer. |
| `wasm/example/` | File-selection demo. |
| `wasm/pkg/` | Generated, directly servable runtime package. |
| `wasm/dist/` | Installable npm archive and its receipt. |

`wasm/build.sh` is the build entry point. Its single packaging step generates the
npm manifest, source/tool checksums and archive. Runtime files remain native ESM
with a separate Wasm asset and worker. This follows wasm-bindgen's
[`--target web` deployment](https://wasm-bindgen.github.io/wasm-bindgen/reference/deployment.html)
and works for direct serving as well as an application bundler. Static
`new URL(..., import.meta.url)` asset references let
[Vite rewrite production URLs](https://vite.dev/guide/assets.html).
The installed-tarball test runs a production Vite build under a non-root base,
then reads an actual File through the emitted worker and Wasm assets.

We keep library prebundling out of this build. The consumer already bundles its
JavaScript, while [Vite library mode](https://vite.dev/guide/build.html#library-mode)
can inline assets. [npm pack](https://docs.npmjs.com/cli/v11/commands/npm-pack/)
provides the local installable archive without registry publication.

## Feed a browser file to Rust

After a file input or drag-and-drop handler supplies a browser `File`, or a
picker supplies a `FileSystemFileHandle`, use the asynchronous File facade:

```js
import {
  readHeaderFromFile, readMetadataFromFile, samplingConsistencyReportFromFile,
  readCwaFileBatches, writeCwaCsvBatches,
} from './pkg/cwa_reader_file.js';

const header = await readHeaderFromFile(fileHandle); // Also accepts File or Blob.
const metadata = await readMetadataFromFile(fileHandle);
const report = await samplingConsistencyReportFromFile(fileHandle);
for await (const data of readCwaFileBatches(fileHandle, { batchPackets: 256 })) {
  await consumeSamples(data);
}
```

Each operation resolves `handle.getFile()` once, preserving one File snapshot
for its read. Metadata/header/report operations run in a dedicated module worker
and release it on completion or error. Serve `cwa_reader_file_worker.js` alongside
the generated module. Rust adapts that worker's `FileReaderSync` range reads to
`Read + Seek`, then invokes the same `CwaReader` as Python. The metadata search
reads the header and necessary first/last packet context; it does not materialize
a complete File or duplicate the boundary algorithm in JavaScript. Skipped
packets near a boundary can require additional probes. The sampling report
intentionally scans all packet metadata in bounded ranges.

The synchronous byte APIs remain available when you already have a complete
input buffer:

```js
import init, {
  readHeader, readMetadata, samplingConsistencyReport,
  readCwaFile, writeCwaCsv, seconds, blocks,
} from './pkg/cwa_reader_browser.js';

await init();
const header = readHeader(new Uint8Array(await file.slice(0, 1024).arrayBuffer()));

// These synchronous byte APIs require a complete input buffer.
const bytes = new Uint8Array(await file.arrayBuffer());
const metadata = readMetadata(bytes);
const report = samplingConsistencyReport(bytes);
const data = readCwaFile(bytes, {
  cut: seconds(1.2, 3.7),
  resample_hz: 60,
  include_light: false,
  fixed_utc_offset_seconds: 19800,
});
console.log(data.timestamps_us[0], data.columns.acc_x, data.timezone);
const csvBytes = writeCwaCsv(bytes, { cut: blocks(3, 10) });
const csvText = new TextDecoder().decode(csvBytes);
const csvBlob = new Blob([csvBytes], { type: 'text/csv' });

// The same original File can be uploaded to your existing endpoint.
const form = new FormData();
form.append('recording', file);
// await fetch(yourUploadUrl, { method: 'POST', body: form });
```

The byte calls are synchronous. Run them in a worker for interactive applications.
The example uses worker-only `readMetadataFromFileSync` and
`samplingConsistencyReportFromFileSync` with its selected File; these bridge
exports require a dedicated worker where `FileReaderSync` is available. The
async File facade manages that worker for callers on the main thread.

To consume a recording without materializing the complete `File`, import the
separate browser source adapter. It drives the same core packet-batch decoder:

```js
import { readCwaFileBatches, writeCwaCsvBatches } from './pkg/cwa_reader_file.js';
import init, { blocks } from './pkg/cwa_reader_browser.js';

await init();
const controller = new AbortController();
for await (const data of readCwaFileBatches(file, {
  batchPackets: 256,
  overlapPackets: 1,
  resample_hz: 60,
  signal: controller.signal,
})) {
  await consumeSamples(data); // Backpressure: the next range is not read yet.
  // break; also releases the core reader without reading another batch.
}

// Consume chunks in a writable sink instead of retaining a complete CSV.
for await (const chunk of writeCwaCsvBatches(file, { cut: blocks(3, 10) })) {
  await consumeCsvBytes(chunk);
}
```

The adapter awaits `File.slice(offset, end).arrayBuffer()` once per requested
range. Data payload requests contain an owned batch and its configured overlap
in one contiguous read. Small timestamp-seed requests and planning passes are
separate source reads. Rust decodes each preloaded range synchronously; no DOM
`File` or host pathname is passed to the parser. Breaking iteration frees the
reader. Aborting prevents further reads or output after the current Blob read
finishes; an already-started Blob read cannot be cancelled by this adapter.

| Export | Input and result |
| --- | --- |
| `readHeader(bytes)` | At least 1,024 bytes; header configuration only. Additional bytes are ignored. |
| `readMetadata(bytes)` | Complete CWA bytes; header fields plus actual first/last sample timing. |
| `samplingConsistencyReport(bytes)` | Complete bytes; configured and data-derived duration/sample rates. |
| `readCwaFile(bytes, options?)` | Complete bytes; selected timestamps and numeric channel arrays. |
| `writeCwaCsv(bytes, options?)` | Complete bytes; CSV as `Uint8Array`. No output path is needed. |
| `seconds(start?, end?)`, `blocks(start?, end?)` | Validated cut objects; start inclusive, end exclusive. |
| `readHeaderFromFile(source)` | File, Blob or file handle; Promise of header configuration, reading 1,024 bytes. |
| `readMetadataFromFile(source)` | Same inputs; Promise of header fields and actual bounds from targeted reads. |
| `samplingConsistencyReportFromFile(source)` | Same inputs; Promise of report, scanning bounded packet ranges. |
| `readCwaFileBatches(source, options?)` | Async iterator of selected `CwaSamples`, reading bounded File slices. |
| `writeCwaCsvBatches(source, options?)` | Async iterator of CSV `Uint8Array` chunks, with one header. |

Options use the Python names for channel flags, `resample_hz` and
`resample_method`. See [shared reader behavior](../docs/reader-behavior.md)
for cut boundaries, resampling, channel defaults and packet ownership.

`batchPackets` counts owned 512-byte data packets and defaults to 256;
`overlapPackets` defaults to 1. Both also apply to the full-byte collectors.
Insufficient configured context throws a JavaScript `Error` with
`code === 'InsufficientContext'`, `side`, `ownedPackets`, `loadedPackets` and
`reason`. Its packet ranges are `[start, end]`, end exclusive.

Absent channels have no property in `columns`; missing samples in a present
channel are `NaN`. Individual batches can have different optional channels.
A collector must form their union and fill missing rows with `NaN`; the
full-byte API does this in Rust.

`fixed_utc_offset_seconds` replaces Python's fixed `datetime.timezone` object.
It accepts a finite offset strictly inside +/-24 hours, rounded to microseconds
with ties to even. The offset is subtracted from the device clock. Supplying it,
including zero, makes `data.timezone` equal to `'UTC'`; omission gives `null` for
naive time. See [timestamp semantics](../docs/timestamps.md) for the device clock
and fixed-offset interpretation.

## Timestamp and output precision

`data.timestamps_us` is a JavaScript `BigInt64Array` containing exact signed
integer microseconds, the core parser's native resolution. Do not convert these
values to floating-point nanoseconds. To compare with a pandas nanosecond index,
use `timestamp_us * 1000n`. This multiplication stays in JavaScript bigint space
and does not require storing nanoseconds in a signed 64-bit array.

Each property in `data.columns` is an owned `Float32Array`. These arrays remain
valid after later Wasm calls or memory growth; they are copies rather than views
into Wasm memory. Metadata/report fields use the same names as the Python API.
Their `*_raw` timestamp strings preserve the naive device clock and missing
values are `null`. `readHeader` omits `start_from_data_raw` and `end_from_data_raw`,
which require data packets. A header preview cannot establish actual sample
count, timing or measured channels.

CSV uses the [shared output formatting](../docs/timestamps.md). Invalid
input/options throw a JavaScript `Error`; callers can catch it and process
another file with the same module.

## Copies and memory

The header preview materializes only 1,024 bytes. File metadata keeps input to
its requested boundary ranges; `FileReaderSync` creates one range ArrayBuffer
which is copied into the Rust read buffer. File reports scan bounded ranges
through that same adapter. They neither use MEMFS nor require SharedArrayBuffer.
The File iterators keep input
to requested ranges, including fixed overlap, and allocate one decoded output
batch at a time in Rust. wasm-bindgen copies input bytes into Wasm; returned
numeric arrays or CSV chunks are further owned JavaScript copies. Discarding
batches keeps recording-sized sample output out of memory. Holding batches,
joining a full result, or building a CSV Blob allocates the retained output.
The example's sample action retains only a summary, while its CSV action collects
chunks in a Blob for download. A worker moves decoding off the UI thread.

The synchronous byte APIs still materialize a complete input buffer and copy it
into Wasm. Their sample/CSV collectors also retain complete selected output.
A small cut reduces output size, but does not reduce that full input copy.
No path, temporary file or virtual filesystem is required by either interface.
There is no zero-copy loading or all-day collector memory guarantee.

## Browser tests and measurements

Build the native package from the same checkout, then run:

```sh
uv venv --python 3.13 /tmp/cwa-browser-native
uv pip install --python /tmp/cwa-browser-native/bin/python ./python pytest
cd wasm
npm ci
npx playwright install chromium
npm run typecheck
CWA_NATIVE_PYTHON=/tmp/cwa-browser-native/bin/python npm test
CWA_NATIVE_PYTHON=/tmp/cwa-browser-native/bin/python npm run test:package
```

Eighteen actual Chromium tests compare the byte and File interfaces with the
native Python package from the same checkout. The [shared validation guide](../docs/validation.md)
describes the 31 parser/sample/CSV cases, exact timestamp checks and numerical
tolerances. Browser-specific checks include a worker CSV download and an early
worker load failure that keeps full actions disabled while header preview works.
File metadata/report tests use Files, Blobs and real file handles, compare native
fields and errors, and resolve each handle once per operation. A 512 MiB sparse
file in browser storage matches native metadata while worker instrumentation
rejects complete-file buffering and measures less than 4 KiB of boundary reads.
File tests additionally reject skipped-only selections with the full-byte error,
concatenate all 31 cases at different packet counts,
check the exact global resampling grid across boundaries, compare CSV chunks,
and verify cancellation, backpressure and structured insufficient-context errors.

Generated comparison inputs live in ignored `wasm/.test-data/`. CWA fixtures,
native arrays and recovered CSV are excluded from runtime artifacts. The local
server exposes test inputs only with `--test-fixtures`; fixture provenance and
redistribution limits are documented in the shared validation guide.

`wasm/test-results/header-metrics.json` and `recording-metrics.json` record browser
version, timings, selected output sizes and committed Wasm memory. These are
machine-specific measurements with coarse browser timers, not performance
promises. Linear memory capacity is not peak process memory or JavaScript heap
usage. Initialization and file selection are outside the parser timing interval.

Measure packet sizes against your own local recording without serving its bytes:

```sh
node wasm/scripts/bench.mjs --input /local/recording.cwa --output /tmp/cwa-batches.json \
  --alias recording --batches 64,256,1024,2048,8192 --repeats 3 --mode all
# Add --resample 60 for the same full/early/middle/late sweep with cubic resampling.
# Add --seconds-cuts 0:30,3600:3630,7170:7200 to supply three seconds cuts
# instead of the default 256-packet early/middle/late cuts; choose times for your input.
```

The tool selects a native browser File, discards output batches, and creates a
fresh page/Wasm instance per size, selection and repeat. It records all session
read calls/bytes, File-read and total time, output bytes, largest output batch
and committed Wasm capacity. Initialization/UI preview are excluded, with no
explicit decoder warmup. Reports contain only the supplied alias and aggregate
measurements, never the input path or sample values. The private recording is
not uploaded. The benchmark uses a separate local server on port 5297.

The separate `Standalone browser WASM` workflow builds/tests the module and
uploads `standalone-browser-wasm`, the installable `standalone-browser-npm`
archive, and JSON test results. `test-results/npm-consumer.json` records the
installed production consumer and its native metadata/sample parity. Artifact names do not
match the native release workflow's `wheels-*/*` publication glob. Nothing is
published to npm, PyPI or a conda channel by this workflow.
