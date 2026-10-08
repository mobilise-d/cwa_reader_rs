# Standalone browser reader

`wasm/` builds a browser module directly from the shared `crates/cwa-core` crate.
The core has no Python dependencies; the root crate is the Python extension.
It uses `wasm32-unknown-unknown`, Rust 1.90.0 and wasm-bindgen 0.2.129. This bundle
is independent of the Xeus Python extension and its Emscripten ABI.

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
worker. The timing report materializes the complete input; a CSV download retains
the complete output. No recording
bytes are sent to a server or written to a virtual filesystem.

The generated JS, Wasm, type declarations, license and checksum/compiler manifest
are in `wasm/pkg/`. Serve them with your application; the `.wasm` content type
should be `application/wasm`. Rust and npm dependency locks live in
`wasm/Cargo.lock` and `wasm/package-lock.json`. The root Cargo workspace excludes
`wasm/`, so its pinned build and lock stay independent of the Python/Emscripten
toolchains.

## Feed a browser file to Rust

After your file input or drag-and-drop handler supplies a browser `File`:

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

Use a worker for complete-file operations in an interactive application, as the
example does. The parsing calls themselves are synchronous.

To consume a recording without materializing the complete `File`, import the
separate browser source adapter. It drives the same core packet-batch decoder:

```js
import { readCwaFileBatches, writeCwaCsvBatches } from './pkg/cwa_reader_file.js';

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
| `readCwaFileBatches(file, options?)` | Async iterator of selected `CwaSamples`, reading bounded File slices. |
| `writeCwaCsvBatches(file, options?)` | Async iterator of CSV `Uint8Array` chunks, with one header. |

Options use the same names as Python for channel flags, `resample_hz` and
`resample_method`. Cubic resampling includes the existing linear edge behavior.
Seconds cuts start relative to the first valid sample. Block cuts count 512-byte
data packets after the header. Omitting `cut` reads the full recording.

`batchPackets` counts owned 512-byte data packets, not output rows. It defaults
to 256. `overlapPackets` defaults to one physical packet on each side, clipped
at actual file boundaries. Both options also apply to `readCwaFile` and
`writeCwaCsv`, whose full results collect the same engine. Independent batches
share one resampling grid and exclusive output ownership; overlap samples are
not emitted twice. Packet times are assumed ordered. Seconds cuts use rate-guided
packet probes and corrections instead of scanning the complete recording.
CSV performs a bounded channel-union pass before emitting its header and data.

If skipped or sparse packets leave insufficient timestamp/interpolation context
inside the configured preload, parsing throws an `Error` with
`code === 'InsufficientContext'`, `side`, `ownedPackets`, `loadedPackets` and
`reason`. Packet ranges are `[start, end]`, end exclusive. Increase
`overlapPackets` for a fresh read. The decoder does not refill or emit partial
samples from a failed batch. Earlier delivered batches remain valid.

`readCwaFile` includes temperature, light and battery by default; `writeCwaCsv`
omits these auxiliary columns by default. Magnetometer inclusion defaults to true
in both. Gyro/magnetometer columns occur only when the selected samples contain
those sensors. Real zero measurements remain zero; missing samples in a present
channel are `NaN`, and absent channels have no property in `columns`.
Individual batches can have different optional channels. A collector must form
their union and fill missing rows with `NaN`; the full-byte API does this in Rust.

`fixed_utc_offset_seconds` replaces Python's fixed `datetime.timezone` object.
It accepts a finite offset strictly inside +/-24 hours, rounded to microseconds
with ties to even. The offset is subtracted from the device clock. Supplying it,
including zero, makes `data.timezone` equal to `'UTC'`; omission gives `null` for
naive time. It does not infer an IANA timezone or DST rules.

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

CSV preserves the native writer's formatting, including four decimal places for
numeric `time` and six for channel values. CSV formatting therefore has lower
timestamp precision than the sample arrays. Invalid input/options throw a
JavaScript `Error`; callers can catch it and process another file with the same
module.

## Copies and memory

The header preview materializes only 1,024 bytes. The File iterators keep input
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

Metadata lookup
seeks the first and last usable packets and their needed predecessor; the
sampling consistency report scans packet metadata throughout the recording.
Neither operation allocates decoded sample columns, but both still copy the
complete input bytes into Wasm. Metadata lookup does not validate unvisited
interior packets; use decoding or the consistency report to inspect them.
This bundle does not expose a targeted full-metadata File facade. Use manual
`file.slice(0, 1024)` for header preview, or supply complete bytes for
`readMetadata` and `samplingConsistencyReport`.

## Browser tests and measurements

Build the native package from the same checkout, then run:

```sh
uv venv --python 3.13 /tmp/cwa-browser-native
uv pip install --python /tmp/cwa-browser-native/bin/python . pytest
cd wasm
npm ci
npx playwright install chromium
CWA_NATIVE_PYTHON=/tmp/cwa-browser-native/bin/python npm test
```

Thirteen actual Chromium tests compare full metadata/report fields and 31 sample/CSV
cases against the native Python package from the same checkout. Cases cover full
reads, block/seconds cuts, resampling, channel flags, packed samples, 3/6/9-axis and
mixed layouts, recorded zeros, missing values, fixed positive/negative/zero and
fractional offsets, native error messages, and a real worker CSV download. An
early worker load failure leaves header preview usable and full actions disabled.
File tests additionally concatenate all 31 cases at different packet counts,
check the exact global resampling grid across boundaries, compare CSV chunks,
and verify cancellation, backpressure and structured insufficient-context errors.

Timestamps and raw sensor values compare exactly. Raw calibrated light uses a
one-float32-ULP bound because `10_f32.powf(raw / 341)` uses different math runtimes
on native and standalone Wasm. The observed maximum difference on this fixture
was 0.000003814697265625, with relative difference at most 1.05e-7. Resampled
columns allow `rtol=1e-6`, `atol=1e-6`, with identical NaN locations. CSV compares
byte-for-byte except explicitly requested calibrated light, where the bound also
allows 1e-6 for six-decimal printing; all other fields stay exact.

Tests read the third-party `example-610-steps.cwa` directly from the source
checkout and reuse existing channel fixture builders. Provenance and the
redistribution limitation are in `tests/reference_data/openmovement/README.md`.
Generated comparison inputs live in ignored `wasm/.test-data/`. Neither CWA
fixtures, native arrays nor recovered CSV are bundled or uploaded as artifacts.
The local server exposes test inputs only with `--test-fixtures`.

`wasm/test-results/header-metrics.json` and `recording-metrics.json` record browser
version, timings, selected output sizes and committed Wasm memory. These are
machine-specific measurements with coarse browser timers, not performance
promises. Linear memory capacity is not peak process memory or JavaScript heap
usage. Initialization and file selection are outside the parser timing interval.

Measure packet sizes against your own local recording without serving its bytes:

```sh
node wasm/bench.mjs --input /local/recording.cwa --output /tmp/cwa-batches.json \
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
uploads `standalone-browser-wasm` plus JSON test results. Artifact names do not
match the native release workflow's `wheels-*/*` publication glob. Nothing is
published to npm, PyPI or a conda channel by this workflow.
