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
or download CSV. Complete-file operations run in a module worker. No recording
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

| Export | Input and result |
| --- | --- |
| `readHeader(bytes)` | At least 1,024 bytes; header configuration only. Additional bytes are ignored. |
| `readMetadata(bytes)` | Complete CWA bytes; header fields plus actual first/last sample timing. |
| `samplingConsistencyReport(bytes)` | Complete bytes; configured and data-derived duration/sample rates. |
| `readCwaFile(bytes, options?)` | Complete bytes; selected timestamps and numeric channel arrays. |
| `writeCwaCsv(bytes, options?)` | Complete bytes; CSV as `Uint8Array`. No output path is needed. |
| `seconds(start?, end?)`, `blocks(start?, end?)` | Validated cut objects; start inclusive, end exclusive. |

Options use the same names as Python for channel flags, `resample_hz` and
`resample_method`. Cubic resampling includes the existing linear edge behavior.
Seconds cuts start relative to the first valid sample. Block cuts count 512-byte
data packets after the header. Omitting `cut` reads the full recording.

`readCwaFile` includes temperature, light and battery by default; `writeCwaCsv`
omits these auxiliary columns by default. Magnetometer inclusion defaults to true
in both. Gyro/magnetometer columns occur only when the selected samples contain
those sensors. Real zero measurements remain zero; missing samples in a present
channel are `NaN`, and absent channels have no property in `columns`.

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

The header preview selects a `Blob.slice` and materializes only 1,024 bytes in
JavaScript. Complete operations materialize the full recording with
`file.arrayBuffer()`. wasm-bindgen copies each input byte slice into Wasm linear
memory. The Rust core borrows that copy through `Cursor`; it does not need a path,
a temporary file, or a second whole-file input buffer.

Decoding allocates selected sample columns in Rust. Returning them makes further
copies into JavaScript typed arrays. CSV export accumulates the complete selected
CSV in Rust and copies it into a JavaScript `Uint8Array`. The example transfers
that array from its worker before creating the download Blob. Scanning metadata
or a report avoids decoded sample columns but still copies the input bytes.

This API is full-buffer input, not a lazy or constant-memory recording stream.
The core decoder/resampler can process packets internally while its returned
sample columns still allocate the selected recording. A small cut can reduce
output size but does not reduce the full input copy. Very large recordings need
measured input/output memory limits and a separate incremental browser adapter.
A worker keeps parsing off the UI thread; it does not remove those allocations.

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

Seven actual Chromium tests compare full metadata/report fields and 31 sample/CSV
cases against the native Python package from the same checkout. Cases cover full
reads, block/seconds cuts, resampling, channel flags, packed samples, 3/6/9-axis and
mixed layouts, recorded zeros, missing values, fixed positive/negative/zero and
fractional offsets, native error messages, and a real worker CSV download.

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
promises. A local Chromium 156 run decoded the 305,664-byte fixture into 71,400
rows and 2,284,800 bytes of returned arrays in 9.4 ms. The default CSV had
3,099,794 bytes. Committed Wasm memory grew from 1,114,112 to 6,422,528 bytes after
that read/export pair; the complete 31-case run ended at 11,272,192 bytes. Linear memory capacity is not peak process memory or JavaScript heap
usage. Initialization and file selection are outside the parser timing interval.

The separate `Standalone browser WASM` workflow builds/tests the module and
uploads `standalone-browser-wasm` plus JSON test results. Artifact names do not
match the native release workflow's `wheels-*/*` publication glob. Nothing is
published to npm, PyPI or a conda channel by this workflow.
