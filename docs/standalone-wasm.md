# Standalone browser header reader

`wasm/` builds a browser module from the shared Rust parser with Python disabled.
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

Open `http://127.0.0.1:5287`. Select a CWA file to display its header metadata.
The example does not send the recording to a server. It only fetches the JS and
Wasm module. Serve `wasm/pkg/` with your application; the `.wasm` content type
should be `application/wasm`. The generated JS, Wasm, type declarations, license
and checksum/compiler manifest are in `wasm/pkg/`. The Rust and npm dependency
locks live in `wasm/Cargo.lock` and `wasm/package-lock.json`.

## Feed a browser file to Rust

After your file input or drag-and-drop handler supplies a browser `File`:

```js
import init, { readHeader } from './pkg/cwa_reader_browser.js';

await init();
const headerBytes = new Uint8Array(await file.slice(0, 1024).arrayBuffer());
const header = readHeader(headerBytes);
console.log(header.device_id, header.sample_rate_hz, header.annotation);

// The same original File can then be uploaded to your existing endpoint.
const form = new FormData();
form.append('recording', file);
// await fetch(yourUploadUrl, { method: 'POST', body: form });
```

`readHeader(Uint8Array)` requires at least 1,024 bytes and ignores later bytes.
Invalid or truncated metadata throws a JavaScript `Error`; callers can catch it
and inspect another file using the same module.

The returned object uses the header fields from Python's `read_metadata`, including
`logging_start_time_raw`, `logging_end_time_raw` and `last_change_time_raw`.
These are naive device-clock strings, with `null` for missing values. They do
not identify the recording's timezone. Other fields describe the device/session,
annotation, nominal sample rate, acceleration range, and configured AX6 sensors.

Header-only parsing omits `start_from_data_raw` and `end_from_data_raw`. Those
fields in Python require a scan of data packets. A header preview cannot prove
that a recording contains valid samples or establish its actual sample count,
timing or measured channels. Decoding samples is not yet exported by this browser
adapter. The shared Rust core accepts `Read + Seek` and bytes for a future sample
adapter.

## Copies and memory

`Blob.slice` selects the header region. `arrayBuffer` materializes those 1,024
bytes in JavaScript memory. wasm-bindgen copies the `Uint8Array` into Wasm linear
memory to supply Rust's borrowed byte slice. The core reader allocates its header
buffer, and conversion creates JavaScript strings and an object for the result.
This is not zero-copy loading. No full recording buffer or sample DataFrame is
needed by the selected-file example.

A future full-content API would need a separate memory and scheduling design.
Passing a complete recording as a `Uint8Array` copies it into Wasm. Decoded arrays
allocate additional memory, and synchronous parsing can block the UI. Large
recordings should use a worker and a measured chunking strategy. Header-only
measurements do not establish full-recording scalability.

## Browser tests and measurements

Build the native package from the same checkout, then run:

```sh
uv venv --python 3.13 /tmp/cwa-browser-native
uv pip install --python /tmp/cwa-browser-native/bin/python .
cd wasm
npm ci
npx playwright install chromium
CWA_NATIVE_PYTHON=/tmp/cwa-browser-native/bin/python npm test
```

The tests select the real `example-610-steps.cwa` through a Chromium file input
and compare every returned field directly with the native Python package.
They also exercise truncated and malformed files, recovery with a valid file,
missing times, AX6 sensor configuration and naive timestamps.

Tests use the third-party fixture directly from the source checkout. Its source
and redistribution limitation are recorded in
`tests/reference_data/openmovement/README.md`. Neither the browser bundle nor CI
artifacts include CWA fixtures. The local server exposes `/fixture.cwa` only with
`--test-fixtures`; normal `npm run dev` does not expose it.

`wasm/test-results/header-metrics.json` records the browser version, file size,
header-read time, 1,000 parse calls, and Wasm linear memory before/after those
calls. A local Chromium 156.0.8078.4 run on the 305,664-byte fixture read 1,024
bytes in 1.1 ms and parsed that header 1,000 times in 18.6 ms. Wasm linear memory
remained at 1,179,648 bytes. These are one-machine observations with coarse browser
timer resolution, not performance guarantees. Linear memory size is not peak
process memory or JavaScript heap usage. Initialization and file selection are
outside the measured interval.

The separate `Standalone browser WASM` workflow builds and tests the module and
uploads `standalone-browser-wasm` plus test results. Artifact names do not match
the native release workflow's `wheels-*/*` publication glob. Nothing is published
to npm, PyPI or a conda channel by this workflow.
