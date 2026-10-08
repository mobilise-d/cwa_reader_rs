# Xeus Python WASM package

The `recipes/xeus` recipe produces a local `emscripten-wasm32` conda package
containing a CPython extension side module built from the [Python distribution](../../python/README.md).
Run the commands below from the repository root. It preserves the existing path-based
Python API. Shared reader behavior and timestamp semantics are described in
[the common documentation](../../docs/README.md). The standalone JavaScript build is described separately in
[the standalone distribution](../../wasm/README.md).

## Reproduce locally (Linux x86-64)

Install micromamba, then create build tools with the same rattler CLI used by CI:

```sh
micromamba create -y -n cwa-wasm-build -c conda-forge rattler-build=0.67.0
micromamba activate cwa-wasm-build
# Node 24 and Python 3.13 must also be on PATH.
tools/wasm/build-xeus.sh /tmp/cwa-xeus
```

The recipe resolves forge compiler activation, cross-Python, matching target
headers/sysconfig and target NumPy/pandas. It builds Rust std from source with
`nightly-2026-02-16` (rustc `873b4beb0`, LLVM 22.1.0), using Emscripten 4.0.9
and forge's Wasm exception flags. `CARGO_UNSTABLE_BUILD_STD` and locked Cargo
resolution are set in the recipe. No pthread build flag is added. Rust's std
imports ordinary pthread stubs supplied by the single-thread runtime; this does
not require SharedArrayBuffer or cross-origin isolation.

Maturin 1.15.0 accepts forge's `MATURIN_PYTHON_SYSCONFIGDATA_DIR` **file** path.
The actual target extension suffix is `.cpython-313-wasm32-emscripten.so`.
The intermediate wheel tag is `cp313-cp313-emscripten_4_0_9_wasm32`; that wheel
is not advertised as interchangeable with Pyodide or other Emscripten ABIs.
`record-artifacts.py` checks Wasm imports/exports and `dylink.0`, including
`PyInit_cwa_reader_rs`, and records checksums. The first module section was also
verified as `dylink.0` with LLVM's `llvm-readobj --sections` locally.

The target package pins:

| Package | Version | Build |
|---|---|---|
| python | 3.13.1 | h_2efca29_11_cp313 |
| python_abi | 3.13 | 9_cp313 |
| emscripten-abi | 4.0.9 | h267e887_9 |
| numpy | 2.4.6 | py313hcf5bae3_0 |
| pandas | 3.0.6 | np23py313h124dbc7_0 |
| xeus-python (test runtime) | 0.19.0 | py313he5686da_3 |

The package includes distribution metadata and the MIT license. NumPy and pandas
are dependency metadata, not bundled library copies. Exact solved build/host
package URLs and checksums are retained in the conda package's
`info/recipe/rendered_recipe.yaml`. Compiler output, target sysconfig and SHA256
of the compiled source files are in `share/cwa-reader-build`. The hashes include
`python/src` adapter sources, nested `crates/cwa-core` Rust sources and Cargo
manifests, along with package metadata and licenses. The recipe stages the local
core crate from the same checkout as the Python adapter. The external
`artifact-manifest.json` records source revision, dirty status and artifact hashes.
A dirty status means the revision alone does not identify all source content;
the source-file hashes identify the compilation inputs.

## Install into a downstream Xeus environment

Rattler generates the channel's `emscripten-wasm32/repodata.json`. Put its absolute
local `file://` channel first in the downstream environment:

```yaml
name: my-xeus-environment
channels:
  - file:///tmp/cwa-xeus/channel
  - https://repo.prefix.dev/emscripten-forge-4x
  - conda-forge
dependencies:
  - cwa_reader_rs=0.5.0
  - xeus-python=0.19.0=py313he5686da_3
```

Run `jupyter lite build` from the directory containing that `environment.yml`.
JupyterLite-Xeus solves an Emscripten prefix, installs the local package and
empack includes its extension and Python distribution in `kernel_packages`.
No acceptance into an official channel and no publishing are involved. When
relocating artifacts, update the local channel URI; it is not embedded in the
extension ABI.

## Run the real browser test

From the repository checkout, with the built channel available:

```sh
uv sync --project python --dev --python 3.13
uv run --project python --no-sync pytest -q python/tests
uv run --project python --no-sync python tools/wasm/parity.py "$PWD" /tmp/cwa-xeus
uv venv --python 3.13 /tmp/cwa-browser-tools
uv pip install --python /tmp/cwa-browser-tools/bin/python \
  jupyterlite-xeus==5.1.0 jupyterlite-core==0.8.6 jupyterlab==4.6.4 \
  empack==6.0.1 playwright==1.58.0
/tmp/cwa-browser-tools/bin/playwright install --with-deps chromium
export PATH="/tmp/cwa-browser-tools/bin:$PATH"
python tools/wasm/prepare-runtime.py /tmp/cwa-xeus
python tools/wasm/headless-test.py /tmp/cwa-xeus
```

The test starts the actual `xpython` Web Worker through JupyterLite, imports the
compiled extension, executes the repository's pytest suite in that worker and
compares 25 native/browser calls from the same source/options. Index values are
converted to integer nanoseconds and compared exactly; dtype and timezone are
also compared. Recorded values are compared exactly; resampling uses `rtol=atol=1e-6`
with matching NaNs.
Metadata/report fields and exception type/message are compared directly. CSV
bytes are recovered from worker storage and their hash is checked against native.
Existing C-export tests retain their existing timestamp formatting tolerance.

Fixture bytes are served from the checkout locally. Tests, fixtures, native
reference arrays, recovered CSV and the test runtime are not in the conda package
or CI upload paths. The CI uploads the package, repodata, compiler/source manifest,
resolved runtime metadata and browser result report under `xeus-wasm-*`, separate
from the native release workflow's `wheels-*/*` glob.

## Browser file access

A DOM `File` is not a Rust filesystem path. The tested bridge fetches local
fixture bytes in the **worker**, converts an `ArrayBuffer` to `Uint8Array`, then
through `pyjs` to Python bytes, and writes the bytes to worker MEMFS. The unchanged
`read_cwa_file(path)` and `write_cwa_csv(input_path, output_path)` work there.
The test recovers CSV with the worker's `pyjs` fetch bridge to a local endpoint.
A production UI can recover those bytes to a main-thread Blob/download instead.

```python
import pyjs
response = await pyjs.js.fetch(local_test_url)
buffer = await response.arrayBuffer()
content = bytes(pyjs.to_py(pyjs.js.Uint8Array.new(buffer)))
with open('/tmp/recording.cwa', 'wb') as stream:
    stream.write(content)
data = cwa_reader_rs.read_cwa_file('/tmp/recording.cwa')
```

This is transient memory storage; it does not inherently upload data to a remote
server or persist it in IndexedDB/OPFS.

A selected local `File` can also be read without staging its entire contents.
The large-file benchmark passes the File through Xeus's main-thread
`callGlobalReceiver` RPC to a worker object, then mounts it read-only with a
compatible WORKERFS adapter. Rust opens the resulting worker path normally.
WORKERFS uses `FileReaderSync` on `File.slice()` for the requested ranges; the
packet engine requests bounded preloaded ranges. This requires no network upload
and no persistent browser storage.

The pinned Xeus runtime exposes `globalThis.Module.FS` inside the worker, but
has no built-in WORKERFS backend. Load a compatible adapter before mounting.
[The benchmark runner](../../tools/benchmarks/xeus.py) accepts that adapter as an
explicit file and demonstrates the complete File transfer/mount/read sequence.
It neither modifies nor rebuilds the downstream runtime. The adapter is a runtime
integration dependency, separate from the Python extension package.

For example, after loading the adapted official WORKERFS source with
`pyjs.js.eval(adapter_source)`, register a worker-side receiver:

```python
pyjs.js.eval("""
globalThis.cwaLocalFiles = {
  mount(files) {
    const FS = globalThis.Module.FS;
    FS.mkdirTree('/local-cwa');
    FS.mount(globalThis.WORKERFS, {
      blobs: [{name: 'recording.cwa', data: files[0]}]
    }, '/local-cwa');
  }
};
""")
```

The main-thread UI can then transfer its selected File, after the kernel and
receiver are ready:

```javascript
await window.callGlobalReceiver('cwaLocalFiles', 'mount', [input.files[0]]);
```

Python reads `cwa_reader_rs.read_cwa_file('/local-cwa/recording.cwa')`. Unmount the
old mount before replacing a selection. Directory selections can supply multiple
Files; the application must map their relative names into worker paths.

These reads still copy each requested slice into JavaScript and Wasm memory;
this is not zero-copy decoding. The full DataFrame API retains every selected
sample, and DataFrame/array conversions can add allocations. Cuts reduce that
output. `write_cwa_csv` processes bounded batches, but a CSV written to MEMFS
still retains its complete output there. An external streaming sink is required
to avoid that storage cost. See [the batch benchmarks](../../docs/packet-batch-benchmarks.md)
for measured full-file bounded decoding and browser File access.

## Local measurements and limits

At source `f0d08d922ec1d926c0e20a67270b7201a6cd6da9`, a clean local Xeus
artifact passed all 128 repository Python tests and 25 direct native/browser
comparisons, including CSV recovery. On the real 305,664-byte OpenMovement
fixture (71,400 rows, six float32 columns), the first full read took 13.5 ms and
the median of six subsequent reads was 2.3 ms. The DataFrame/index occupied
2,284,800 bytes. Fixture transfer/extraction took 33.4 ms. The committed Wasm
heap capacity stayed at 139,198,464 bytes; this is allocation capacity rather
than peak live Rust/Python memory. Runtime/NumPy/pandas allocations are included.
Runtime downloads and fixture transfer are excluded from reader timing.

The source-clean conda artifact SHA256 was
`8b739122fdcc7851cae159933244d27be2489ae0af4e2cd50479c4237ac3f430`.
Regenerate the artifact manifest and browser report on the consumer's hardware;
these measurements are evidence for this pinned ABI and runtime.

The ordinary accelerometer-only fixture cannot validate gyro-dependent mobgap
presets. Synthetic fixtures validate channel handling, but downstream algorithm
integration with participant metadata and an appropriate real gyro recording
remains the downstream runtime task.
