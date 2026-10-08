# Xeus Python WASM package

The `recipes/xeus` recipe produces a local `emscripten-wasm32` conda package
containing a CPython extension side module. It preserves the existing path-based
Python API. The standalone JavaScript build is described separately in
[`standalone-wasm.md`](standalone-wasm.md).

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
root Python adapter sources, nested `crates/cwa-core` Rust sources and Cargo
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
  - cwa_reader_rs=0.4.0
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
uv sync --dev --python 3.13
uv run --no-sync pytest -q tests
uv run --no-sync python tools/wasm/parity.py "$PWD" /tmp/cwa-xeus
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
server or persist it in IndexedDB/OPFS. A main-thread selected `File` needs an
explicit worker transfer, or the JupyterLite contents filesystem integration.
The pinned Xeus runtime exposes `pyjs._module.FS` but does **not** contain
Emscripten WORKERFS. It cannot directly mount a DOM File using WORKERFS as shipped.
A custom read-only filesystem backend using `FileReaderSync` on `File.slice()`
in the worker could avoid copying the whole input file; that adapter is not part
of this implementation. The standalone module can already parse selected File
slices without a filesystem mount.

The tested path copies input bytes through JavaScript and Python into MEMFS.
The returned full DataFrame allocates all selected samples; streaming decoder
internals do not make full reads constant-memory. Cuts reduce output allocation.
No all-day recording scalability or zero-copy loading is claimed.

## Local measurements and limits

On the real 305,664-byte OpenMovement fixture (71,400 rows, six float32 columns),
a cached-runtime browser run returned a 2,284,800-byte DataFrame/index. Across the local T3 and headless Chromium runs, the median
of six warm full reads ranged from 2.5 to 6.6 ms; first measured reads ranged
from 12.2 to 26.5 ms. These timings include decoding and DataFrame construction and exclude
runtime downloads and fixture transfer. The test ZIP transfer/extraction took
about 29–40 ms. The worker's committed Wasm heap capacity was 139,198,464 bytes
before and after full reads. This measures allocated linear-memory capacity,
not peak live Rust/Python allocations; retained runtime/NumPy/pandas dominate it.
Machine, browser caches and test work affect timing. Regenerate reports for the
consumer's hardware and realistic file sizes.

The ordinary accelerometer-only fixture cannot validate gyro-dependent mobgap
presets. Synthetic fixtures validate channel handling, but downstream algorithm
integration with participant metadata and an appropriate real gyro recording
remains the downstream runtime task.
