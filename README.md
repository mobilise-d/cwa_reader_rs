# CWA reader

A shared Rust parser for [Open Movement](https://github.com/openmovementproject/openmovement)
CWA recordings, with Python and browser JavaScript distributions. It reads header
metadata and sensor samples, preserves device-clock timestamps, supports partial
reads and resampling, and exports CSV.

The parser lives in one independent crate. Python and JavaScript provide the
interfaces and file access appropriate to their environments.

| Component | Purpose | Documentation |
| --- | --- | --- |
| `crates/cwa-core/` | Rust parsing, seeking, packet batches, resampling and CSV, without Python or JavaScript dependencies | [Core crate](crates/cwa-core/README.md) |
| `python/` | Native Python extension returning pandas DataFrames; Python wheel and source distribution | [Python installation and usage](python/README.md) |
| `wasm/` | Browser JS/Wasm reader accepting bytes, Files and file handles; local npm tarball | [JavaScript installation and usage](wasm/README.md) |
| `recipes/xeus/` | The Python extension compiled for the pinned browser Python/Emscripten runtime | [Xeus build and integration](recipes/xeus/README.md) |

Browser file access is local: reading a selected file does not require uploading
it to a server. Metadata operations seek to the required ranges. Sample reads
use bounded batches of 512-byte packets, with shared decoding behavior across
Rust, Python and JavaScript. Collecting a full DataFrame or sample array still
allocates the selected output.

Read the [shared documentation](docs/README.md) for reader behavior, timestamp
interpretation, validation and performance. In particular, device-clock times
need a known UTC offset before they can be interpreted as wall-clock instants.

## Building and validation

Each distribution's README gives its build, installation and test commands.
The root Cargo workspace contains the shared core and Python bridge; the
standalone Wasm crate has its own pinned toolchain and dependency lock.

Native wheels and source archives, the Xeus conda package, and the standalone
npm tarball are separate artifacts with different runtime requirements. The
npm tarball and Xeus channel can be installed locally. Their CI artifacts are
separate from native PyPI release uploads.

Correctness checks compare targets with native Python and the Open Movement C
reference. See [validation](docs/validation.md) for parity rules, test fixtures
and packaging checks.

The project uses the [MIT license](LICENSE).
