#!/usr/bin/env bash
set -euo pipefail
# Forge activation supplies target Python, headers, side-module flags and emcc.
export MATURIN_PYTHON_SYSCONFIGDATA_DIR="$PREFIX/etc/conda/_sysconfigdata__emscripten_wasm32-emscripten.py"
# The forge rust package's activation selects floating nightly. Override it.
export RUSTUP_TOOLCHAIN=nightly-2026-02-16
rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal --component rust-src
export CARGO_BUILD_TARGET=wasm32-unknown-emscripten
export RUSTFLAGS="${RUST_WASM_EXCEPTIONS}"
# Rebuild Rust std with the same emcc ABI and exception handling as Xeus.
export CARGO_UNSTABLE_BUILD_STD=std,panic_abort
export MATURIN_PEP517_ARGS=--locked
mkdir -p "$PREFIX/share/cwa-reader-build"
python - <<'PY'
import hashlib, json, os, runpy
from pathlib import Path
p=Path(os.environ['PREFIX'])/'share/cwa-reader-build'
s=runpy.run_path(os.environ['MATURIN_PYTHON_SYSCONFIGDATA_DIR'])['build_time_vars']
(p/'target-sysconfig.json').write_text(json.dumps(s,indent=2))
files = sorted([*Path('src').rglob('*.rs'), Path('Cargo.toml'), Path('Cargo.lock'), Path('pyproject.toml')])
(p/'source-files.json').write_text(json.dumps({str(f): hashlib.sha256(f.read_bytes()).hexdigest() for f in files}, indent=2))
PY
rustc -Vv > "$PREFIX/share/cwa-reader-build/rustc.txt"
emcc -v 2> "$PREFIX/share/cwa-reader-build/emcc.txt"
maturin --version > "$PREFIX/share/cwa-reader-build/maturin.txt"
"$PYTHON" -m pip install . --no-build-isolation --no-deps -vv
