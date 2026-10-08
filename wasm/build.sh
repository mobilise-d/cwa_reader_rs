#!/usr/bin/env bash
set -euo pipefail
wasm_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$wasm_dir"
expected_bindgen='wasm-bindgen 0.2.129'
if [[ "$(wasm-bindgen --version)" != "$expected_bindgen" ]]; then
  printf 'Install the matching CLI: cargo install wasm-bindgen-cli --version 0.2.129 --locked\n' >&2
  exit 1
fi
cargo +1.90.0 build --locked --release --target wasm32-unknown-unknown --target-dir "$wasm_dir/target"
mkdir -p pkg
wasm-bindgen target/wasm32-unknown-unknown/release/cwa_reader_browser.wasm \
  --target web --out-dir pkg --out-name cwa_reader_browser
cp file-reader.js pkg/cwa_reader_file.js
cp file-reader.d.ts pkg/cwa_reader_file.d.ts
cp ../LICENSE pkg/LICENSE
node build-metadata.mjs
printf 'Browser bundle written to %s/pkg\n' "$wasm_dir"
