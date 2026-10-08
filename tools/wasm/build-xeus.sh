#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CWA_WASM_OUT=${1:-"$REPO_ROOT/dist/xeus-wasm"}
mkdir -p "$CWA_WASM_OUT"
rattler-build build --recipe "$REPO_ROOT/recipes/xeus" \
  --target-platform emscripten-wasm32 --package-format tar-bz2 \
  -m "$REPO_ROOT/recipes/xeus/variants.yaml" \
  -c https://repo.prefix.dev/emscripten-forge-4x -c conda-forge \
  --output-dir "$CWA_WASM_OUT/channel" --no-test
python "$REPO_ROOT/tools/wasm/record-artifacts.py" "$CWA_WASM_OUT"
