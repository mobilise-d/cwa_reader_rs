---
name: python-release-workflow
description: Release cwa_reader_rs across native Python, standalone browser npm/Wasm, and Xeus Python distributions. Use for version preparation, GitHub release assets and PyPI trusted publishing.
---

# Release cwa_reader_rs

Run commands from the repository root. A published GitHub Release starts three workflows: `CI.yml`, `standalone-wasm.yml`, and `wasm-xeus.yml`. A tag push alone does not publish. Native Python artifacts go to PyPI and GitHub; browser and Xeus artifacts go to GitHub. npm registry or official conda channel publication requires a separate request.

## Layout and version

| Component | Source and version | Build entry |
| --- | --- | --- |
| Python extension | `python/Cargo.toml`, dynamic version in `python/pyproject.toml` | `uv build --project python --out-dir dist` |
| Shared Rust parser | `crates/cwa-core/Cargo.toml` | `cargo test --workspace` |
| Standalone browser/npm | `wasm/Cargo.toml`; npm metadata derives its version from the Python crate | `wasm/build.sh` |
| Xeus Python side module | `recipes/xeus/recipe.yaml` | `tools/wasm/build-xeus.sh /tmp/cwa-xeus-release` |

The root `Cargo.toml` is a virtual workspace. Python commands need `--project python`; maturin commands need `--manifest-path python/Cargo.toml`. Distribution instructions live in `python/README.md`, `wasm/README.md`, and `recipes/xeus/README.md`. Shared behavior and validation are in `docs/`.

For a coordinated release, synchronize Python, core and Wasm crate versions, local core dependency versions, and the Xeus recipe version. Refresh the root, Wasm and benchmark Cargo locks. Check `python/uv.lock` without inventing a version for its editable project. Update the current runtime package pin in `tools/wasm/prepare-runtime.py` and current install examples. Leave historical benchmark versions and artifact checksums unchanged.

## Prepare the exact source

1. Inspect worktree, branch, current releases and PyPI versions. Choose an unused version and keep unrelated work out of release commits.
2. Run `cargo test --workspace`, `uv sync --project python --dev --python 3.10`, and `uv run --project python --no-sync pytest -q python/tests`. Build the Python sdist, build a wheel from that sdist, and smoke-test its installation in a clean environment. Verify version, license and source inclusion.
3. Build and test the browser package using `wasm/README.md`, including the installed npm tarball consumer. Validate the Xeus extension in the actual browser worker using `recipes/xeus/README.md`. CI performs these browser checks; native import or a generic Wasm file is insufficient.
4. Complete review, push, and merge through the normal PR process. Preserve already reviewed history. Record the exact merge SHA, then wait for all three workflows on that SHA. CI artifacts from a PR synthetic merge are not release artifacts for a different commit.
5. Confirm the tag, GitHub Release and PyPI version are unused. Inspect versions at the tested merge SHA, not merely in the working tree. Prepare release notes describing the reader changes, installable distributions and Xeus ABI constraints.

## Publish and verify

Publishing must be authorized by the user. An explicit request to merge and release provides this authorization; do not request it again.

```bash
gh release create vX.Y.Z --target <tested-merge-sha> --title vX.Y.Z --notes-file <release-notes-file>
```

Publish the Release, rather than saving a draft, to start the release workflows. The native workflow uses the `pypi` environment and trusted publishing. Keep browser and Xeus outputs outside its `wheels-*/*` upload glob.

Wait for all three release-event runs on the tag to finish. Inspect the Release assets and download them for verification:

- Native Python wheels for the configured platform/interpreter matrix and the source distribution. Match their filenames and SHA-256 values against PyPI's version JSON.
- The installable `@mobilise-d/cwa-reader` npm tarball, pack receipt, browser distribution archive and browser test results. Inspect the package version, worker/Wasm assets and build metadata.
- The Xeus conda package and local channel archive, including repodata, resolved runtime/compiler metadata and browser parity report. Confirm repodata checksums match the packaged binary.
- Per-distribution checksum manifests for the downloadable artifacts.

Compare recorded source revisions with the release tag. Confirm that published archives exclude CWA fixtures and generated reference CSVs. Smoke-test a downloaded native wheel from PyPI. Do not call the release complete merely because its GitHub page exists or a workflow uploaded CI artifacts.

The Xeus package targets its recorded CPython and Emscripten ABI. Do not describe it as a portable Pyodide wheel. The npm package is prebuilt ESM, Wasm and a worker; consumers do not need a Rust toolchain.

## Recover a partial release

Inspect failed jobs and the existing PyPI and GitHub inventories before retrying. A transient failure can be retried against the same tag and source. Do not move a published tag, replace published PyPI content, or overwrite GitHub assets with different bytes. If a source change is required after publication, prepare a new version. Report which distributions succeeded and what remains incomplete.
