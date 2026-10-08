---
name: python-release-workflow
description: Release cwa_reader_rs, a maturin-built Rust/Python package, through a GitHub Release that triggers PyPI trusted publishing.
---

# Python Release Workflow

Use this workflow for patch, minor, and major releases of `cwa_reader_rs`. The version comes from `python/Cargo.toml`; maturin supplies the Python package version. Publishing a GitHub Release triggers `.github/workflows/CI.yml` to build and upload the wheels and source archive to PyPI. A tag push alone does not publish. Run the commands below from the repository root.

## Prepare and verify

1. Check `git status -sb` and recent commits. Keep unrelated work out of the release changes.
2. Choose the next version. Update the package version in `python/Cargo.toml` and regenerate the root `Cargo.lock` so its `cwa_reader_rs` entry matches. Check that `python/pyproject.toml` still uses the dynamic version supplied by maturin. The root `Cargo.toml` is only a workspace manifest.
3. Run `cargo test --workspace`, `uv sync --project python --dev --python 3.10`, `uv run --project python --no-sync pytest -q python/tests`, and `uv build --project python --out-dir dist`. Resolve failures before proceeding.
4. Commit the version change, push it, and merge it into `main` through the normal review process. Record the exact merged commit SHA. Wait for the `CI` workflow on that SHA to succeed; it tests Python 3.10 and 3.11 and builds the distribution artifacts.

## Publish

1. Check that the planned tag `vX.Y.Z` and GitHub Release do not already exist, and that the merged commit has the intended version in `python/Cargo.toml` and the root `Cargo.lock`.
2. Create the GitHub Release for the tested commit, for example:

   ```bash
   gh release create vX.Y.Z --target <merged-commit-sha> --title vX.Y.Z --generate-notes
   ```

   This creates the tag if needed. Publish the Release rather than saving it as a draft. GitHub's `release: published` event starts the PyPI job; pushing the tag separately does not.
3. Watch the `CI` run for the Release event through completion. Confirm the publish job succeeds and the new version and expected files appear on PyPI. Do not report the release complete based only on the GitHub Release page.

If publishing fails, inspect the run and correct the cause before trying again. PyPI versions cannot be replaced; do not reuse a version for different artifacts or create a second release without checking what was uploaded.
