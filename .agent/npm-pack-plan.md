# Installable standalone npm artifact

Status: implementation. New scope base d9c61a137196cdae3e41bc75f2888fab860c7487.
Delivery remains PR https://github.com/mobilise-d/cwa_reader_rs/pull/7.
Previously reviewed history is immutable; use normal additional commits.

COMPACTION CONTINUITY: Re-read implement-code-change and the task-defining artifacts before continuing after compaction or session restoration.

The user accepted npm pack for distribution of the standalone JS/Wasm reader.
Produce an installable local tarball and a CI artifact. No registry publication.
Use @mobilise-d/cwa-reader as the local package name, without claiming registry
scope ownership. Derive its version from the existing source package version.

Include precompiled Wasm, JavaScript bindings, the File/handle facade and worker,
TypeScript declarations, license and README. Export the File facade at the
package root and the byte API at an explicit subpath. Keep runtime dependencies
and installation build scripts unnecessary. Use an explicit package file list;
exclude tests, fixtures, examples and build tools from the installable package.
Preserve the existing directly served browser bundle and native/Xeus workflows.

Standalone agent owns wasm/**, standalone guide and its CI workflow. Parent owns
this plan, README integration, final review and PR delivery. Packaging and its
consumer proof form one coherent review unit, committed after focused checks.
Parent documentation/delivery follows after the package interface is stable.

Verification must install the actual npm-pack tarball into a small consumer,
build for production and run in a real browser. Read metadata from a File and
consume sample batches. This catches missing worker/Wasm assets and incorrect
asset URLs which direct source-checkout tests cannot detect. Verify TypeScript
imports, archive contents, and the existing standalone browser suite. CI must
upload the tarball and run the installed-consumer check. Do not add tests that
merely restate manifest fields. Record artifact checksum and exact commands.

Finish per-commit reviews, review this new scope from the exact base above,
preserve reviewed commits and corrections, push/update the existing PR, and
verify the CI artifact. Do not merge or publish.

## Wrapper layout and bundling clarification

The user asked for current online guidance and called the wrapper folder chaotic.
Research sources: wasm-bindgen/reference/deployment.html at
https://wasm-bindgen.github.io/wasm-bindgen/reference/deployment.html,
https://vite.dev/guide/features.html#web-workers,
https://vite.dev/config/build-options.html#build-assetsinlinelimit,
https://webpack.js.org/guides/web-workers/ and npm package.json exports/files docs.
These describe deployment targets, asset/worker handling and package entry points;
they do not mandate a repository directory tree.

Keep wasm-bindgen web output as native ESM with separate Wasm and module-worker
assets. Let consuming applications bundle it. Do not add library-mode bundling,
base64 Wasm, a CommonJS build or a TypeScript migration without a concrete need.
Vite library mode inlines assets; the installed-tarball production application
already works without an asset plugin or custom build configuration.

Clean the maintainer layout within the packaging slice: handwritten wrapper,
declarations, worker and npm README under js/; tooling under scripts/; Rust src/,
tests/, example/, generated pkg/ and tarball dist/ remain distinct. Keep a real
top-level build.sh entry if useful, without compatibility forwarding stubs.
Consolidate packaging helpers where that makes the build easier to follow.
Update all consumers, commands and CI references and rerun the same source and
installed-consumer checks after moving files.
