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


## Implementation evidence

8b6074e implements the package and source layout. The runtime package has 11
files, native ESM exports at the root and /bytes, and no runtime dependencies or
install hooks. ./wasm/build.sh produces pkg/ and
wasm/dist/mobilise-d-cwa-reader-0.4.0.tgz plus npm-pack.json. Its package version
comes from root Cargo metadata. Three packaging helpers are consolidated into
scripts/package.mjs; handwritten wrapper/type/worker sources are under js/.

Pinned build, 18 existing browser tests, strict declarations, archive inspection
and the moved benchmark smoke pass. npm run test:package installs the actual
tarball offline into a temporary consumer and builds with Vite 8.3.4. The real
browser loads worker and Wasm assets under /reader-test/ without custom asset
configuration. Metadata matches native; the selected 840 sample rows have exact
integer timestamps and acceleration. CI includes this check and uploads the
standalone-browser-npm artifact. Final review, CI artifact proof and delivery
remain pending. No parser behavior or native/Xeus build was changed.

## Python distribution and documentation relocation

The user further requested that the Python wrapper leave the repository root,
with a short root README explaining the project and linking to per-crate and
per-distribution READMEs. Move the Python distribution coherently to python/,
keep the shared core at crates/cwa-core/ and standalone distribution at wasm/.
The root Cargo manifest becomes the shared workspace. Preserve Python signatures,
native wheels/sdist behavior, Xeus recipe/runtime pins, shared test fixtures and
all browser readers. No legacy root forwarding crate or duplicate parser.

Core agent owns the precise Python path mapping, Python manifest/source/config,
native CI and tests, python/README.md and crates/cwa-core/README.md. Standalone
owns its build/test/CI path updates and moves its detailed guide to wasm/README.md.
Xeus owns recipe, tools/wasm, Xeus CI/guide and benchmark-tool path updates. Parent
owns root README, this plan and final integration. Agents coordinate path mapping
before dependent edits. Shared reference fixtures need not move merely for layout.

Each relocation slice must update its consumers and pass focused checks before
commit. Final gates include the native tests and clean sdist-built wheel, actual
Xeus build/browser parity, standalone npm archive plus production consumer tests,
link/path checks and final scope review from the recorded d9c61a1 base. Earlier
package-only evidence remains useful but is not a substitute for post-move builds.

The Python move and its native/Xeus/standalone consumers are inseparable: parent
will commit them atomically with the root and distribution READMEs after native
and standalone focused checks and Xeus path/recipe checks. Agents leave these
relocation edits uncommitted for that explicit integration commit. Xeus rebuilds
its complete artifact/browser proof from the resulting clean commit. Python tests
move to python/tests; shared tests/reference_data stays at the root.

The user also requested READMEs for the other crates/distributions and common
information under /docs. Distribution entry points are python/README.md,
wasm/README.md and recipes/xeus/README.md; the core has its own README. Shared
reader behavior, timestamp interpretation and cross-target validation live in
docs/{reader-behavior,timestamps,validation}.md, with docs/README.md as the index
and the existing shared benchmark report retained. Move the former Xeus guide
out of docs into its recipe README, remove obsolete guide paths, and update
incoming links. Distribution-specific examples stay with their distributions;
shared explanations are linked rather than copied. Root README stays an overview.
