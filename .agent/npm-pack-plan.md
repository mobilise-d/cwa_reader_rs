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
