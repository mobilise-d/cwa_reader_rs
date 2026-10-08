# Release 0.5.0

The user authorizes merging PR #7, publishing version 0.5.0 to PyPI, and publishing all distribution artifacts on its GitHub Release. npm registry and official conda channel publication are outside this task.

Base: `109e5533c6001de251f17f431056cf996bb58384`. Preserve the reviewed history and add normal commits.

COMPACTION CONTINUITY: Re-read implement-code-change and the task-defining artifacts before continuing after compaction or session restoration.

## Review units and verification

1. Core agent: synchronize Python, core, Wasm and Xeus versions and locks. Run Rust/native tests and build and install the Python wheel from its sdist before committing.
2. Standalone agent: add release-event artifact publishing for npm and browser bundles. Inspect assembled archives and workflow configuration before committing.
3. Xeus agent: attach native artifacts and Xeus package/channel assets on release. Inspect archive contents and workflow configuration before committing.
4. Root: update `.agent/python-release-workflow/SKILL.md` for the new layout, all distributions, exact-source verification and publication recovery. Check instructions against the implemented workflows before committing.

## Delivery gates

- Resolve and close per-commit reviews, then review the complete release changes from the base above.
- Push PR #7 and pass native, standalone and Xeus CI on the versioned head.
- Merge without rewriting reviewed commits. Record the merge SHA and wait for its three build workflows.
- Check tag, release and PyPI version availability. Publish `v0.5.0` at that exact tested merge SHA.
- Wait for native PyPI publishing and all GitHub release uploads. Download assets, verify checksums and installation metadata, and confirm PyPI's file inventory.
- Report the release and PyPI links, artifact inventory and any remaining limitations.
