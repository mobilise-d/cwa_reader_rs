# Metadata boundary lookup

Task: replace the full scan in `read_metadata` with a dedicated lookup that searches
forward for the first valid data packet and backward for the last valid packet and
its valid predecessor. Preserve sample offsets and continuity correction. Retain the
full scan for `sampling_consistency_report`. Skip non-data and empty sectors;
retain errors for malformed packets encountered by the search and partial sectors.
Unvisited middle packets are no longer validated by metadata reads.

Base: 026ddf9edca6aaf28a4318dc3023d3d98f886056.
Branch: t3code/check-metadata-file-reading. Initial worktree clean.

One review unit: boundary lookup, documentation, and validation. Verify existing
metadata tests before and after, compare boundary timestamps to full-scan reports
with skipped sectors and continuity cases, and inspect I/O on a large recording.
Commit only after focused verification; finish with Rust tests, full Python tests,
formatting, per-commit review, final range review, push and PR.

Verification: baseline and updated metadata/dataframe suite both passed, 21 tests.
Full Python suite passed, 122 tests; Rust suite passed, 5 tests; formatting and
diff checks passed. An ad hoc comparison against the full report passed 107
boundary cases, including skipped sectors, zero/one/two packets, sample offsets,
gaps and backward timestamps. Partial trailing sectors still raise an error.
A sparse 512 MB recording required 2,560 file bytes, plus 107 bytes of /proc I/O
accounting. No permanent test seam was added for this internal optimization.
Default Python 3.14 tried to build locked pandas from source; verification used
Python 3.11 matching CI in /tmp/cwa-metadata-venv.

The user explicitly chose to retain the current tests after review 14173 recommended
persistent backward-search coverage. That recommendation is deferred by user decision.
A wheel build and metadata smoke test in a clean environment also passed.

Implementation commit: 9f32884 before final curation. PR: #8.
Final review and delivery state are tracked in the session task state.

## Integration into the byte-capable core

PR #8 merged into main as 53830c8. Its boundary lookup was already adapted in
b50bb9a to the generic Read+Seek implementation in crates/cwa-core/src/header.rs.
The root Python bridge in src/python/header.rs delegates to CwaReader; no legacy
src/header.rs implementation remains. Sampling reports retain the full timing
scan and real sample count, and metadata retains the same serialized fields.
The source PR's decision against new permanent optimization tests remains in force.

Merge review unit: preserve reviewed history with a normal merge of origin/main,
retain the extracted implementation, consolidate the duplicate README metadata
text, run the existing 13 Rust and 122 native Python tests plus formatting and
boundary parity checks, then commit and close the merge review. The parent owns
pushing and PR delivery. No buffering changes are included in this merge.
