# Return existing channels only

COMPACTION CONTINUITY: Re-read implement-code-change and the task-defining artifacts before continuing after compaction or session restoration.

Task: omit channels absent from recorded data, retain measured zeros, respect include flags, and apply the same output schema to CSV. User requested new regression tests only through read_cwa_file, including cuts and resampling.
Policy: .agents/refactor-policy.md, explicitly accepted in conversation. Pre-1.0 breaking changes permitted.
Base: 33529b2. Initial worktree clean. Integration owner: root.

Commit units and gates:
1. Record accepted compatibility policy and repository review guidance. Verify roborev setup/configuration and commit before behavior work.
2. Omit absent sensor channels in reader and CSV, update docs and affected consumers. Demonstrate failing reader regression before fix; run focused reader regressions, existing Python suite, Rust tests and formatting; commit.
3. Resolve per-commit reviews, curate stack, verify final state, run whole-range review and deliver branch/PR if upstream access is available.

Progress:
- Setup committed as 6f2762b; roborev v0.69.0 configuration and repository checks passed. Review 13251 passed and closed. Draft PR #3 created and setup pushed.
- Baseline: 5 Rust tests and 16 Python tests passed.
- Reader regression reproduced the zero-filled absent gyro/magnetometer keys before implementation; now passes.
- Reader checks cover packed/unpacked accelerometer, 6/9 axes, real zeros, inclusion flags, block/time cuts, 100/60 Hz resampling and changing packet layouts. New tests only exercise read_cwa_file as requested; existing CSV assertions updated.
- Missing samples within a present channel are NaN. Streaming CSV scans selected packet layouts before writing the header so mixed layouts have a stable schema.
- Behavior slice verification and commit gate: cargo fmt --check, cargo test, uv run --no-sync pytest -q tests, git diff --check.
- Remaining: behavior commit/review, final whole-range review, final push and PR description.

Review correction:
- Review 13253 identified a source sensor segment missed by the resampling grid. Reader regression reproduced the omitted gyro key. Track selected source presence independently of interpolation, retaining NaN arrays. Add a focused reader test; verify and commit as fixup to 38ef012 before final stack review.

- Correction review 13260 found early output completion could stop observing source presence before the cut end. A bounded 2 Hz regression reproduced this. Continue observing source samples through the cut end without generating or buffering additional outputs; verify and fix up the behavior commit.
