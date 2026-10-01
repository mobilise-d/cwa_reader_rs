# Return existing channels only

COMPACTION CONTINUITY: Re-read implement-code-change and the task-defining artifacts before continuing after compaction or session restoration.

Task: omit channels absent from recorded data, retain measured zeros, respect include flags, and apply the same output schema to CSV. User requested new regression tests only through read_cwa_file, including cuts and resampling.
Policy: .agents/refactor-policy.md, explicitly accepted in conversation. Pre-1.0 breaking changes permitted.
Base: 33529b2. Initial worktree clean. Integration owner: root.

Commit units and gates:
1. Record accepted compatibility policy and repository review guidance. Verify roborev setup/configuration and commit before behavior work.
2. Omit absent sensor channels in reader and CSV, update docs and affected consumers. Demonstrate failing reader regression before fix; run focused reader regressions, existing Python suite, Rust tests and formatting; commit.
3. Resolve per-commit reviews, curate stack, verify final state, run whole-range review and deliver branch/PR if upstream access is available.
