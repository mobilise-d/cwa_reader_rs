# Shared documentation

These guides describe behavior shared by the Rust parser and its distributions.

- [Reader behavior](reader-behavior.md): metadata lookup, cuts, packet batches,
  interpolation, missing context and memory use.
- [Timestamps and clock interpretation](timestamps.md): the device clock, fixed
  UTC offsets, daylight-saving changes and sampling-rate reports.
- [Validation](validation.md): native/browser parity, C reference comparisons,
  numerical tolerances and shared fixtures.
- [Performance measurements](packet-batch-benchmarks.md): measured workloads,
  batch-size tradeoffs, runtime versions and memory definitions.

For installation, build commands and language-specific examples, use the
[Rust core](../crates/cwa-core/README.md), [Python](../python/README.md),
[JavaScript/Wasm](../wasm/README.md) or [Xeus](../recipes/xeus/README.md) README.
