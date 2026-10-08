# Native core benchmark

This unpublished, benchmark-only crate consumes `cwa-core` batches and discards
output. It measures decoding, input reads and memory without Python DataFrame
collection or CSV formatting. It is not a reader distribution.

See the [benchmark guide](../README.md) for invocation and measurement conditions,
the [measured results](../../../docs/packet-batch-benchmarks.md), and the
[shared reader behavior](../../../docs/reader-behavior.md).
