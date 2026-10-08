# cwa-core

The shared Rust parser for Open Movement CWA recordings. This crate contains
header and packet parsing, timing, cuts, resampling and CSV output. It has no
Python or JavaScript dependencies. The [Python extension](../../python/README.md)
and [standalone Wasm package](../../wasm/README.md) both call this implementation.

## Reader interface

`CwaReader<R: Read + Seek>` accepts a file or an in-memory cursor. Every operation
works on bytes without a temporary file; CSV accepts any `Write` sink.

```rust,no_run
use cwa_core::reader::{CwaReadOptions, CwaReader};
use std::io::Cursor;

fn read_recording(bytes: &[u8]) -> Result<(), cwa_core::errors::CwaError> {
    let mut reader = CwaReader::new(Cursor::new(bytes));
    let header = reader.read_header()?;
    let metadata = reader.read_metadata()?;
    let report = reader.sampling_consistency_report()?;
    let options = CwaReadOptions::default();
    let samples = reader.read_data(&options)?;
    let mut csv = Vec::new();
    reader.write_csv(&mut csv, &options)?;
    Ok(())
}
```

`CwaReader::open("recording.cwa")` is the path convenience constructor. Output
columns contain `f32` measurements and timestamps contain integer microseconds.
Absent optional sensors have no column; missing values in a recorded channel are
NaN. Device-clock timestamps stay naive unless an explicit fixed UTC offset is
provided. See the shared [reader behavior](../../docs/reader-behavior.md) and
[timestamp guide](../../docs/timestamps.md) for cuts and clock semantics.

## Preloaded packet batches

`CwaBatchSession` requests byte ranges through `request()` and consumes each
completed preload through `provide()`. A `BatchDescriptor` contains the timing
and ownership context needed to decode that range independently. Source access
stays with the caller, so synchronous readers and asynchronous browser Files use
the same decoder.

The shared [reader behavior guide](../../docs/reader-behavior.md) documents packet
ownership, fixed overlap, interpolation context and output memory. See the
[batch benchmarks](../../docs/packet-batch-benchmarks.md) for measurements and the
[validation guide](../../docs/validation.md) for cross-target parity.

From the repository root:

```sh
cargo test -p cwa-core
cargo test --workspace
```
