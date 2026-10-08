# Packet batch measurements

Measurements use an anonymized local AX6 recording, 436,792,320 bytes, spanning
345,594.81 seconds (about four days) at the header sampling rate of 100 Hz.
The returned data has acceleration, gyroscope and auxiliary channels: nine
float32 columns. The input and participant-derived fingerprints remain outside
the repository.

The native and Xeus package source is
`8375b9b7119c0c2d5074c889ae55dd35e6358b5a`. The source-clean Emscripten conda
artifact SHA256 is
`3bf96e832b01f283f3f301f9535554bb91b0a6bd8bbd174945dd425295f9649e`.
The actual Xeus worker passed 128 Python tests and 25 native/browser comparisons.
See [the build guide](xeus-wasm.md) for the pinned runtime and install commands.

## Measurement conditions

Measurements ran on an AMD Ryzen AI 9 HX PRO 375 Linux workstation.
Runs execute sequentially with other agents' sustained builds and measurements
paused. Files remain in the host OS cache; these are warm-storage measurements,
not cold-disk latency. Three repeats are used unless stated otherwise. Reader
timings exclude dependency imports, metadata used to choose window coordinates,
and correctness hashing. The native Rust full-input timing includes session
header/planning requests and discards every returned batch. Xeus uses a selected
DOM File transferred to its worker and a compatible WORKERFS adapter; there is
no whole-file MEMFS staging or additional read-ahead cache.

Native read counts are successful `File::read` calls, not physical disk accesses.
Xeus physical counters wrap `FileReaderSync.readAsArrayBuffer`; logical counters
wrap filesystem reads, so EOF probes can differ. Byte counts include repeated
physical overlap and metadata/probe reads. Native memory is Linux process peak
RSS. Browser memory is committed Wasm linear-memory capacity, not peak live
allocation or whole-browser RSS. The interpreter/runtime is included where
applicable.

Native Python uses CPython 3.13.12, NumPy 2.5.3 and pandas 3.0.6. The standalone
native Rust runner uses rustc 1.99.0 (`b940084d7`). Xeus uses CPython 3.13.1,
NumPy 2.4.6, pandas 3.0.6 and Emscripten 4.0.9, built with the pinned nightly
in the recipe. Reproduction commands are in
[tools/benchmarks](../tools/benchmarks/README.md). Keep full JSON receipts outside
the checkout.

## Full decode with bounded output

The full raw recording contains 34,124,320 rows, representing 1,501,470,080 bytes
of decoded columns and timestamps. At 60 Hz it contains 20,735,689 rows and
912,370,316 decoded bytes. Those bytes are consumed and discarded batch by batch;
they are not simultaneously resident.

| Packets per batch | Native raw median, s | Native 60 Hz median, s | Full input read calls | Input bytes read | Native peak RSS, MiB |
|---:|---:|---:|---:|---:|---:|
| 64 | 1.255 | 2.115 | 13,331 | 450,440,194 | 3.69 |
| 256 | 1.230 | 2.099 | 3,334 | 440,203,266 | 5.63 |
| 1024 | 1.218 | 2.079 | 835 | 437,644,290 | 13.38 |
| 2048 | 1.322 | 2.354 | 418 | 437,217,282 | 25.33 |
| 8192 | 1.992 | 2.610 | 106 | 436,897,794 | 74.61 |

RSS is the maximum across raw and resampled repeats. Larger batches reduce
requests but increase working memory and do not guarantee better throughput.
The default 256 packets gives a small working set with near-best native times.

## Standalone browser bounded output

The browser `File` iterator consumes and discards every decoded batch. Three
fresh page/Wasm instances per case give the following medians. These dense-input
measurements use source `88d2664`; the subsequent empty-selection error correction
in `8375b9b` does not change their requests or output. Browser committed memory
is the maximum linear-memory capacity across raw and resampled runs.

| Packets per batch | Browser raw median, s | Browser 60 Hz median, s | Committed Wasm capacity, MiB |
|---:|---:|---:|---:|
| 64 | 6.5565 | 12.1561 | 2.0000 |
| 256 | 5.5834 | 10.3982 | 4.3750 |
| 1024 | 5.1001 | 10.1406 | 13.8750 |
| 2048 | 5.0708 | 10.0329 | 26.4375 |
| 8192 | 4.9232 | 9.1789 | 101.5625 |

The native and browser bounded timings measure the same recording and output
row counts. Their memory metrics differ, so compare capacity/RSS within each
runtime. The larger browser batch improves throughput at a substantial memory
cost. The default 256 uses 4.375 MiB while decoding the four-day recording.

## Xeus local File windows

These Python reads return a 60-second DataFrame. Each browser invocation starts a
fresh Xeus kernel, then runs three repeats per position with counters reset on a
new mount. The kernel remains alive between repeats. Times vary at millisecond
scale; there is no consistent advantage to a large batch for these small cuts.

| Packets | Raw first/middle/last median, ms | 60 Hz first/middle/last median, ms |
|---:|---|---|
| 64 | 3.3 / 4.6 / 5.1 | 4.1 / 5.7 / 3.6 |
| 256 | 4.9 / 5.0 / 5.1 | 3.1 / 4.4 / 3.6 |
| 1024 | 2.8 / 6.6 / 4.1 | 3.5 / 4.0 / 4.1 |
| 2048 | 3.0 / 4.2 / 4.6 | 3.7 / 4.4 / 3.1 |
| 8192 | 3.9 / 5.5 / 4.6 | 4.1 / 5.1 / 4.8 |

At default 256 packets, the complete workload performs 11/20/16 actual
`FileReaderSync` reads for first/middle/last cuts, totalling 79,994/81,288/81,168
input bytes. These counters include the separate boundary metadata lookup used
to select window coordinates; reader timings exclude that lookup. Raw and 60 Hz
cuts use the same input requests. The largest requested slice is 78,336 bytes.
At 64 packets, each window needs two additional reads and 2,048 extra overlap
bytes. All five batch sizes retain the runtime's 139,198,464-byte committed heap
capacity. All 90 window outputs agreed with native Python in row counts, timestamps and
raw float32 fingerprints on this recording. Raw output has 5,924 rows and
occupies 260,656 bytes; 60 Hz output has
3,600 rows and occupies 158,400 bytes. Narrow late cuts do not scan the full file.

## Xeus full scans and CSV

`read_metadata` performs five actual Blob reads totalling 2,560 bytes and has a
2.1 ms median. The full sampling consistency report has a 1.195 s median,
3,340 actual Blob reads and 436,795,904 bytes read. Its 3,341 logical filesystem
reads include one EOF probe that does not invoke `FileReaderSync`. Report scans
use a fixed 256-packet buffer, independent of the DataFrame batch tuning option.

Full raw CSV uses the same bounded packet engine, two passes for channel schema
and output, and the API's default CSV channel options. Those defaults include
acceleration/gyroscope but omit auxiliary columns. The sink is `/dev/null`,
so no full CSV is retained in MEMFS. Formatting cost is included.

| Packets | Repeats | CSV median, s | Actual Blob reads | Bytes read | Committed heap after, MiB |
|---:|---:|---:|---:|---:|---:|
| 64 | 1 | 39.194 | 26,666 | 900,882,946 | 132.750 |
| 256 | 3 | 33.621 | 6,672 | 880,409,090 | 132.750 |
| 8192 | 1 | 30.496 | 216 | 873,798,146 | 229.438 |

Only the default has three full CSV repeats; the outer sizes are single
observations. Counters include the separate boundary metadata call. These
Xeus heap capacities include the Python runtime, NumPy and pandas, unlike the
small standalone Wasm module. CSV storage/formatting and bounded binary batch
consumption are different workloads.

## Native Python collection

These calls use the ordinary raw `read_cwa_file` API with all default channels,
including auxiliary values. Each repeat runs in a fresh process. Reader timing
and process peak RSS are captured immediately after the call, before bounded
correctness hashing. All repeats agreed on output fingerprints, row counts, dtypes and integer
nanosecond timestamps.

| Selection | Rows | DataFrame/index bytes | Median reader time, s | Read-phase process peak RSS, MiB |
|---|---:|---:|---:|---:|
| Full four-day recording | 34,124,320 | 1,501,470,080 | 1.5871 | 1509.5 |
| First 24 hours | 8,530,963 | 375,362,372 | 0.4476 | 441.3 |
| Middle 24 hours | 8,531,332 | 375,378,608 | 0.3909 | 440.3 |
| Last 24 hours | 8,531,344 | 375,379,136 | 0.3908 | 441.5 |

The middle window starts half a day before the recording midpoint. The last
window ends at the final valid sample time. The full collector retains roughly
1.4 GiB even though the decoder uses batches; use bounded output when memory
must remain small. CSV and the native count-and-discard runner measure different
operations from this DataFrame API.

## Output allocation limits

A full Python `read_cwa_file` collects all selected rows, so its memory use is
separate from the bounded decoder above. A full CSV sink also includes text
formatting and schema discovery; it cannot be compared directly with count-and-
discard decoding. Writing that CSV into worker MEMFS would retain its complete
output. The benchmark uses `/dev/null` to measure processing without retaining
output storage. No full four-day DataFrame is attempted in the browser.
