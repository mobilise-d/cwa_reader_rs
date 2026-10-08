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
