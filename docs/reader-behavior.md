# Shared reader behavior

The independent `cwa-core` crate implements parsing, timestamp reconstruction,
cuts, resampling and CSV. Native Python, browser Python and standalone JavaScript
use this core. Their input adapters and output representations differ; their
interpretation of a recording does not.

## Header, metadata and sampling reports

Header parsing reads the 1,024-byte CWA header. It reports configured timing and
sensor settings, which need not match the actual sample boundaries.

The metadata operation also searches forward for the first valid data packet and
backward for the last valid data packet and its predecessor. It skips non-data
and empty packets, applies sample offsets and continuity correction, and returns
the actual first and last sample timestamps. Missing sample bounds remain absent.
It does not decode sensor values or scan the recording interior. Consequently it
does not detect errors in unvisited interior packets.

The sampling consistency report scans all packet metadata using bulk reads. It
compares configured and sample-derived timing without returning sensor samples.
Header duration is configured end minus configured start. Data duration is the
first-to-last sample span, and the effective sampling rate is
`(sample_count - 1) / duration`. The configured rate and effective rate answer
different questions; see [clock interpretation](timestamps.md#sampling-rate-and-clock-drift).

## Cuts

Block cuts count 512-byte data packets after the file header. They include the
start block and exclude the end block. Packets can contain different numbers of
samples, so a packet count is not a row count.

Seconds cuts are relative to the first valid sample, not the configured logging
start. They include the start time and exclude the end time. Without resampling,
they return original samples only. A start between samples selects the next
original sample; a sample exactly at the end is excluded.

Packet times are assumed to be ordered. The seconds locator estimates a packet
position using sampling information, probes its timing, and corrects the estimate
within a narrowing range until it finds the cut. It does not scan or validate
unvisited parts of a recording.

Partial reads preserve the timestamp continuity correction of full reads. They
look back for the previous valid packet rather than treating the first selected
packet as the recording start. This is a deliberate difference from an isolated
C partial export; see [reference comparisons](validation.md#c-reference).

## Packet batches and memory

One sequential engine handles sample reads and CSV output. By default, each
batch owns 256 physical data packets and preloads one additional physical packet
on each side, clipped to the recording boundaries. These parameters are tunable
through each distribution's interface. Processing does not create threads or
processes.

Overlap provides timestamp and interpolation context. Each batch emits only its
owned output, so overlapping input does not duplicate output samples. Metadata
and cut-planning probes are separate from the larger payload preloads.

If the preload lacks enough valid context, the reader returns
`InsufficientContext`. It does not silently use a linear edge at an artificial
buffer boundary, fetch extra payload pages, or switch to an older reader. Retry
with a larger overlap. A failed batch emits no provisional output; batches
already delivered remain valid.

Individual batches may have different optional channels. Full collection combines
them with missing values where a channel is absent. Missing measurements and
absent channels are not converted to zero.

Bounded input processing does not make full output free. A Python DataFrame or
complete JavaScript sample result retains all selected rows. Batch consumers can
release output as they proceed. CSV remains bounded only if its sink does not
retain the whole output. Browser file reads also copy requested bytes into Wasm
memory; this is not a zero-copy interface. See [measurements](packet-batch-benchmarks.md)
for the distinction between process RSS, Wasm capacity and output size.

## Resampling

The current resampling method is local cubic interpolation with linear edge
handling. It uses original timestamped samples, not recursively interpolated
output, and each numeric channel is interpolated independently.

All batches share one output grid:

```text
t_out[i] = t_start + i / target_hz
```

For seconds cuts, `t_start` is exactly the first recording sample time plus the
requested start offset. Otherwise it is the first selected sample timestamp.
Seconds-cut output stops before the requested end. Without a seconds end,
output stops when the next target cannot be bracketed by input samples. The
reader never extrapolates beyond available input.

For an interior target bracketed by samples 1 and 2, the cubic calculation uses
the nearest four original samples, 0 through 3:

```text
y(t) = sum(y[j] * L[j](t), j=0..3)
L[j](t) = product((t - x[m]) / (x[j] - x[m]), m != j)
```

This is a four-point Lagrange polynomial, not a global spline. Near a real edge
of the selected input domain, or when duplicate or near-duplicate timestamps
make the polynomial degenerate, the calculation falls back to linear
interpolation between the bracketing samples. Insufficient artificial preload
context is an error instead.

The cut is resolved using original timestamps before interpolation. Neighboring
packets may supply context, but output stays in the selected interval. There is
no independent duration override: sample-derived timing defines the span.
