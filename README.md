# cwa_reader_rs

[![PyPI](https://img.shields.io/pypi/v/cwa-reader-rs)](https://pypi.org/project/cwa-reader-rs/)
[![Python Versions](https://img.shields.io/pypi/pyversions/cwa-reader-rs)](https://pypi.org/project/cwa-reader-rs/)
[![CI](https://github.com/mobilise-d/cwa_reader_rs/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/mobilise-d/cwa_reader_rs/actions/workflows/CI.yml)
![PyPI - Downloads](https://img.shields.io/pypi/dm/cwa-reader-rs)

`cwa_reader_rs` is a Rust-based reader for [Open Movement](https://github.com/openmovementproject/openmovement) CWA files from AX6 sensors, focused on modern IMU configurations.

It was created to provide a fast, small, and easier-to-distribute loader that integrates well with [mobgap](https://github.com/mobilise-d/mobgap). The port is mostly agent-generated and tested for correctness using multiple example files, including parity checks against the original Open Movement C implementation. Full-file reads are expected to match the C output, aside from the C CSV export's millisecond timestamp formatting tolerance; partial reads deliberately preserve full-read timestamp consistency. See [Comparison To The C Reference](#comparison-to-the-c-reference) for details.

## Installation

Install from PyPI with `uv`:

```bash
uv add cwa-reader-rs
```

Or install into the current environment:

```bash
uv pip install cwa-reader-rs
```

### Local Development

Clone the repository and install the package locally:

```bash
git clone https://github.com/mobilise-d/cwa_reader_rs.git
cd cwa_reader_rs
uv sync --dev
uv pip install -e .
```

Because this package contains a Rust extension module built with [maturin](https://www.maturin.rs/), local source installs may require a working Rust toolchain. Install Rust with [rustup](https://rustup.rs/) if your platform does not have a pre-built wheel available.

## Usage

### Full File Read

```python
from cwa_reader_rs import read_cwa_file

data = read_cwa_file(
    "recording.cwa",
    include_magnetometer=False,
    include_temperature=False,
    include_light=False,
    include_battery=False,
)

timestamps_us = data["timestamp"]
acc_x = data["acc_x"]
acc_y = data["acc_y"]
acc_z = data["acc_z"]
```

The returned object is a dictionary of NumPy arrays. Timestamps are integer Unix timestamps in microseconds.

### Header Read

```python
from cwa_reader_rs import read_header

header = read_header("recording.cwa")

device_id = header["device_id"]
sample_rate_hz = header["sample_rate_hz"]
logging_start_time = header["logging_start_time"]
```

The header read returns metadata from the 1024-byte CWA metadata block without parsing sample data. It includes device and session identifiers (`hardware_type`, `device_id`, `session_id`), recording timing fields (`logging_start_time`, `logging_end_time`, `last_change_time`), nominal sensor configuration (`sample_rate_hz`, `accel_range`, `gyro_range`, `magnetometer_enabled`, `firmware_revision`), and the free-form `annotation`.

Time fields are returned as RFC 3339 strings when present, or `None` when the CWA header uses an unset start/end marker.

### Sampling Consistency Report

```python
from cwa_reader_rs import sampling_consistency_report

report = sampling_consistency_report("recording.cwa")

start_from_header = report["start_from_header"]
end_from_header = report["end_from_header"]
duration_s_from_header = report["duration_s_from_header"]
start_from_data = report["start_from_data"]
end_from_data = report["end_from_data"]
duration_s_from_data = report["duration_s_from_data"]
samplingrate_hz_from_header = report["samplingrate_hz_from_header"]
samplingrate_hz_from_data = report["samplingrate_hz_from_data"]
```

This helper compares the timing implied by the CWA metadata header with the timing implied by the data packets. It scans packet metadata only; it does not decode or return sample values.

Header start/end and data start/end are returned as RFC 3339 strings or `None`. Header duration is `end_from_header - start_from_header`. Data duration is the inclusive first-sample-to-last-sample span, using the same packet timestamp, `timestampOffset`, and continuity correction as `read_cwa_file`. The header sampling rate is decoded from the metadata rate code. The data sampling rate is `(sample_count - 1) / duration_s_from_data`.

The values provided in the header are configured values, not measured values. In timed recordings, data-derived start and end timestamps may differ from the configured header start and end by a few seconds, for example because logging starts after the device wakes and stops when the device reaches its configured stop condition.

Open Movement documents two relevant time bases. The device has an internal RTC used for packet timestamps and configured start/end times. The [AX6 datasheet](https://github.com/openmovementproject/openmovement/blob/master/Docs/ax3/AX6%20Datasheet.pdf) lists the RTC precision as `+/-50 ppm` typical, which is about `+/-4.3 s/day`; the [AX3/AX6 FAQ](https://github.com/openmovementproject/openmovement/blob/master/Docs/ax3/ax3-faq.md#synchronizing-data-between-devices-or-with-other-devices) describes possible clock drift as being on the order of seconds per day. This report cannot detect RTC drift relative to external UTC, because both header times and packet timestamps are expressed in the device's own clock. External event markers or another synchronized reference are required for that.

In addition to the RTC, the underlying movement sensor has its own sample timing. Open Movement notes that the sensor output rate can vary slightly compared to the onboard RTC. That means a time interval measured by packet timestamps may contain slightly more or fewer samples than expected from the nominal header sampling rate. Over long recordings this can produce a noticeable difference between the expected and actual number of samples, even if the RTC itself were perfectly stable. This is reflected in `samplingrate_hz_from_data`. In local validation data, we saw effective rates around `100.6 Hz` for recordings configured as `100 Hz`, and the official Open Movement example fixture has an effective rate around `98.52 Hz`.

Without additional external timing information, this report cannot determine whether an inconsistency comes from RTC drift, sample-clock drift, delayed start/stop behavior, or file conversion artifacts.
For most AX6 workflows, the RTC-derived recording duration should be treated as the authoritative time span, and resampling should adjust the sample grid rather than forcing duration from sample count.

When a fixed-rate downstream pipeline is required, use `resample_hz=report["samplingrate_hz_from_header"]` or `resample_hz=read_header("recording.cwa")["sample_rate_hz"]` and let the reader resample from the data-derived timestamps.

### Partial Block Read

```python
from cwa_reader_rs import blocks, read_cwa_file

data = read_cwa_file(
    "recording.cwa",
    cut=blocks(25, 32),
    include_magnetometer=False,
    include_temperature=False,
    include_light=False,
    include_battery=False,
)
```

`blocks(start, end)` uses end-exclusive CWA data block indexes after the 1024-byte file header. Each data block is 512 bytes.

Partial reads are designed to be consistent with full reads: reading a block window directly should produce the same timestamps and values as reading the full file and slicing out the same samples.

### Partial Time Read

```python
from cwa_reader_rs import read_cwa_file, seconds

file_path = "recording.cwa"
start_seconds = 2.0
end_seconds = 12.0

data = read_cwa_file(
    file_path,
    cut=seconds(start_seconds, end_seconds),
    include_magnetometer=False,
    include_temperature=False,
    include_light=False,
    include_battery=False,
)
```

`seconds(start, end)` is measured in seconds since the first valid sample in the file, and `end` is exclusive.

Without resampling, a seconds cut returns original samples only. If `start` falls between two samples, the first returned sample is the first original sample at or after `start`. If `end` falls between two samples, output stops before the first original sample at or after `end`; a sample exactly at `end` is not included.

### Resample

```python
from cwa_reader_rs import read_cwa_file, read_header

expected_sampling_rate = read_header("recording.cwa")["sample_rate_hz"]

data = read_cwa_file(
    "recording.cwa",
    include_magnetometer=False,
    include_temperature=False,
    include_light=False,
    include_battery=False,
    resample_hz=expected_sampling_rate,
    resample_method="cubic",
)
```

Raw CWA output does not provide perfectly consistent sample times. For downstream pipelines that expect a regular grid, resampling is often desirable.

`cwa_reader_rs` provides built-in cubic resampling through `resample_hz` and `resample_method="cubic"`. Resampling during the read is significantly faster than loading the full raw dataset into Python and resampling afterward, especially for large files or narrow time windows. This mode is intended to get closer to the resampling performed in the original Mobilise-D preprocessing pipeline.

Resampling trusts the timestamps calculated from the CWA samples and interpolates those values onto a fixed-rate grid. There is no separate resampling duration override: the output span is defined by the selected data. For full-file reads this is the recording's sample timestamp span, for block cuts this is the selected block span, and for `seconds(...)` cuts this is the requested time window.

### Partial Time Read And Resample

```python
from cwa_reader_rs import read_cwa_file, seconds

file_path = "recording.cwa"
target_hz = 100.0
start_seconds = 2.0
target_samples = 1_000
end_seconds = start_seconds + target_samples / target_hz

data = read_cwa_file(
    file_path,
    cut=seconds(start_seconds, end_seconds),
    include_magnetometer=False,
    include_temperature=False,
    include_light=False,
    include_battery=False,
    resample_hz=target_hz,
    resample_method="cubic",
)
```

For combined cuts and resampling, the requested `seconds(...)` window is resolved against the original sample timestamps before interpolation. Neighboring samples or blocks may still be read as interpolation context for the cubic kernel, but emitted resampled timestamps remain inside the requested `[start, end)` window. The implementation does not resample a larger output grid and then cut on interpolated timestamps.

#### Interpolation Details

The resampler is streaming and currently supports `resample_method="cubic"` only.

Output timestamps are generated as:

```text
t_out[i] = t_start + i / resample_hz
```

`t_start` is the first selected sample timestamp, except for `seconds(start, end)` cuts where it is exactly `recording_start + start`. The `seconds(...)` end is exclusive: output stops before `recording_start + end`. Without a seconds end, output stops once the next target timestamp can no longer be bracketed by input samples.

For each output timestamp, each included numeric channel is interpolated independently from the timestamped input samples. For an interior target timestamp `t` bracketed by input samples `(x1, y1)` and `(x2, y2)`, the cubic path uses the nearest four samples:

```text
(x0, y0), (x1, y1), (x2, y2), (x3, y3)
```

and evaluates the 4-point Lagrange polynomial:

```text
y(t) = y0 * L0(t) + y1 * L1(t) + y2 * L2(t) + y3 * L3(t)

Lj(t) = product((t - xm) / (xj - xm) for m != j)
```

This is a local cubic interpolation, not a global cubic spline. If a target timestamp is near the start or end of the available samples, or if the four-point polynomial is numerically degenerate because timestamps are duplicated or too close together, the implementation falls back to linear interpolation between the bracketing samples:

```text
y(t) = y_left + (y_right - y_left) * (t - x_left) / (x_right - x_left)
```

The resampler never extrapolates beyond the selected input samples. For `seconds(...)` cuts, neighboring blocks may be read as interpolation context, but emitted samples remain inside the requested time window.

### CSV Export

```python
from cwa_reader_rs import blocks, write_cwa_csv

write_cwa_csv(
    "recording.cwa",
    "recording.csv",
    cut=blocks(25, 32),
    include_magnetometer=False,
    include_temperature=True,
    include_light=False,
    include_battery=True,
)
```

## Comparison To The C Reference

The reference implementation is Open Movement's `cwa-convert` C exporter:

https://github.com/openmovementproject/openmovement/tree/master/Software/AX3/cwa-convert/c

This repository includes reproducible comparison tools under [`tools/cwa_reference`](tools/cwa_reference/README.md). They download and build the C exporter, run parity comparisons, and benchmark selected read paths.

```bash
uv run python tools/cwa_reference/compare_windows.py
uv run python tools/cwa_reference/benchmark_scan.py --loops 50
```

### Full Reads

For full-file reads, the Rust implementation is expected to match the original C implementation in time span and sample values. In the included Open Movement reference fixture, accelerometer values match exactly.

Timestamp comparisons against C CSV output can differ by `+/-1 ms`. This is caused by the C exporter formatting timestamps to millisecond precision through a single-precision `float` fractional-second path when writing CSV. It is a CSV representation detail, not a difference in the internal timestamp model.

### Partial Reads

CWA packet timestamps are not fully independent. The packet-local timestamp gives a natural packet start and end, but the C exporter also applies a continuity correction using the previous packet end time when packets are read as a stream.

The C `cwa-convert -blockstart/-blockcount` partial export starts without previous-packet context, so the first block in a partial C export can differ slightly from the same block in a full C export.

`cwa_reader_rs` deliberately looks back to the previous valid packet for partial reads and seeds the same continuity correction that a full read would use. This means:

- Rust partial read vs Rust full-read slice: exact timestamp agreement in the tested fixtures.
- Rust partial read vs C full-read slice: agreement within the `+/-1 ms` C CSV formatting tolerance.
- Rust partial read vs C partial export: small first-window timestamp differences are expected.

In the included reference fixture, the largest observed Rust-partial vs C-partial timestamp difference is `20 ms` at `100 Hz`. This is the consequence of preserving full-read consistency in Rust while the standalone C partial export omits the previous-packet continuity context.

## Development

Run the Rust and Python tests:

```bash
cargo test
uv run pytest -q
```

The C reference tools require `cc` and internet access on first run to download the Open Movement reference sources and example data. Downloaded assets are cached under `.cache/cwa-reference/`.
