# cwa_reader_rs

[![PyPI](https://img.shields.io/pypi/v/cwa-reader-rs)](https://pypi.org/project/cwa-reader-rs/)
[![Python Versions](https://img.shields.io/pypi/pyversions/cwa-reader-rs)](https://pypi.org/project/cwa-reader-rs/)
[![CI](https://github.com/mobilise-d/cwa_reader_rs/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/mobilise-d/cwa_reader_rs/actions/workflows/CI.yml)
![PyPI - Downloads](https://img.shields.io/pypi/dm/cwa-reader-rs)

`cwa_reader_rs` is a Rust-based reader for [Open Movement](https://github.com/openmovementproject/openmovement) CWA files from AX6 sensors, focused on modern IMU configurations.

It was created to provide a fast, small, and easier-to-distribute loader that integrates well with [mobgap](https://github.com/mobilise-d/mobgap). The port is mostly agent-generated and tested for correctness using multiple example files, including parity checks against the original Open Movement C implementation. Full-file reads are expected to match the C output, aside from the C CSV export's millisecond timestamp formatting tolerance; partial reads deliberately preserve full-read timestamp consistency. See [Comparison To The C Reference](#comparison-to-the-c-reference) for details.

Read [Timezone handling](#timezone-handling) before working with this library directly.

## Installation

Install from PyPI with `uv` or `pip`:

```bash
uv add cwa-reader-rs
# Or:
pip install cwa-reader-rs
```

We support Python 3.10 or newer.

### Local Development

Clone the repository and install the package locally:

```bash
git clone https://github.com/mobilise-d/cwa_reader_rs.git
cd cwa_reader_rs
uv sync --dev
```

Because this package contains a Rust extension module built with [maturin](https://www.maturin.rs/), local source installs may require a working Rust toolchain. Install Rust with [rustup](https://rustup.rs/) if your platform does not have a pre-built wheel available.

### Browser builds

The shared Rust parser lives in the [`cwa-core`](crates/cwa-core) crate. The Python
extension and standalone Wasm adapter depend on it. Two browser builds serve
different callers:

- [Standalone JavaScript/Wasm](docs/standalone-wasm.md) accepts bytes for header
  preview, full metadata, sampling reports, sample reads, cuts, resampling and
  CSV export. Its File adapter reads bounded packet batches from a selected
  local file in a worker, including incremental CSV output. No upload or
  persistent browser storage is needed.
- [Xeus-Python](docs/xeus-wasm.md) uses a locally built Emscripten Python extension
  and the existing Python API. The browser must first make the file available in
  the kernel worker's virtual filesystem, then pass its path to the reader.

These artifacts have separate build commands and runtime requirements. A desktop
Python wheel does not work in either browser environment. Header-only parsing
reads only the first 1,024 bytes. It differs from `read_metadata()`, which searches
packet metadata from both ends for actual sample start and end times.
`sampling_consistency_report()` scans all packet metadata. The byte-array
interface still requires its supplied input buffer; the File adapter loads only
requested ranges. Full sample arrays and pandas DataFrames allocate the selected
output even when input processing uses bounded batches.

Rust consumers use `CwaReader<R: Read + Seek>` from `cwa-core`. A `Cursor` over
bytes supports every operation without a temporary file; CSV output accepts any
`Write` sink, including a byte vector. The core has no Python or JavaScript
dependencies and does not need to be published separately to build either adapter.

## Usage

Load a full recording, resample to its configured sampling rate, and convert the
timestamps to local time:

```python
from datetime import timezone
from zoneinfo import ZoneInfo

import pandas as pd
from cwa_reader_rs import read_cwa_file, read_metadata

path = "recording.cwa"
tz = "Europe/Berlin"  # Timezone of the computer that synchronized the sensor.
metadata = read_metadata(path)
last_change_raw = metadata["last_change_time_raw"]
expected_sampling_rate = metadata["sample_rate_hz"]

# ASSUMPTION: last metadata change = last clock synchronization.
# pandas raises if the configuration time is ambiguous or nonexistent.
configured_local = pd.Timestamp(last_change_raw).tz_localize(ZoneInfo(tz))
clock_timezone = timezone(configured_local.utcoffset())  # Fixed offset, no DST rules.

data_utc = read_cwa_file(
    path,
    fixed_utc_offset_timezone=clock_timezone,
    resample_hz=expected_sampling_rate,
    resample_method="cubic",
    include_magnetometer=True,
    include_temperature=True,
    include_light=True,
    include_battery=True,
)

# Optional local-time analysis. tz_convert applies the timezone's DST rules.
data_local = data_utc.tz_convert(tz)
```

See [metadata reads](#metadata-read), [timezone handling](#timezone-handling),
and [partial reads](#partial-block-read) for more details.

## Timezone handling

AX3/AX6 sensors do not store timezone-aware sample timestamps. During normal
configuration, the sensor synchronizes its clock with the local time of the
computer used to configure it. The header's `lastChangeTime` field records the
last metadata/configuration write. `read_metadata` exposes this as
`last_change_time_raw`. In the usual configuration workflow, this is also when
the clock was last synchronized, but it is not a dedicated clock-sync log.

> **IF YOU ARE NOT USING THE DEFAULT AX6 CONFIGURATION SOFTWARE, DOUBLE-CHECK
> THAT `last_change_time_raw` ALSO REPRESENTS THE LAST CLOCK SYNCHRONIZATION.**

The sensor clock counts seconds forward from synchronization. It does not adjust
for daylight saving time or later timezone changes on the configuring computer.
Sample timestamps, configured start/stop times, and scheduled triggers such as
"start at midnight" therefore continue to use the UTC offset that applied when
the clock was synchronized. See the
[AX3/AX6 time-zone FAQ](https://github.com/openmovementproject/openmovement/blob/master/Docs/ax3/ax3-faq.md#time-zone-and-dst).

This affects the local start and end of a recording:

- A recording scheduled from midnight to midnight across a DST change follows
  the sensor clock. A 24-hour recording starting at midnight before Berlin's
  spring change ends at 01:00 local time the next day. Across the autumn change,
  it ends at 23:00 local time on the same calendar date. A recording spanning
  several days can likewise finish one hour later or earlier than local midnight.
- If DST changes between configuration and a scheduled future start, a trigger
  for sensor-clock midnight can occur at 01:00 or 23:00 local time instead.

Convert both sample timestamps and the raw start/stop times to UTC or local time
before analysis. Conversion gives the actual timing of the recorded data; it
cannot recover an hour the sensor did not record or change when a trigger fired.
Use the offset at clock synchronization, even when recording starts days later.

### Load in UTC and convert header times

For a scheduled recording, use this workflow:

1. Read `last_change_time_raw`, `logging_start_time_raw`, and
   `logging_end_time_raw` from the header. These are the unaltered sensor-clock
   values, represented as naive ISO 8601 strings.
2. Use Python's [`zoneinfo`](https://docs.python.org/3/library/zoneinfo.html) and pandas to determine the configuration timezone's
   offset at `last_change_time_raw`. This assumes configuration also synchronized
   the clock. Check that assumption in your configuration software.
3. Build a fixed `datetime.timezone` from that offset and pass it as
   `fixed_utc_offset_timezone`. The data index is UTC.
4. Interpret the raw logging start/end using the same fixed offset, then convert
   them to UTC. Convert to your analysis timezone with pandas when needed.

```python
from datetime import timedelta, timezone
from zoneinfo import ZoneInfo

import pandas as pd
from cwa_reader_rs import read_cwa_file, read_metadata

path = "recording.cwa"
tz = "Europe/Berlin"  # Timezone of the computer that synchronized the sensor.
metadata = read_metadata(path)
last_change_raw = metadata["last_change_time_raw"]
logging_start_raw = metadata["logging_start_time_raw"]
logging_end_raw = metadata["logging_end_time_raw"]
if any(
    value is None for value in (last_change_raw, logging_start_raw, logging_end_raw)
):
    raise ValueError(
        "This example requires configuration and scheduled start/end times"
    )

# ASSUMPTION: last metadata change = last clock synchronization.
# pandas raises if the configuration time is ambiguous or nonexistent.
configured_local = pd.Timestamp(last_change_raw).tz_localize(ZoneInfo(tz))
clock_timezone = timezone(configured_local.utcoffset())  # Fixed offset, no DST rules.

data = read_cwa_file(path, fixed_utc_offset_timezone=clock_timezone)
logging_start_utc = (
    pd.Timestamp(logging_start_raw).tz_localize(clock_timezone).tz_convert("UTC")
)
logging_end_utc = (
    pd.Timestamp(logging_end_raw).tz_localize(clock_timezone).tz_convert("UTC")
)

# Optional local-time analysis. tz_convert applies the timezone's DST rules.
data_local = data.tz_convert(tz)
logging_start_local = logging_start_utc.tz_convert(tz)
logging_end_local = logging_end_utc.tz_convert(tz)
```

Do not localize the raw logging start/end directly with `Europe/Berlin` or another
named timezone. Its offset at recording start or stop may differ from the sensor's
fixed offset. First interpret them using `clock_timezone` as shown above.
For a DataFrame index, use `data.tz_convert(tz)`; `.dt.tz_convert(tz)` is for a
Series of datetime values.

If a header time is unset, `read_metadata` returns `None`. Supply a known clock-sync
offset if the configuration time is unavailable. Use the sample timestamps for
actual recording boundaries when scheduled header start/end times are absent.

`fixed_utc_offset_timezone` accepts a Python `datetime.timezone` object, such as
`timezone(timedelta(hours=2))`. This means the device clock is two hours ahead of
UTC, so sensor time `12:00` becomes `10:00` UTC. Use `timezone.utc` for zero offset;
negative and fractional offsets such as `timezone(timedelta(hours=-4))` and
`timezone(timedelta(hours=5, minutes=45))` are supported. Pass a fixed timezone,
as shown above, rather than a named `ZoneInfo` timezone with DST rules.
The reader applies the same offset throughout full reads, partial reads, and
resampling. It does not infer a timezone or offset from the file. Without
`fixed_utc_offset_timezone`, the data index remains naive.

`read_metadata` and `sampling_consistency_report` always return raw device-clock
timestamps under `_raw` keys and accept no UTC offset or timezone. Convert those
values in Python using the same fixed clock offset as the samples.
`write_cwa_csv` accepts `fixed_utc_offset_timezone` too. CSV `time` values encode
the device clock by default and UTC Unix seconds with an offset. Elapsed-second
cuts, durations, and sampling rates are unchanged.

### Footgun: 24-hour bouts versus local calendar days

Decide whether a "day" means 24 elapsed hours or a date on the local calendar.
`seconds(0, 86400)` selects a 24-hour bout. A local calendar day runs between
consecutive local midnights and may contain 23 or 25 hours at a DST change.

For example, in `Europe/Berlin`:

| Local calendar day | Elapsed hours | Elapsed seconds |
| --- | ---: | ---: |
| 2026-03-29, spring DST change | 23 | 82,800 |
| 2026-10-25, autumn DST change | 25 | 90,000 |

Define day boundaries in the local timezone, then subtract timezone-aware pandas
timestamps to calculate elapsed seconds. pandas accounts for DST in that
subtraction. Advance calendar days with `freq="D"` or `pd.DateOffset(days=1)`;
adding `pd.Timedelta(hours=24)` instead advances exactly 24 elapsed hours.

The loader's `seconds(...)` offsets are **relative to the first valid sample**,
which can arrive after the configured `logging_start_local`. The header contains
the scheduled start, not the measured first-sample time, and that scheduled value
can be unset. Header information alone therefore does not determine the exact
origin of a seconds cut. `read_metadata` also provides `start_from_data_raw` and
`end_from_data_raw` by searching packet metadata from both ends without decoding sample values.
Use those measured timestamps to choose cuts without first loading all samples.

Depending on your application, you may want to start 24-hour bouts at the
configured logging start or at the first valid sample. Local calendar days use
local midnight as their boundary.

The example below continues from the header-conversion example and uses the
configured logging start and end as hard boundaries. It excludes samples before
the configured start and at or after the configured end. It stops at the final
recorded date, so an early stop does not cause cuts for later days with no data.

To express each cut relative to the first sample, calculate `first_sample_delay`
and subtract it from each day's start/end offsets relative to the logging start.

```python
from cwa_reader_rs import seconds

first_sample_local = (
    pd.Timestamp(metadata["start_from_data_raw"])
    .tz_localize(clock_timezone)
    .tz_convert(tz)
)
last_sample_local = (
    pd.Timestamp(metadata["end_from_data_raw"])
    .tz_localize(clock_timezone)
    .tz_convert(tz)
)
first_sample_delay = (first_sample_local - logging_start_local).total_seconds()

# Local midnights, including the boundary after the final recorded date.
day_boundaries = pd.date_range(
    start=max(logging_start_local, first_sample_local).normalize(),
    end=min(logging_end_local, last_sample_local).normalize() + pd.DateOffset(days=1),
    freq="D",
)

for day_start, day_end in zip(day_boundaries[:-1], day_boundaries[1:]):
    start_local = max(day_start, logging_start_local)
    end_local = min(day_end, logging_end_local)
    start_seconds = max(
        0.0, (start_local - logging_start_local).total_seconds() - first_sample_delay
    )
    end_seconds = (end_local - logging_start_local).total_seconds() - first_sample_delay
    if end_seconds <= start_seconds:
        continue

    day_data = read_cwa_file(
        path,
        fixed_utc_offset_timezone=clock_timezone,
        cut=seconds(start_seconds, end_seconds),
    )
    day_data_local = day_data.tz_convert(tz)
    # Analyse day_data_local for the calendar date day_start.date().
```

For complete local days, the cut spans 82,800 or 90,000 seconds on the Berlin DST
transition dates above. Adjacent cuts meet at the same local midnight; the loader
uses an exclusive end, so a sample at midnight belongs to the following day.

### Footgun: configuration during a repeated local hour

When clocks move backward, some local timestamps occur twice. In Berlin's autumn
change, the interval from 02:00 up to 03:00 repeats. A raw configuration time of
`02:30` could mean the first occurrence at UTC+2 or the second at UTC+1. Other
timezones may repeat a different hour.

`last_change_time_raw` does not distinguish those occurrences, so it cannot
automatically determine the correct UTC offset. The configuration example raises
for that ambiguity. Supply a known offset manually, for example
`clock_timezone = timezone(timedelta(hours=2))` for the first occurrence in Berlin
or `timezone(timedelta(hours=1))` for the second, and use the same fixed offset
when converting the raw header times. Do not guess from recording start.
Avoid configuring sensors during the repeated hour if you do not have
another record of the synchronization time.

## Advanced usage

### Metadata read

```python
from cwa_reader_rs import read_metadata

metadata = read_metadata("recording.cwa")

device_id = metadata["device_id"]
sample_rate_hz = metadata["sample_rate_hz"]
logging_start_time_raw = metadata["logging_start_time_raw"]
last_change_time_raw = metadata["last_change_time_raw"]
first_sample_raw = metadata["start_from_data_raw"]
last_sample_raw = metadata["end_from_data_raw"]
```

The metadata read parses the 1024-byte CWA header, searches forward for the first data packet, and searches backward for the last data packet and its preceding data packet. It skips non-data and empty packets and does not decode sensor values or scan the recording interior. Errors in unvisited interior packets are not detected by this lookup; `sampling_consistency_report` still scans all packet metadata.

Metadata includes device and session identifiers (`hardware_type`, `device_id`, `session_id`), recording timing fields (`logging_start_time_raw`, `logging_end_time_raw`, `last_change_time_raw`), nominal sensor configuration (`sample_rate_hz`, `accel_range`, `gyro_range`, `magnetometer_enabled`, `firmware_revision`), and the free-form `annotation`. It also returns the first and last actual sample timestamps as `start_from_data_raw` and `end_from_data_raw`, including packet sample offsets and continuity correction. These can differ from the configured logging start/end and are `None` when no samples exist.

The `_raw` time fields are timezone-naive ISO 8601 strings when present, or `None`
when unset. They decode the unaltered time values recorded by the sensor, without
applying any UTC offset or timezone conversion. These values need conversion to
UTC or local time for most analysis steps. `read_metadata` accepts no offset.
`last_change_time_raw` records the last metadata write and may differ from the last
clock synchronization. Check your configuration software before using it to
derive the UTC offset as shown above.

### Sampling Consistency Report

```python
from cwa_reader_rs import sampling_consistency_report

report = sampling_consistency_report("recording.cwa")

start_from_header_raw = report["start_from_header_raw"]
end_from_header_raw = report["end_from_header_raw"]
duration_s_from_header = report["duration_s_from_header"]
start_from_data_raw = report["start_from_data_raw"]
end_from_data_raw = report["end_from_data_raw"]
duration_s_from_data = report["duration_s_from_data"]
samplingrate_hz_from_header = report["samplingrate_hz_from_header"]
samplingrate_hz_from_data = report["samplingrate_hz_from_data"]
```

This helper compares the timing implied by the CWA metadata header with the timing implied by the data packets. It scans packet metadata only; it does not decode or return sample values.

Header start/end and data start/end use `_raw` keys and are always timezone-naive
ISO 8601 strings or `None`. They preserve the sensor clock and need conversion
to UTC or local time for most analysis. This report accepts no offset or timezone.
Header duration is `end_from_header_raw - start_from_header_raw`. Data duration is the inclusive first-sample-to-last-sample span, using the same packet timestamp, `timestampOffset`, and continuity correction as `read_cwa_file`. The header sampling rate is decoded from the metadata rate code. The data sampling rate is `(sample_count - 1) / duration_s_from_data`.

The values provided in the header are configured values, not measured values. In timed recordings, data-derived start and end timestamps may differ from the configured header start and end by a few seconds, for example because logging starts after the device wakes and stops when the device reaches its configured stop condition.

Open Movement documents two relevant time bases. The device has an internal RTC used for packet timestamps and configured start/end times. The [AX6 datasheet](https://github.com/openmovementproject/openmovement/blob/master/Docs/ax3/AX6%20Datasheet.pdf) lists the RTC precision as `+/-50 ppm` typical, which is about `+/-4.3 s/day`; the [AX3/AX6 FAQ](https://github.com/openmovementproject/openmovement/blob/master/Docs/ax3/ax3-faq.md#synchronizing-data-between-devices-or-with-other-devices) describes possible clock drift as being on the order of seconds per day. This report cannot detect RTC drift relative to external UTC, because both header times and packet timestamps are expressed in the device's own clock. External event markers or another synchronized reference are required for that.

In addition to the RTC, the underlying movement sensor has its own sample timing. Open Movement notes that the sensor output rate can vary slightly compared to the onboard RTC. That means a time interval measured by packet timestamps may contain slightly more or fewer samples than expected from the nominal header sampling rate. Over long recordings this can produce a noticeable difference between the expected and actual number of samples, even if the RTC itself were perfectly stable. This is reflected in `samplingrate_hz_from_data`. In local validation data, we saw effective rates around `100.6 Hz` for recordings configured as `100 Hz`, and the official Open Movement example fixture has an effective rate around `98.52 Hz`.

Without additional external timing information, this report cannot determine whether an inconsistency comes from RTC drift, sample-clock drift, delayed start/stop behavior, or file conversion artifacts.
For most AX6 workflows, the RTC-derived recording duration should be treated as the authoritative time span, and resampling should adjust the sample grid rather than forcing duration from sample count.

When a fixed-rate downstream pipeline is required, use `resample_hz=report["samplingrate_hz_from_header"]` or `resample_hz=read_metadata("recording.cwa")["sample_rate_hz"]` and let the reader resample from the data-derived timestamps.

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
from cwa_reader_rs import read_cwa_file, read_metadata

expected_sampling_rate = read_metadata("recording.cwa")["sample_rate_hz"]

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

The resampler processes packet batches and currently supports
`resample_method="cubic"` only. Every batch uses the same output sampling grid;
batch boundaries do not reset interpolation.

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

This is a local cubic interpolation, not a global cubic spline. If a target timestamp is near the actual start or end of the selected input domain, or if the four-point polynomial is numerically degenerate because timestamps are duplicated or too close together, the implementation falls back to linear interpolation between the bracketing samples:

```text
y(t) = y_left + (y_right - y_left) * (t - x_left) / (x_right - x_left)
```

The resampler never extrapolates beyond the selected input samples. For `seconds(...)` cuts, neighboring blocks may be read as interpolation context, but emitted samples remain inside the requested time window.

### Packet batches

Data reads and CSV export use one packet-batch engine. `batch_packets` controls
how many 512-byte data packets a batch owns; it does not specify a row count.
`overlap_packets` adds that many physical packets on either side as interpolation
context, clipped to the recording boundaries. Defaults are 256 and 1:

```python
data = read_cwa_file(
    "recording.cwa",
    cut=seconds(3600, 3660),
    resample_hz=100,
    batch_packets=256,
    overlap_packets=1,
)
```

`write_cwa_csv` accepts the same tuning keywords. Processing is sequential; this
version does not start threads or processes. Each batch emits only its owned
output, so overlap does not duplicate samples. If the preload does not contain
enough valid context, Python raises a `RuntimeError` whose `code` attribute is
`"InsufficientContext"`. It does not use linear interpolation at an artificial
buffer boundary. Retry with a larger
`overlap_packets` value. No additional payload pages are fetched automatically.

Header and metadata operations request their required bytes separately. Seconds
cuts assume ordered packet times: the locator estimates a packet position from
sampling information, probes its timing and narrows the search to the exact cut
boundaries. It does not scan or validate unvisited portions of the recording.
Sampling consistency reports still inspect all packet metadata, using bulk reads.

The Python data reader returns one complete DataFrame. CSV output and the
[JavaScript File batch interface](docs/standalone-wasm.md) can release output as
they proceed. Individual sample batches can have different optional channels;
full reads combine them with missing values for absent segments. See the
[benchmark tools and measurements](tools/benchmarks/README.md) for batch-size
tradeoffs and reproduction commands.

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
