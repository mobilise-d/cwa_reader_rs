# cwa_reader_rs Python package

[![PyPI](https://img.shields.io/pypi/v/cwa-reader-rs)](https://pypi.org/project/cwa-reader-rs/)
[![CI](https://github.com/mobilise-d/cwa_reader_rs/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/mobilise-d/cwa_reader_rs/actions/workflows/CI.yml)

A Python extension for reading Open Movement CWA recordings into pandas, backed
by the shared [Rust core](../crates/cwa-core/README.md). Python 3.10 or newer is
supported.

## Installation

```sh
pip install cwa-reader-rs
# Or add it to a uv project:
uv add cwa-reader-rs
```

For a source checkout, from the repository root:

```sh
uv sync --project python --dev
# Or install the native distribution directly:
pip install ./python
```

Source builds require a Rust toolchain. Native wheels and the separately built
[Xeus-Python package](../recipes/xeus/README.md) use the same Python API. The Xeus
guide describes browser file transfer into the kernel filesystem. JavaScript
callers use the separate [Wasm distribution](../wasm/README.md).

## Reading samples

```python
from cwa_reader_rs import read_cwa_file, read_metadata

metadata = read_metadata("recording.cwa")
data = read_cwa_file("recording.cwa")
regular = read_cwa_file("recording.cwa", resample_hz=metadata["sample_rate_hz"])
```

The result is a pandas DataFrame with a datetime index and `float32` measurement
columns. Read the shared [timestamp guide](../docs/timestamps.md) before choosing
UTC offsets or interpreting local dates, and the [reader behavior guide](../docs/reader-behavior.md)
for channels, cuts, interpolation and memory use.

### Options

`read_cwa_file(path, ...)` accepts these options (all can be passed by keyword):

| Option | Default | Effect |
| --- | --- | --- |
| `cut` | `None` | Select a range made by `seconds(...)` or `blocks(...)`. |
| `include_magnetometer` | `True` | Include recorded `mag_*` columns. |
| `include_temperature` | `True` | Include `temperature`. |
| `include_light` | `True` | Include `light`. |
| `include_battery` | `True` | Include `battery`. |
| `resample_hz` | `None` | Interpolate onto a fixed-rate grid. |
| `resample_method` | `"cubic"` | Currently only cubic is supported. |
| `fixed_utc_offset_timezone` | `None` | Interpret the device clock using a fixed `datetime.timezone` offset. |
| `batch_packets` | `256` | Number of owned 512-byte packets per preload. |
| `overlap_packets` | `1` | Physical context packets on each side. |

`fixed_utc_offset_timezone`, `batch_packets` and `overlap_packets` are keyword-only.

Recorded accelerometer and gyroscope columns are `acc_x/y/z` and `gyro_x/y/z`.
Optional sensor columns are absent when that sensor is not recorded; missing
values inside a recorded channel are NaN. The reader returns all selected output
in one DataFrame, so batching does not bound the final DataFrame's memory.

### Cuts and resampling

```python
from cwa_reader_rs import blocks, read_cwa_file, seconds

window = read_cwa_file("recording.cwa", cut=seconds(3600, 3660), resample_hz=100)
packets = read_cwa_file("recording.cwa", cut=blocks(25, 32))
```

`seconds(start=None, end=None)` uses elapsed seconds relative to the first valid
sample. `blocks(start=None, end=None)` uses data-packet indexes after the header.
Both helpers exclude the end boundary. See [reader behavior](../docs/reader-behavior.md) for
boundary and interpolation details.

### Fixed UTC offsets

```python
from datetime import timedelta, timezone
from cwa_reader_rs import read_cwa_file

# Use the known fixed offset of the device clock at synchronization.
data_utc = read_cwa_file(
    "recording.cwa", fixed_utc_offset_timezone=timezone(timedelta(hours=2))
)
data_local = data_utc.tz_convert("Europe/Berlin")
```

The argument must be a `datetime.timezone`, rather than a `ZoneInfo` timezone.
Without it, the index remains naive. Header and report `_raw` fields always retain
the device clock. See [timestamps](../docs/timestamps.md) for offset selection,
DST and clock drift. The [Python timestamp recipes](timestamp-recipes.md) show
how to derive the synchronization offset from configuration time and select local
calendar days using `seconds(...)` cuts.

## Metadata and timing reports

```python
from cwa_reader_rs import read_metadata, sampling_consistency_report

metadata = read_metadata("recording.cwa")
first_sample = metadata["start_from_data_raw"]
last_sample = metadata["end_from_data_raw"]
report = sampling_consistency_report("recording.cwa")
nominal_rate = report["samplingrate_hz_from_header"]
observed_rate = report["samplingrate_hz_from_data"]
```

`read_metadata` returns identifiers, sensor configuration, annotations, scheduled
header times and actual sample bounds. `_raw` times are naive ISO 8601 strings or
`None`. `sampling_consistency_report` adds header/data durations and sampling
rates. Neither function accepts an offset. The [reader behavior guide](../docs/reader-behavior.md)
explains their different source-access patterns.

## CSV export

```python
from cwa_reader_rs import seconds, write_cwa_csv

write_cwa_csv(
    "recording.cwa", "recording.csv", cut=seconds(3600, 3660),
    include_temperature=True, resample_hz=100,
)
```

`write_cwa_csv(input_path, output_path, ...)` accepts the same options as the data
reader. Its temperature, light and battery defaults are `False`; magnetometer
still defaults to `True`. CSV uses bounded output batches with one channel header.

Missing preload context raises `RuntimeError` with `code="InsufficientContext"`,
`side`, `owned_packets`, `loaded_packets` and `reason` attributes. Increase
`overlap_packets` when more original samples are required. Ordinary invalid
options raise `ValueError`; input failures raise `RuntimeError`.

## Development

From the repository root:

```sh
cargo test --workspace
uv run --project python pytest -q python/tests
uv build --project python --out-dir dist
```

Python tests live here; shared reference recordings stay in
[`tests/reference_data`](../tests/reference_data/openmovement/README.md) at the
repository root and are excluded from distributions. See the shared
[validation guide](../docs/validation.md), [C reference tools](../tools/cwa_reference/README.md)
and [benchmarks](../tools/benchmarks/README.md) for comparison and reproduction.
