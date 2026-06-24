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

### Partial Time Read And Resample

```python
from cwa_reader_rs import read_cwa_file, seconds

file_path = "recording.cwa"
target_hz = 100.0
start_seconds = 2.0
end_seconds = 12.0

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

`seconds(start, end)` is measured in seconds since the first valid sample in the file, and `end` is exclusive. To request exactly `target_samples` output samples when resampling, use `end = start + target_samples / resample_hz`.

Raw CWA output does not provide perfectly consistent sample times. For downstream pipelines that expect a regular grid, resampling is often desirable.

`cwa_reader_rs` provides built-in cubic resampling through `resample_hz` and `resample_method="cubic"`. Resampling during the read is significantly faster than loading the full raw dataset into Python and resampling afterward, especially for large files or narrow time windows. This mode is intended to get closer to the resampling performed in the original Mobilise-D preprocessing pipeline.

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
