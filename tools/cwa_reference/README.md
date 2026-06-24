# CWA Reference Tools

This folder contains reproducible scripts for:

- comparing `cwa_reader_rs` output against the original C reference exporter (`cwa-convert`),
- checking behavior for partial block reads,
- benchmarking metadata-only timestamp scanning vs full sample parsing.

These scripts are self-contained and do not require OpenMovement to be pre-installed.

## What the scripts do

- Download C reference sources from GitHub:
  - `Software/AX3/cwa-convert/c/main.c`
  - `Software/AX3/cwa-convert/c/cwa.c`
  - `Software/AX3/cwa-convert/c/cwa.h`
  - Reference implementation: https://github.com/openmovementproject/openmovement/tree/master/Software/AX3/cwa-convert/c
- Build a local `cwa-convert` binary using `cc`.
- Download the public sample file `example-610-steps.cwa` (unless `--file` is supplied).
- Run Rust-vs-C comparisons and benchmark commands.

Downloaded/compiled assets are cached under `.cache/cwa-reference/`.

## Requirements

- Python environment with this project installed (for example `uv sync --dev`)
- `cc` in `PATH`
- Internet access on first run (to download reference sources/data)

## Scripts

### 1) Compare partial windows against C

```bash
uv run python tools/cwa_reference/compare_windows.py
```

Useful options:

```bash
uv run python tools/cwa_reference/compare_windows.py \
  --file /path/to/data.cwa \
  --windows "1:3,25:7,123:11"
```

Output per window includes:

- Rust vs C partial export stats
- Rust partial vs full-C-slice stats

Timestamp numbers are in milliseconds (`min`, `max`, `mean`), and `xyz_max` is maximum absolute accel difference.

### 2) Benchmark metadata scan vs full parse

```bash
uv run python tools/cwa_reference/benchmark_scan.py
```

Useful options:

```bash
uv run python tools/cwa_reference/benchmark_scan.py \
  --file /path/to/data.cwa \
  --loops 50 \
  --projected-gb 15
```

This prints average runtimes and a simple projection for larger files.

## Notes on block indexing

- `cwa_reader_rs` `start_block` counts data blocks after the 1024-byte file header.
- C `cwa-convert -blockstart` counts 512-byte sectors from the start of the file.
- Mapping: `c_blockstart = rust_start_block + 2`.
