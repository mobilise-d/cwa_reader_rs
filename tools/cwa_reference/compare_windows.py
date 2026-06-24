from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

import numpy as np
import pandas as pd

from cwa_reader_rs import blocks, read_cwa_file

from common import ensure_cwa_convert, ensure_example_cwa


def parse_windows(text: str) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        start, count = item.split(":", maxsplit=1)
        out.append((int(start), int(count)))
    return out


def to_df_rust(data: dict) -> pd.DataFrame:
    df = pd.DataFrame(data)[["timestamp", "acc_x", "acc_y", "acc_z"]]
    df["ts"] = pd.to_datetime(df["timestamp"], unit="us", utc=True)
    return df[["ts", "acc_x", "acc_y", "acc_z"]]


def to_df_c(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, header=None, names=["ts", "acc_x", "acc_y", "acc_z"])
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    return df[["ts", "acc_x", "acc_y", "acc_z"]]


def compare_df(a: pd.DataFrame, b: pd.DataFrame) -> tuple[float, float, float, float]:
    n = min(len(a), len(b))
    if n == 0:
        return 0.0, 0.0, 0.0, 0.0

    a = a.iloc[:n].reset_index(drop=True)
    b = b.iloc[:n].reset_index(drop=True)
    delta_ms = (a["ts"] - b["ts"]).dt.total_seconds() * 1000

    xyz_max = 0.0
    for col in ("acc_x", "acc_y", "acc_z"):
        xyz_max = max(xyz_max, float((a[col] - b[col]).abs().max()))

    return float(delta_ms.min()), float(delta_ms.max()), float(delta_ms.mean()), xyz_max


def run_c_window(
    cwa_convert: Path, cwa_file: Path, out_csv: Path, start_block: int, num_blocks: int
) -> None:
    # cwa-convert's -blockstart is sector index from file start (includes two 512-byte header sectors).
    sector_start = start_block + 2
    cmd = [
        str(cwa_convert),
        str(cwa_file),
        "-f:csv",
        "-v:float",
        "-t:timestamp",
        "-out",
        str(out_csv),
        "-blockstart",
        str(sector_start),
        "-blockcount",
        str(num_blocks),
    ]
    subprocess.run(
        cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare Rust partial reads against C reference output."
    )
    parser.add_argument("--file", type=Path, help="Path to .cwa file")
    parser.add_argument(
        "--windows",
        default="1:3,25:7,123:11,300:10,500:20",
        help="Comma-separated windows as start:count",
    )
    parser.add_argument(
        "--cache-dir",
        default=".cache/cwa-reference",
        help="Cache dir for tools/data/output",
    )
    args = parser.parse_args()

    cache = Path(args.cache_dir)
    out_dir = cache / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    cwa_convert = ensure_cwa_convert(args.cache_dir)
    cwa_file = (
        args.file if args.file is not None else ensure_example_cwa(args.cache_dir)
    )
    if not cwa_file.exists():
        raise FileNotFoundError(f"CWA file not found: {cwa_file}")

    windows = parse_windows(args.windows)

    full_c_csv = out_dir / "c_full.csv"
    subprocess.run(
        [
            str(cwa_convert),
            str(cwa_file),
            "-f:csv",
            "-v:float",
            "-t:timestamp",
            "-out",
            str(full_c_csv),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    c_full = to_df_c(full_c_csv)

    opts = dict(
        include_magnetometer=False,
        include_temperature=False,
        include_light=False,
        include_battery=False,
    )

    total_blocks = (os.path.getsize(cwa_file) - 1024) // 512
    block_ranges: list[tuple[int, int]] = []
    cursor = 0
    for b in range(total_blocks):
        try:
            n = len(
                read_cwa_file(str(cwa_file), cut=blocks(b, b + 1), **opts)[
                    "timestamp"
                ]
            )
        except Exception:
            n = 0
        block_ranges.append((cursor, cursor + n))
        cursor += n

    print(f"file={cwa_file}")
    print(f"total_blocks={total_blocks} total_samples={cursor}")
    print(
        "window rust-vs-c-partial(ts_min,ts_max,ts_mean,xyz_max) rust-vs-c-full-slice(ts_min,ts_max,ts_mean,xyz_max)"
    )

    for start, count in windows:
        if start < 0 or count <= 0 or start + count > total_blocks:
            print(f"{start}:{count} skipped")
            continue

        rust_df = to_df_rust(
            read_cwa_file(str(cwa_file), cut=blocks(start, start + count), **opts)
        )

        c_part_csv = out_dir / f"c_partial_{start}_{count}.csv"
        run_c_window(cwa_convert, cwa_file, c_part_csv, start, count)
        c_part_df = to_df_c(c_part_csv)

        s0 = block_ranges[start][0]
        s1 = block_ranges[start + count - 1][1]
        c_slice_df = c_full.iloc[s0:s1].reset_index(drop=True)

        part_stats = compare_df(rust_df, c_part_df)
        full_slice_stats = compare_df(rust_df, c_slice_df)

        print(
            f"{start}:{count} "
            f"({part_stats[0]:.1f},{part_stats[1]:.1f},{part_stats[2]:.3f},{part_stats[3]:.6f}) "
            f"({full_slice_stats[0]:.1f},{full_slice_stats[1]:.1f},{full_slice_stats[2]:.3f},{full_slice_stats[3]:.6f})"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
