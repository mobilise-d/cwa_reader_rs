from __future__ import annotations

import argparse
import os
import struct
import time
from pathlib import Path

from cwa_reader_rs import blocks, read_cwa_file

from common import ensure_example_cwa


def metadata_scan_seconds(file_path: Path, loops: int) -> float:
    start = time.perf_counter()
    for _ in range(loops):
        with file_path.open("rb") as fh:
            fh.seek(1024)
            while True:
                block = fh.read(512)
                if len(block) < 512:
                    break
                if block[0:2] != b"AX":
                    continue
                _sample_rate = block[24]
                _timestamp_offset = struct.unpack_from("<h", block, 26)[0]
                _sample_count = struct.unpack_from("<H", block, 28)[0]
                _timestamp = struct.unpack_from("<I", block, 14)[0]
    end = time.perf_counter()
    return (end - start) / loops


def full_parse_seconds(file_path: Path, loops: int) -> float:
    total_blocks = (os.path.getsize(file_path) - 1024) // 512
    opts = dict(
        include_magnetometer=False,
        include_temperature=False,
        include_light=False,
        include_battery=False,
    )

    start = time.perf_counter()
    for _ in range(loops):
        _ = read_cwa_file(str(file_path), cut=blocks(0, total_blocks), **opts)
    end = time.perf_counter()
    return (end - start) / loops


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark metadata-only timestamp scan vs full parse"
    )
    parser.add_argument("--file", type=Path, help="Path to .cwa file")
    parser.add_argument("--loops", type=int, default=200, help="Iterations")
    parser.add_argument(
        "--projected-gb",
        type=float,
        default=15.0,
        help="Projected file size for extrapolation",
    )
    parser.add_argument(
        "--cache-dir",
        default=".cache/cwa-reference",
        help="Cache dir used for default sample",
    )
    args = parser.parse_args()

    file_path = (
        args.file if args.file is not None else ensure_example_cwa(args.cache_dir)
    )
    if not file_path.exists():
        raise FileNotFoundError(file_path)

    size_bytes = os.path.getsize(file_path)
    size_gb = size_bytes / (1024**3)

    meta_s = metadata_scan_seconds(file_path, args.loops)
    full_s = full_parse_seconds(file_path, args.loops)

    meta_throughput = size_gb / meta_s if meta_s > 0 else 0.0
    full_throughput = size_gb / full_s if full_s > 0 else 0.0

    projected_meta_s = (
        args.projected_gb / meta_throughput if meta_throughput > 0 else float("inf")
    )
    projected_full_s = (
        args.projected_gb / full_throughput if full_throughput > 0 else float("inf")
    )

    print(f"file={file_path}")
    print(f"size_gb={size_gb:.6f} loops={args.loops}")
    print(f"metadata_scan_avg_s={meta_s:.6f} throughput_gb_s={meta_throughput:.3f}")
    print(f"full_parse_avg_s={full_s:.6f} throughput_gb_s={full_throughput:.3f}")
    print(f"speedup_full_over_meta={full_s / meta_s:.3f}")
    print(f"projected_{args.projected_gb:.1f}GB_metadata_scan_s={projected_meta_s:.2f}")
    print(f"projected_{args.projected_gb:.1f}GB_full_parse_s={projected_full_s:.2f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
