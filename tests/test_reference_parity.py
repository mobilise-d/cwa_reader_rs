from __future__ import annotations

import csv
import struct
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import pytest

from cwa_reader_rs import read_cwa_file


FIXTURE_DIR = Path(__file__).resolve().parent / "reference_data" / "openmovement"
CWA_FILE = FIXTURE_DIR / "example-610-steps.cwa"
C_EXPORT_FILE = FIXTURE_DIR / "example-610-steps.cwa.cwa-convert.full.csv"


def _parse_c_timestamp_ms(value: str) -> int:
    dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


@lru_cache(maxsize=1)
def _c_rows() -> list[tuple[int, float, float, float]]:
    rows: list[tuple[int, float, float, float]] = []
    with C_EXPORT_FILE.open("r", newline="") as fh:
        reader = csv.reader(fh)
        for row in reader:
            rows.append(
                (
                    _parse_c_timestamp_ms(row[0]),
                    float(row[1]),
                    float(row[2]),
                    float(row[3]),
                )
            )
    return rows


@lru_cache(maxsize=1)
def _sample_count_by_block() -> list[int]:
    counts: list[int] = []
    with CWA_FILE.open("rb") as fh:
        fh.seek(1024)
        while True:
            block = fh.read(512)
            if len(block) < 512:
                break
            if block[0:2] != b"AX":
                counts.append(0)
                continue
            sample_rate = block[24]
            if sample_rate == 0:
                counts.append(0)
                continue
            sample_count = struct.unpack_from("<H", block, 28)[0]
            counts.append(sample_count)
    return counts


def _first_valid_block_aux() -> tuple[int, int, int]:
    with CWA_FILE.open("rb") as fh:
        fh.seek(1024)
        while True:
            block = fh.read(512)
            if len(block) < 512:
                break
            if block[0:2] != b"AX":
                continue
            sample_rate = block[24]
            sample_count = struct.unpack_from("<H", block, 28)[0]
            if sample_rate == 0 or sample_count == 0:
                continue
            raw_temp = struct.unpack_from("<H", block, 20)[0]
            raw_batt = block[23]
            return raw_temp, raw_batt, sample_count
    raise AssertionError("No valid AX data block found")


def _rust_rows(
    start_block: int, num_blocks: int
) -> list[tuple[int, float, float, float]]:
    data = read_cwa_file(
        str(CWA_FILE),
        start_block,
        num_blocks,
        include_magnetometer=False,
        include_temperature=False,
        include_light=False,
        include_battery=False,
    )

    rows: list[tuple[int, float, float, float]] = []
    for i in range(len(data["timestamp"])):
        ms = int(data["timestamp"][i] // 1000)
        rows.append(
            (
                ms,
                float(data["acc_x"][i]),
                float(data["acc_y"][i]),
                float(data["acc_z"][i]),
            )
        )
    return rows


def _expected_slice(
    start_block: int, num_blocks: int
) -> list[tuple[int, float, float, float]]:
    counts = _sample_count_by_block()
    c_rows = _c_rows()
    prefix = [0]
    for n in counts:
        prefix.append(prefix[-1] + n)
    start = prefix[start_block]
    end = prefix[start_block + num_blocks]
    return c_rows[start:end]


def _assert_rows_match(
    rust_rows: list[tuple[int, float, float, float]],
    c_rows: list[tuple[int, float, float, float]],
) -> None:
    assert len(rust_rows) == len(c_rows)
    for (r_ms, r_x, r_y, r_z), (c_ms, c_x, c_y, c_z) in zip(rust_rows, c_rows):
        assert abs(r_ms - c_ms) <= 1
        assert abs(r_x - c_x) <= 1e-6
        assert abs(r_y - c_y) <= 1e-6
        assert abs(r_z - c_z) <= 1e-6


def test_full_read_matches_c_reference_export() -> None:
    counts = _sample_count_by_block()
    total_blocks = len(counts)
    rust_rows = _rust_rows(0, total_blocks)
    c_rows = _c_rows()
    _assert_rows_match(rust_rows, c_rows)


@pytest.mark.parametrize(
    "start_block,num_blocks", [(1, 3), (25, 7), (123, 11), (300, 10), (500, 20)]
)
def test_partial_read_matches_slice_from_full_c_reference(
    start_block: int, num_blocks: int
) -> None:
    rust_rows = _rust_rows(start_block, num_blocks)
    expected = _expected_slice(start_block, num_blocks)
    _assert_rows_match(rust_rows, expected)


def test_temperature_and_battery_match_c_export_formulas() -> None:
    raw_temp, raw_batt, sample_count = _first_valid_block_aux()
    expected_temp_c = (raw_temp * 75.0 / 256.0) - 50.0
    expected_batt_v = 6.0 * (512.0 + raw_batt) / 1024.0

    data = read_cwa_file(
        str(CWA_FILE),
        0,
        1,
        include_magnetometer=False,
        include_temperature=True,
        include_light=False,
        include_battery=True,
    )

    assert len(data["temperature"]) == sample_count
    assert len(data["battery"]) == sample_count
    for i in range(sample_count):
        assert abs(float(data["temperature"][i]) - expected_temp_c) <= 1e-6
        assert abs(float(data["battery"][i]) - expected_batt_v) <= 1e-6
