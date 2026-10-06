from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from cwa_reader_rs import (
    blocks,
    read_cwa_file,
    sampling_consistency_report,
    seconds,
    write_cwa_csv,
)


FIXTURE_DIR = Path(__file__).resolve().parent / "reference_data" / "openmovement"
CWA_FILE = FIXTURE_DIR / "example-610-steps.cwa"


def _parse_timestamp_us(value: str) -> int:
    return pd.Timestamp(value).value // 1000


def test_sampling_consistency_report_matches_reader_timestamps() -> None:
    report = sampling_consistency_report(str(CWA_FILE))
    data = read_cwa_file(
        str(CWA_FILE),
        include_magnetometer=False,
        include_temperature=False,
        include_light=False,
        include_battery=False,
    )

    assert report["start_from_header"] is None
    assert report["end_from_header"] is None
    assert report["duration_s_from_header"] is None
    assert report["samplingrate_hz_from_header"] == 100.0

    start_us = data.index[0].value // 1000
    end_us = data.index[-1].value // 1000
    duration_s = (end_us - start_us) / 1_000_000.0

    assert _parse_timestamp_us(report["start_from_data"]) == start_us
    assert _parse_timestamp_us(report["end_from_data"]) == end_us
    assert report["duration_s_from_data"] == duration_s
    assert report["samplingrate_hz_from_data"] == pytest.approx(
        (len(data) - 1) / duration_s
    )


def test_sampling_consistency_report_docstring_describes_fields() -> None:
    doc = sampling_consistency_report.__doc__

    assert doc is not None
    assert "start_from_header" in doc
    assert "end_from_data" in doc
    assert "(sample_count - 1) / duration_s_from_data" in doc


def test_write_cwa_csv_matches_read_api_for_partial_window(tmp_path: Path) -> None:
    out_csv = tmp_path / "partial.csv"

    write_cwa_csv(
        str(CWA_FILE),
        str(out_csv),
        cut=blocks(25, 32),
        include_magnetometer=False,
        include_temperature=True,
        include_light=False,
        include_battery=True,
    )

    written = pd.read_csv(out_csv)
    data = read_cwa_file(
        str(CWA_FILE),
        cut=blocks(25, 32),
        include_magnetometer=False,
        include_temperature=True,
        include_light=False,
        include_battery=True,
    )

    assert len(written) == len(data)
    assert list(written.columns) == [
        "time",
        "acc_x",
        "acc_y",
        "acc_z",
        "temperature",
        "battery",
    ]

    sample_n = min(50, len(written))
    expected_time = data.index[:sample_n].as_unit("us").asi8 / 1_000_000.0
    assert ((written["time"].to_numpy()[:sample_n] - expected_time) < 1e-4).all()

    for col in [
        "acc_x",
        "acc_y",
        "acc_z",
        "temperature",
        "battery",
    ]:
        assert (
            (written[col].to_numpy()[:sample_n] - data[col].iloc[:sample_n].to_numpy())
            .astype("float64")
            .__abs__()
            < 1e-6
        ).all()


def test_read_resample_with_time_range_returns_regular_grid() -> None:
    source = read_cwa_file(
        str(CWA_FILE),
        cut=blocks(25, 32),
        include_magnetometer=False,
        include_temperature=False,
        include_light=False,
        include_battery=False,
    )
    origin = read_cwa_file(str(CWA_FILE), cut=blocks(0, 1)).index[0].value / 1_000_000_000.0
    start = source.index[20].value / 1_000_000_000.0 - origin
    end = start + 1.0

    data = read_cwa_file(
        str(CWA_FILE),
        cut=seconds(start, end),
        include_magnetometer=False,
        include_temperature=False,
        include_light=False,
        include_battery=False,
        resample_hz=100.0,
    )

    assert len(data) == 100
    assert abs(data.index[0].value / 1_000_000_000.0 - (origin + start)) < 1e-6
    step = (data.index[1] - data.index[0]).total_seconds()
    assert abs(float(step) - 0.01) < 1e-9


def test_resampled_partial_read_matches_full_read_for_same_window() -> None:
    start = 2.0
    end = 5.0

    options = {
        "include_magnetometer": False,
        "include_temperature": True,
        "include_light": True,
        "include_battery": True,
        "resample_hz": 100.0,
    }
    full = read_cwa_file(str(CWA_FILE), **options)
    partial = read_cwa_file(str(CWA_FILE), cut=seconds(start, end), **options)
    start_timestamp = partial.index[0]
    end_timestamp = start_timestamp + pd.Timedelta(seconds=end - start)
    full_mask = (full.index >= start_timestamp) & (full.index < end_timestamp)

    pd.testing.assert_frame_equal(partial, full.loc[full_mask])


def test_invalid_seconds_cut_is_rejected_before_opening_file() -> None:
    with pytest.raises(ValueError, match="seconds end"):
        read_cwa_file(
            "does-not-matter.cwa",
            cut=seconds(2.0, 1.0),
        )


def test_invalid_resample_rate_is_rejected_before_opening_file() -> None:
    with pytest.raises(ValueError, match="resample_hz"):
        read_cwa_file("does-not-matter.cwa", resample_hz=10_001.0)


def test_non_data_sector_is_skipped_by_reads_export_and_timing_report(tmp_path: Path) -> None:
    source = CWA_FILE.read_bytes()
    with_gap = tmp_path / "with-gap.cwa"
    with_gap.write_bytes(source[:1536] + bytes(512) + source[1536:])

    options = dict(
        include_magnetometer=False,
        include_temperature=False,
        include_light=False,
        include_battery=False,
    )
    expected = read_cwa_file(str(CWA_FILE), **options)
    actual = read_cwa_file(str(with_gap), **options)
    pd.testing.assert_frame_equal(actual, expected)

    expected_window = read_cwa_file(
        str(CWA_FILE), cut=seconds(1.0, 2.0), resample_hz=100.0, **options
    )
    window = read_cwa_file(
        str(with_gap), cut=seconds(1.0, 2.0), resample_hz=100.0, **options
    )
    pd.testing.assert_frame_equal(window, expected_window)
    assert sampling_consistency_report(str(with_gap)) == sampling_consistency_report(str(CWA_FILE))

    output = tmp_path / "with-gap.csv"
    write_cwa_csv(str(with_gap), str(output), **options)
    assert len(pd.read_csv(output)) == len(actual)


def test_incomplete_data_sector_is_rejected_by_reader_and_report(tmp_path: Path) -> None:
    truncated = tmp_path / "truncated.cwa"
    truncated.write_bytes(CWA_FILE.read_bytes() + b"AX")

    with pytest.raises(RuntimeError, match="Incomplete CWA data block"):
        read_cwa_file(str(truncated), include_magnetometer=False)
    with pytest.raises(RuntimeError, match="IO error"):
        sampling_consistency_report(str(truncated))
