from pathlib import Path
import struct

import pandas as pd
import pytest

from cwa_reader_rs import (
    blocks,
    read_cwa_file,
    read_header,
    sampling_consistency_report,
    seconds,
    write_cwa_csv,
)


SOURCE = Path(__file__).parent / "reference_data/openmovement/example-610-steps.cwa"


def test_reader_returns_dataframe_with_naive_datetime_index() -> None:
    data = read_cwa_file(str(SOURCE), cut=blocks(0, 1))

    assert isinstance(data, pd.DataFrame)
    assert isinstance(data.index, pd.DatetimeIndex)
    assert data.index.name == "timestamp"
    assert data.index.tz is None
    assert "timestamp" not in data.columns
    pd.testing.assert_series_equal(data.loc[data.index[0]], data.iloc[0])


def _timestamp_bits(time: str) -> int:
    dt = pd.Timestamp(time)
    return (
        ((dt.year - 2000) << 26)
        | (dt.month << 22)
        | (dt.day << 17)
        | (dt.hour << 12)
        | (dt.minute << 6)
        | dt.second
    )


def _recording(tmp_path: Path, *times: str, configured_at: str | None = None) -> Path:
    source = SOURCE.read_bytes()
    header = bytearray(source[:1024])
    packets = []
    encoded_times = []
    for time in times:
        encoded = _timestamp_bits(time)
        encoded_times.append(encoded)
        packet = bytearray(source[1024:1536])
        struct.pack_into("<I", packet, 14, encoded)
        struct.pack_into("<hH", packet, 26, 0, 20)
        checksum = (-sum(struct.unpack("<255H", packet[:510]))) & 0xFFFF
        struct.pack_into("<H", packet, 510, checksum)
        packets.append(packet)
    struct.pack_into("<I", header, 13, encoded_times[0])
    struct.pack_into("<I", header, 17, encoded_times[-1])
    struct.pack_into("<I", header, 37, _timestamp_bits(configured_at or times[0]))
    path = tmp_path / "recording.cwa"
    path.write_bytes(header + b"".join(packets))
    return path


def test_configuration_offset_can_precede_dst_and_recording_start(tmp_path: Path) -> None:
    path = _recording(
        tmp_path, "2026-03-30T00:00:00", configured_at="2026-03-28T12:00:00"
    )
    header = read_header(str(path))
    assert header["last_change_time_raw"] == "2026-03-28T12:00:00"
    configured = pd.Timestamp(header["last_change_time_raw"]).tz_localize("Europe/Berlin")
    offset = configured.strftime("%z")
    utc_offset = f"UTC{offset[:3]}:{offset[3:]}"

    data = read_cwa_file(str(path), utc_offset=utc_offset)

    assert data.index[0] == pd.Timestamp("2026-03-29T23:00:00Z")
    assert data.tz_convert("Europe/Berlin").index[0] == pd.Timestamp(
        "2026-03-30T01:00:00+02:00"
    )


@pytest.mark.parametrize(
    "start,after_change,utc_offset,expected_start_utc,expected_after_local",
    [
        (
            "2026-03-29T00:00:00",
            "2026-03-29T03:00:00",
            "UTC+1",
            "2026-03-28T23:00:00Z",
            "2026-03-29T04:00:00+02:00",
        ),
        (
            "2026-10-25T00:00:00",
            "2026-10-25T03:00:00",
            "UTC+2",
            "2026-10-24T22:00:00Z",
            "2026-10-25T02:00:00+01:00",
        ),
    ],
)
def test_utc_offset_stays_fixed_across_dst(
    tmp_path: Path,
    start: str,
    after_change: str,
    utc_offset: str,
    expected_start_utc: str,
    expected_after_local: str,
) -> None:
    path = _recording(tmp_path, start, after_change)
    data = read_cwa_file(str(path), utc_offset=utc_offset)

    assert str(data.index.tz) == "UTC"
    assert data.index[0] == pd.Timestamp(expected_start_utc)
    localised = data.tz_convert("Europe/Berlin")
    assert localised.index[20] == pd.Timestamp(expected_after_local)
    assert (data.index[20] - data.index[0]).total_seconds() == 3 * 3600


@pytest.mark.parametrize("utc_offset", [None, "UTC+1"])
def test_header_stays_raw_while_report_and_csv_use_utc_offset(
    tmp_path: Path,
    utc_offset: str | None,
) -> None:
    path = _recording(tmp_path, "2026-03-29T00:00:00", "2026-03-29T03:00:00")
    kwargs = {"utc_offset": utc_offset}
    data = read_cwa_file(str(path), **kwargs)
    header = read_header(str(path))
    report = sampling_consistency_report(str(path), **kwargs)

    assert header["logging_start_time_raw"] == "2026-03-29T00:00:00"
    assert header["logging_end_time_raw"] == "2026-03-29T03:00:00"
    assert header["last_change_time_raw"] == "2026-03-29T00:00:00"
    assert pd.Timestamp(report["start_from_data"]) == data.index[0]
    assert pd.Timestamp(report["end_from_data"]) == data.index[-1]
    assert pd.Timestamp(report["start_from_header"]) == data.index[0]
    assert pd.Timestamp(report["end_from_header"]) == data.index[20]
    assert report["duration_s_from_header"] == 10800.0
    assert report["duration_s_from_data"] == pytest.approx(10800.19)

    output = tmp_path / "recording.csv"
    write_cwa_csv(str(path), str(output), **kwargs)
    written = pd.read_csv(output)
    assert written["time"].to_numpy() == pytest.approx(
        data.index.as_unit("us").asi8 / 1_000_000,
        abs=0.0001,
        rel=0,
    )


@pytest.mark.parametrize("resample_hz", [None, 100.0])
@pytest.mark.parametrize("cut", [blocks(1, 2), seconds(10800.0, 10800.1)])
def test_partial_reads_and_csv_retain_fixed_utc_offset(
    tmp_path: Path,
    cut: dict,
    resample_hz: float | None,
) -> None:
    path = _recording(tmp_path, "2026-03-29T00:00:00", "2026-03-29T03:00:00")
    options = {"cut": cut, "resample_hz": resample_hz}
    naive = read_cwa_file(str(path), **options)
    utc = read_cwa_file(str(path), utc_offset="UTC+1", **options)
    expected = naive.copy()
    expected.index = (
        (naive.index - pd.Timedelta(hours=1)).tz_localize("UTC").as_unit("us")
    )
    pd.testing.assert_frame_equal(utc, expected)
    assert utc.index[0] == pd.Timestamp("2026-03-29T02:00:00Z")

    output = tmp_path / "partial.csv"
    write_cwa_csv(str(path), str(output), utc_offset="UTC+1", **options)
    assert pd.read_csv(output)["time"].to_numpy() == pytest.approx(
        utc.index.as_unit("us").asi8 / 1_000_000,
        abs=0.0001,
        rel=0,
    )


@pytest.mark.parametrize(
    "start,utc_offset,expected_utc",
    [
        ("2026-10-25T02:30:00", "UTC+2", "2026-10-25T00:30:00Z"),
        ("2026-03-29T02:30:00", "UTC+1", "2026-03-29T01:30:00Z"),
    ],
)
def test_fixed_offset_accepts_device_times_in_local_dst_gaps_and_overlaps(
    tmp_path: Path, start: str, utc_offset: str, expected_utc: str
) -> None:
    path = _recording(tmp_path, start)
    assert read_cwa_file(str(path), utc_offset=utc_offset).index[0] == pd.Timestamp(
        expected_utc
    )


@pytest.mark.parametrize("utc_offset", ["Europe/Berlin", "UTC+24", "UTC+01:60"])
def test_invalid_utc_offset_is_rejected(utc_offset: str) -> None:
    with pytest.raises(ValueError, match="Invalid utc_offset"):
        read_cwa_file(str(SOURCE), utc_offset=utc_offset)


@pytest.mark.parametrize(
    "utc_offset,expected_utc",
    [
        ("UTC", "2026-07-01T00:00:00Z"),
        ("UTC+0", "2026-07-01T00:00:00Z"),
        ("UTC-00:30", "2026-07-01T00:30:00Z"),
        ("UTC-4", "2026-07-01T04:00:00Z"),
        ("UTC+05:45", "2026-06-30T18:15:00Z"),
    ],
)
def test_utc_offset_supports_zero_negative_and_fractional_offsets(
    tmp_path: Path,
    utc_offset: str,
    expected_utc: str,
) -> None:
    path = _recording(tmp_path, "2026-07-01T00:00:00")
    assert read_cwa_file(str(path), utc_offset=utc_offset).index[0] == pd.Timestamp(
        expected_utc
    )


def test_fixed_offset_does_not_require_configuration_time(tmp_path: Path) -> None:
    path = _recording(tmp_path, "2026-03-30T00:00:00")
    contents = bytearray(path.read_bytes())
    struct.pack_into("<I", contents, 37, 0)
    path.write_bytes(contents)

    assert read_header(str(path))["last_change_time_raw"] is None
    assert read_cwa_file(str(path), utc_offset="UTC+1").index[0] == pd.Timestamp(
        "2026-03-29T23:00:00Z"
    )


@pytest.mark.parametrize("utc_offset", [None, "UTC+1"])
def test_header_only_recording_returns_raw_times_and_report_uses_offset(
    tmp_path: Path,
    utc_offset: str | None,
) -> None:
    path = _recording(tmp_path, "2026-03-29T00:00:00")
    path.write_bytes(path.read_bytes()[:1024])
    header = read_header(str(path))
    expected = "2026-03-28T23:00:00Z" if utc_offset else "2026-03-29T00:00:00"
    assert header["logging_start_time_raw"] == "2026-03-29T00:00:00"
    report = sampling_consistency_report(str(path), utc_offset=utc_offset)
    assert report["start_from_data"] is None
    assert report["end_from_data"] is None
    assert pd.Timestamp(report["start_from_header"]) == pd.Timestamp(expected)
