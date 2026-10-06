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


def _recording(tmp_path: Path, *times: str) -> Path:
    source = SOURCE.read_bytes()
    header = bytearray(source[:1024])
    packets = []
    encoded_times = []
    for time in times:
        dt = pd.Timestamp(time)
        encoded = (
            ((dt.year - 2000) << 26)
            | (dt.month << 22)
            | (dt.day << 17)
            | (dt.hour << 12)
            | (dt.minute << 6)
            | dt.second
        )
        encoded_times.append(encoded)
        packet = bytearray(source[1024:1536])
        struct.pack_into("<I", packet, 14, encoded)
        struct.pack_into("<hH", packet, 26, 0, 20)
        checksum = (-sum(struct.unpack("<255H", packet[:510]))) & 0xFFFF
        struct.pack_into("<H", packet, 510, checksum)
        packets.append(packet)
    struct.pack_into("<I", header, 13, encoded_times[0])
    struct.pack_into("<I", header, 17, encoded_times[-1])
    struct.pack_into("<I", header, 37, encoded_times[0])
    path = tmp_path / "recording.cwa"
    path.write_bytes(header + b"".join(packets))
    return path


@pytest.mark.parametrize(
    "start,after_change,expected_start_utc,expected_after_local",
    [
        (
            "2026-03-29T00:00:00",
            "2026-03-29T03:00:00",
            "2026-03-28T23:00:00Z",
            "2026-03-29T04:00:00+02:00",
        ),
        (
            "2026-10-25T00:00:00",
            "2026-10-25T03:00:00",
            "2026-10-24T22:00:00Z",
            "2026-10-25T02:00:00+01:00",
        ),
    ],
)
def test_recording_timezone_uses_one_start_offset_across_dst(
    tmp_path: Path,
    start: str,
    after_change: str,
    expected_start_utc: str,
    expected_after_local: str,
) -> None:
    path = _recording(tmp_path, start, after_change)
    data = read_cwa_file(str(path), recording_timezone="Europe/Berlin")

    assert str(data.index.tz) == "UTC"
    assert data.index[0] == pd.Timestamp(expected_start_utc)
    localised = data.tz_convert("Europe/Berlin")
    assert localised.index[20] == pd.Timestamp(expected_after_local)
    assert (data.index[20] - data.index[0]).total_seconds() == 3 * 3600


@pytest.mark.parametrize("recording_timezone", [None, "Europe/Berlin"])
def test_header_report_and_csv_use_the_same_recording_clock(
    tmp_path: Path,
    recording_timezone: str | None,
) -> None:
    path = _recording(tmp_path, "2026-03-29T00:00:00", "2026-03-29T03:00:00")
    kwargs = {"recording_timezone": recording_timezone}
    data = read_cwa_file(str(path), **kwargs)
    header = read_header(str(path), **kwargs)
    report = sampling_consistency_report(str(path), **kwargs)

    assert pd.Timestamp(header["logging_start_time"]) == data.index[0]
    assert pd.Timestamp(header["logging_end_time"]) == data.index[20]
    assert pd.Timestamp(header["last_change_time"]) == data.index[0]
    assert pd.Timestamp(report["start_from_data"]) == data.index[0]
    assert pd.Timestamp(report["end_from_data"]) == data.index[-1]
    assert report["start_from_header"] == header["logging_start_time"]
    assert report["end_from_header"] == header["logging_end_time"]
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
def test_timezone_partial_reads_and_csv_retain_full_recording_start_offset(
    tmp_path: Path,
    cut: dict,
    resample_hz: float | None,
) -> None:
    path = _recording(tmp_path, "2026-03-29T00:00:00", "2026-03-29T03:00:00")
    options = {"cut": cut, "resample_hz": resample_hz}
    naive = read_cwa_file(str(path), **options)
    utc = read_cwa_file(str(path), recording_timezone="Europe/Berlin", **options)
    expected = naive.copy()
    expected.index = (
        (naive.index - pd.Timedelta(hours=1)).tz_localize("UTC").as_unit("us")
    )
    pd.testing.assert_frame_equal(utc, expected)
    assert utc.index[0] == pd.Timestamp("2026-03-29T02:00:00Z")

    output = tmp_path / "partial.csv"
    write_cwa_csv(str(path), str(output), recording_timezone="Europe/Berlin", **options)
    assert pd.read_csv(output)["time"].to_numpy() == pytest.approx(
        utc.index.as_unit("us").asi8 / 1_000_000,
        abs=0.0001,
        rel=0,
    )


@pytest.mark.parametrize(
    "start,error",
    [("2026-10-25T02:30:00", "ambiguous"), ("2026-03-29T02:30:00", "does not exist")],
)
def test_ambiguous_or_nonexistent_recording_start_is_rejected(
    tmp_path: Path,
    start: str,
    error: str,
) -> None:
    path = _recording(tmp_path, start)
    with pytest.raises(ValueError, match=error):
        read_cwa_file(str(path), recording_timezone="Europe/Berlin")
    assert read_cwa_file(str(path)).index[0] == pd.Timestamp(start)


def test_unknown_recording_timezone_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown recording_timezone"):
        read_cwa_file(str(SOURCE), recording_timezone="Unknown/Zone")


@pytest.mark.parametrize(
    "timezone,expected_utc",
    [
        ("UTC", "2026-07-01T00:00:00Z"),
        ("America/New_York", "2026-07-01T04:00:00Z"),
        ("Asia/Kathmandu", "2026-06-30T18:15:00Z"),
    ],
)
def test_recording_timezone_supports_zero_negative_and_fractional_offsets(
    tmp_path: Path,
    timezone: str,
    expected_utc: str,
) -> None:
    path = _recording(tmp_path, "2026-07-01T00:00:00")
    assert read_cwa_file(str(path), recording_timezone=timezone).index[
        0
    ] == pd.Timestamp(expected_utc)


def test_recording_start_offset_comes_from_first_sample_rather_than_header(
    tmp_path: Path,
) -> None:
    path = _recording(tmp_path, "2026-03-29T00:00:00", "2026-03-29T03:00:00")
    contents = path.read_bytes()
    path.write_bytes(contents[:1024] + bytes(512) + contents[1536:])
    data = read_cwa_file(str(path), recording_timezone="Europe/Berlin")
    assert data.index[0] == pd.Timestamp("2026-03-29T01:00:00Z")
    report = sampling_consistency_report(str(path), recording_timezone="Europe/Berlin")
    assert pd.Timestamp(report["start_from_data"]) == data.index[0]


@pytest.mark.parametrize("recording_timezone", [None, "Europe/Berlin"])
def test_header_only_recording_uses_configured_start_for_timezone(
    tmp_path: Path,
    recording_timezone: str | None,
) -> None:
    path = _recording(tmp_path, "2026-03-29T00:00:00")
    path.write_bytes(path.read_bytes()[:1024])
    header = read_header(str(path), recording_timezone=recording_timezone)
    expected = "2026-03-28T23:00:00Z" if recording_timezone else "2026-03-29T00:00:00"
    assert pd.Timestamp(header["logging_start_time"]) == pd.Timestamp(expected)
    report = sampling_consistency_report(
        str(path), recording_timezone=recording_timezone
    )
    assert report["start_from_data"] is None
    assert report["end_from_data"] is None
    assert report["start_from_header"] == header["logging_start_time"]
