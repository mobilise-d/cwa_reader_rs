from pathlib import Path
import struct

import numpy as np
import pytest

from cwa_reader_rs import blocks, read_cwa_file, seconds


SOURCE = Path(__file__).parent / "reference_data/openmovement/example-610-steps.cwa"


def _recording(tmp_path: Path, axes: int, packing: int = 2) -> Path:
    source = SOURCE.read_bytes()
    packet = bytearray(source[1024:1536])
    packet[25] = (axes << 4) | packing
    struct.pack_into("<hH", packet, 26, 0, 20)
    packet[30:510] = bytes(480)
    # All recorded sensor values are real zeros. The metadata header is copied
    # unchanged so channel presence must come from the sample packet layout.
    checksum = (-sum(struct.unpack("<255H", packet[:510]))) & 0xFFFF
    struct.pack_into("<H", packet, 510, checksum)
    recording = tmp_path / "channels.cwa"
    recording.write_bytes(source[:1024] + packet)
    return recording


def test_accelerometer_recording_omits_absent_channels(tmp_path: Path) -> None:
    data = read_cwa_file(str(_recording(tmp_path, 3)))
    assert set(data) == {
        "acc_x", "acc_y", "acc_z", "temperature", "light", "battery",
    }
    assert len(data) == 20


@pytest.mark.parametrize("axes,packing", [(3, 0), (3, 2), (6, 2), (9, 2)])
@pytest.mark.parametrize("resample_hz", [None, 100.0, 60.0])
@pytest.mark.parametrize("cut", [None, blocks(0, 1), seconds(0.02, 0.08)])
@pytest.mark.parametrize("include_magnetometer", [False, True])
def test_reader_returns_only_recorded_channels_and_preserves_zero_measurements(
    tmp_path: Path,
    axes: int,
    packing: int,
    resample_hz: float | None,
    cut: dict | None,
    include_magnetometer: bool,
) -> None:
    data = read_cwa_file(
        str(_recording(tmp_path, axes, packing)),
        cut=cut,
        resample_hz=resample_hz,
        include_magnetometer=include_magnetometer,
        include_temperature=False,
        include_light=False,
        include_battery=False,
    )
    expected = {"acc_x", "acc_y", "acc_z"}
    if axes >= 6:
        expected.update({"gyro_x", "gyro_y", "gyro_z"})
    if axes == 9 and include_magnetometer:
        expected.update({"mag_x", "mag_y", "mag_z"})
    assert set(data) == expected
    count = len(data)
    assert count > 0
    for key in expected:
        assert data[key].dtype == np.float32
        np.testing.assert_array_equal(data[key], np.zeros(count, dtype=np.float32))


@pytest.mark.parametrize("resample_hz", [None, 100.0])
@pytest.mark.parametrize(
    "cut,has_gyro",
    [
        (None, True),
        (blocks(0, 1), False),
        (blocks(1, 2), True),
        (seconds(0.02, 0.08), False),
        (seconds(0.22, 0.28), True),
    ],
)
def test_channel_presence_follows_selected_samples_when_packet_layout_changes(
    tmp_path: Path,
    resample_hz: float | None,
    cut: dict | None,
    has_gyro: bool,
) -> None:
    first = _recording(tmp_path, 3).read_bytes()
    second = bytearray(_recording(tmp_path, 9).read_bytes()[1024:])
    struct.pack_into("<h", second, 26, -20)
    checksum = (-sum(struct.unpack("<255H", second[:510]))) & 0xFFFF
    struct.pack_into("<H", second, 510, checksum)
    recording = tmp_path / "mixed.cwa"
    recording.write_bytes(first + second)
    data = read_cwa_file(str(recording), cut=cut, resample_hz=resample_hz)
    for sensor in ["gyro", "mag"]:
        for axis in "xyz":
            key = f"{sensor}_{axis}"
            assert (key in data) == has_gyro
            if has_gyro:
                assert len(data[key]) == len(data)
                if cut is not None:
                    np.testing.assert_array_equal(
                        data[key], np.zeros(len(data[key]), dtype=np.float32)
                    )
                else:
                    assert np.isnan(data[key].iloc[:20]).all()
                    np.testing.assert_array_equal(
                        data[key].iloc[20:], np.zeros(len(data[key]) - 20, dtype=np.float32)
                    )


@pytest.mark.parametrize("cut,resample_hz", [(None, 60.0), (seconds(0.0, 0.4), 2.0)])
def test_resampling_retains_channels_in_short_segments_missed_by_output_grid(
    tmp_path: Path, cut: dict | None, resample_hz: float,
) -> None:
    source = _recording(tmp_path, 3).read_bytes()
    first = bytearray(source[1024:])
    sensor = bytearray(_recording(tmp_path, 9).read_bytes()[1024:])
    last = bytearray(first)
    for packet, offset, count in [(first, 0, 21), (sensor, -21, 1), (last, -22, 20)]:
        struct.pack_into("<hH", packet, 26, offset, count)
        checksum = (-sum(struct.unpack("<255H", packet[:510]))) & 0xFFFF
        struct.pack_into("<H", packet, 510, checksum)
    recording = tmp_path / "short-sensor-segment.cwa"
    recording.write_bytes(source[:1024] + first + sensor + last)
    data = read_cwa_file(str(recording), cut=cut, resample_hz=resample_hz)
    for sensor_name in ["gyro", "mag"]:
        for axis in "xyz":
            values = data[f"{sensor_name}_{axis}"]
            assert len(values) == len(data)
            assert np.isnan(values).all()
