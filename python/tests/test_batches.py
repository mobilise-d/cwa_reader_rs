"""Public Python controls over the independently preloaded packet engine."""
from datetime import timedelta, timezone
import hashlib
from pathlib import Path
import struct

import numpy as np
import pytest

from cwa_reader_rs import read_cwa_file, write_cwa_csv


def _recording(path: Path, *, packets: int = 4, count: int = 2, contiguous: bool = True) -> Path:
    data = bytearray(1024 + packets * 512)
    data[:2] = b"MD"
    for packet_index in range(packets):
        start = 1024 + packet_index * 512
        data[start:start+2] = b"AX"
        struct.pack_into("<H", data, start+2, 508)
        rtc = (12 << 26) | (1 << 22) | (1 << 17)
        if not contiguous:
            rtc |= packet_index
        struct.pack_into("<I", data, start+14, rtc)
        data[start+24:start+26] = bytes([0x49, 0x32])
        struct.pack_into("<hH", data, start+26, -packet_index*count if contiguous else 0, count)
        for sample in range(count):
            value = (packet_index*count+sample)**3 * 64
            struct.pack_into("<h", data, start+30+sample*6, value)
    path.write_bytes(data)
    return path


@pytest.mark.parametrize("batch_packets", [1, 2, 256])
def test_batch_controls_preserve_cubic_join_values_and_fixed_offset(tmp_path: Path, batch_packets: int) -> None:
    source = _recording(tmp_path / "polynomial.cwa")
    data = read_cwa_file(
        str(source), resample_hz=60, batch_packets=batch_packets,
        fixed_utc_offset_timezone=timezone(timedelta(seconds=1.25)),
        include_temperature=False, include_light=False, include_battery=False,
    )
    # Captured from the pre-refactor binary, including the noninteger60Hz grid.
    expected_us = np.array([1325376000000000,1325376000016666,1325376000033333,
        1325376000050000,1325376000066666,1325376000083333,1325376000100000,
        1325376000116666,1325376000133333],dtype=np.int64)-1_250_000
    expected_x = np.array([0.0,0.2083333283662796,1.1574074029922485,3.90625,
        9.259358406066895,18.084489822387695,31.25,49.62407302856445,75.16767883300781],dtype=np.float32)
    np.testing.assert_array_equal(data.index.as_unit("us").asi8,expected_us)
    np.testing.assert_array_equal(data.acc_x.to_numpy(),expected_x)
    assert str(data.index.dtype) == "datetime64[us, UTC]"
    assert all(dtype == np.float32 for dtype in data.dtypes)
    csv = tmp_path / "output.csv"
    write_cwa_csv(str(source),str(csv),resample_hz=60,batch_packets=batch_packets)
    assert hashlib.sha256(csv.read_bytes()).hexdigest() == "8c5ca9023af7730d2d5be124504e2789f5a614bbd4eeba7ff4431a16e79eded2"


def test_insufficient_context_is_structured_and_larger_overlap_can_be_selected(tmp_path: Path) -> None:
    source = _recording(tmp_path / "short-packets.cwa",packets=6,count=1,contiguous=False)
    with pytest.raises(RuntimeError,match="InsufficientContext") as failure:
        read_cwa_file(str(source),resample_hz=25,batch_packets=2)
    assert failure.value.code == "InsufficientContext"
    assert failure.value.side == "right"
    assert failure.value.owned_packets == (0,2)
    assert failure.value.loaded_packets == (0,3)
    assert "original samples" in failure.value.reason
    assert len(read_cwa_file(str(source),resample_hz=25,batch_packets=2,overlap_packets=2)) > 0


@pytest.mark.parametrize("options", [{"batch_packets":0},{"overlap_packets":2**64-1}])
def test_invalid_batch_controls_do_not_allocate_payloads(tmp_path: Path, options: dict) -> None:
    source = _recording(tmp_path / "small.cwa")
    with pytest.raises((ValueError,OverflowError)):
        read_cwa_file(str(source),**options)
