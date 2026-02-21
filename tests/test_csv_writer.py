from __future__ import annotations

from pathlib import Path

import pandas as pd

from cwa_reader_rs import read_cwa_file, write_cwa_csv


FIXTURE_DIR = Path(__file__).resolve().parent / "reference_data" / "openmovement"
CWA_FILE = FIXTURE_DIR / "example-610-steps.cwa"


def test_write_cwa_csv_matches_read_api_for_partial_window(tmp_path: Path) -> None:
    out_csv = tmp_path / "partial.csv"

    write_cwa_csv(
        str(CWA_FILE),
        str(out_csv),
        25,
        7,
        include_magnetometer=False,
        include_temperature=True,
        include_light=False,
        include_battery=True,
    )

    written = pd.read_csv(out_csv)
    data = read_cwa_file(
        str(CWA_FILE),
        25,
        7,
        include_magnetometer=False,
        include_temperature=True,
        include_light=False,
        include_battery=True,
    )

    assert len(written) == len(data["timestamp"])
    assert list(written.columns) == [
        "time",
        "acc_x",
        "acc_y",
        "acc_z",
        "gyro_x",
        "gyro_y",
        "gyro_z",
        "temperature",
        "battery",
    ]

    sample_n = min(50, len(written))
    expected_time = data["timestamp"][:sample_n] / 1_000_000.0
    assert ((written["time"].to_numpy()[:sample_n] - expected_time) < 1e-4).all()

    for col in [
        "acc_x",
        "acc_y",
        "acc_z",
        "gyro_x",
        "gyro_y",
        "gyro_z",
        "temperature",
        "battery",
    ]:
        assert (
            (written[col].to_numpy()[:sample_n] - data[col][:sample_n])
            .astype("float64")
            .__abs__()
            < 1e-6
        ).all()
