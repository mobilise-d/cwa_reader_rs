from pathlib import Path

import pandas as pd

from cwa_reader_rs import blocks, read_cwa_file


SOURCE = Path(__file__).parent / "reference_data/openmovement/example-610-steps.cwa"


def test_reader_returns_dataframe_with_naive_datetime_index() -> None:
    data = read_cwa_file(str(SOURCE), cut=blocks(0, 1))

    assert isinstance(data, pd.DataFrame)
    assert isinstance(data.index, pd.DatetimeIndex)
    assert data.index.name == "timestamp"
    assert data.index.tz is None
    assert "timestamp" not in data.columns
    pd.testing.assert_series_equal(data.loc[data.index[0]], data.iloc[0])
