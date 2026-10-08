# Python timestamp recipes

Read the shared [timestamp guide](../docs/timestamps.md) for device-clock
semantics, drift and DST. These examples show Python conversions and cut calls.

## Derive a fixed offset from configuration time

Use this workflow only when the configuration software's last metadata write is
also the last clock synchronization. The recording does not identify that fact or
its timezone. Supply a known synchronization offset when it cannot be established.
Localizing the configuration time raises for ambiguous or nonexistent local times;
resolve those using external synchronization information.

```python
from datetime import timedelta, timezone
from zoneinfo import ZoneInfo

import pandas as pd
from cwa_reader_rs import read_cwa_file, read_metadata

path = "recording.cwa"
tz = "Europe/Berlin"  # Timezone of the computer that synchronized the sensor.
metadata = read_metadata(path)
last_change_raw = metadata["last_change_time_raw"]
logging_start_raw = metadata["logging_start_time_raw"]
logging_end_raw = metadata["logging_end_time_raw"]
if any(
    value is None for value in (last_change_raw, logging_start_raw, logging_end_raw)
):
    raise ValueError(
        "This example requires configuration and scheduled start/end times"
    )

# ASSUMPTION: last metadata change = last clock synchronization.
# pandas raises if the configuration time is ambiguous or nonexistent.
configured_local = pd.Timestamp(last_change_raw).tz_localize(ZoneInfo(tz))
clock_timezone = timezone(configured_local.utcoffset())  # Fixed offset, no DST rules.

data = read_cwa_file(path, fixed_utc_offset_timezone=clock_timezone)
logging_start_utc = (
    pd.Timestamp(logging_start_raw).tz_localize(clock_timezone).tz_convert("UTC")
)
logging_end_utc = (
    pd.Timestamp(logging_end_raw).tz_localize(clock_timezone).tz_convert("UTC")
)

# Optional local-time analysis. tz_convert applies the timezone's DST rules.
data_local = data.tz_convert(tz)
logging_start_local = logging_start_utc.tz_convert(tz)
logging_end_local = logging_end_utc.tz_convert(tz)
```

Raw scheduled times use the same fixed device offset as samples. Apply
`clock_timezone` before converting them to a named timezone. Metadata fields can
be `None`; the example requires scheduled bounds and a configuration time.

## Read local calendar days

Continue from the previous example. Use calendar midnights and constrain each
window by the configured logging limits and actual recording bounds. Translate
those windows to elapsed seconds relative to the first valid sample, which can
arrive later than the scheduled start.

```python
from cwa_reader_rs import seconds

first_sample_local = (
    pd.Timestamp(metadata["start_from_data_raw"])
    .tz_localize(clock_timezone)
    .tz_convert(tz)
)
last_sample_local = (
    pd.Timestamp(metadata["end_from_data_raw"])
    .tz_localize(clock_timezone)
    .tz_convert(tz)
)
first_sample_delay = (first_sample_local - logging_start_local).total_seconds()

# Local midnights, including the boundary after the final recorded date.
day_boundaries = pd.date_range(
    start=max(logging_start_local, first_sample_local).normalize(),
    end=min(logging_end_local, last_sample_local).normalize() + pd.DateOffset(days=1),
    freq="D",
)

for day_start, day_end in zip(day_boundaries[:-1], day_boundaries[1:]):
    start_local = max(day_start, logging_start_local)
    end_local = min(day_end, logging_end_local)
    start_seconds = max(
        0.0, (start_local - logging_start_local).total_seconds() - first_sample_delay
    )
    end_seconds = (end_local - logging_start_local).total_seconds() - first_sample_delay
    if end_seconds <= start_seconds:
        continue

    day_data = read_cwa_file(
        path,
        fixed_utc_offset_timezone=clock_timezone,
        cut=seconds(start_seconds, end_seconds),
    )
    day_data_local = day_data.tz_convert(tz)
    # Analyse day_data_local for the calendar date day_start.date().
```

`seconds(...)` excludes the end boundary, so adjacent local-day windows share no
samples. See the shared guide for the difference between a calendar day and a
24-hour bout.
