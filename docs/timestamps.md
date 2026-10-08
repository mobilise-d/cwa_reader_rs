# Timestamps and clock interpretation

CWA sample times describe the device clock. They do not include a time zone, and
the reader does not infer one. Header and sampling-report fields ending in
`_raw` preserve this clock as naive ISO 8601 strings when present. Configured
logging times can be absent and can differ from actual sample boundaries.

## Synchronization and fixed UTC offsets

In the normal AX3/AX6 configuration workflow, the sensor synchronizes to the
configuring computer's local time. It then counts forward without applying later
daylight-saving or computer time-zone changes. The offset to use is the one at
clock synchronization, even if logging starts days later. See the upstream
[time-zone FAQ](https://github.com/openmovementproject/openmovement/blob/master/Docs/ax3/ax3-faq.md#time-zone-and-dst).

The header's `lastChangeTime`, exposed as `last_change_time_raw`, records the last
metadata/configuration write. It is not a dedicated clock-synchronization log.
Confirm how your configuration software uses it before treating it as the last
clock synchronization.

The reader can apply a supplied fixed offset to samples and CSV output:

```text
UTC time = device-clock time - fixed UTC offset
```

For example, a device synchronized at UTC+2 records `12:00` for `10:00` UTC.
Negative and fractional offsets are supported. The same offset applies to the
whole recording, cuts and resampling. It does not change elapsed durations,
cut offsets or sampling rates.

Metadata and sampling reports stay raw and accept no time-zone conversion.
Interpret their times using the same fixed offset as the samples, then convert
to a named analysis time zone if needed. Do not directly localize each recorded
timestamp using a named zone whose offset may have changed during recording.
See the [Python conversion examples](../python/README.md#fixed-utc-offsets)
and [JavaScript offset option](../wasm/README.md).

If a configuration time falls in a repeated local hour at an autumn clock
change, the raw timestamp cannot distinguish the two possible offsets. Supply
a known synchronization offset rather than guessing from recording start.
Missing configuration times likewise require information outside the file to
establish the clock's UTC offset.

## Elapsed days and calendar days

A 24-hour interval is 86,400 elapsed seconds. A local calendar day runs between
consecutive local midnights and can be 23 or 25 hours at a daylight-saving change.
Define calendar boundaries in the analysis time zone, convert them to instants,
then compute elapsed seconds relative to the first valid sample for each cut.
Use an exclusive end so adjacent windows do not duplicate boundary samples.

A sensor-clock midnight trigger does not follow a later daylight-saving change.
A scheduled 24-hour recording beginning at local midnight before a spring change
can end at 01:00 local time the next day; across an autumn change it can end at
23:00 on the same calendar date. Converting timestamps cannot recover an hour
that was never recorded or change when the device's trigger fired.

## Sampling rate and clock drift

Configured start/end times and nominal sampling rates are settings. The actual
first and last samples and sample count can differ because of startup/stop
behavior and the timing of the movement sensor relative to the onboard clock.

The sampling report derives an effective rate from the sample count and the
device-clock duration. It does not measure drift relative to external UTC:
header times and packet times both use the same device clock. Independent event
markers or another synchronized reference are needed for that comparison.

Open Movement describes both RTC drift and variation of sensor output rate
relative to the RTC in its
[clock synchronization FAQ](https://github.com/openmovementproject/openmovement/blob/master/Docs/ax3/ax3-faq.md#synchronizing-data-between-devices-or-with-other-devices).
The report alone cannot distinguish clock drift, delayed recording boundaries,
sensor-rate variation and file conversion effects.

Resampling uses the sample-derived timestamps and preserves their time span.
Choose a target sampling rate required by the downstream analysis, often the
nominal header rate. Do not force the recording duration from sample count alone.
