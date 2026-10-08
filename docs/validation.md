# Cross-target validation

The shared parser is checked through the Rust core, native Python, the actual
Xeus browser worker and standalone browser interfaces. Distribution READMEs
provide the commands for their respective suites; see the
[documentation index](README.md).

## Native and browser parity

Compare builds from the same source and options. Checks cover metadata and
sampling reports, full reads, block/seconds cuts, resampling, optional and mixed
channels, packed sample layouts, fixed offsets, CSV and malformed inputs.
Missing values, zeros and absent columns are distinct cases.

Timestamp comparisons use integer representations with explicit units, rather
than rounded display strings. Native Python index timestamps are compared in
integer nanoseconds, together with datetime dtype and time-zone information.
Standalone JavaScript exposes its documented integer timestamp representation;
its oracle accounts for that representation. Raw channels and timestamps are
compared exactly where the target arithmetic is identical.

Standalone browser/native tests allow one float32 ULP for calibrated light. That
channel uses `10_f32.powf(raw / 341)`, whose implementation can differ across
targets. The observed maximum difference in the tested fixtures is
`3.814697265625e-6`, about `1.05e-7` relative. Resampled channels use
`rtol=1e-6` and `atol=1e-6`, with identical NaN positions. CSV comparisons are
exact except for requested light output, which allows that difference plus
`1e-6` for printed precision. These allowances do not turn NaNs into zeros or
relax timestamp equality.

The Xeus checks import the actual Python side module, run the repository Python
tests in its worker, compare native outputs, write CSV to worker storage and
recover the output. Native success or a generic Wasm compilation is not a
substitute for this runtime check.

Standalone tests exercise byte input, real browser Files and file handles,
bounded metadata ranges, packet iteration and CSV. The npm consumer test installs
the actual tarball into a temporary application and runs a production browser
build under a non-root URL. This checks worker/Wasm asset resolution as well as
native-equivalent metadata and selected samples.

## C reference

The reference exporter is Open Movement's
[cwa-convert](https://github.com/openmovementproject/openmovement/tree/master/Software/AX3/cwa-convert/c).
The [reference tools](../tools/cwa_reference/README.md) download/build it and
perform reproducible comparisons.

Full reads are expected to match its time span and sensor values. Acceleration
matches exactly in the included Open Movement fixture. C CSV timestamps allow
`+/-1 ms` because the exporter formats fractional seconds through a float path
at millisecond precision. This tolerance is specific to the C CSV comparison;
it is not used to weaken native/browser timestamp checks.

C packet timing includes a continuity correction from the preceding packet.
Its isolated `-blockstart/-blockcount` export starts without that context, so its
first packet can differ from the corresponding part of a full C export. The Rust
reader looks back to preserve full-read continuity. Therefore:

- Rust partial reads match the corresponding Rust full-read timestamps exactly
  in the tested fixtures.
- Rust partial reads match C full-read slices within the C CSV formatting
  tolerance.
- Small initial differences from isolated C partial exports are expected. The
  largest observed difference in the included fixture is 20 ms at 100 Hz.

## Fixtures, packaging and performance

Shared source fixtures remain in `tests/reference_data/`. Python tests live in
`python/tests/`; browser tests also reuse fixture builders from that directory.
Third-party recordings remain excluded from sdists and distribution artifacts
where redistribution terms have not been resolved. Run those tests from the
source checkout or obtain fixtures as documented by the reference tools.

Native packaging checks build a wheel from the sdist and install it into a clean
environment. Browser artifacts record source and compiler versions and checksums.
The Xeus package additionally checks dynamic-link metadata and the Python module
initializer. The npm tarball contains compiled runtime files, not test fixtures
or build tools.

[Performance measurements](packet-batch-benchmarks.md) separate full output
collection from bounded batch consumption. Private multiday recordings and
participant-derived outputs are not distributed. Historical comparison tools
and the old WORKERFS cache were removed from the production tree; useful
current-reader benchmark tools remain under [tools/benchmarks](../tools/benchmarks/README.md).
