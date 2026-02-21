# OpenMovement Reference Fixtures

This directory contains third-party reference data used by automated tests.

## Files

- `example-610-steps.cwa`
  - Source: `https://github.com/openmovementproject/openmovement/blob/master/Software/ThirdParty/pedometer/data/example-610-steps.cwa`
- `example-610-steps.cwa.cwa-convert.full.csv`
  - Generated from the file above using OpenMovement `cwa-convert` with:

```bash
cwa-convert example-610-steps.cwa -f:csv -v:float -t:timestamp -out example-610-steps.cwa.cwa-convert.full.csv
```

## Provenance and license note

The source repository is:

- `https://github.com/openmovementproject/openmovement`

At import time, GitHub metadata did not report a detected top-level license for that repository.
Treat this directory as third-party reference material used for compatibility testing.

If license requirements change upstream, update this file and fixture usage accordingly.
