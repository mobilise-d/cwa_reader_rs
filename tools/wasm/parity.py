"""Same-revision native/Xeus parity, plus the existing fixture-based pytest suite."""
import datetime
import hashlib
import json
import platform
import shutil
import struct
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import cwa_reader_rs as reader


def normalized(value):
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: normalized(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [normalized(item) for item in value]
    return value


def cases(root):
    path = root / 'tests/reference_data/openmovement/example-610-steps.cwa'
    yield 'full', path, {}
    yield 'blocks', path, {'cut': reader.blocks(3, 10)}
    yield 'seconds', path, {'cut': reader.seconds(1.2, 3.7)}
    for hz in (60.0, 100.0):
        yield f'resample-{hz}', path, {'resample_hz': hz}
        yield f'resample-cut-{hz}', path, {'cut': reader.seconds(1.2, 3.7), 'resample_hz': hz}
    for hours in (5.5, -3.5, 0):
        yield f'offset-{hours}', path, {'fixed_utc_offset_timezone': datetime.timezone(datetime.timedelta(hours=hours)), 'cut': reader.seconds(1.2, 3.7)}
    # Use repository fixture builders for recorded-zero and packed channel cases.
    sys.path.insert(0, str(root / 'python/tests'))
    from test_channels import _recording
    folder = root / 'generated'
    folder.mkdir(exist_ok=True)
    for axes, packing in ((3, 0), (3, 2), (6, 2), (9, 2)):
        generated = folder / f'{axes}-{packing}'
        generated.mkdir(exist_ok=True)
        path = _recording(generated, axes, packing)
        for label, opts in [('raw', {}), ('cut', {'cut': reader.seconds(.02, .08)}), ('resample', {'resample_hz': 60.0})]:
            yield f'channels-{axes}-{packing}-{label}', path, opts
    # Preserve nonzero gyro/magnetometer units and NaNs from mixed layouts.
    folder = root / 'generated/nonzero'
    folder.mkdir(exist_ok=True)
    base = _recording(folder, 9).read_bytes()
    packet = bytearray(base[1024:])
    for sample in range(20):
        struct.pack_into('<9h', packet, 30 + sample * 18, 128, -256, 384, 1024, -2048, 4096, 10, -20, 30)
    struct.pack_into('<H', packet, 510, (-sum(struct.unpack('<255H', packet[:510]))) & 0xFFFF)
    path = folder / 'nonzero.cwa'
    path.write_bytes(base[:1024] + packet)
    yield 'nonzero-nine-axis', path, {}
    first = _recording(folder, 3).read_bytes()
    struct.pack_into('<h', packet, 26, -20)
    struct.pack_into('<H', packet, 510, (-sum(struct.unpack('<255H', packet[:510]))) & 0xFFFF)
    mixed = folder / 'mixed.cwa'
    mixed.write_bytes(first + packet)
    yield 'mixed-layout', mixed, {}
    yield 'mixed-resample', mixed, {'resample_hz': 60.0}


def collect(root, expected=None):
    output = {'python': platform.python_version(), 'numpy': np.__version__, 'pandas': pd.__version__, 'cases': {}}
    arrays = {}
    timings = {}
    for name, path, opts in cases(root):
        start = time.perf_counter()
        data = reader.read_cwa_file(str(path), **opts)
        timings[name] = time.perf_counter() - start
        info = {'columns': list(data.columns), 'dtypes': [str(x) for x in data.dtypes],
                'index_dtype': str(data.index.dtype), 'timezone': str(data.index.tz),
                'shape': list(data.shape), 'dataframe_bytes': int(data.memory_usage(index=True, deep=True).sum())}
        output['cases'][name] = info
        # datetime values explicitly converted to integer nanoseconds on both sides.
        arrays[name + '-index'] = data.index.as_unit('ns').asi8
        arrays[name + '-values'] = data.to_numpy()
        if expected is not None:
            assert info == expected['report']['cases'][name], (name, info)
            np.testing.assert_array_equal(arrays[name + '-index'], expected['arrays'][name + '-index'])
            if opts.get('resample_hz') is None:
                np.testing.assert_array_equal(arrays[name + '-values'], expected['arrays'][name + '-values'])
            else:
                # f32 interpolation allows rounding error; NaNs must still match.
                np.testing.assert_allclose(arrays[name + '-values'], expected['arrays'][name + '-values'], rtol=1e-6, atol=1e-6, equal_nan=True)
    path = root / 'tests/reference_data/openmovement/example-610-steps.cwa'
    output['metadata'] = normalized(reader.read_metadata(str(path)))
    output['sampling_consistency_report'] = normalized(reader.sampling_consistency_report(str(path)))
    export = root / 'export.csv'
    reader.write_cwa_csv(str(path), str(export), cut=reader.seconds(1.2, 3.7), fixed_utc_offset_timezone=datetime.timezone(datetime.timedelta(hours=5.5)))
    output['csv_sha256'] = hashlib.sha256(export.read_bytes()).hexdigest()
    output['csv_bytes'] = export.stat().st_size
    errors = {}
    broken = root / 'truncated.cwa'
    broken.write_bytes(path.read_bytes()[:1100])
    for name, fn in [('truncated', lambda: reader.read_cwa_file(str(broken))),
                     ('invalid-rate', lambda: reader.read_cwa_file(str(path), resample_hz=-1)),
                     ('invalid-cut', lambda: reader.read_cwa_file(str(path), cut=reader.seconds(3, 1)))]:
        try:
            fn()
        except Exception as exc:
            errors[name] = {'type': type(exc).__name__, 'message': str(exc)}
        else:
            raise AssertionError(f'{name} did not raise')
    output['errors'] = errors
    if expected is not None:
        for field in ('metadata', 'sampling_consistency_report', 'csv_sha256', 'csv_bytes', 'errors'):
            assert output[field] == expected['report'][field], (field, output[field], expected['report'][field])
    output['timings_seconds'] = timings
    output['fixture_bytes'] = path.stat().st_size
    return output, arrays


if __name__ == '__main__':
    root = Path(sys.argv[1]).resolve()
    out = Path(sys.argv[2]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    checkout = out / 'native-checkout'
    shutil.copytree(root / 'python/tests', checkout / 'python/tests', dirs_exist_ok=True)
    shutil.copytree(root / 'tests/reference_data', checkout / 'tests/reference_data', dirs_exist_ok=True)
    report, arrays = collect(checkout)
    (out / 'native-report.json').write_text(json.dumps(report, indent=2) + '\n')
    np.savez_compressed(out / 'native-arrays.npz', **arrays)
