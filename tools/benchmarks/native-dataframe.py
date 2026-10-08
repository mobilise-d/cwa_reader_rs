"""Measure full/24-hour DataFrame collection with an explicitly installed reader.

Fingerprints and input paths belong in private reports outside the checkout.
RSS is captured immediately after read_cwa_file, before hashing allocations.
"""
import argparse
import datetime
import hashlib
import json
import platform
import time
from pathlib import Path
import numpy as np
import pandas as pd
import cwa_reader_rs as reader

parser = argparse.ArgumentParser()
parser.add_argument('file', type=Path)
parser.add_argument('--case', choices=['full', 'first-day', 'middle-day', 'last-day'], required=True)
parser.add_argument('--batch-packets', type=int, default=256)
args = parser.parse_args()
metadata = reader.read_metadata(str(args.file))
duration = (datetime.datetime.fromisoformat(metadata['end_from_data_raw']) -
            datetime.datetime.fromisoformat(metadata['start_from_data_raw'])).total_seconds()
options = {'batch_packets': args.batch_packets}
if args.case != 'full':
    if duration < 86400:
        parser.error('24-hour cases require at least 24 hours of valid recording')
    start = {'first-day': 0, 'middle-day': duration / 2 - 43200,
             'last-day': duration - 86400}[args.case]
    options['cut'] = reader.seconds(start, start + 86400)

# Linux VmHWM measures this process, including Python/dependency import costs.
def peak_rss_bytes():
    return int(next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines()
                    if line.startswith('VmHWM:'))) * 1024

started = time.perf_counter()
frame = reader.read_cwa_file(str(args.file), **options)
elapsed = time.perf_counter() - started
read_peak_rss = peak_rss_bytes()
# Hash outside reader timing with bounded temporary buffers. Do not materialize
# a second full DataFrame or a full row-major values array.
index_hash = hashlib.sha256()
for offset in range(0, len(frame), 262144):
    index_chunk = frame.index[offset:offset + 262144].as_unit('ns').asi8
    index_hash.update(index_chunk.tobytes())
values_hash = {}
for name in frame.columns:
    digest = hashlib.sha256()
    values = frame[name].to_numpy(copy=False)
    for offset in range(0, len(frame), 262144):
        chunk = values[offset:offset + 262144].copy()
        chunk[np.isnan(chunk)] = np.float32('nan')
        digest.update(chunk.tobytes())
    values_hash[name] = digest.hexdigest()
print(json.dumps({'case': args.case, 'options': {'batch_packets': args.batch_packets},
    'reader_seconds': elapsed, 'rows': len(frame), 'columns': list(frame.columns),
    'dtypes': [str(dtype) for dtype in frame.dtypes], 'index_dtype': str(frame.index.dtype),
    'timezone': str(frame.index.tz), 'dataframe_bytes': int(frame.memory_usage(index=True).sum()),
    'index_sha256': index_hash.hexdigest(), 'values_sha256': values_hash,
    'reader_process_peak_rss_bytes': read_peak_rss,
    'total_process_peak_rss_bytes': peak_rss_bytes(), 'input_bytes': args.file.stat().st_size,
    'duration_seconds': duration, 'python': platform.python_version(),
    'numpy': np.__version__, 'pandas': pd.__version__}))
