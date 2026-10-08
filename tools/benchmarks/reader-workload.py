"""Execute one reader workload; used by native Python and the Xeus worker.

Parameters BENCH_PATH/BENCH_CASE/BENCH_OPTIONS are supplied by the runner.
Output contains aggregate measurements and hashes, never recorded sensor values.
"""
import datetime
import hashlib
import json
import time
import cwa_reader_rs as reader
# Import DataFrame dependencies outside operation timing on both targets.
import numpy as np
import pandas as pd

def run_workload(BENCH_PATH, BENCH_CASE, BENCH_OPTIONS):
    started = time.perf_counter()
    metadata_started = time.perf_counter()
    metadata = reader.read_metadata(BENCH_PATH)
    metadata_seconds = time.perf_counter() - metadata_started
    start = datetime.datetime.fromisoformat(metadata['start_from_data_raw'])
    end = datetime.datetime.fromisoformat(metadata['end_from_data_raw'])
    duration = (end - start).total_seconds()
    options = dict(BENCH_OPTIONS)
    if BENCH_CASE in ('early', 'middle', 'late'):
        seconds = {'early': 0.0, 'middle': duration / 2, 'late': max(0, duration - 61)}[BENCH_CASE]
        options['cut'] = reader.seconds(seconds, seconds + 60)
        reader_started = time.perf_counter()
        frame = reader.read_cwa_file(BENCH_PATH, **options)
        reader_seconds = time.perf_counter() - reader_started
        index = frame.index.as_unit('ns').asi8
        values = frame.to_numpy().copy()
        values[values != values] = float('nan')
        result = {'rows': len(frame), 'columns': len(frame.columns),
                  'dataframe_bytes': int(frame.memory_usage(index=True, deep=True).sum()),
                  'index_sha256': hashlib.sha256(index.tobytes()).hexdigest(),
                  'values_sha256': hashlib.sha256(values.tobytes()).hexdigest()}
    elif BENCH_CASE == 'report':
        reader_started = time.perf_counter()
        report = reader.sampling_consistency_report(BENCH_PATH)
        reader_seconds = time.perf_counter() - reader_started
        result = {'report_sha256': hashlib.sha256(json.dumps(report, sort_keys=True, default=str).encode()).hexdigest()}
    elif BENCH_CASE == 'csv-sink':
        reader_started = time.perf_counter()
        reader.write_cwa_csv(BENCH_PATH, '/dev/null', **options)
        reader_seconds = time.perf_counter() - reader_started
        result = {'sink': '/dev/null', 'collector': False}
    elif BENCH_CASE == 'metadata':
        reader_seconds = metadata_seconds
        result = {}
    else:
        raise ValueError(BENCH_CASE)
    result.update(reader_seconds=reader_seconds, metadata_seconds=metadata_seconds,
                  end_to_end_seconds=time.perf_counter() - started, duration_seconds=duration,
                  sampling_rate_hz=metadata['sample_rate_hz'], hardware=metadata['hardware_type'],
                  python=__import__('platform').python_version(), numpy=np.__version__, pandas=pd.__version__)
    return result


BENCH_RESULT = run_workload(BENCH_PATH, BENCH_CASE, BENCH_OPTIONS)
