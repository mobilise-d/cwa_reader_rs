"""Executed in the actual Xeus worker; transfer browser bytes into worker MEMFS."""
import io
import json
import sys
import time
import traceback
import zipfile
from pathlib import Path
import pyjs

async def fetch_bytes(name):
    response = await pyjs.js.fetch(CWA_TEST_ORIGIN + '/assets/cwa-test/' + name)
    if not response.ok:
        raise RuntimeError(f'fetch failed: {name}')
    # Uint8Array conversion is explicit; the resulting bytes are copied to MEMFS.
    buffer = await response.arrayBuffer()
    return bytes(pyjs.to_py(pyjs.js.Uint8Array.new(buffer)))

def heap_bytes():
    # A pyjs buffer view exposes the actual Emscripten memory buffer.
    import numpy as np
    probe = np.zeros(1, dtype=np.uint8)
    return int(pyjs.buffer_to_js_typed_array(probe, view=True).buffer.byteLength)

report = {}
try:
    root = Path('/cwa-browser-test')
    root.mkdir(exist_ok=True)
    transfer_start = time.perf_counter()
    zipfile.ZipFile(io.BytesIO(await fetch_bytes('checkout-tests.zip'))).extractall(root)
    report['fixture_transfer_seconds'] = time.perf_counter() - transfer_start
    sys.path.insert(0, str(root))
    import parity
    import numpy as np
    import gc
    import statistics
    import cwa_reader_rs
    gc.collect()
    before = heap_bytes()
    full_timings = []
    for repeat in range(7):
        start = time.perf_counter()
        data = cwa_reader_rs.read_cwa_file(str(root / 'tests/reference_data/openmovement/example-610-steps.cwa'))
        full_timings.append(time.perf_counter() - start)
        after = heap_bytes()
        dataframe_bytes = int(data.memory_usage(index=True, deep=True).sum())
        del data
    report['measurement'] = {'full_read_seconds': full_timings, 'warm_median_seconds': statistics.median(full_timings[1:]),
        'wasm_committed_heap_before_bytes': before, 'wasm_committed_heap_after_bytes': after,
        'dataframe_bytes': dataframe_bytes, 'note': 'Committed heap capacity, not peak live Rust/Python allocation'}
    native = json.loads((await fetch_bytes('native-report.json')).decode())
    arrays = np.load(io.BytesIO(await fetch_bytes('native-arrays.npz')))
    report['parity'], _ = parity.collect(root, {'report': native, 'arrays': arrays})
    import pytest
    start = time.perf_counter()
    class Summary:
        def pytest_sessionfinish(self, session, exitstatus):
            report['pytest_tests_collected'] = session.testscollected
    report['pytest_exit_code'] = int(pytest.main(['-q', str(root / 'python/tests'), '-p', 'no:cacheprovider'], plugins=[Summary()]))
    report['pytest_seconds'] = time.perf_counter() - start
    # Recover output from worker storage through the same worker JS bridge.
    csv = (root / 'export.csv').read_bytes()
    response = await pyjs.js.fetch(CWA_TEST_ORIGIN + '/results/export.csv', pyjs.to_js({'method': 'POST', 'body': csv.decode()}))
    assert response.ok
    report['success'] = report['pytest_exit_code'] == 0
except BaseException:
    report['success'] = False
    report['error'] = traceback.format_exc()
response = await pyjs.js.fetch(CWA_TEST_ORIGIN + '/results/browser-report.json', pyjs.to_js({'method': 'POST', 'body': json.dumps(report)}))
print('CWA_BROWSER_RESULT', json.dumps(report))
if not report['success']:
    raise RuntimeError('Xeus browser validation failed')
