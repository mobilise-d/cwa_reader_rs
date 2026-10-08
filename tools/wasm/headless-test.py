"""Run the browser acceptance test and verify recovered CSV bytes."""
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen
from playwright.sync_api import sync_playwright

repo = Path(__file__).resolve().parents[2]
out = Path(sys.argv[1]).resolve()
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8793
origin = f'http://127.0.0.1:{port}'
(out / 'results').mkdir(parents=True, exist_ok=True)
report_path = out / 'results/browser-report.json'
report_path.unlink(missing_ok=True)
server_log = (out / 'results/server.log').open('w')
server = subprocess.Popen([sys.executable, str(repo / 'tools/wasm/serve-runtime.py'), str(out), '--port', str(port)], stdout=server_log, stderr=server_log)
try:
    for attempt in range(100):
        try:
            urlopen(origin + '/lab/index.html').close()
            break
        except OSError:
            time.sleep(.1)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_default_timeout(180000)
        page.on('console', lambda message: print('browser console:', message.type, message.text, flush=True) if message.type in ('warning', 'error') or message.text.startswith('CWA stage:') else None)
        page.on('pageerror', lambda error: print('browser page error:', error, flush=True))
        page.goto(origin + '/lab/index.html?exposeAppInBrowser=true')
        page.wait_for_function('Boolean(window.jupyterapp)', timeout=120000)
        page.evaluate('source => {globalThis.eval(source);}', (repo / 'tools/wasm/browser-test.js').read_text())
        page.wait_for_function('window.cwaTestDone === true', timeout=180000)
        errors = page.evaluate('({error:window.cwaTestError,messages:window.cwaTestMessages})')
        browser.close()
    if not report_path.exists():
        raise RuntimeError(json.dumps(errors))
    report = json.loads(report_path.read_text())
    if not report.get('success'):
        raise RuntimeError(json.dumps(report))
    recovered = out / 'results/export.csv'
    assert hashlib.sha256(recovered.read_bytes()).hexdigest() == report['parity']['csv_sha256']
    print(f"Xeus browser parity passed: {len(report['parity']['cases'])} direct cases and existing pytest suite")
finally:
    server.terminate()
    server.wait(timeout=10)
    server_log.close()
