"""Benchmark local Files in a real Xeus worker without whole-file MEMFS staging.

Pass the adapted official WORKERFS backend from a compatible runtime. Neither the
input recording nor its pathname is included in the report. Every case remounts
its File and resets counters; the kernel/allocator stays warm between cases.
"""
import argparse
import json
import subprocess
import time
from pathlib import Path
from urllib.request import urlopen
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright

parser = argparse.ArgumentParser()
parser.add_argument('output', type=Path, help='built tools/wasm runtime output')
parser.add_argument('file', type=Path)
parser.add_argument('workerfs', type=Path, help='adapted official WORKERFS JavaScript backend')
parser.add_argument('--report', type=Path, required=True)
parser.add_argument('--batch-packets', type=int)
parser.add_argument('--port', type=int, default=8795)
parser.add_argument('--cases', default='metadata,report,early,middle,late')
parser.add_argument('--repeats', type=int, default=3)
parser.add_argument('--resample-hz', type=float)
parser.add_argument('--timeout-seconds', type=int, default=180)
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
origin = f'http://127.0.0.1:{args.port}'
args.report.parent.mkdir(parents=True, exist_ok=True)
log = args.report.with_suffix('.server.log').open('w')
server = subprocess.Popen([__import__('sys').executable, str(repo / 'tools/wasm/serve-runtime.py'), str(args.output), '--port', str(args.port)], stdout=log, stderr=log)
results = []
args.report.write_text('[]\n')
receipt = args.output / 'artifact-manifest.json'
metadata = {'reader_artifact':json.loads(receipt.read_text()) if receipt.exists() else None,
            'workerfs_sha256':__import__('hashlib').sha256(args.workerfs.read_bytes()).hexdigest(),
            'runner_python':__import__('sys').version, 'repeats':args.repeats,
            'timeout_seconds':args.timeout_seconds,
            'benchmark_tools_sha256':{p.name:__import__('hashlib').sha256(p.read_bytes()).hexdigest() for p in (repo/'tools/benchmarks').iterdir() if p.suffix in ('.py','.js','.mjs')}}
# Keep the verbose tool/ABI receipt next to results, without input file paths.
args.report.with_suffix('.metadata.json').write_text(json.dumps(metadata,indent=2))
try:
    for _ in range(100):
        try:
            urlopen(origin + '/lab/index.html').close()
            break
        except OSError:
            time.sleep(.1)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        metadata['browser_version'] = browser.version
        args.report.with_suffix('.metadata.json').write_text(json.dumps(metadata,indent=2))
        page = browser.new_page()
        page.set_default_timeout(600000)
        page.goto(origin + '/lab/index.html?exposeAppInBrowser=true')
        page.wait_for_function('Boolean(window.jupyterapp)')
        page.evaluate('''async () => {
          const app=window.jupyterapp; await app.started; await app.serviceManager.ready;
          window.cwaKernel=await app.serviceManager.kernels.startNew({name:'xpython'});
          window.cwaExecute=async code => {
            const messages=[]; const request=window.cwaKernel.requestExecute({code,store_history:false});
            request.onIOPub=msg=> {if(msg.header.msg_type==='stream')messages.push(msg.content.text);
              if(msg.header.msg_type==='error')messages.push(JSON.stringify(msg.content));};
            const reply=await request.done;
            if(reply.content.status!=='ok')throw new Error(JSON.stringify(reply.content));
            return messages.join('');
          };
          const input=document.createElement('input');input.type='file';input.id='cwa-benchmark-input';document.body.append(input);
        }''')
        adapter = args.workerfs.read_text()
        meter = (repo / 'tools/benchmarks/workerfs-meter.js').read_text()
        page.evaluate('code => window.cwaExecute(code)', 'import pyjs,numpy as np,pandas as pd,json\npyjs.js.eval(' + repr(adapter) + ')\npyjs.js.eval(' + repr(meter) + ')')
        page.locator('#cwa-benchmark-input').set_input_files(str(args.file.resolve()))
        options = {}
        if args.batch_packets is not None:
            options['batch_packets'] = args.batch_packets
        if args.resample_hz is not None:
            options['resample_hz'] = args.resample_hz
        workload = (repo / 'tools/benchmarks/reader-workload.py').read_text()
        for case in args.cases.split(','):
            for repeat in range(args.repeats):
                page.evaluate("() => window.callGlobalReceiver('cwaBenchmarkFiles','mount', Array.from(document.getElementById('cwa-benchmark-input').files))")
                code = "import numpy as np,json\n_heap_before=pyjs.buffer_to_js_typed_array(np.zeros(1,dtype=np.uint8),view=True).buffer.byteLength\n"
                code += f"_bench_scope={{'BENCH_PATH':'/cwa-benchmark/recording.cwa','BENCH_CASE':{case!r},'BENCH_OPTIONS':{options!r}}}\nexec({workload!r}, _bench_scope)\nBENCH_RESULT=_bench_scope['BENCH_RESULT']\ndel _bench_scope\n"
                code += "\nBENCH_RESULT['wasm_committed_bytes_before']=int(_heap_before)\nBENCH_RESULT['wasm_committed_bytes_after']=int(pyjs.buffer_to_js_typed_array(np.zeros(1,dtype=np.uint8),view=True).buffer.byteLength)\nBENCH_RESULT['reads']=json.loads(str(pyjs.js.JSON.stringify(pyjs.js.cwaBenchmarkFiles.stats())))\nprint('CWA_BENCH_RESULT='+json.dumps(BENCH_RESULT))\n"
                page.evaluate('code => {window.cwaPending={done:false}; window.cwaExecute(code).then(output=>{window.cwaPending={done:true,output};},error=>{window.cwaPending={done:true,error:String(error)};});}', code)
                try:
                    page.wait_for_function('window.cwaPending.done', timeout=args.timeout_seconds * 1000)
                except PlaywrightTimeoutError:
                    results.append({'case':case, 'repeat':repeat, 'options':options,
                                    'status':'timeout', 'execution_seconds_lower_bound':args.timeout_seconds,
                                    'input_bytes':args.file.stat().st_size})
                    args.report.write_text(json.dumps(results, indent=2))
                    raise
                pending = page.evaluate('window.cwaPending')
                if pending.get('error'):
                    raise RuntimeError(pending['error'])
                output = pending['output']
                payload = next(line.removeprefix('CWA_BENCH_RESULT=') for line in output.splitlines() if line.startswith('CWA_BENCH_RESULT='))
                result = json.loads(payload)
                result.update(case=case, repeat=repeat, options=options, input_bytes=args.file.stat().st_size)
                results.append(result)
                args.report.write_text(json.dumps(results, indent=2))
                print(f"{case} repeat={repeat} seconds={result['reader_seconds']:.3f} physical_reads={result['reads']['physicalReadCalls']}", flush=True)
        page.evaluate('() => window.cwaKernel.shutdown()')
        browser.close()
except Exception as error:
    if not results or results[-1].get('status') != 'timeout':
        results.append({'status':'failed', 'error':type(error).__name__})
        args.report.write_text(json.dumps(results, indent=2))
    raise
finally:
    server.terminate()
    server.wait(timeout=10)
    log.close()
