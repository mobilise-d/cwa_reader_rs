"""Build a local JupyterLite/Xeus runtime consuming the local conda channel."""
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

repo = Path(__file__).resolve().parents[2]
out = Path(sys.argv[1]).resolve()
runtime = out / 'runtime'
runtime.mkdir(parents=True, exist_ok=True)
channel = (out / 'channel').as_uri()
(runtime / 'environment.yml').write_text(f'''name: cwa-reader-wasm
channels:
  - {channel}
  - https://repo.prefix.dev/emscripten-forge-4x
  - conda-forge
dependencies:
  - cwa_reader_rs=0.5.0
  - xeus-python=0.19.0=py313he5686da_3
  - pytest=8.4.2
''')
(runtime / 'jupyter-lite.json').write_text(json.dumps({'jupyter-lite-schema-version': 0,
    'jupyter-config-data': {'exposeAppInBrowser': True}}))
# Third-party fixtures stay local, outside distributable packages/CI upload paths.
assets = runtime / 'dist/assets/cwa-test'
subprocess.run(['jupyter', 'lite', 'build', '--output-dir', 'dist'], cwd=runtime, check=True)
config_path = runtime / 'dist/jupyter-lite.json'
config = json.loads(config_path.read_text())
config.setdefault('jupyter-config-data', {})['exposeAppInBrowser'] = True
config_path.write_text(json.dumps(config, indent=2))
assets.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(assets / 'checkout-tests.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
    for folder in ('python/tests', 'tests/reference_data'):
        for path in sorted((repo / folder).rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts:
                archive.write(path, path.relative_to(repo))
    archive.write(repo / 'tools/wasm/parity.py', 'parity.py')
for name in ('native-report.json', 'native-arrays.npz'):
    shutil.copyfile(out / name, assets / name)
shutil.copyfile(repo / 'tools/wasm/worker-test.py', assets / 'worker-test.py')
metadata = runtime / 'dist/xeus/cwa-reader-wasm/empack_env_meta.json'
shutil.copyfile(metadata, out / 'runtime-packages.json')
print(runtime / 'dist')
