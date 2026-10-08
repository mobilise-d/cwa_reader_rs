"""Assemble tested Xeus package and a fixture-free local-channel release archive."""
import argparse
import gzip
import hashlib
import json
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('output', type=Path, help='successful build-xeus/runtime/headless-test output')
parser.add_argument('--release-tag', help='require the built version to match this release tag')
parser.add_argument('--source-revision', help='require provenance from this exact tested commit')
args = parser.parse_args()
out = args.output.resolve()
manifest = json.loads((out / 'artifact-manifest.json').read_text())
assert not manifest['source_dirty'], 'build source is dirty'
if args.source_revision:
    assert manifest['source_revision'] == args.source_revision, 'build source and release tag commit differ'
artifact = manifest['artifacts'][0]
package = out / artifact['path']
assert hashlib.sha256(package.read_bytes()).hexdigest() == artifact['sha256'], 'package checksum mismatch'
report = json.loads((out / 'results/browser-report.json').read_text())
assert report['success'] and report['pytest_exit_code'] == 0, 'browser acceptance failed'
with tarfile.open(package) as archive:
    index = json.load(archive.extractfile('info/index.json'))
    assert not any(name.endswith('.cwa') or 'reference_data/' in name for name in archive.getnames()), 'package contains recording fixtures'
runtime = json.loads((out / 'runtime-packages.json').read_text())
packages = {package['name']: package for package in runtime['packages']}
version = index['version']
assert (packages['cwa_reader_rs']['version'], packages['cwa_reader_rs']['build']) == (version, index['build']), 'runtime reader differs from package'
if args.release_tag:
    assert args.release_tag.removeprefix('v') == version, 'release tag and package version differ'
    tagged = subprocess.check_output(
        ['git', 'rev-parse', f'{args.release_tag}^{{commit}}'],
        cwd=Path(__file__).resolve().parents[2], text=True).strip()
    assert tagged == manifest['source_revision'], 'build source and release tag commit differ'
pins = ('cwa_reader_rs', 'xeus-python', 'python', 'python_abi', 'emscripten-abi', 'numpy', 'pandas')
dependencies = '\n'.join(f"  - {name}={packages[name]['version']}={packages[name]['build']}" for name in pins)
stem = f'cwa_reader_rs-{version}-xeus-python313-emscripten409'
assets = out / 'release'
assets.mkdir(exist_ok=True)
shutil.copyfile(package, assets / package.name)
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary) / (stem + '-channel')
    for relative in (artifact['path'], 'channel/emscripten-wasm32/repodata.json',
                     'channel/noarch/repodata.json', 'artifact-manifest.json',
                     'runtime-packages.json', 'results/browser-report.json'):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(out / relative, target)
    (root / 'README.md').write_text(f'''# cwa_reader_rs {version} Xeus local channel

This package targets CPython 3.13.1 / Emscripten 4.0.9, with the exact runtime
pins and tested source recorded in artifact-manifest.json and runtime-packages.json.
The conda package contains compiler/sysconfig/source metadata in share/cwa-reader-build.
The browser result report records actual Xeus import, reader and CSV validation.

Extract the archive and verify its files with `sha256sum -c SHA256SUMS.txt`.
Add the absolute file:// URL of its channel/ directory first in your Xeus environment:

```yaml
channels:
  - file:///absolute/path/to/{root.name}/channel
  - https://repo.prefix.dev/emscripten-forge-4x
  - conda-forge
dependencies:
{dependencies}
```

Run `jupyter lite build` with this environment.yml. Runtime dependencies are
resolved from the listed channels; this archive supplies the reader's local channel.
Recording fixtures and test runtime downloads are excluded.

Full build/install guide at the exact source:
https://github.com/mobilise-d/cwa_reader_rs/blob/{manifest['source_revision']}/recipes/xeus/README.md
''')
    files = sorted(path for path in root.rglob('*') if path.is_file())
    (root / 'SHA256SUMS.txt').write_text(''.join(
        f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}\n' for path in files))
    bundle = assets / (stem + '-channel.tar.gz')
    def normalized(info):
        info.uid = info.gid = info.mtime = 0
        info.uname = info.gname = ''
        return info
    with bundle.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as archive:
            archive.add(root, arcname=root.name, filter=normalized)
checksums = assets / (stem + '-SHA256SUMS.txt')
checksums.write_text(''.join(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n'
                            for path in (assets / package.name, bundle)))
print('\n'.join(str(path) for path in (assets / package.name, bundle, checksums)))
