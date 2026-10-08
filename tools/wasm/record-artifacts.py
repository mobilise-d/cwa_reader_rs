"""Record source revision, exact solved recipe metadata and artifact hashes."""
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[2]
out = Path(sys.argv[1]).resolve()
packages = sorted((out / 'channel/emscripten-wasm32').glob('cwa_reader_rs-*.tar.bz2'))
if not packages:
    raise SystemExit('No built cwa_reader_rs conda artifact')
manifest = {
    'source_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip(),
    'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=repo, text=True)),
    'rattler_build': subprocess.check_output(['rattler-build', '--version'], text=True).strip(),
    'artifacts': [],
}
for path in packages:
    with tarfile.open(path) as archive:
        index = json.load(archive.extractfile('info/index.json'))
        module_name = next(name for name in archive.getnames() if name.endswith('.so'))
        module_bytes = archive.extractfile(module_name).read()
        metadata = {name: archive.extractfile(name).read().decode() for name in archive.getnames()
                    if name.startswith('share/cwa-reader-build/') or name in ('info/index.json', 'info/recipe/rendered_recipe.yaml')}
    # Rattler can retain old repodata when replacing the same local build name.
    repodata_path = path.parent / 'repodata.json'
    repodata = json.loads(repodata_path.read_text())
    repodata.setdefault('packages', {})[path.name] = {**index, 'size': path.stat().st_size,
        'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'md5': hashlib.md5(path.read_bytes()).hexdigest()}
    repodata_path.write_text(json.dumps(repodata, indent=2) + '\n')
    with tempfile.NamedTemporaryFile(suffix='.so') as module_file:
        module_file.write(module_bytes)
        module_file.flush()
        inspection = json.loads(subprocess.check_output(['node', str(Path(__file__).with_name('inspect-module.js')), module_file.name], text=True))
    manifest['artifacts'].append({'path': str(path.relative_to(out)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                                  'size_bytes': path.stat().st_size, 'module_path': module_name, 'module_sha256': hashlib.sha256(module_bytes).hexdigest(), 'module_inspection': inspection, 'metadata': metadata})
(out / 'artifact-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(out / 'artifact-manifest.json')
