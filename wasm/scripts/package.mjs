// Maintainer build step: manifest, provenance and local npm archive. No install hook.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

process.chdir(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'));

const cargoMetadata = JSON.parse(execFileSync('cargo', ['+1.90.0', 'metadata', '--no-deps', '--format-version', '1', '--manifest-path', '../Cargo.toml'], { encoding: 'utf8' }));
const source = cargoMetadata.packages.find(pkg => pkg.name === 'cwa_reader_rs');
const manifest = {
  name: '@mobilise-d/cwa-reader',
  version: source.version,
  description: 'Browser CWA metadata and packet-batch reader backed by Rust/Wasm',
  private: true,
  type: 'module',
  license: source.license,
  main: './cwa_reader_file.js',
  types: './cwa_reader_file.d.ts',
  exports: {
    '.': { types: './cwa_reader_file.d.ts', import: './cwa_reader_file.js', default: './cwa_reader_file.js' },
    './bytes': { types: './cwa_reader_browser.d.ts', import: './cwa_reader_browser.js', default: './cwa_reader_browser.js' },
  },
  files: [
    'cwa_reader_file.js', 'cwa_reader_file.d.ts', 'cwa_reader_file_worker.js',
    'cwa_reader_browser.js', 'cwa_reader_browser.d.ts',
    'cwa_reader_browser_bg.wasm', 'cwa_reader_browser_bg.wasm.d.ts',
    'build-metadata.json', 'LICENSE', 'README.md',
  ],
};
writeFileSync('pkg/package.json', JSON.stringify(manifest, null, 2) + '\n');
writeFileSync('pkg/README.md', readFileSync('js/npm-README.md'));

const command = (...args) => execFileSync(args[0], args.slice(1), { encoding: 'utf8' }).trim();
const buildMetadata = {
  source_revision: command('git', 'rev-parse', 'HEAD'),
  source_dirty: command('git', 'status', '--porcelain', '--', '../src', '../crates', '../Cargo.toml', '../Cargo.lock', '.') !== '',
  target: 'wasm32-unknown-unknown',
  rustc: command('rustc', '+1.90.0', '--version'),
  cargo: command('cargo', '+1.90.0', '--version'),
  wasm_bindgen: command('wasm-bindgen', '--version'),
  node: process.version,
  dependency_lock_sha256: createHash('sha256').update(readFileSync('Cargo.lock')).digest('hex'),
  sha256: {},
};
for (const name of readdirSync('pkg').filter(name => name !== 'build-metadata.json').sort()) {
  buildMetadata.sha256[name] = createHash('sha256').update(readFileSync(`pkg/${name}`)).digest('hex');
}
writeFileSync('pkg/build-metadata.json', JSON.stringify(buildMetadata, null, 2) + '\n');

mkdirSync('dist', { recursive: true });
const [packed] = JSON.parse(execFileSync('npm', ['pack', './pkg', '--ignore-scripts', '--pack-destination', 'dist', '--json'], { encoding: 'utf8' }));
const receipt = { ...packed, sha256: createHash('sha256').update(readFileSync(`dist/${packed.filename}`)).digest('hex') };
writeFileSync('dist/npm-pack.json', JSON.stringify(receipt, null, 2) + '\n');
console.log(`Local npm package: dist/${packed.filename}`);
