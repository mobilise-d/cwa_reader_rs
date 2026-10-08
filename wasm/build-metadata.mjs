import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';

const command = (...args) => execFileSync(args[0], args.slice(1), { encoding: 'utf8' }).trim();
const manifest = {
  source_revision: command('git', 'rev-parse', 'HEAD'),
  source_dirty: command('git', 'status', '--porcelain', '--', '../src', '../Cargo.toml', '../Cargo.lock', '.') !== '',
  target: 'wasm32-unknown-unknown',
  rustc: command('rustc', '+1.90.0', '--version'),
  cargo: command('cargo', '+1.90.0', '--version'),
  wasm_bindgen: command('wasm-bindgen', '--version'),
  node: process.version,
  dependency_lock_sha256: createHash('sha256').update(readFileSync('Cargo.lock')).digest('hex'),
  sha256: {},
};
for (const name of readdirSync('pkg').filter(name => name !== 'build-metadata.json').sort()) {
  manifest.sha256[name] = createHash('sha256').update(readFileSync(`pkg/${name}`)).digest('hex');
}
writeFileSync('pkg/build-metadata.json', JSON.stringify(manifest, null, 2) + '\n');
