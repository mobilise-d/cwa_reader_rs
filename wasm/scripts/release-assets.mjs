// Assemble tested browser assets. This script never uploads or publishes them.
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);
const manifest = JSON.parse(readFileSync('pkg/package.json'));
const metadata = JSON.parse(readFileSync('pkg/build-metadata.json'));
const receipt = JSON.parse(readFileSync('dist/npm-pack.json'));
const consumer = JSON.parse(readFileSync('test-results/npm-consumer.json'));
const tests = JSON.parse(readFileSync('test-results/results.json'));
const digest = file => createHash('sha256').update(readFileSync(file)).digest('hex');
assert.equal(digest(`dist/${receipt.filename}`), receipt.sha256);
assert.equal(consumer.tarball_sha256, receipt.sha256);
assert.equal(consumer.version, manifest.version);
assert(consumer.metadata_matches_native && consumer.exact_sample_timestamps && consumer.exact_acceleration);
assert.equal(tests.stats.unexpected, 0);
if (process.env.RELEASE_TAG) {
  assert.equal(process.env.RELEASE_TAG.replace(/^v/, ''), manifest.version);
  const revision = ref => execFileSync('git', ['rev-parse', ref], { encoding: 'utf8' }).trim();
  assert.equal(metadata.source_revision, revision('HEAD'));
  assert.equal(metadata.source_revision, revision(`${process.env.RELEASE_TAG}^{commit}`));
  assert.equal(metadata.source_dirty, false);
}
const prefix = `cwa-reader-browser-${manifest.version}`;
const output = path.join(root, 'dist/release');
rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });
const staging = mkdtempSync(path.join(tmpdir(), 'cwa-browser-release-'));
const assets = [];
const copyAsset = (source, name) => { cpSync(source, path.join(output, name)); assets.push(name); };
const archive = name => {
  const filename = `${name}.tar.gz`;
  execFileSync('tar', ['--sort=name', '--mtime=@0', '--owner=0', '--group=0', '--numeric-owner', '-czf', path.join(output, filename), '-C', staging, name]);
  assets.push(filename);
};
try {
  const browser = path.join(staging, prefix);
  mkdirSync(path.join(browser, 'pkg'), { recursive: true });
  for (const { path: name } of receipt.files) cpSync(path.join(root, 'pkg', name), path.join(browser, 'pkg', name));
  mkdirSync(path.join(browser, 'example'));
  for (const name of ['index.html', 'inspect.js', 'reader-worker.js']) cpSync(`example/${name}`, path.join(browser, 'example', name));
  mkdirSync(path.join(browser, 'scripts'));
  cpSync('scripts/serve.mjs', path.join(browser, 'scripts/serve.mjs'));
  cpSync('pkg/LICENSE', path.join(browser, 'LICENSE'));
  writeFileSync(path.join(browser, 'README.md'), readFileSync('js/npm-README.md', 'utf8') + '\n## Run the included demo\n\nFrom this extracted directory, run `node scripts/serve.mjs` with Node.js 24,\nthen open http://127.0.0.1:5287. No npm installation is needed for the demo.\nSelect your own CWA file; recording bytes stay in the browser.\n');
  archive(prefix);
  const validation = path.join(staging, `${prefix}-validation`);
  mkdirSync(validation);
  for (const name of ['results.json', 'header-metrics.json', 'recording-metrics.json', 'batch-metrics.json', 'npm-consumer.json']) cpSync(`test-results/${name}`, path.join(validation, name));
  cpSync('pkg/build-metadata.json', path.join(validation, 'build-metadata.json'));
  cpSync('dist/npm-pack.json', path.join(validation, 'npm-pack.json'));
  archive(`${prefix}-validation`);
  copyAsset(`dist/${receipt.filename}`, receipt.filename);
  copyAsset('dist/npm-pack.json', `${prefix}-npm-pack.json`);
  copyAsset('pkg/build-metadata.json', `${prefix}-build-metadata.json`);
  writeFileSync(path.join(output, `${prefix}-SHA256SUMS.txt`), assets.sort().map(name => `${digest(path.join(output, name))}  ${name}\n`).join(''));
  console.log(`Release assets assembled in ${output}`);
} finally {
  rmSync(staging, { recursive: true, force: true });
}
