// Install the actual tarball, then test its production assets under a non-root base.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, cpSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { build, preview } from 'vite';
import { chromium } from '@playwright/test';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const receipt = JSON.parse(readFileSync(path.join(root, 'dist/npm-pack.json')));
const archive = path.join(root, 'dist', receipt.filename);
const consumer = mkdtempSync(path.join(tmpdir(), 'cwa-npm-consumer-'));
let server, browser;
try {
  cpSync(path.join(root, 'tests/npm-consumer'), consumer, { recursive: true });
  writeFileSync(path.join(consumer, 'package.json'), JSON.stringify({ name: 'cwa-installed-consumer', private: true, type: 'module' }));
  execFileSync('npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', archive], { cwd: consumer, stdio: 'pipe' });
  execFileSync(process.execPath, [path.join(root, 'node_modules/typescript/bin/tsc'), '--noEmit', '--strict', '--target', 'ES2022', '--module', 'ESNext', '--moduleResolution', 'bundler', '--lib', 'ES2022,DOM,ESNext.Disposable', 'main.ts'], { cwd: consumer, stdio: 'pipe' });
  await build({ configFile: false, root: consumer, base: '/reader-test/', logLevel: 'warn' });
  server = await preview({ configFile: false, root: consumer, base: '/reader-test/', logLevel: 'warn', preview: { host: '127.0.0.1', port: 5307, strictPort: true } });
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const failures = [];
  const assets = [];
  page.on('requestfailed', request => failures.push(request.url()));
  page.on('pageerror', error => failures.push(error.message));
  page.on('response', response => { if (response.url().includes('/assets/')) assets.push({ url: response.url(), status: response.status() }); });
  await page.goto('http://127.0.0.1:5307/reader-test/');
  await page.locator('#file').setInputFiles(path.join(root, '../tests/reference_data/openmovement/example-610-steps.cwa'));
  await page.waitForFunction(() => document.querySelector('#result').dataset.done === 'true');
  const actual = JSON.parse(await page.locator('#result').textContent());
  execFileSync(process.env.CWA_NATIVE_PYTHON || 'python3', [path.join(root, 'tests/native-oracle.py'), path.join(root, '.test-data')], { stdio: 'pipe' });
  const expected = JSON.parse(readFileSync(path.join(root, '.test-data/expected.json')));
  const selected = expected.cases.find(spec => spec.name === 'blocks');
  const { start_from_data_raw, end_from_data_raw, ...header } = expected.metadata;
  assert.deepEqual(actual.metadata, expected.metadata);
  assert.deepEqual(actual.header, header);
  assert.equal(actual.rows, selected.rows);
  assert.equal(actual.timestamps_sha256, selected.timestamps_sha256);
  assert.equal(actual.acc_x_sha256, selected.column_sha256.acc_x);
  assert.deepEqual(failures, []);
  assert(assets.some(asset => asset.url.endsWith('.wasm') && asset.status === 200), 'Installed production app must load its Wasm asset');
  assert(assets.every(asset => asset.status === 200), 'Production asset request failed');
  const installed = JSON.parse(readFileSync(path.join(consumer, 'node_modules/@mobilise-d/cwa-reader/package.json')));
  const report = { package: installed.name, version: installed.version, tarball_sha256: receipt.sha256,
    vite: JSON.parse(readFileSync(path.join(root, 'node_modules/vite/package.json'))).version,
    browser: browser.version(), base: '/reader-test/', metadata_matches_native: true,
    sample_rows: actual.rows, exact_sample_timestamps: true, exact_acceleration: true, assets };
  mkdirSync(path.join(root, 'test-results'), { recursive: true });
  writeFileSync(path.join(root, 'test-results/npm-consumer.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report));
} finally {
  await browser?.close();
  await new Promise(resolve => server ? server.httpServer.close(resolve) : resolve());
  rmSync(consumer, { recursive: true, force: true });
}
