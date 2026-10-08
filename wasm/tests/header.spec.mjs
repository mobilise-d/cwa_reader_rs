import { test, expect } from '@playwright/test';
import { writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const fixture = path.join(root, 'tests/reference_data/openmovement/example-610-steps.cwa');

function nativeHeader() {
  const result = spawnSync(process.env.CWA_NATIVE_PYTHON || 'python3', ['-c', `
import json, cwa_reader_rs
metadata = cwa_reader_rs.read_metadata(${JSON.stringify(fixture)})
metadata.pop('start_from_data_raw')
metadata.pop('end_from_data_raw')
print(json.dumps(metadata))
`], { encoding: 'utf8', cwd: root });
  if (result.status !== 0) throw new Error(`Native oracle failed: ${result.stderr}`);
  return JSON.parse(result.stdout);
}

test('selected browser File header matches the native Python package', async ({ page, browser }) => {
  const expected = nativeHeader();
  await page.goto('/');
  await expect(page.getByLabel('Select a CWA file')).toBeEnabled();
  await page.getByLabel('Select a CWA file').setInputFiles(fixture);
  await expect(page.getByRole('status')).toContainText('Read 1,024 bytes');
  expect(JSON.parse(await page.locator('#metadata').textContent())).toEqual(expected);
  const metrics = await page.evaluate(async () => {
    const { default: init, readHeader } = await import('/pkg/cwa_reader_browser.js');
    const wasm = await init();
    const file = document.querySelector('#file').files[0];
    const readStart = performance.now();
    const bytes = new Uint8Array(await file.slice(0, 1024).arrayBuffer());
    const header_read_ms = performance.now() - readStart;
    const wasm_memory_before_bytes = wasm.memory.buffer.byteLength;
    const parseStart = performance.now();
    for (let i = 0; i < 1000; ++i) readHeader(bytes);
    return {
      file_bytes: file.size, header_bytes: bytes.length, header_read_ms,
      iterations: 1000, parse_total_ms: performance.now() - parseStart,
      wasm_memory_before_bytes,
      wasm_memory_after_bytes: wasm.memory.buffer.byteLength,
    };
  });
  metrics.browser = browser.version();
  writeFileSync('test-results/header-metrics.json', JSON.stringify(metrics, null, 2) + '\n');
  await test.info().attach('header-metrics', { body: JSON.stringify(metrics), contentType: 'application/json' });
});

test('invalid browser files throw recoverable Errors and the next valid file works', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByLabel('Select a CWA file')).toBeEnabled();
  for (const bytes of [Buffer.alloc(1023), Buffer.alloc(1024)]) {
    await page.getByLabel('Select a CWA file').setInputFiles({
      name: 'invalid.cwa', mimeType: 'application/octet-stream', buffer: bytes,
    });
    await expect(page.getByRole('status')).toContainText('Cannot read header:');
    await expect(page.locator('#metadata')).toHaveText('No metadata available.');
  }
  const result = await page.evaluate(async () => {
    const { readHeader } = await import('/pkg/cwa_reader_browser.js');
    try { readHeader(new Uint8Array(0)); }
    catch (error) { return { isError: error instanceof Error, message: error.message }; }
  });
  expect(result.isError).toBe(true);
  expect(result.message).toContain('failed to fill whole buffer');
  await page.getByLabel('Select a CWA file').setInputFiles(fixture);
  await expect(page.getByRole('status')).toContainText('Read 1,024 bytes');
  expect(JSON.parse(await page.locator('#metadata').textContent())).toEqual(nativeHeader());
});

test('configured AX6 sensors and naive device timestamps survive the browser bridge', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByLabel('Select a CWA file')).toBeEnabled();
  const metadata = await page.evaluate(async () => {
    const { readHeader } = await import('/pkg/cwa_reader_browser.js');
    const bytes = new Uint8Array(await (await fetch('/fixture.cwa')).arrayBuffer());
    bytes[4] = 0x64; // AX6
    bytes[35] = 0x14; // 500 dps gyro, magnetometer enabled
    const view = new DataView(bytes.buffer);
    // Documented CWA packed timestamp for 2026-03-29T00:00:00.
    view.setUint32(13, (26 << 26) | (3 << 22) | (29 << 17), true);
    view.setUint32(17, 0xffffffff, true);
    return readHeader(bytes.subarray(0, 1024));
  });
  expect(metadata.hardware_type).toBe('AX6');
  expect(metadata.gyro_range).toBe(500);
  expect(metadata.magnetometer_enabled).toBe(true);
  expect(metadata.logging_start_time_raw).toBe('2026-03-29T00:00:00');
  expect(metadata.logging_end_time_raw).toBeNull();
  expect(metadata.last_change_time_raw).toBe('2012-03-27T10:14:08');
});
