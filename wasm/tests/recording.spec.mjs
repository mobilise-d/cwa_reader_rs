import { test, expect } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const fixture = path.join(root, 'tests/reference_data/openmovement/example-610-steps.cwa');

test.beforeAll(() => {
  const generated = spawnSync(process.env.CWA_NATIVE_PYTHON || 'python3', [
    path.join(root, 'wasm/tests/native-oracle.py'), path.join(root, 'wasm/.test-data'),
  ], { encoding: 'utf8', cwd: root });
  if (generated.status !== 0) throw new Error(generated.stderr);
});

test('full-file byte metadata and sampling report match native Python', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByLabel('Select a CWA file')).toBeEnabled();
  const actual = await page.evaluate(async () => {
    const reader = await import('/pkg/cwa_reader_browser.js');
    const bytes = new Uint8Array(await (await fetch('/fixture.cwa')).arrayBuffer());
    const expected = await (await fetch('/test-data/expected.json')).json();
    return { actual: { metadata: reader.readMetadata(bytes), report: reader.samplingConsistencyReport(bytes) }, expected: { metadata: expected.metadata, report: expected.report } };
  });
  expect(actual.actual).toEqual(actual.expected);
});

test('sample bytes, cuts, resampling, channels, offsets and CSV match native Python', async ({ page, browser }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await expect(page.getByLabel('Select a CWA file')).toBeEnabled();
  const report = await page.evaluate(async () => {
    const reader = await import('/pkg/cwa_reader_browser.js');
    const wasm = await reader.default();
    const expected = await (await fetch('/test-data/expected.json')).json();
    const wasm_memory_before_bytes = wasm.memory.buffer.byteLength;
    const digest = async (array) => Array.from(new Uint8Array(await crypto.subtle.digest(
      'SHA-256', new Uint8Array(array.buffer, array.byteOffset, array.byteLength),
    )), x => x.toString(16).padStart(2, '0')).join('');
    const check = (condition, message) => { if (!condition) throw new Error(message); };
    const results = [];
    for (const spec of expected.cases) {
      const bytes = new Uint8Array(await (await fetch(`/test-data/${spec.file}`)).arrayBuffer());
      const memory_before_bytes = wasm.memory.buffer.byteLength;
      const start = performance.now();
      const data = reader.readCwaFile(bytes, spec.options);
      const read_ms = performance.now() - start;
      check(data.timestamps_us instanceof BigInt64Array, `${spec.name}: timestamp precision/type`);
      check(data.timestamps_us.length === spec.rows, `${spec.name}: row count`);
      check(data.timezone === spec.timezone, `${spec.name}: timezone`);
      check(JSON.stringify(Object.keys(data.columns)) === JSON.stringify(spec.columns), `${spec.name}: column presence/order`);
      check(await digest(data.timestamps_us) === spec.timestamps_sha256, `${spec.name}: exact timestamps`);
      for (const column of spec.columns) {
        const values = data.columns[column];
        check(values instanceof Float32Array, `${spec.name}/${column}: float32 dtype`);
        check(values.length === spec.rows, `${spec.name}/${column}: column length`);
        if (column === 'light' && spec.options.resample_hz == null) {
          // powf calibration can differ by one float32 ULP across math runtimes.
          const actualBits = new Uint32Array(values.buffer, values.byteOffset, values.length);
          const nativeBits = new Uint32Array(Float32Array.from(spec.values.light).buffer);
          for (let i = 0; i < values.length; ++i) {
            check(Math.abs(actualBits[i] - nativeBits[i]) <= 1, `${spec.name}/light[${i}]: calibrated value exceeds one ULP`);
          }
        } else if (spec.values?.[column]) {
          for (let i = 0; i < values.length; ++i) {
            const target = spec.values[column][i];
            check(target === null ? Number.isNaN(values[i]) : Number.isFinite(values[i]) && Math.abs(values[i] - target) <= 1e-6 + 1e-6 * Math.abs(target), `${spec.name}/${column}[${i}]: computed value or NaN`);
          }
        } else {
          check(await digest(values) === spec.column_sha256[column], `${spec.name}/${column}: recorded values including zeros/NaNs`);
        }
      }
      const csv = reader.writeCwaCsv(bytes, spec.options);
      check(csv instanceof Uint8Array, `${spec.name}: CSV byte output`);
      if (spec.csv_text) {
        const actualRows = new TextDecoder().decode(csv).trimEnd().split('\n').map(row => row.split(','));
        const nativeRows = spec.csv_text.trimEnd().split('\n').map(row => row.split(','));
        check(actualRows.length === nativeRows.length, `${spec.name}: CSV row count`);
        const light = nativeRows[0].indexOf('light');
        for (let row = 0; row < nativeRows.length; ++row) {
          check(actualRows[row].length === nativeRows[row].length, `${spec.name}: CSV column count`);
          for (let col = 0; col < nativeRows[row].length; ++col) {
            if (row > 0 && col === light) {
              const actual = Number(actualRows[row][col]);
              const native = Number(nativeRows[row][col]);
              check(Math.abs(actual - native) <= 1e-6 + 2 ** -23 * Math.max(Math.abs(actual), Math.abs(native)), `${spec.name}: CSV calibrated light`);
            } else {
              check(actualRows[row][col] === nativeRows[row][col], `${spec.name}: exact CSV row ${row} column ${col}`);
            }
          }
        }
      } else {
        check(await digest(csv) === spec.csv_sha256, `${spec.name}: CSV parity`);
      }
      results.push({ name: spec.name, input_bytes: bytes.length, rows: spec.rows, columns: spec.columns, read_ms, output_array_bytes: data.timestamps_us.byteLength + Object.values(data.columns).reduce((sum, values) => sum + values.byteLength, 0), memory_before_bytes, memory_after_bytes: wasm.memory.buffer.byteLength, csv_bytes: csv.length });
    }
    return { cases: results, wasm_memory_before_bytes, wasm_memory_after_bytes: wasm.memory.buffer.byteLength };
  });
  expect(report.cases).toHaveLength(31);
  report.browser = browser.version();
  const { writeFileSync } = await import('node:fs');
  writeFileSync('test-results/recording-metrics.json', JSON.stringify(report, null, 2) + '\n');
  await test.info().attach('recording-metrics', { body: JSON.stringify(report), contentType: 'application/json' });
});

test('byte operations retain native errors and validate browser cut/offset options', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByLabel('Select a CWA file')).toBeEnabled();
  const results = await page.evaluate(async () => {
    const reader = await import('/pkg/cwa_reader_browser.js');
    const expected = await (await fetch('/test-data/expected.json')).json();
    const results = [];
    for (const spec of expected.errors) {
      const bytes = new Uint8Array(await (await fetch(`/test-data/${spec.file}`)).arrayBuffer());
      for (const [js, native] of [['readCwaFile', 'read_cwa_file'], ['writeCwaCsv', 'write_cwa_csv']]) {
        let error;
        try { reader[js](bytes, spec.options); }
        catch (caught) { error = caught; }
        if (!(error instanceof Error) || error.message !== spec.messages[native]) {
          throw new Error(`${spec.name}/${js}: expected ${spec.messages[native]}, got ${error?.message}`);
        }
        results.push(`${spec.name}/${js}`);
      }
    }
    const bytes = new Uint8Array(await (await fetch('/fixture.cwa')).arrayBuffer());
    for (const call of [
      () => reader.blocks(-1, 2), () => reader.blocks(1.5, 2), () => reader.blocks(3, 1),
      () => reader.seconds(-1), () => reader.seconds(3, 1), () => reader.seconds(NaN),
      () => reader.readCwaFile(bytes, { fixed_utc_offset_seconds: 86400 }),
      () => reader.readCwaFile(bytes, { fixed_utc_offset_seconds: Infinity }),
    ]) {
      let error;
      try { call(); } catch (caught) { error = caught; }
      if (!(error instanceof Error)) throw new Error('Invalid browser option did not throw Error');
    }
    const blocks = reader.readCwaFile(bytes, { cut: reader.blocks(3, 10) });
    const seconds = reader.readCwaFile(bytes, { cut: reader.seconds(1.2, 3.7) });
    return { errors: results, blocks_rows: blocks.timestamps_us.length, seconds_rows: seconds.timestamps_us.length, expected_seconds_rows: expected.cases.find(spec => spec.name === 'seconds').rows };
  });
  expect(results.errors).toHaveLength(12);
  expect(results.blocks_rows).toBeGreaterThan(0);
  expect(results.seconds_rows).toBe(results.expected_seconds_rows);
});

test('selected File decodes in the example worker and exports a downloadable CSV', async ({ page }) => {
  const { readFileSync } = await import('node:fs');
  const { createHash } = await import('node:crypto');
  const expected = JSON.parse(readFileSync(path.join(root, 'wasm/.test-data/expected.json'), 'utf8')).cases.find(spec => spec.name === 'full');
  await page.goto('/');
  await expect(page.getByLabel('Select a CWA file')).toBeEnabled();
  await page.getByLabel('Select a CWA file').setInputFiles(fixture);
  await expect(page.getByRole('status')).toContainText('Read 1,024 bytes');
  await page.getByRole('button', { name: 'Read complete recording' }).click();
  await expect(page.getByRole('status')).toContainText('Decoded 71,400 samples in the worker');
  const summary = JSON.parse(await page.locator('#metadata').textContent());
  expect(summary.rows).toBe(expected.rows);
  expect(summary.columns).toEqual(expected.columns);
  expect(summary.first_timestamp_us).toBe('1332846897500000');
  const downloading = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export complete CSV' }).click();
  const download = await downloading;
  expect(download.suggestedFilename()).toBe('example-610-steps.csv');
  const csv = readFileSync(await download.path());
  expect(createHash('sha256').update(csv).digest('hex')).toBe(expected.csv_sha256);
  await expect(page.getByRole('status')).toContainText('CSV bytes');
});
