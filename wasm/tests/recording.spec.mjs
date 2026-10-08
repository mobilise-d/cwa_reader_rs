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

test('File packet batches preserve exact samples while reading only bounded slices', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByLabel('Select a CWA file')).toBeEnabled();
  const result = await page.evaluate(async () => {
    const { readCwaFileBatches } = await import('/pkg/cwa_reader_file.js');
    const expected = (await (await fetch('/test-data/expected.json')).json()).cases.find(x => x.name === 'full');
    const file = new File([await (await fetch('/fixture.cwa')).arrayBuffer()], 'recording.cwa');
    const reads = [];
    const slice = file.slice.bind(file);
    file.slice = (start, end) => { reads.push([start, end]); return slice(start, end); };
    file.arrayBuffer = () => { throw new Error('The complete File must not be materialized'); };
    const batches = [];
    for await (const batch of readCwaFileBatches(file, { batchPackets: 32, overlapPackets: 1 })) batches.push(batch);
    const timestamps = new BigInt64Array(expected.rows);
    const columns = Object.fromEntries(expected.columns.map(name => [name, new Float32Array(expected.rows)]));
    let offset = 0;
    for (const batch of batches) {
      if (!(batch.timestamps_us instanceof BigInt64Array)) throw new Error('Batch timestamps lose precision');
      if (JSON.stringify(Object.keys(batch.columns)) !== JSON.stringify(expected.columns)) throw new Error('Batch columns differ');
      timestamps.set(batch.timestamps_us, offset);
      for (const name of expected.columns) columns[name].set(batch.columns[name], offset);
      offset += batch.timestamps_us.length;
    }
    const digest = async array => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', array)), x => x.toString(16).padStart(2, '0')).join('');
    return { batches: batches.length, rows: offset, reads, timestamps: await digest(timestamps), expected_timestamps: expected.timestamps_sha256,
      acceleration: await digest(columns.acc_x), expected_acceleration: expected.column_sha256.acc_x };
  });
  expect(result.batches).toBe(19);
  expect(result.rows).toBe(71400);
  expect(result.timestamps).toBe(result.expected_timestamps);
  expect(result.acceleration).toBe(result.expected_acceleration);
  expect(result.reads.length).toBeGreaterThanOrEqual(result.batches);
  expect(result.reads.length).toBeLessThanOrEqual(result.batches + 8);
  for (const [start, end] of result.reads) {
    expect(end - start).toBeLessThanOrEqual(34 * 512);
  }
});

test('File resampling keeps the global grid across packet batch and cut boundaries', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await expect(page.getByLabel('Select a CWA file')).toBeEnabled();
  const cases = await page.evaluate(async () => {
    const { readCwaFileBatches } = await import('/pkg/cwa_reader_file.js');
    const expected = await (await fetch('/test-data/expected.json')).json();
    const results = [];
    for (const name of ['resample-60.0', 'resample-cut-60.0']) {
      const spec = expected.cases.find(x => x.name === name);
      const file = new File([await (await fetch(`/test-data/${spec.file}`)).arrayBuffer()], 'recording.cwa');
      for (const batchPackets of [1, 7, 256]) {
        let readBytes = 0;
        const slice = File.prototype.slice.bind(file);
        file.slice = (start, end) => { readBytes += end - start; return slice(start, end); };
        const timestamps = new BigInt64Array(spec.rows);
        let row = 0;
        for await (const batch of readCwaFileBatches(file, { ...spec.options, batchPackets })) {
          timestamps.set(batch.timestamps_us, row);
          for (const name of spec.columns) {
            const values = batch.columns[name];
            for (let i = 0; i < values.length; ++i) {
              const target = spec.values[name][row + i];
              if (!(target === null ? Number.isNaN(values[i]) : Number.isFinite(values[i]) && Math.abs(values[i] - target) <= 1e-6 + 1e-6 * Math.abs(target))) {
                throw new Error(`${spec.name}/${batchPackets}/${name}[${row + i}]: interpolation differs from native`);
              }
            }
          }
          row += batch.timestamps_us.length;
        }
        const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', timestamps)), x => x.toString(16).padStart(2, '0')).join('');
        if (row !== spec.rows || digest !== spec.timestamps_sha256) throw new Error(`${spec.name}/${batchPackets}: global timestamps or ownership differ`);
        if (name === 'resample-cut-60.0' && readBytes >= file.size / 4) throw new Error(`${spec.name}/${batchPackets}: short seconds cut scans the complete input`);
        results.push({ name, batchPackets, rows: row });
      }
    }
    return results;
  });
  expect(cases).toHaveLength(6);
});

test('a short interior resampled cut needs no unused next-packet context', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByLabel('Select a CWA file')).toBeEnabled();
  const results = await page.evaluate(async () => {
    const reader = await import('/pkg/cwa_reader_browser.js');
    const { readCwaFileBatches } = await import('/pkg/cwa_reader_file.js');
    const expected = (await (await fetch('/test-data/expected.json')).json()).short_interior_cut;
    const bytes = new Uint8Array(await (await fetch(`/test-data/${expected.file}`)).arrayBuffer());
    const options = { ...expected.options, batchPackets: 1, overlapPackets: 0 };
    const direct = reader.readCwaFile(bytes, options);
    const file = new File([bytes], 'short.cwa');
    const slices = [];
    const slice = file.slice.bind(file);
    file.slice = (start, end) => { slices.push([start, end]); return slice(start, end); };
    const batches = [];
    for await (const data of readCwaFileBatches(file, options)) batches.push(data);
    const normalize = data => ({ timestamps_us: Array.from(data.timestamps_us, String),
      columns: Object.fromEntries(Object.entries(data.columns).map(([name, values]) => [name, Array.from(values)])) });
    return { expected: { timestamps_us: expected.timestamps_us.map(String), columns: expected.columns },
      direct: normalize(direct), batches: batches.filter(data => data.timestamps_us.length > 0).map(normalize),
      payloads: slices.filter(([start, end]) => start >= 1024 && end - start >= 512) };
  });
  expect(results.expected.timestamps_us).toHaveLength(6);
  expect(results.direct.timestamps_us).toEqual(results.expected.timestamps_us);
  expect(results.batches).toHaveLength(1);
  expect(results.batches[0].timestamps_us).toEqual(results.expected.timestamps_us);
  for (const result of [results.direct, results.batches[0]]) {
    expect(Object.keys(result.columns)).toEqual(Object.keys(results.expected.columns));
    for (const [name, values] of Object.entries(result.columns)) {
      values.forEach((value, i) => expect(value).toBeCloseTo(results.expected.columns[name][i], 5));
    }
  }
  expect(results.payloads[0]).toEqual([1024, 1536]);
  expect(results.payloads.every(([start, end]) => end - start === 512)).toBe(true);
});

test('File iteration stops reads on cancellation and never refills insufficient overlap', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByLabel('Select a CWA file')).toBeEnabled();
  const result = await page.evaluate(async () => {
    const { readCwaFileBatches } = await import('/pkg/cwa_reader_file.js');
    const content = await (await fetch('/fixture.cwa')).arrayBuffer();
    const trackedFile = () => {
      const file = new File([content], 'recording.cwa');
      const slice = file.slice.bind(file);
      const reads = [];
      file.slice = (start, end) => { reads.push([start, end]); return slice(start, end); };
      return { file, reads };
    };
    const early = trackedFile();
    const iterator = readCwaFileBatches(early.file, { batchPackets: 32 });
    const first = await iterator.next();
    const firstReads = early.reads.length;
    await new Promise(resolve => setTimeout(resolve, 0));
    const prefetched = early.reads.length - firstReads;
    await iterator.return();
    const returned = await iterator.next();

    const cancelled = trackedFile();
    const controller = new AbortController();
    const cancellable = readCwaFileBatches(cancelled.file, { batchPackets: 32, signal: controller.signal });
    await cancellable.next();
    const beforeAbort = cancelled.reads.length;
    controller.abort();
    let abort;
    try { await cancellable.next(); } catch (error) { abort = error.name; }

    const insufficient = trackedFile();
    let emitted = 0;
    let error;
    try {
      for await (const batch of readCwaFileBatches(insufficient.file, { batchPackets: 1, overlapPackets: 0, resample_hz: 60 })) {
        emitted += batch.timestamps_us.length;
      }
    } catch (caught) { error = { isError: caught instanceof Error, message: caught.message,
      code: caught.code, side: caught.side, ownedPackets: caught.ownedPackets, loadedPackets: caught.loadedPackets, reason: caught.reason }; }
    const byteReader = await import('/pkg/cwa_reader_browser.js');
    const byteErrors = [];
    for (const operation of ['readCwaFile', 'writeCwaCsv']) {
      try { byteReader[operation](new Uint8Array(content), { batchPackets: 1, overlapPackets: 0, resample_hz: 60 }); }
      catch (error) { byteErrors.push({ code: error.code, side: error.side, ownedPackets: error.ownedPackets, loadedPackets: error.loadedPackets }); }
    }
    return { firstRows: first.value.timestamps_us.length, firstPayloadReads: early.reads.filter(([start, end]) => start >= 1024 && end - start >= 512).length,
      prefetched, done: returned.done, firstReads, afterReturn: early.reads.length,
      abort, beforeAbort, afterAbort: cancelled.reads.length, emitted, error, byteErrors, insufficientReads: insufficient.reads };
  });
  expect(result.firstRows).toBe(3840);
  expect(result.firstPayloadReads).toBe(1);
  expect(result.prefetched).toBe(0);
  expect(result.done).toBe(true);
  expect(result.afterReturn).toBe(result.firstReads);
  expect(result.abort).toBe('AbortError');
  expect(result.afterAbort).toBe(result.beforeAbort);
  expect(result.emitted).toBe(0);
  expect(result.error.isError).toBe(true);
  expect(result.error.message).toContain('InsufficientContext');
  const context = { code: 'InsufficientContext', side: 'right', ownedPackets: [0, 1], loadedPackets: [0, 1] };
  expect(result.error).toMatchObject(context);
  expect(result.error.reason.length).toBeGreaterThan(0);
  expect(result.byteErrors).toEqual([context, context]);
  expect(result.insufficientReads.filter(([start, end]) => start >= 1024 && end - start >= 512)).toEqual([[1024, 1536]]);
});

test('File selections with no valid samples retain the full-byte error', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByLabel('Select a CWA file')).toBeEnabled();
  const results = await page.evaluate(async () => {
    const { readCwaFileBatches } = await import('/pkg/cwa_reader_file.js');
    const reader = await import('/pkg/cwa_reader_browser.js');
    const original = new Uint8Array(await (await fetch('/fixture.cwa')).arrayBuffer());
    const skipped = original.slice();
    skipped[1024] = 0;
    skipped[1025] = 0;
    const cases = [
      { bytes: skipped.slice(0, 1536), options: {} },
      { bytes: skipped, options: { cut: reader.blocks(0, 1) } },
    ];
    const results = [];
    for (const { bytes, options } of cases) {
      let expected, actual;
      try { reader.readCwaFile(bytes, options); } catch (error) { expected = error.message; }
      let rows = 0;
      try {
        for await (const data of readCwaFileBatches(new File([bytes], 'skipped.cwa'), options)) rows += data.timestamps_us.length;
      } catch (error) { actual = error.message; }
      results.push({ expected, actual, rows });
    }
    return results;
  });
  for (const result of results) {
    expect(result.expected).toContain('No valid sample data');
    expect(result.actual).toBe(result.expected);
    expect(result.rows).toBe(0);
  }
});

test('File batch channel unions, cuts, offsets and packed layouts match all native cases', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await expect(page.getByLabel('Select a CWA file')).toBeEnabled();
  const count = await page.evaluate(async () => {
    const { readCwaFileBatches } = await import('/pkg/cwa_reader_file.js');
    const expected = await (await fetch('/test-data/expected.json')).json();
    const digest = async array => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', array)), x => x.toString(16).padStart(2, '0')).join('');
    let checked = 0;
    for (const spec of expected.cases) {
      const file = new File([await (await fetch(`/test-data/${spec.file}`)).arrayBuffer()], 'recording.cwa');
      for (const batchPackets of [3, 256]) {
        const timestamps = new BigInt64Array(spec.rows);
        const columns = Object.fromEntries(spec.columns.map(name => [name, new Float32Array(spec.rows).fill(NaN)]));
        const seen = new Set();
        let row = 0;
        for await (const batch of readCwaFileBatches(file, { ...spec.options, batchPackets })) {
          if (batch.timezone !== spec.timezone) throw new Error(`${spec.name}: timezone`);
          timestamps.set(batch.timestamps_us, row);
          for (const [name, values] of Object.entries(batch.columns)) {
            if (!columns[name] || !(values instanceof Float32Array) || values.length !== batch.timestamps_us.length) throw new Error(`${spec.name}: batch column ${name}`);
            columns[name].set(values, row);
            seen.add(name);
          }
          row += batch.timestamps_us.length;
        }
        if (row !== spec.rows || seen.size !== spec.columns.length || await digest(timestamps) !== spec.timestamps_sha256) throw new Error(`${spec.name}/${batchPackets}: rows, channels or timestamps`);
        for (const [name, values] of Object.entries(columns)) {
          if (name === 'light' && spec.options.resample_hz == null) {
            const actualBits = new Uint32Array(values.buffer);
            const nativeBits = new Uint32Array(Float32Array.from(spec.values.light).buffer);
            for (let i = 0; i < values.length; ++i) {
              if (Math.abs(actualBits[i] - nativeBits[i]) > 1) throw new Error(`${spec.name}: light calibration`);
            }
          } else if (spec.values?.[name]) {
            for (let i = 0; i < values.length; ++i) {
              const target = spec.values[name][i];
              if (!(target === null ? Number.isNaN(values[i]) : Number.isFinite(values[i]) && Math.abs(values[i] - target) <= 1e-6 + 1e-6 * Math.abs(target))) throw new Error(`${spec.name}/${batchPackets}/${name}[${i}]: computed value or NaN`);
            }
          } else if (await digest(values) !== spec.column_sha256[name]) {
            throw new Error(`${spec.name}/${batchPackets}/${name}: exact recorded values`);
          }
        }
        ++checked;
      }
    }
    return checked;
  });
  expect(count).toBe(62);
});

test('File CSV chunks have one native header and preserve every recording option', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await expect(page.getByLabel('Select a CWA file')).toBeEnabled();
  const count = await page.evaluate(async () => {
    const { writeCwaCsvBatches } = await import('/pkg/cwa_reader_file.js');
    const expected = await (await fetch('/test-data/expected.json')).json();
    for (const spec of expected.cases) {
      const file = new File([await (await fetch(`/test-data/${spec.file}`)).arrayBuffer()], 'recording.cwa');
      const chunks = [];
      for await (const chunk of writeCwaCsvBatches(file, { ...spec.options, batchPackets: 3 })) {
        if (!(chunk instanceof Uint8Array)) throw new Error(`${spec.name}: CSV output type`);
        chunks.push(chunk);
      }
      const csv = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
      let offset = 0;
      for (const chunk of chunks) { csv.set(chunk, offset); offset += chunk.length; }
      if (!spec.csv_text) {
        const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', csv)), x => x.toString(16).padStart(2, '0')).join('');
        if (hash !== spec.csv_sha256) throw new Error(`${spec.name}: native CSV hash, header or output ownership differs`);
      } else {
        const actual = new TextDecoder().decode(csv).trimEnd().split('\n').map(row => row.split(','));
        const native = spec.csv_text.trimEnd().split('\n').map(row => row.split(','));
        if (actual.length !== native.length) throw new Error(`${spec.name}: CSV row count`);
        const light = native[0].indexOf('light');
        for (let row = 0; row < native.length; ++row) {
          if (actual[row].length !== native[row].length) throw new Error(`${spec.name}: CSV columns`);
          for (let col = 0; col < native[row].length; ++col) {
            if (row > 0 && col === light) {
              const a = Number(actual[row][col]), b = Number(native[row][col]);
              if (Math.abs(a - b) > 1e-6 + 2 ** -23 * Math.max(Math.abs(a), Math.abs(b))) throw new Error(`${spec.name}: CSV calibrated light`);
            } else if (actual[row][col] !== native[row][col]) throw new Error(`${spec.name}: exact CSV row ${row} column ${col}`);
          }
        }
      }
    }
    return expected.cases.length;
  });
  expect(count).toBe(31);
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

test('an early worker load failure keeps full actions disabled while headers remain usable', async ({ page }) => {
  let releaseWasm;
  const wasmGate = new Promise(resolve => { releaseWasm = resolve; });
  await page.route('**/cwa_reader_browser_bg.wasm', async route => {
    await wasmGate;
    await route.continue();
  });
  await page.route('**/reader-worker.js', route => route.abort());
  await page.goto('/', { waitUntil: 'commit' });
  try {
    await expect(page.getByRole('status')).toContainText('Recording worker failed to load');
  } finally {
    releaseWasm();
  }
  const input = page.getByLabel('Select a CWA file');
  await expect(input).toBeEnabled();
  for (let selection = 0; selection < 2; ++selection) {
    await input.setInputFiles(fixture);
    await expect(page.getByRole('status')).toContainText('Read 1,024 bytes');
    await expect(page.getByRole('status')).toContainText('Recording worker failed to load');
    await expect(input).toBeEnabled();
    for (const name of ['Scan actual timing', 'Read complete recording', 'Export complete CSV']) {
      await expect(page.getByRole('button', { name })).toBeDisabled();
    }
  }
});
