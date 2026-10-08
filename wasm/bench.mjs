// Local recordings are selected as native File objects, never served or staged in JS.
import { chromium } from '@playwright/test';
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const root = path.dirname(fileURLToPath(import.meta.url));
const { values } = parseArgs({ options: {
  input: { type: 'string' }, output: { type: 'string' },
  alias: { type: 'string', default: 'recording' },
  batches: { type: 'string', default: '64,256,1024,2048,8192' },
  repeats: { type: 'string', default: '3' },
  mode: { type: 'string', default: 'all' },
  resample: { type: 'string' },
  'seconds-cuts': { type: 'string' },
  port: { type: 'string', default: '5297' },
} });
if (!values.input || !values.output) throw new Error('--input and --output are required');
const repeats = Number(values.repeats);
if (!Number.isInteger(repeats) || repeats < 1) throw new Error('--repeats must be a positive integer');
if (!['full', 'cuts', 'all'].includes(values.mode)) throw new Error('--mode must be full, cuts or all');
const grid = values.batches.split(',').map(Number);
const secondsCuts = values['seconds-cuts']?.split(',').map(cut => cut.split(':').map(Number));
if (secondsCuts && (secondsCuts.length !== 3 || secondsCuts.some(cut => cut.length !== 2))) throw new Error('--seconds-cuts requires early,middle,late start:end pairs');
const server = spawn(process.execPath, ['serve.mjs'], {
  cwd: root, env: { ...process.env, PORT: values.port }, stdio: ['ignore', 'pipe', 'pipe'],
});
let browser;
try {
  await new Promise((resolve, reject) => {
    server.stdout.once('data', resolve);
    server.once('error', reject);
    server.once('exit', code => reject(new Error(`Benchmark server exited with code ${code}`)));
  });
  browser = await chromium.launch({ headless: true });
  const report = { input_alias: values.alias, browser: browser.version(), node: process.version,
    method: 'Fresh page/Wasm instance per case and repeat; initialization and UI header preview excluded; no explicit decoder warmup; all batch-session header/planning/payload reads, decode, array copies and iteration included; output batches discarded.',
    memory_metric: 'Committed Wasm linear-memory capacity and largest returned typed-array batch; neither is peak browser/process memory.',
    bundle_provenance: undefined, cases: [] };
  for (const batchPackets of grid) {
    const selections = values.mode === 'full' ? ['full'] : values.mode === 'cuts' ? ['early', 'middle', 'late'] : ['full', 'early', 'middle', 'late'];
    for (const selection of selections) for (let repeat = 0; repeat < repeats; ++repeat) {
      const page = await browser.newPage();
      try {
        await page.goto(`http://127.0.0.1:${values.port}/`);
        await page.waitForFunction(() => !document.querySelector('#file').disabled);
        await page.locator('#file').setInputFiles(values.input);
        await page.waitForFunction(() => !document.querySelector('#file').disabled && document.querySelector('#status').textContent.startsWith('Read '));
        const result = await page.evaluate(async ({ batchPackets, selection, resample, secondsCuts }) => {
          const { readCwaFileBatches } = await import('/pkg/cwa_reader_file.js');
          const reader = await import('/pkg/cwa_reader_browser.js');
          const wasm = await reader.default();
          const file = document.querySelector('#file').files[0];
          const packetCount = (file.size - 1024) / 512;
          const selected = Math.min(256, packetCount);
          const start = selection === 'middle' ? Math.floor((packetCount - selected) / 2) : selection === 'late' ? packetCount - selected : 0;
          const seconds = selection === 'full' || !secondsCuts ? null : secondsCuts[['early', 'middle', 'late'].indexOf(selection)];
          const options = { batchPackets, overlapPackets: 1,
            ...(selection === 'full' ? {} : { cut: seconds ? reader.seconds(...seconds) : reader.blocks(start, start + selected) }),
            ...(resample == null ? {} : { resample_hz: resample }),
          };
          const slice = file.slice.bind(file);
          let read_calls = 0, read_bytes = 0, max_read_bytes = 0, read_ms = 0;
          file.slice = (start, end) => {
            ++read_calls;
            read_bytes += end - start;
            max_read_bytes = Math.max(max_read_bytes, end - start);
            const blob = slice(start, end);
            const arrayBuffer = blob.arrayBuffer.bind(blob);
            blob.arrayBuffer = async () => {
              const start = performance.now();
              const bytes = await arrayBuffer();
              read_ms += performance.now() - start;
              return bytes;
            };
            return blob;
          };
          file.arrayBuffer = () => { throw new Error('Benchmark attempted whole-file staging'); };
          let batches = 0, rows = 0, output_bytes = 0, max_output_batch_bytes = 0;
          let first, last;
          const columns = new Set();
          const wasm_capacity_before_bytes = wasm.memory.buffer.byteLength;
          const started = performance.now();
          for await (const batch of readCwaFileBatches(file, options)) {
            ++batches;
            rows += batch.timestamps_us.length;
            first ??= batch.timestamps_us[0];
            last = batch.timestamps_us.at(-1) ?? last;
            for (const name of Object.keys(batch.columns)) columns.add(name);
            const bytes = batch.timestamps_us.byteLength + Object.values(batch.columns).reduce((sum, values) => sum + values.byteLength, 0);
            output_bytes += bytes;
            max_output_batch_bytes = Math.max(max_output_batch_bytes, bytes);
          }
          return { input_bytes: file.size, batchPackets, overlapPackets: 1, selection, resample_hz: resample,
            cut_unit: selection === 'full' ? null : seconds ? 'seconds' : 'blocks', cut_start: selection === 'full' ? null : seconds?.[0] ?? start, cut_end: selection === 'full' ? null : seconds?.[1] ?? start + selected,
            elapsed_ms: performance.now() - started, read_ms, read_calls, read_bytes, max_read_bytes,
            batches, rows, columns: [...columns], duration_s: first == null ? null : Number(last - first) / 1e6,
            output_bytes, max_output_batch_bytes, wasm_capacity_before_bytes, wasm_capacity_after_bytes: wasm.memory.buffer.byteLength };
        }, { batchPackets, selection, resample: values.resample == null ? null : Number(values.resample), secondsCuts });
        if (!report.bundle_provenance) report.bundle_provenance = await page.evaluate(async () => (await fetch('/pkg/build-metadata.json')).json());
        report.cases.push({ ...result, repeat });
        writeFileSync(values.output, JSON.stringify(report, null, 2) + '\n');
        console.log(JSON.stringify({ input_alias: values.alias, ...result, repeat }));
      } finally {
        await page.close();
      }
    }
  }
} finally {
  await browser?.close();
  server.kill();
}
