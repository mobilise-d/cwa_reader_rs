import init, { readMetadata, samplingConsistencyReport } from '/pkg/cwa_reader_browser.js';
import { readCwaFileBatches, writeCwaCsvBatches } from '/pkg/cwa_reader_file.js';

const initialized = init();
initialized.then(
  () => self.postMessage({ ready: true }),
  error => self.postMessage({ unavailable: true, error: error.message }),
);
self.onmessage = async ({ data: { file, operation } }) => {
  try {
    await initialized;
    if (operation === 'csv') {
      const chunks = [];
      for await (const chunk of writeCwaCsvBatches(file)) chunks.push(chunk);
      const csv = new Blob(chunks, { type: 'text/csv' });
      self.postMessage({ csv });
    } else if (operation === 'scan') {
      const bytes = new Uint8Array(await file.arrayBuffer());
      self.postMessage({ operation, result: { metadata: readMetadata(bytes), sampling: samplingConsistencyReport(bytes) } });
    } else {
      let rows = 0, first, last, timezone = null;
      const columns = new Set();
      const first_samples = {};
      for await (const data of readCwaFileBatches(file)) {
        first ??= data.timestamps_us[0];
        last = data.timestamps_us.at(-1) ?? last;
        timezone = data.timezone;
        for (const name of Object.keys(data.columns)) {
          columns.add(name);
          first_samples[name] ??= Array(Math.min(rows, 5)).fill(NaN);
        }
        for (const name of columns) {
          const count = Math.min(5 - first_samples[name].length, data.timestamps_us.length);
          first_samples[name].push(...(data.columns[name]?.slice(0, count) ?? Array(count).fill(NaN)));
        }
        rows += data.timestamps_us.length;
      }
      self.postMessage({ operation, result: {
        rows, timezone,
        first_timestamp_us: first?.toString() ?? null,
        last_timestamp_us: last?.toString() ?? null,
        columns: [...columns], first_samples,
      } });
    }
  } catch (error) {
    self.postMessage({ error: error.message });
  }
};
