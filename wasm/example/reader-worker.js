import init, { readMetadata, samplingConsistencyReport, readCwaFile, writeCwaCsv } from '/pkg/cwa_reader_browser.js';

const initialized = init();
initialized.then(
  () => self.postMessage({ ready: true }),
  error => self.postMessage({ unavailable: true, error: error.message }),
);
self.onmessage = async ({ data: { file, operation } }) => {
  try {
    await initialized;
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (operation === 'csv') {
      const csv = writeCwaCsv(bytes);
      self.postMessage({ csv }, [csv.buffer]);
    } else if (operation === 'scan') {
      self.postMessage({ operation, result: { metadata: readMetadata(bytes), sampling: samplingConsistencyReport(bytes) } });
    } else {
      const data = readCwaFile(bytes);
      self.postMessage({ operation, result: {
        rows: data.timestamps_us.length,
        timezone: data.timezone,
        first_timestamp_us: data.timestamps_us[0]?.toString() ?? null,
        last_timestamp_us: data.timestamps_us.at(-1)?.toString() ?? null,
        columns: Object.keys(data.columns),
        first_samples: Object.fromEntries(Object.entries(data.columns).map(([name, values]) => [name, Array.from(values.slice(0, 5))])),
      } });
    }
  } catch (error) {
    self.postMessage({ error: error.message });
  }
};
