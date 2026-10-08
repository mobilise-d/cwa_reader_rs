import init, {
  readHeaderFromFileSync, readMetadataFromFileSync, samplingConsistencyReportFromFileSync,
} from './cwa_reader_browser.js';

const operations = { header: readHeaderFromFileSync, metadata: readMetadataFromFileSync, report: samplingConsistencyReportFromFileSync };
self.onmessage = async ({ data: { file, operation } }) => {
  try {
    await init();
    self.postMessage({ result: operations[operation](file) });
  } catch (error) {
    self.postMessage({ error: error.message });
  }
};
