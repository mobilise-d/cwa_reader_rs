import init, { readHeader } from '/pkg/cwa_reader_browser.js';

const input = document.querySelector('#file');
const status = document.querySelector('#status');
const output = document.querySelector('#metadata');
const actions = ['scan', 'read', 'csv'].map(id => document.getElementById(id));
const worker = new Worker('/reader-worker.js', { type: 'module' });
let selectedFile;
let headerReady = false;
let workerAvailable = false;
let workerFailure;
let processing = false;

function busy(value) {
  processing = value;
  input.disabled = value || !headerReady;
  for (const button of actions) button.disabled = value || !selectedFile || !workerAvailable;
}

worker.onmessage = ({ data }) => {
  if (data.ready) {
    workerAvailable = true;
    busy(processing);
    return;
  }
  if (data.unavailable) {
    workerFailed(data.error);
    return;
  }
  busy(false);
  if (data.error) {
    status.textContent = `Cannot process recording: ${data.error}`;
    return;
  }
  if (data.csv) {
    const url = URL.createObjectURL(data.csv);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${selectedFile.name.replace(/\.cwa$/i, '')}.csv`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    status.textContent = `Exported ${data.csv.size.toLocaleString('en-US')} CSV bytes.`;
  } else {
    output.textContent = JSON.stringify(data.result, null, 2);
    status.textContent = data.operation === 'read'
      ? `Decoded ${data.result.rows.toLocaleString('en-US')} samples in the worker.`
      : 'Scanned recording timing in the worker.';
  }
};
function workerFailed(detail) {
  workerAvailable = false;
  workerFailure = `Recording worker failed to load.${detail ? ` ${detail}` : ''}`;
  busy(false);
  status.textContent = workerFailure;
}
worker.onerror = () => workerFailed();

try {
  await init();
  headerReady = true;
  busy(false);
  status.textContent = workerFailure || 'Ready to read a header.';
} catch (error) {
  status.textContent = `Reader failed to load: ${error.message}`;
}

input.addEventListener('change', async () => {
  const file = input.files[0];
  selectedFile = undefined;
  if (!file) { busy(false); return; }
  busy(true);
  try {
    const bytes = new Uint8Array(await file.slice(0, 1024).arrayBuffer());
    output.textContent = JSON.stringify(readHeader(bytes), null, 2);
    status.textContent = `Read ${bytes.length.toLocaleString('en-US')} bytes from ${file.name}.${workerFailure ? ` ${workerFailure}` : ''}`;
    selectedFile = file;
  } catch (error) {
    output.textContent = 'No metadata available.';
    status.textContent = `Cannot read header: ${error.message}`;
  } finally {
    busy(false);
  }
});

for (const button of actions) button.addEventListener('click', () => {
  busy(true);
  status.textContent = `Reading complete file: ${selectedFile.name}...`;
  worker.postMessage({ operation: button.id, file: selectedFile });
});
