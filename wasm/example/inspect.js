import init, { readHeader } from '/pkg/cwa_reader_browser.js';

const input = document.querySelector('#file');
const status = document.querySelector('#status');
const output = document.querySelector('#metadata');

try {
  await init();
  input.disabled = false;
  status.textContent = 'Ready to read a header.';
} catch (error) {
  status.textContent = `Reader failed to load: ${error.message}`;
}

input.addEventListener('change', async () => {
  const file = input.files[0];
  if (!file) return;
  input.disabled = true;
  try {
    const bytes = new Uint8Array(await file.slice(0, 1024).arrayBuffer());
    const metadata = readHeader(bytes);
    output.textContent = JSON.stringify(metadata, null, 2);
    status.textContent = `Read ${bytes.length.toLocaleString('en-US')} bytes from ${file.name}.`;
  } catch (error) {
    output.textContent = 'No metadata available.';
    status.textContent = `Cannot read header: ${error.message}`;
  } finally {
    input.disabled = false;
  }
});
