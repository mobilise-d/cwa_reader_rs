import { readMetadataFromFile, readCwaFileBatches } from '@mobilise-d/cwa-reader';
import init, { blocks, readHeader } from '@mobilise-d/cwa-reader/bytes';

const input = document.querySelector<HTMLInputElement>('#file')!;
const output = document.querySelector<HTMLPreElement>('#result')!;
const hash = async (bytes: ArrayBuffer) => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), byte => byte.toString(16).padStart(2, '0')).join('');

input.onchange = async () => {
  try {
    const file = input.files![0];
    const metadata = await readMetadataFromFile(file);
    await init();
    const header = readHeader(new Uint8Array(await file.slice(0, 1024).arrayBuffer()));
    const batches = [];
    let rows = 0;
    for await (const data of readCwaFileBatches(file, { cut: blocks(3, 10), batchPackets: 3 })) {
      rows += data.timestamps_us.length;
      batches.push(data);
    }
    const timestamps = new BigInt64Array(rows);
    const x = new Float32Array(rows);
    let offset = 0;
    for (const data of batches) {
      timestamps.set(data.timestamps_us, offset);
      x.set(data.columns.acc_x, offset);
      offset += data.timestamps_us.length;
    }
    output.textContent = JSON.stringify({ metadata, header, rows,
      timestamps_sha256: await hash(timestamps.buffer), acc_x_sha256: await hash(x.buffer) });
    output.dataset.done = 'true';
  } catch (error) {
    output.textContent = JSON.stringify({ error: String(error) });
    output.dataset.done = 'true';
  }
};
