import init, { PacketBatchReader } from './cwa_reader_browser.js';

let initialized;

async function fileOf(source) {
  return typeof source.getFile === 'function' ? source.getFile() : source;
}

async function fileOperation(source, operation) {
  const file = await fileOf(source);
  const worker = new Worker(new URL('./cwa_reader_file_worker.js', import.meta.url), { type: 'module' });
  try {
    return await new Promise((resolve, reject) => {
      worker.onmessage = ({ data }) => data.error ? reject(new Error(data.error)) : resolve(data.result);
      worker.onerror = event => reject(new Error(event.message || 'CWA File worker failed to load'));
      worker.onmessageerror = () => reject(new Error('CWA File worker response could not be read'));
      worker.postMessage({ file, operation });
    });
  } finally { worker.terminate(); }
}

/** Read header settings from a File, Blob or file handle in a worker. */
export function readHeaderFromFile(source) { return fileOperation(source, 'header'); }

/** Read actual sample bounds using the core's targeted seek algorithm. */
export function readMetadataFromFile(source) { return fileOperation(source, 'metadata'); }

/** Scan packet metadata in bounded ranges without staging the complete File. */
export function samplingConsistencyReportFromFile(source) { return fileOperation(source, 'report'); }

async function* batches(source, options, csv) {
  const { signal, ...readOptions } = options;
  await (initialized ??= init());
  signal?.throwIfAborted();
  const file = await fileOf(source);
  signal?.throwIfAborted();
  const reader = new PacketBatchReader(file.size, csv, readOptions);
  try {
    for (let request; (request = reader.request()) !== null;) {
      signal?.throwIfAborted();
      const bytes = new Uint8Array(await file.slice(request.offset, request.offset + request.length).arrayBuffer());
      signal?.throwIfAborted();
      const output = reader.provide(bytes);
      if (output !== null) yield output;
    }
  } finally {
    reader.free();
  }
}

/** Decode one owned packet batch at a time, reading only its planned File ranges. */
export function readCwaFileBatches(file, options = {}) {
  return batches(file, options, false);
}

/** Yield CSV byte chunks with one header, using the same packet batch engine. */
export function writeCwaCsvBatches(file, options = {}) {
  return batches(file, options, true);
}
