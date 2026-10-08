import init, { PacketBatchReader } from './cwa_reader_browser.js';

let initialized;

async function* batches(file, options, csv) {
  const { signal, ...readOptions } = options;
  await (initialized ??= init());
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
