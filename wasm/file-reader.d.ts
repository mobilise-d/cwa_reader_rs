import type { CwaSamples, ReadOptions } from './cwa_reader_browser.js';

export interface FileReadOptions extends ReadOptions {
    /** Abort stops further reads and output; a pending Blob read finishes first. */
    signal?: AbortSignal;
}

/** Pull-driven iteration. Breaking the loop frees its core reader without prefetching. */
export function readCwaFileBatches(file: Blob, options?: FileReadOptions): AsyncGenerator<CwaSamples>;

/** Concatenate or consume the yielded byte chunks; the CSV header appears once. */
export function writeCwaCsvBatches(file: Blob, options?: FileReadOptions): AsyncGenerator<Uint8Array>;
