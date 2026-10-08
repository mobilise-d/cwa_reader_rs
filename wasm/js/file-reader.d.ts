import type { CwaHeader, CwaMetadata, SamplingConsistencyReport, CwaSamples, ReadOptions } from './cwa_reader_browser.js';

export type FileSource = Blob | FileSystemFileHandle;

/** Read header settings in a dedicated worker, materializing only 1,024 bytes. */
export function readHeaderFromFile(source: FileSource): Promise<CwaHeader>;

/** Seek to actual sample bounds through the same core reader as Python. */
export function readMetadataFromFile(source: FileSource): Promise<CwaMetadata>;

/** Scan all packet metadata in bounded ranges; does not stage complete input. */
export function samplingConsistencyReportFromFile(source: FileSource): Promise<SamplingConsistencyReport>;

export interface FileReadOptions extends ReadOptions {
    /** Abort stops further reads and output; a pending Blob read finishes first. */
    signal?: AbortSignal;
}

/** Pull-driven iteration. Breaking the loop frees its core reader without prefetching. */
export function readCwaFileBatches(source: FileSource, options?: FileReadOptions): AsyncGenerator<CwaSamples>;

/** Concatenate or consume the yielded byte chunks; the CSV header appears once. */
export function writeCwaCsvBatches(source: FileSource, options?: FileReadOptions): AsyncGenerator<Uint8Array>;
