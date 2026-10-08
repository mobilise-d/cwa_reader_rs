# Browser CWA reader

This precompiled local package reads CWA recordings in a browser. It is packaged
as `@mobilise-d/cwa-reader` for local installation; the scope name is provisional.
No registry publication or scope ownership is implied.

```sh
npm install /path/to/mobilise-d-cwa-reader-VERSION.tgz
```

```js
import { readMetadataFromFile, readCwaFileBatches } from '@mobilise-d/cwa-reader';

const metadata = await readMetadataFromFile(file); // File, Blob or file handle.
for await (const samples of readCwaFileBatches(file)) {
  await consume(samples.timestamps_us, samples.columns);
}
```

The package root exposes the File/handle facade. Metadata runs in a module worker
and uses the same seekable Rust reader as Python. It reads the header and required
sample boundaries without buffering the complete recording. Header and sampling
report helpers are also exported; the sampling report scans all packet metadata
in bounded ranges. Handles are resolved once per operation.

The explicit byte API is available separately:

```js
import init, { readHeader, readCwaFile } from '@mobilise-d/cwa-reader/bytes';

await init();
const header = readHeader(new Uint8Array(await file.slice(0, 1024).arrayBuffer()));
// readCwaFile accepts complete input bytes and returns a complete selected result.
```

JavaScript, Wasm, worker, declarations and license are included. Installation has
no scripts, compiler requirements or runtime npm dependencies. A production Vite
consumer is tested; serve the emitted Wasm/worker assets with the application.
For direct browser serving, keep the included files together and serve Wasm as
`application/wasm`. The File facade needs a browser dedicated module worker with
FileReaderSync. It does not need MEMFS or SharedArrayBuffer.

Sample/CSV batch options include `batchPackets` (default 256) and `overlapPackets`
(default 1). Breaking iteration or aborting its signal stops additional input
reads. Insufficient configured interpolation context raises an Error with
`code === 'InsufficientContext'`; restart with more overlap when needed. Retaining
output batches or constructing a complete CSV still allocates that output.

Timestamps are exact microseconds in `BigInt64Array`; channels are owned
`Float32Array` copies. Real zeros remain zero, missing samples in present channels
are NaN, and absent channels have no property. Individual batches can have
different optional channels. Byte API options retain native channel/cut semantics.
Device-clock metadata strings are naive; the parser does not infer a timezone.

`build-metadata.json` records the source revision, compiler versions and checksums.

Shared behavior, timestamp rules and validation are documented in the
[repository docs](https://github.com/mobilise-d/cwa_reader_rs/tree/main/docs).
The [standalone guide](https://github.com/mobilise-d/cwa_reader_rs/tree/main/wasm)
contains build and deployment instructions.
