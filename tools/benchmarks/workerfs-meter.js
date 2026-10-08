// Benchmark-only instrumentation around the installed Emscripten WORKERFS backend.
// cacheBytes=0 measures direct FileReaderSync reads; 1048576 matches downstream read-ahead.
((cacheBytes) => {
  const {FS} = globalThis.Module;
  const backend = globalThis.WORKERFS;
  const original = backend.stream_ops.read;
  let mounted = false;
  let cache;
  let stats;
  let instrumented = false;
  backend.stream_ops.read = function(stream, buffer, offset, length, position) {
    const count = Math.max(0, Math.min(length, stream.node.size - position));
    stats.logicalReadCalls++;
    stats.logicalBytesRead += count;
    stats.maxLogicalReadBytes = Math.max(stats.maxLogicalReadBytes, count);
    if (!cacheBytes) {
      const actual = original(stream, buffer, offset, length, position);
      return actual;
    }
    let copied = 0;
    while (copied < count) {
      const absolute = position + copied;
      const start = Math.floor(absolute / cacheBytes) * cacheBytes;
      if (!cache || cache.file !== stream.node.contents || cache.start !== start) {
        const bytes = new Uint8Array(backend.reader.readAsArrayBuffer(stream.node.contents.slice(start, start + cacheBytes)));
        cache = {file: stream.node.contents, start, bytes};
      }
      const within = absolute - start;
      const take = Math.min(count - copied, cache.bytes.length - within);
      buffer.set(cache.bytes.subarray(within, within + take), offset + copied);
      copied += take;
    }
    stats.cacheResidentBytes = cache?.bytes.length ?? 0;
    return count;
  };
  globalThis.cwaBenchmarkFiles = {
    mount(files) {
      if (mounted) FS.unmount('/cwa-benchmark');
      else FS.mkdirTree('/cwa-benchmark');
      cache = undefined;
      stats = {logicalReadCalls: 0, logicalBytesRead: 0, maxLogicalReadBytes: 0,
        physicalReadCalls: 0, physicalBytesRead: 0, maxPhysicalReadBytes: 0,
        cacheCapacityBytes: cacheBytes, cacheResidentBytes: 0};
      FS.mount(backend, {blobs: [{name:'recording.cwa',data:files[0]}]}, '/cwa-benchmark');
      if (!instrumented) {
        const readArrayBuffer = backend.reader.readAsArrayBuffer.bind(backend.reader);
        backend.reader.readAsArrayBuffer = function(blob) {
          const bytes = readArrayBuffer(blob);
          stats.physicalReadCalls++;
          stats.physicalBytesRead += bytes.byteLength;
          stats.maxPhysicalReadBytes = Math.max(stats.maxPhysicalReadBytes, bytes.byteLength);
          return bytes;
        };
        instrumented = true;
      }
      mounted = true;
    },
    stats() { return stats; }
  };
})(CWA_CACHE_BYTES);
