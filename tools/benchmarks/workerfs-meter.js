// Benchmark-only counters around the installed Emscripten WORKERFS backend.
(() => {
  const {FS} = globalThis.Module;
  const backend = globalThis.WORKERFS;
  const original = backend.stream_ops.read;
  let mounted = false;
  let stats;
  let instrumented = false;
  backend.stream_ops.read = function(stream, buffer, offset, length, position) {
    const actual = original(stream, buffer, offset, length, position);
    stats.logicalReadCalls++;
    stats.logicalBytesRead += actual;
    stats.maxLogicalReadBytes = Math.max(stats.maxLogicalReadBytes, actual);
    return actual;
  };
  globalThis.cwaBenchmarkFiles = {
    mount(files) {
      if (mounted) FS.unmount('/cwa-benchmark');
      else FS.mkdirTree('/cwa-benchmark');
      stats = {logicalReadCalls: 0, logicalBytesRead: 0, maxLogicalReadBytes: 0,
        physicalReadCalls: 0, physicalBytesRead: 0, maxPhysicalReadBytes: 0};
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
})();
