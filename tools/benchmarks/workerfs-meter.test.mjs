import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('./workerfs-meter.js', import.meta.url), 'utf8');
for (const capacity of [0, 1024]) {
  const data = Uint8Array.from({length: 4099}, (_, i) => i % 251);
  const file = {size:data.length,slice:(start,end)=>data.slice(start,end)};
  const context = {
    Module:{FS:{mkdirTree(){},unmount(){},mount(){}}},
    WORKERFS:{reader:{readAsArrayBuffer:bytes=>bytes.buffer},stream_ops:{read(stream,buffer,offset,length,position){
      if (position >= stream.node.size) return 0;
      const bytes=new Uint8Array(context.WORKERFS.reader.readAsArrayBuffer(file.slice(position,position+length)));buffer.set(bytes,offset);return bytes.length;
    }}}
  };
  vm.createContext(context);
  vm.runInContext(source.replace('CWA_CACHE_BYTES',String(capacity)),context);
  context.cwaBenchmarkFiles.mount([file]);
  const result = new Uint8Array(2053);
  const read = context.WORKERFS.stream_ops.read;
  assert.equal(read({node:{size:data.length,contents:file}},result,0,2053,1020),2053);
  assert.deepEqual(result,data.slice(1020,3073));
  const stats=context.cwaBenchmarkFiles.stats();
  assert.equal(stats.logicalReadCalls,1);
  assert.equal(stats.logicalBytesRead,2053);
  assert.equal(stats.physicalReadCalls,capacity?4:1);
  assert.equal(stats.physicalBytesRead,capacity?4096:2053);
  // An overlapping request reuses the resident last cache block.
  const tail=new Uint8Array(8);
  read({node:{size:data.length,contents:file}},tail,0,8,3072);
  assert.deepEqual(tail,data.slice(3072,3080));
  assert.equal(stats.physicalReadCalls,capacity?4:2);
  assert.equal(read({node:{size:data.length,contents:file}},tail,0,8,data.length),0);
  assert.equal(stats.logicalReadCalls,3);
  assert.equal(stats.physicalReadCalls,capacity?4:2);
  context.cwaBenchmarkFiles.mount([file]);
  assert.equal(context.cwaBenchmarkFiles.stats().logicalBytesRead,0);
}
console.log('WORKERFS benchmark counter/cache checks passed');
