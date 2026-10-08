import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('./workerfs-meter.js', import.meta.url), 'utf8');
const data = Uint8Array.from({length: 4099}, (_, i) => i % 251);
const file = {size:data.length,slice:(start,end)=>data.slice(start,end)};
const context = {
  Module:{FS:{mkdirTree(){},unmount(){},mount(){}}},
  WORKERFS:{reader:{readAsArrayBuffer:bytes=>bytes.buffer},stream_ops:{read(stream,buffer,offset,length,position){
    if (position >= stream.node.size) return 0;
    const bytes=new Uint8Array(context.WORKERFS.reader.readAsArrayBuffer(file.slice(position,position+length)));
    buffer.set(bytes,offset);return bytes.length;
  }}}
};
vm.createContext(context);
vm.runInContext(source,context);
context.cwaBenchmarkFiles.mount([file]);
const result = new Uint8Array(2053);
const read = context.WORKERFS.stream_ops.read;
assert.equal(read({node:{size:data.length,contents:file}},result,0,2053,1020),2053);
assert.deepEqual(result,data.slice(1020,3073));
const stats=context.cwaBenchmarkFiles.stats();
assert.equal(stats.logicalReadCalls,1);
assert.equal(stats.logicalBytesRead,2053);
assert.equal(stats.physicalReadCalls,1);
assert.equal(stats.physicalBytesRead,2053);
// EOF is a filesystem call without a FileReaderSync call.
assert.equal(read({node:{size:data.length,contents:file}},result,0,8,data.length),0);
assert.equal(stats.logicalReadCalls,2);
assert.equal(stats.physicalReadCalls,1);
context.cwaBenchmarkFiles.mount([file]);
assert.equal(context.cwaBenchmarkFiles.stats().logicalBytesRead,0);
read({node:{size:data.length,contents:file}},result,0,8,0);
assert.equal(context.cwaBenchmarkFiles.stats().physicalReadCalls,1);
console.log('WORKERFS read counters and EOF checks passed');
