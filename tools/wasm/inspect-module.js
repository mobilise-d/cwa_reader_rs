// Inspect a real side module using the runtime's WebAssembly parser.
const fs = require('node:fs');
const bytes = fs.readFileSync(process.argv[2]);
const module_ = new WebAssembly.Module(bytes);
const imports = WebAssembly.Module.imports(module_);
const exports_ = WebAssembly.Module.exports(module_);
const dylink = WebAssembly.Module.customSections(module_, 'dylink.0');
if (dylink.length !== 1 || !exports_.some(x => x.name === 'PyInit_cwa_reader_rs')) {
  throw new Error('Missing Python module initializer or dylink.0 section');
}
console.log(JSON.stringify({imports, exports: exports_, dylink_0_bytes: Buffer.from(dylink[0]).toString('hex')}, null, 2));
