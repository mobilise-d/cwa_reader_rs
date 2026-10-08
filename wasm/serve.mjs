import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const serveFixture = process.argv.includes('--test-fixtures');
const port = Number(process.env.PORT || 5287);
const types = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.json': 'application/json' };

http.createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://localhost').pathname;
  let file;
  if (pathname === '/' || pathname === '/index.html') file = path.join(root, 'example/index.html');
  else if (pathname === '/inspect.js') file = path.join(root, 'example/inspect.js');
  else if (pathname === '/reader-worker.js') file = path.join(root, 'example/reader-worker.js');
  else if (/^\/pkg\/[a-zA-Z0-9_.-]+$/.test(pathname)) file = path.join(root, pathname);
  else if (serveFixture && pathname === '/fixture.cwa') {
    file = path.join(root, '../tests/reference_data/openmovement/example-610-steps.cwa');
  }
  else if (serveFixture && /^\/test-data\/[a-zA-Z0-9_.-]+$/.test(pathname)) {
    file = path.join(root, '.test-data', pathname.slice('/test-data/'.length));
  }
  if (!file) { response.writeHead(404).end('Not found'); return; }
  try {
    const bytes = await readFile(file);
    response.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream' }).end(bytes);
  } catch {
    response.writeHead(404).end('Run wasm/build.sh first');
  }
}).listen(port, '127.0.0.1', () => console.log(`CWA header example: http://127.0.0.1:${port}`));
