"""Local runtime server with a narrow worker-output recovery endpoint."""
import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('output', type=Path)
parser.add_argument('--port', type=int, default=8793)
args = parser.parse_args()
out = args.output.resolve()
results = out / 'results'
results.mkdir(exist_ok=True)

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(out / 'runtime/dist'), **kwargs)

    def do_POST(self):
        name = self.path.removeprefix('/results/')
        if name not in ('browser-report.json', 'export.csv') or self.path != '/results/' + name:
            self.send_error(404)
            return
        (results / name).write_bytes(self.rfile.read(int(self.headers['Content-Length'])))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')

ThreadingHTTPServer(('127.0.0.1', args.port), Handler).serve_forever()
