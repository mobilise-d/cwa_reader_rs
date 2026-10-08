"""Run an isolated native workload; private input paths are never written to results."""
import argparse
import json
import resource
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('file', type=Path)
parser.add_argument('--case', choices=['metadata', 'report', 'csv-sink', 'early', 'middle', 'late'], required=True)
parser.add_argument('--batch-packets', type=int)
parser.add_argument('--resample-hz', type=float)
args = parser.parse_args()
options = {}
if args.batch_packets is not None:
    options['batch_packets'] = args.batch_packets
if args.resample_hz is not None:
    options['resample_hz'] = args.resample_hz
scope = {'BENCH_PATH': str(args.file), 'BENCH_CASE': args.case, 'BENCH_OPTIONS': options}
exec(compile(Path(__file__).with_name('reader-workload.py').read_text(), 'reader-workload.py', 'exec'), scope)
result = scope['BENCH_RESULT']
# Linux VmHWM belongs to this executable's memory map. ru_maxrss can retain an
# earlier executable's peak when a shell replaces itself with this process.
status = Path('/proc/self/status')
if status.exists():
    rss = int(next(line.split()[1] for line in status.read_text().splitlines() if line.startswith('VmHWM:'))) * 1024
    rss_metric = 'Linux /proc/self/status VmHWM'
else:
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if __import__('sys').platform == 'darwin' else 1024)
    rss_metric = 'getrusage ru_maxrss'
result.update(case=args.case, options=options, input_bytes=args.file.stat().st_size,
              process_peak_rss_bytes=rss, memory_metric=rss_metric)
print(json.dumps(result))
