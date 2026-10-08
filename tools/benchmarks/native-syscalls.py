"""Summarize a path-filtered strace log without exposing paths or input bytes."""
import json
import re
import sys
from pathlib import Path

stats = {'read_calls':0, 'returned_bytes':0, 'max_returned_bytes':0, 'seek_calls':0,
         'write_calls':0, 'written_bytes':0}
read = re.compile(r'read\(.*?, (\d+)\)\s+=\s+(\d+)')
write = re.compile(r'write\(.*?, (\d+)\)\s+=\s+(\d+)')
with Path(sys.argv[1]).open() as trace:
    for line in trace:
        if line.startswith('lseek('):
            stats['seek_calls'] += 1
        if match := read.match(line):
            size = int(match[2])
            stats['read_calls'] += 1
            stats['returned_bytes'] += size
            stats['max_returned_bytes'] = max(stats['max_returned_bytes'], size)
        if match := write.match(line):
            stats['write_calls'] += 1
            stats['written_bytes'] += int(match[2])
print(json.dumps(stats))
