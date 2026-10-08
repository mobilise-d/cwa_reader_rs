"""Summarize a path-filtered strace log without exposing paths or input bytes."""
import json
import re
import sys
from pathlib import Path


def summarize(lines):
    stats = {'read_calls':0, 'returned_bytes':0, 'max_returned_bytes':0, 'seek_calls':0,
             'write_calls':0, 'written_bytes':0}
    returned = re.compile(r'\)\s+=\s+(\d+)(?:\s|$)')
    for line in lines:
        if line.startswith('lseek('):
            stats['seek_calls'] += 1
        if line.startswith('read('):
            stats['read_calls'] += 1
            if match := returned.search(line):
                size = int(match[1])
                stats['returned_bytes'] += size
                stats['max_returned_bytes'] = max(stats['max_returned_bytes'], size)
        if line.startswith('write('):
            stats['write_calls'] += 1
            if match := returned.search(line):
                stats['written_bytes'] += int(match[1])
    return stats


if __name__ == '__main__':
    with Path(sys.argv[1]).open() as trace:
        print(json.dumps(summarize(trace)))
