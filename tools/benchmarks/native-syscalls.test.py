"""Check attempts, successful bytes, interrupted retries and EOF separately."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('native_syscalls', Path(__file__).with_name('native-syscalls.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
result = module.summarize('''read(4, ""..., 512) = -1 EINTR (Interrupted system call)
read(4, ""..., 512) = ? ERESTARTSYS (To be restarted)
read(4, ""..., 512) = 511
read(4, "", 1) = 0
write(5, ""..., 8) = -1 ENOSPC (No space left on device)
write(5, ""..., 8) = 4
lseek(4, 0, SEEK_SET) = 0
'''.splitlines())
assert result == {'read_calls':4, 'returned_bytes':511, 'max_returned_bytes':511,
                  'seek_calls':1, 'write_calls':2, 'written_bytes':4}
print('Native syscall attempt/byte checks passed')
