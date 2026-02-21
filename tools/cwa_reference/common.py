from __future__ import annotations

import shutil
import subprocess
import urllib.request
from pathlib import Path


OPENMOVEMENT_BASE = (
    "https://raw.githubusercontent.com/openmovementproject/openmovement/master"
)


def ensure_cwa_convert(cache_dir: str = ".cache/cwa-reference") -> Path:
    cache = Path(cache_dir)
    src_dir = cache / "cwa-convert-src"
    bin_path = cache / "cwa-convert"
    src_dir.mkdir(parents=True, exist_ok=True)

    if bin_path.exists():
        return bin_path

    if shutil.which("cc") is None:
        raise RuntimeError("C compiler 'cc' not found in PATH")

    files = {
        "main.c": f"{OPENMOVEMENT_BASE}/Software/AX3/cwa-convert/c/main.c",
        "cwa.c": f"{OPENMOVEMENT_BASE}/Software/AX3/cwa-convert/c/cwa.c",
        "cwa.h": f"{OPENMOVEMENT_BASE}/Software/AX3/cwa-convert/c/cwa.h",
    }

    for name, url in files.items():
        target = src_dir / name
        if not target.exists():
            urllib.request.urlretrieve(url, target)

    cmd = [
        "cc",
        "-O2",
        str(src_dir / "main.c"),
        str(src_dir / "cwa.c"),
        "-lm",
        "-o",
        str(bin_path),
    ]
    subprocess.run(cmd, check=True)
    return bin_path


def ensure_example_cwa(cache_dir: str = ".cache/cwa-reference") -> Path:
    cache = Path(cache_dir)
    data_dir = cache / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    file_path = data_dir / "example-610-steps.cwa"
    if file_path.exists():
        return file_path

    url = (
        f"{OPENMOVEMENT_BASE}/Software/ThirdParty/pedometer/data/example-610-steps.cwa"
    )
    urllib.request.urlretrieve(url, file_path)
    return file_path
