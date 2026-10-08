"""Create independent native expected values using the checkout's fixture builders."""
import datetime
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import numpy as np
import cwa_reader_rs as reader

root = Path(__file__).resolve().parents[2]
out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)
checkout = out / "checkout"
fixture = root / "tests/reference_data/openmovement/example-610-steps.cwa"
reference = checkout / "tests/reference_data/openmovement/example-610-steps.cwa"
reference.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(fixture, reference)
sys.path.insert(0, str(root / "tests"))
from test_channels import _recording

spec = importlib.util.spec_from_file_location("cwa_parity_cases", root / "tools/wasm/parity.py")
parity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parity)
all_cases = list(parity.cases(checkout))
all_cases.append(("aux-selected", reference, dict(cut=reader.seconds(1.2, 3.7), include_temperature=True, include_light=True, include_battery=True)))
all_cases.append(("flags", reference, dict(include_magnetometer=False, include_temperature=False, include_light=False, include_battery=False)))
all_cases.append(("offset-fractional-seconds", reference, dict(cut=reader.seconds(1.2, 3.7), fixed_utc_offset_timezone=datetime.timezone(datetime.timedelta(seconds=19800.123456)))))
nonzero = checkout / "generated/nonzero/nonzero.cwa"
all_cases.append(("nine-axis-no-mag", nonzero, dict(include_magnetometer=False, include_temperature=False)))
mixed = checkout / "generated/nonzero/mixed.cwa"
all_cases.extend((name, mixed, dict(cut=reader.blocks(start, end))) for name, start, end in [("mixed-first", 0, 1), ("mixed-last", 1, 2)])

manifest = {"metadata": reader.read_metadata(str(fixture)), "report": reader.sampling_consistency_report(str(fixture)), "cases": []}
for name, path, options in all_cases:
    data = reader.read_cwa_file(str(path), **options)
    browser_options = dict(options)
    timezone = browser_options.pop("fixed_utc_offset_timezone", None)
    if timezone is not None:
        browser_options["fixed_utc_offset_seconds"] = timezone.utcoffset(None).total_seconds()
    filename = f"{name}.cwa"
    shutil.copyfile(path, out / filename)
    case = {
        "name": name, "file": filename, "options": browser_options,
        "rows": len(data), "columns": list(data.columns),
        "timezone": "UTC" if data.index.tz is not None else None,
        "timestamps_sha256": hashlib.sha256(data.index.as_unit("us").asi8.astype("<i8").tobytes()).hexdigest(),
        "column_sha256": {},
    }
    for column in data:
        values = data[column].to_numpy(dtype=np.float32)
        case["column_sha256"][column] = hashlib.sha256(values.astype("<f4").tobytes()).hexdigest()
    computed = list(data.columns) if options.get("resample_hz") is not None else [column for column in data if column == "light"]
    if computed:
        case["values"] = {column: [None if np.isnan(x) else float(x) for x in data[column]] for column in computed}
    csv_path = out / f"{name}.csv"
    reader.write_cwa_csv(str(path), str(csv_path), **options)
    case["csv_sha256"] = hashlib.sha256(csv_path.read_bytes()).hexdigest()
    if options.get("include_light") is True:
        case["csv_text"] = csv_path.read_text()
    manifest["cases"].append(case)

errors = []
for label, content, options in [
    ("truncated", fixture.read_bytes()[:1100], {}),
    ("malformed", bytes(1536), {}),
    ("invalid-rate", fixture.read_bytes(), {"resample_hz": -1}),
    ("invalid-method", fixture.read_bytes(), {"resample_hz": 60, "resample_method": "linear"}),
    ("invalid-blocks", fixture.read_bytes(), {"cut": {"type": "blocks", "start": 3, "end": 1}}),
    ("invalid-seconds", fixture.read_bytes(), {"cut": {"type": "seconds", "start": -1}}),
]:
    path = out / f"error-{label}.cwa"
    path.write_bytes(content)
    messages = {}
    for operation in ["read_cwa_file", "write_cwa_csv"]:
        try:
            if operation == "read_cwa_file":
                reader.read_cwa_file(str(path), **options)
            else:
                reader.write_cwa_csv(str(path), str(out / "error.csv"), **options)
        except Exception as error:
            messages[operation] = str(error)
        else:
            raise AssertionError(f"{label} did not fail in {operation}")
    errors.append({"name": label, "file": path.name, "options": options, "messages": messages})
manifest["errors"] = errors
(out / "expected.json").write_text(json.dumps(manifest, allow_nan=False) + "\n")
print(f"Generated {len(all_cases)} native comparison cases")
