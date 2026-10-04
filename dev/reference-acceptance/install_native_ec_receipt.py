#!/usr/bin/env python3
"""Install one locally verified native EC receipt and verify the container read-back."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request


CONTAINER = "samlscope-reference-suite"
TARGET = "/data/ec-signature-preparations"
BASE = "http://localhost:18080"


def api(path, payload=None):
    data = None if payload is None else json.dumps(payload).encode('utf-8')
    headers = {} if data is None else {'Content-Type': 'application/json'}
    request = urllib.request.Request(BASE + path, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--evaluate", action="store_true", help="formally reevaluate after the read-back")
    args = parser.parse_args()
    folder = args.folder.resolve()
    run = json.loads((folder / "created.json").read_text())["run"]["id"]
    source = folder / "preparation-receipts" / f"{run}.json"
    raw = source.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    subprocess.run(["docker", "exec", CONTAINER, "mkdir", "-p", TARGET], check=True)
    destination = f"{CONTAINER}:{TARGET}/{run}.json"
    subprocess.run(["docker", "cp", str(source), destination], check=True)
    read_back = subprocess.check_output(
        ["docker", "exec", CONTAINER, "cat", f"{TARGET}/{run}.json"])
    if read_back != raw:
        raise RuntimeError("Native EC receipt read-back mismatch")
    record = {"run": run, "sha256": digest, "read_back": True}
    (folder / "receipt-installation.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n")
    if args.evaluate:
        output = folder / 'evaluation-v133'
        if output.exists():
            raise RuntimeError('Refusing to overwrite formal evaluation')
        output.mkdir()
        before = api(f'/api/runs/{run}/transcript')
        (output / 'transcript-before.json').write_text(json.dumps(before, ensure_ascii=False, indent=2) + '\n')
        evaluation = api(f'/api/runs/{run}/protocol-evidence/evaluate', {})
        after = api(f'/api/runs/{run}/transcript')
        if {entry['id']: entry for entry in before} != {entry['id']: entry for entry in after}:
            raise RuntimeError('Formal evaluation changed a transcript entry')
        result = api(f'/api/runs/{run}/result.json')
        protocol = api(f'/api/runs/{run}/protocol-evidence')
        for name, value in [('evaluate.json', evaluation), ('transcript.json', after),
                            ('result.json', result), ('protocol-evidence.json', protocol)]:
            (output / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    print(run, digest)


if __name__ == "__main__":
    main()
