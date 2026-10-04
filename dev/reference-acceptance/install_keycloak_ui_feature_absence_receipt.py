#!/usr/bin/env python3
"""Install a verified local UI-feature receipt, trigger formal re-evaluation, and read back it."""

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[2]
BASE = "http://localhost:18080"
SUITE = "samlscope-reference-suite"


def save(path, value):
    pathlib.Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def api(path, body=None):
    request = urllib.request.Request(
        BASE + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read()
        return None if not raw else json.loads(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=pathlib.Path)
    args = parser.parse_args()
    folder = args.folder.resolve()
    sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
    import verify_keycloak_ui_feature_absence as verifier

    campaign = verifier.verify_folder(folder, require_adoption=False)
    campaign["tamper"] = verifier.run_tamper_tests(folder)
    save(folder / "pre-install-verification.json", campaign)
    run = campaign["runId"]
    if re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", run) is None:
        raise ValueError("Invalid Run")
    destination = "/data/ui-native-feature-absence/" + run + ".json"
    subprocess.run(["docker", "exec", SUITE, "mkdir", "-p", "/data/ui-native-feature-absence"],
                   check=True, timeout=30)
    absent = subprocess.run(["docker", "exec", SUITE, "test", "!", "-e", destination], timeout=30)
    if absent.returncode:
        raise RuntimeError("Refusing to overwrite an existing Run receipt")
    subprocess.run(["docker", "cp", str(folder / "receipt.json"), SUITE + ":" + destination],
                   check=True, timeout=30)
    readback = subprocess.run(["docker", "exec", SUITE, "cat", destination],
                              check=True, capture_output=True, timeout=30).stdout
    original = (folder / "receipt.json").read_bytes()
    if readback != original:
        raise RuntimeError("Installed receipt read-back differs")
    save(folder / "receipt-installation.json", {
        "runId": run, "destination": destination,
        "sha256": hashlib.sha256(readback).hexdigest(), "readBackEqual": True,
    })
    save(folder / "evaluation.json", api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
    for name in ("result.json", "protocol-evidence"):
        with urllib.request.urlopen(BASE + "/api/runs/" + run + "/" + name, timeout=60) as response:
            target = folder / (name if "." in name else name + ".json")
            target.write_bytes(response.read())
    report = verifier.verify_folder(folder, require_adoption=True)
    report["tamper"] = verifier.run_tamper_tests(folder)
    save(folder / "formal-verification.json", report)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
