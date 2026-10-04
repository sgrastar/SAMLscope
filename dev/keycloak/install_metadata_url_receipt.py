#!/usr/bin/env python3
"""Install one restored Keycloak native metadata-URL receipt into the Suite data directory."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import urllib.request
import zipfile

SUITE = "samlscope-reference-suite"
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
SHA = lambda raw: hashlib.sha256(raw).hexdigest()

COMMON = (
    "manifest.json", "admin-before.json", "admin-configured.json", "admin-final.json",
    "operation-counts.json", "KeycloakMetadataUrlRelay.java", "KeycloakMetadataUrlRelay.class",
    "relay-requests.jsonl", "target-runtime-start.json", "target-runtime-end.json",
    "keycloak-jars-start.json", "keycloak-jars-end.json",
    "provider-inventory-start.json", "provider-inventory-end.json",
    "keycloak-config-start.txt", "keycloak-config-end.txt",
)


def api(path, body=None):
    request = urllib.request.Request(
        "http://localhost:18080" + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.load(response)


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def install(folder):
    folder = Path(folder).resolve()
    manifest = json.loads((folder / "manifest.json").read_text())
    run = manifest.get("runId")
    if RUN_RE.fullmatch(run or "") is None:
        raise ValueError("Invalid Run identifier")
    schema = manifest.get("schema")
    if schema == "samlscope-keycloak-native-mdq-v1":
        suffix = ".mdq"
        files = (*COMMON, "metadata-mdq.xml", "relay-body-1.xml")
    elif schema == "samlscope-keycloak-native-metadata-refresh-v1":
        suffix = ".refresh"
        files = (*COMMON, "metadata-a.xml", "metadata-b.xml",
                 "signature-control.json", "signature-control-response.html",
                 "old-key-control.json", "old-key-control-response.html",
                 "relay-body-1.xml", "relay-body-2.xml", "relay-body-3.xml")
    else:
        raise ValueError("Unsupported Keycloak metadata receipt schema")
    if json.loads((folder / "created.json").read_text())["run"]["id"] != run:
        raise ValueError("Created Run differs from manifest")
    counts = json.loads((folder / "operation-counts.json").read_text())
    expected_roundtrips, expected_fetches = ((2, 1) if suffix == ".mdq" else (4, 3))
    if counts != {
        "restored": True, "productConfigurationWrites": 2, "restorationWrites": 1,
        "protocolRoundTrips": expected_roundtrips, "metadataFetches": expected_fetches,
        "productRestarts": 0, "humanOperations": 0, "temporaryRelayStopped": True,
    }:
        raise ValueError("Operation counts differ from the automatic restored campaign")
    if (folder / "admin-before.json").read_bytes() != (folder / "admin-final.json").read_bytes() \
            or json.loads((folder / "admin-final.json").read_text()) != []:
        raise ValueError("Keycloak state was not restored exactly")
    for name in files:
        path = folder / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("Receipt original is unavailable: " + name)
    destination = "/data/metadata-rejection-evidence/" + run + suffix
    if subprocess.run(["docker", "exec", SUITE, "test", "!", "-e", destination]).returncode != 0:
        raise ValueError("Refusing to overwrite an installed receipt")
    subprocess.run(["docker", "exec", SUITE, "mkdir", "-p", destination], check=True, timeout=30)
    for name in files:
        subprocess.run(["docker", "cp", str(folder / name), SUITE + ":" + destination + "/" + name],
                       check=True, capture_output=True, timeout=60)
    output = subprocess.check_output(
        ["docker", "exec", SUITE, "sha256sum", *[destination + "/" + name for name in files]],
        text=True, timeout=60)
    actual = [line.split()[0] for line in output.splitlines()]
    expected = [SHA((folder / name).read_bytes()) for name in files]
    if actual != expected:
        raise ValueError("Suite receipt read-back differs")
    record = {
        "runId": run, "target": destination, "schema": schema,
        "readBackSha256": actual, "configurationWrites": 2,
        "restorationWrites": 1, "productRestarts": 0, "humanOperations": 0,
    }
    (folder / "receipt-install.json").write_text(json.dumps(record, indent=2) + "\n")
    return run


def evaluate(folder, run, output):
    from metadata_url_campaign import suite_capture

    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = api("/api/runs/" + run + "/transcript")
    save(output / "transcript-before.json", before)
    save(output / "status-before.json", api("/api/runs/" + run + "/protocol-evidence"))
    suite_capture(output)
    runtime_path = output / "suite-runtime.json"
    runtime = json.loads(runtime_path.read_text())
    runtime["runId"] = run
    runtime["phase"] = "formal-evaluation"
    classes = {}
    runner_jar = output / runtime["jars"]["runner"]["file"]
    with zipfile.ZipFile(runner_jar) as archive:
        for name in (
            "com/samlscope/runner/cases/KeycloakMetadataUrlEvidenceFile.class",
            "com/samlscope/runner/cases/MdqAcquisitionConfigurationTestCase.class",
            "com/samlscope/runner/cases/MetadataRefreshEvidenceFile.class",
        ):
            raw = archive.read(name)
            classes[name] = {"sha256": SHA(raw), "size": len(raw)}
    runtime["classes"] = classes
    save(runtime_path, runtime)
    install = json.loads((folder / "receipt-install.json").read_text())
    save(output / "receipt-installation.json", install)
    save(output / "evaluation.json", api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
    after = api("/api/runs/" + run + "/transcript")
    save(output / "transcript.json", after)
    save(output / "result.json", api("/api/runs/" + run + "/result.json"))
    save(output / "status-after.json", api("/api/runs/" + run + "/protocol-evidence"))
    if {entry["id"]: entry for entry in before} != {entry["id"]: entry for entry in after}:
        raise RuntimeError("Run transcript changed during formal re-evaluation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder")
    parser.add_argument("--evaluation-dir", type=Path)
    args = parser.parse_args()
    run = install(args.folder)
    if args.evaluation_dir is not None:
        evaluate(Path(args.folder).resolve(), run, args.evaluation_dir)
    print(run)
