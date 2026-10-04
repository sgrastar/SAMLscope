#!/usr/bin/env python3
"""Install restored native supersession originals; receipt declarations never supply a judgment."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from install_metadata_refresh_receipt import install as install_refresh

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
FIXTURES = {"new-key-explicit-acs", "new-key-default-acs", "new-key-second-acs", "new-key-redirect",
    "old-key-new-acs", "rollover-first-key-new-acs", "rollover-second-key-new-acs", "new-key-old-acs",
    "new-key-invalid-signature"}


def install(folder):
    folder = Path(folder).resolve()
    run = install_refresh(folder)
    probes = json.loads((folder / "supersession-probes.json").read_text())
    if len(probes) != len(FIXTURES) or {probe["fixture"] for probe in probes} != FIXTURES:
        raise ValueError("Complete, nonduplicated Suite outbox matrix required")
    entries = {entry["id"]: entry for entry in json.loads((folder / "transcript.json").read_text())}
    for probe in probes:
        entry = entries[probe["requestReference"]]
        if entry["runId"] != run or entry["samlSummary"]["fixture_id"] != probe["fixture"]:
            raise ValueError("Outbox evidence identity changed")
    readbacks = json.loads((folder / "supersession-readbacks.json").read_text())
    if {(row["kind"], row["phase"]) for row in readbacks} != {
            (kind, phase) for kind in ("providers", "audit") for phase in ("before", "after")} or len(readbacks) != 4:
        raise ValueError("Exactly four real configured-state originals required")
    for row in readbacks:
        raw = (folder / row["file"]).read_bytes()
        if SHA(raw) != row["sha256"] or raw != (folder / ("configured-" + row["kind"] + ".xml")).read_bytes():
            raise ValueError("Read-back is not the configured native original")
    manifest = dict(schema="samlscope-shibboleth-metadata-supersession-v1", runId=run,
        adapter="shibboleth-native-http-supersession-v1",
        targetMetadataSha256=SHA((folder / "target-metadata.xml").read_bytes()),
        baseReceiptSha256=SHA((folder / "metadata-refresh-manifest.json").read_bytes()),
        probes=probes, configurationReadBacks=readbacks,
        nativeAuditSha256=SHA((folder / "native-signature-audit.log").read_bytes()))
    manifest_file = folder / "metadata-supersession-manifest.json"
    manifest_file.write_text(json.dumps(manifest, indent=2) + "\n")
    target = "/data/metadata-rejection-evidence/" + run + ".supersession"
    subprocess.run(["docker", "exec", "samlscope-reference-suite", "mkdir", "-p", target], check=True, timeout=30)
    files = {**{row["file"]: row["file"] for row in readbacks},
        "native-signature-audit.log": "native-audit.log", manifest_file.name: "manifest.json"}
    hashes = {}
    for source, destination in files.items():
        subprocess.run(["docker", "cp", str(folder / source), "samlscope-reference-suite:" + target + "/" + destination],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        live = subprocess.check_output(["docker", "exec", "samlscope-reference-suite", "sha256sum", target + "/" + destination], timeout=30).decode().split()[0]
        if live != SHA((folder / source).read_bytes()):
            raise ValueError("Installed original read-back mismatch")
        hashes[destination] = live
    (folder / "metadata-supersession-install.json").write_text(json.dumps(dict(runId=run,
        target=target, readBackSha256=hashes), indent=2) + "\n")
    return run


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    print(install(args.folder))
