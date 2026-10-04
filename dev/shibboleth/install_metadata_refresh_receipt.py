#!/usr/bin/env python3
"""Install only original, restored Shibboleth recurring-refresh campaign evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
SUITE = "samlscope-reference-suite"
FILES = (
    "original-providers.xml", "configured-providers.xml", "final-providers.xml",
    "original-audit.xml", "configured-audit.xml", "final-audit.xml",
    "operation-counts.json", "restoration.json", "native-refresh.log", "native-signature-audit.log",
    "metadata-a.xml", "metadata-b.xml",
    "target-runtime-start.json", "target-runtime-end.json",
    "target-container-inspect-start.json", "target-container-inspect-end.json",
    "target-image-inspect-start.json", "target-image-inspect-end.json",
    "target-version-runtime-start.txt", "target-version-runtime-end.txt",
    "target-version-source-start.txt", "target-version-source-end.txt",
)
HASH_FIELDS = dict(zip(FILES[:12], (
    "originalConfigSha256", "configuredConfigSha256", "finalConfigSha256",
    "originalAuditSha256", "configuredAuditSha256", "finalAuditSha256",
    "operationCountsSha256", "restorationSha256", "nativeRefreshSha256", "nativeAuditSha256",
    "metadataASha256", "metadataBSha256")))
HASH_FIELDS.update({"target-runtime-start.json": "targetRuntimeStartSha256",
                    "target-runtime-end.json": "targetRuntimeEndSha256"})


def read(path):
    return json.loads(Path(path).read_text())


def prepare(folder):
    folder = Path(folder).resolve()
    run = read(folder / "created.json")["run"]["id"]
    restored = read(folder / "restoration.json")
    if not restored.get("restored") or restored.get("failures") or not restored.get("backingFileRemoved"):
        raise ValueError("Product restoration is incomplete")
    for kind in ("providers", "audit"):
        if (folder / f"original-{kind}.xml").read_bytes() != (folder / f"final-{kind}.xml").read_bytes():
            raise ValueError("Final product configuration differs from original")
    campaign = read(folder / "campaign.json")
    expected_variants = ["control", "no-valid-until"]
    supersession_variants = ["control", "multiple-signing-keys-first", "multiple-signing-keys", "no-valid-until"]
    if campaign["campaignVariants"] not in (expected_variants, supersession_variants):
        raise ValueError("Unexpected campaign variants")
    plan_response = read(folder / "plan.json")["plan"]
    source = "http://samlscope-reference-suite:8080/p/" + plan_response["plan"]["id"] + "/metadata/live?run=" + run
    entries = {entry["id"]: entry for entry in read(folder / "transcript.json")}
    decoded = {entry["id"]: folder / entry["file"] for entry in read(folder / "decoded-manifest.json")}
    records = read(folder / "phase-records.json")
    if [item["variant"] for item in records] != campaign["campaignVariants"]:
        raise ValueError("Both completed phases are required")
    selected_records = [records[0], records[-1]]
    for index, record in enumerate(selected_records):
        for key in ("fetchReference", "preparedReference", "requestReference", "responseReference"):
            if entries[record[key]]["runId"] != run:
                raise ValueError("Another Run in phase references")
        if entries[record["fetchReference"]]["url"] != source:
            raise ValueError("Native fetch does not use the stable product URL")
        shutil.copyfile(decoded[record["preparedReference"]], folder / ("metadata-a.xml" if index == 0 else "metadata-b.xml"))
        record["metadataUrl"] = source
        record["entityId"] = plan_response["entityId"]
    manifest = dict(schema="samlscope-native-metadata-refresh-v1", runId=run,
        adapter="shibboleth-native-http-refresh-v1", entityId=plan_response["entityId"],
        metadataUrl=source, variantB="no-valid-until", refreshWaitSeconds=campaign["pollingDelaySeconds"],
        phaseA=selected_records[0], phaseB=selected_records[1])
    for name, field in HASH_FIELDS.items():
        manifest[field] = SHA((folder / name).read_bytes())
    (folder / "metadata-refresh-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return run, manifest


def install(folder):
    folder = Path(folder).resolve()
    run, manifest = prepare(folder)
    target = "/data/metadata-rejection-evidence/" + run + ".refresh"
    subprocess.run(["docker", "exec", SUITE, "mkdir", "-p", target], check=True, timeout=30)
    for name in FILES:
        subprocess.run(["docker", "cp", str(folder / name), SUITE + ":" + target + "/" + name],
                       check=True, timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    manifest_file = folder / "metadata-refresh-manifest.json"
    subprocess.run(["docker", "cp", str(manifest_file), SUITE + ":" + target + "/manifest.json"],
                   check=True, timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    hashes = subprocess.check_output(["docker", "exec", SUITE, "sha256sum",
        *[target + "/" + name for name in FILES], target + "/manifest.json"], text=True, timeout=30)
    readback = [line.split()[0] for line in hashes.splitlines()]
    expected = [*[SHA((folder / name).read_bytes()) for name in FILES], SHA(manifest_file.read_bytes())]
    if readback != expected:
        raise ValueError("Suite read-back differs from original evidence")
    (folder / "metadata-refresh-receipt-install.json").write_text(json.dumps(dict(
        runId=run, target=target, readBackSha256=readback), indent=2) + "\n")
    return run


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    print(prepare(args.folder)[0] if args.prepare_only else install(args.folder))
