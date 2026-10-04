#!/usr/bin/env python3
"""Append separate native signing capability controls to a complete original matrix.

Both capability fixtures pass through the product's metadata import UI. Only the
temporary client's native signature algorithm is changed; all other imported
policy and key attributes must remain exact. This collector assigns no verdict.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import re
import urllib.request

REPO = Path(__file__).resolve().parents[2]
from import_metadata_batch import api, save, BASE
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
from capture_run_originals import capture
from verify_metadata_intersection import REQUIRED
from native_algorithm_preparation import verify as verify_preparation


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--playwright-modules", type=Path, required=True)
    parser.add_argument("--alternative", choices=["sha384", "sha512"], required=True)
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    required = REQUIRED if args.alternative == "sha384" else {
        {"algorithm-entity-sha384": "algorithm-entity-sha512", "algorithm-signing-256-keysize-excluded": "algorithm-signing-256-512-keysize-excluded",
         "algorithm-signing-384-keysize-excluded": "algorithm-signing-512-256-keysize-excluded"}.get(v, v) for v in REQUIRED}
    operations = json.loads((source / "operations.json").read_bytes())
    if {row["variant"] for row in operations} != required or len(operations) != len(required):
        raise ValueError("Original native matrix is incomplete")
    for variant in required:
        verify_preparation(source, variant)
    created = json.loads((source / "created.json").read_bytes())
    run, plan = created["run"]["id"], created["run"]["planId"]
    entity = BASE + "/p/" + plan
    before = api("/api/runs/" + run + "/transcript")
    if before != json.loads((source / "transcript.json").read_bytes()):
        raise ValueError("Original native matrix transcript changed")
    out.mkdir(parents=True, exist_ok=False)
    # Inspect the actual installed enum before mutating any temporary client. A
    # configuration API accepting an arbitrary string does not prove capability.
    native_jar = out / "native-saml-core.jar"
    subprocess.run(["docker", "cp", "samlscope-reference-keycloak:/opt/keycloak/lib/lib/main/org.keycloak.keycloak-saml-core-26.7.2.jar",
                    str(native_jar)], check=True, capture_output=True, timeout=30)
    enum = subprocess.check_output(["javap", "-cp", str(native_jar), "org.keycloak.saml.SignatureAlgorithm"], timeout=30)
    (out / "native-signature-algorithms.javap.txt").write_bytes(enum)
    values = re.findall(r"public static final org\.keycloak\.saml\.SignatureAlgorithm ([A-Z0-9_]+);", enum.decode())
    save(out / "native-capability-preflight.json", dict(native_jar_sha256=sha(native_jar.read_bytes()),
        signature_algorithms=values, required=["RSA_SHA256", "RSA_" + args.alternative.upper()], product_mutations=0))
    if not {"RSA_SHA256", "RSA_" + args.alternative.upper()} <= set(values):
        raise ValueError("Native required signature algorithm unavailable; no capability mutations performed")
    shutil.copytree(source, out / "source", symlinks=True)
    save(out / "created.json", created)
    save(out / "plan.json", json.loads((source / "plan.json").read_bytes()))
    save(out / "transcript-before.json", before)
    stage = out / "driver"
    stage.mkdir()
    shutil.copy2(Path(__file__).with_name("console_import.mjs"), stage / "console_import.mjs")
    (stage / "node_modules").symlink_to(args.playwright_modules.resolve(), target_is_directory=True)
    records = []
    save(out / "operations.json", records)
    try:
        for label, algorithm in [("sha256", "RSA_SHA256"), (args.alternative, "RSA_" + args.alternative.upper())]:
            folder = out / ("capability-" + label)
            folder.mkdir()
            campaign = api("/api/runs/" + run + "/metadata-lab/automatic-polling",
                           dict(variants=["control"], pollingDelaySeconds=0))
            save(folder / "campaign.json", campaign)
            with urllib.request.urlopen(campaign["automaticStartUrl"], timeout=30) as response:
                if response.status != 202:
                    raise ValueError("Native import fixture fetch not gated")
            with urllib.request.urlopen(campaign["metadataUrl"], timeout=30) as response:
                fixture = response.read()
            (folder / "fixture.xml").write_bytes(fixture)
            follow = shlex.join([sys.executable, str(Path(__file__).with_name("import_metadata_batch.py")),
                                 "--flow-run", run, "--output", str(folder / "flow.json"), "--suite-signature-control"])
            row = dict(label=label, algorithm=algorithm, fixture_sha256=sha(fixture),
                       import_attempted=True, status="incomplete")
            records.append(row)
            save(out / "operations.json", records)
            command = ["node", str(stage / "console_import.mjs"), "--fixture", str(folder / "fixture.xml"),
                       "--record", str(folder / "import.json"), "--entity-id", entity,
                       "--verify-command", follow, "--delete", "--signing-capability", algorithm]
            executed = subprocess.run(command, capture_output=True, text=True, timeout=420)
            (folder / "driver.log").write_text(executed.stdout + executed.stderr)
            row["driver_exit"] = executed.returncode
            receipt = json.loads((folder / "import.json").read_bytes())
            row["restored"] = receipt.get("cleanup", {}).get("read_back_absent") is True
            row["policy_write_attempts"] = receipt.get("import", {}).get("signing_capability_policy", {}).get("write_attempts", 0)
            save(out / "operations.json", records)
            if not row["restored"]:
                raise ValueError("Native capability client removal not verified")
            if executed.returncode or receipt["status"] != "success":
                raise ValueError("Native signing capability flow incomplete")
            row["status"] = "recorded"
            save(out / "operations.json", records)
            print(label + " native signing capability recorded and restored", flush=True)
    finally:
        save(out / "operations.json", records)
        entries = api("/api/runs/" + run + "/transcript")
        if entries[:len(before)] != before:
            raise ValueError("Original native matrix transcript changed")
        save(out / "transcript.json", entries)
        capture(out, run, entries)
        subprocess.run(["docker", "cp", "samlscope-reference-suite:/data/target-metadata/" + run + ".xml",
                        str(out / "target-metadata.xml")], check=True, capture_output=True, timeout=30)
        if (out / "target-metadata.xml").read_bytes() != (source / "target-metadata.xml").read_bytes():
            raise ValueError("Same-Run native target signing keys changed")
        save(out / "operation-counts.json", dict(run=run, import_attempts=len(records),
            import_save_attempts=sum(json.loads((out / ("capability-" + row["label"]) / "import.json").read_bytes())["import"].get("save_clicked", False) for row in records),
            native_policy_write_attempts=sum(row.get("policy_write_attempts", 0) for row in records),
            temporary_clients_removed=sum(row.get("restored", False) for row in records),
            protocol_operation_pairs_attempted=len(records), product_restarts=0, human_operations=0,
            restored=all(row.get("restored") is True for row in records), verdict_adopted=False))
        save(out / "batch-operation-counts.json", dict(run=run, matrix_imports=len(operations),
            capability_imports=len(records), import_save_attempts=len(operations) + len(records),
            native_policy_write_attempts=sum(row.get("policy_write_attempts", 0) for row in records),
            temporary_clients_removed=len(operations) + sum(row.get("restored", False) for row in records),
            protocol_operation_pairs_attempted=len(operations) + len(records), product_restarts=0,
            human_operations=0, restored=all(row.get("restored") is True for row in records), verdict_adopted=False))
    print("Native capability originals recorded; no verdict assigned", flush=True)


if __name__ == "__main__":
    main()
