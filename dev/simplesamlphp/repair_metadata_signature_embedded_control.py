#!/usr/bin/env python3
"""Repair one completed campaign with the positive fixture's exact embedded-anchor control."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
from import_metadata_batch import api, save
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
from capture_run_originals import capture
sys.path.insert(0, str(Path(__file__).resolve().parent))
from metadata_signature_native_campaign import (
    ADAPTER, ADAPTER_LOCAL, CERT_DIR, CONFIG, CONTAINER, RELAY, SHA, TARGET,
    configure, embedded, entity_id, native_validate, record_file, recorder, router_script,
    update_relay, write_in_place,
)
from native_mdq_fixture_campaign import capture_product_runtime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", required=True, type=Path)
    parser.add_argument("--kind", choices=("embedded-anchor", "invalid-signature"),
                        default="embedded-anchor")
    args = parser.parse_args()
    folder = args.campaign.resolve()
    repair = folder / ("repair-embedded-control" if args.kind == "embedded-anchor"
                       else "repair-invalid-control")
    repair.mkdir(exist_ok=False)
    created = json.loads((folder / "created.json").read_text())
    plan_record = json.loads((folder / "plan.json").read_text())
    run = created["run"]["id"]
    plan = plan_record["plan"]["plan"]["id"]
    variant = "signed-other-key-primary-keyinfo" if args.kind == "embedded-anchor" else "bad-signature"
    fixture = (folder / variant / "fixture.xml").read_bytes()
    certificate = embedded(fixture)
    if certificate is None:
        raise RuntimeError("Positive fixture has no embedded certificate")
    original = CONFIG.read_bytes()
    (repair / "original-config.php").write_bytes(original)
    start_runtime = capture_product_runtime(repair, "start")
    operations = []
    relay_started = False
    config = validation = final = None
    anchor_path = fixture_path = None
    try:
        subprocess.run(["docker", "exec", CONTAINER, "sh", "-c", "test ! -e " + RELAY],
                       check=True, timeout=30)
        subprocess.run(["docker", "exec", CONTAINER, "mkdir", "-p", RELAY], check=True, timeout=30)
        router = router_script(RELAY)
        subprocess.run(["docker", "exec", "-i", CONTAINER, "sh", "-c",
                        "cat > " + RELAY + "/router.php"], input=router, check=True, timeout=30)
        subprocess.run(["docker", "exec", "-d", CONTAINER, "sh", "-c",
            "echo $$ > %s/pid; exec php -S 127.0.0.1:8081 -t %s %s/router.php >%s/server.log 2>&1"
            % (RELAY, RELAY, RELAY, RELAY)], check=True, timeout=30)
        relay_started = True
        time.sleep(1)
        subprocess.run(["docker", "exec", "-i", CONTAINER, "sh", "-c", "cat > " + ADAPTER],
                       input=ADAPTER_LOCAL.read_bytes(), check=True, timeout=30)
        fixture_path = RELAY + "/positive-fixture.xml"
        subprocess.run(["docker", "exec", "-i", CONTAINER, "sh", "-c", "cat > " + fixture_path],
                       input=fixture, check=True, timeout=30)
        update_relay(entity_id(fixture), fixture_path)
        label = "positive-embedded" if args.kind == "embedded-anchor" else "invalid-signature"
        config = configure(run, repair, label, original,
            "samlscope-md03-positive-embedded.crt" if args.kind == "embedded-anchor"
            else "samlscope-md03-invalid-embedded.crt",
            __import__("metadata_signature_native_campaign").pem(certificate),
            recorder(plan, run), operations)
        anchor_path = config["containerPath"]
        validation = native_validate(run, plan, repair, label,
            variant, entity_id(fixture), fixture_path, SHA(fixture),
            config, anchor_path, 3)
    finally:
        if CONFIG.read_bytes() != original:
            write_in_place(CONFIG, original)
            operations.append(dict(operation="product-config-restore", sha256=SHA(original)))
        (repair / "final-config.php").write_bytes(CONFIG.read_bytes())
        try:
            final = record_file(run, repair, "configuration-final",
                "/var/simplesamlphp/config/config-override.php", recorder(plan, run))
        finally:
            for path in [anchor_path, fixture_path, ADAPTER]:
                if path:
                    subprocess.run(["docker", "exec", CONTAINER, "rm", "-f", path], check=True, timeout=30)
            if relay_started:
                subprocess.run(["docker", "exec", CONTAINER, "sh", "-c",
                                "kill \"$(cat %s/pid)\"" % RELAY], check=True, timeout=30)
                subprocess.run(["docker", "exec", CONTAINER, "rm", "-rf", RELAY], check=True, timeout=30)
        end_runtime = capture_product_runtime(repair, "end")
        stable = (start_runtime["binding"] == end_runtime["binding"]
                  and start_runtime["version_source"]["sha256"] == end_runtime["version_source"]["sha256"]
                  and start_runtime["runtime_version"]["value"] == end_runtime["runtime_version"]["value"])
        restored = CONFIG.read_bytes() == original
        save(repair / "operations.json", dict(operations=operations, product_configuration_writes=1,
            restoration_writes=1, native_validation_invocations=1, product_restarts=0,
            human_operations=0, restored=restored, runtime_stable=stable))
        if not (restored and stable):
            raise RuntimeError("Repair did not restore the product exactly")
    if not config or not validation or not final:
        raise RuntimeError("Repair evidence incomplete")

    receipt_path = (folder / "signature-verification-receipt-repaired.json"
                    if args.kind == "invalid-signature"
                    else folder / "signature-verification-receipt.json")
    receipt = json.loads(receipt_path.read_text())
    control = next(row for row in receipt["negativeControls"] if row["kind"] == args.kind)
    control["nativeRejectionReference"] = validation["reference"]
    control["nativeRejectionSha256"] = validation["sha256"]
    control["configurationReadBack"] = {key: value for key, value in config.items()
                                         if key != "containerPath"}
    receipt["restorationReadBack"]["finalReference"] = final["reference"]
    receipt["restorationReadBack"]["finalSha256"] = final["sha256"]
    output_receipt = folder / ("signature-verification-receipt-repaired-v2.json"
                               if args.kind == "invalid-signature"
                               else "signature-verification-receipt-repaired.json")
    save(output_receipt, receipt)
    destination = "/data/metadata-rejection-evidence/" + run + ".signature-verification.json"
    subprocess.run(["docker", "cp", str(output_receipt),
                    "samlscope-reference-suite:" + destination], check=True, timeout=30)
    installed = subprocess.check_output(["docker", "exec", "samlscope-reference-suite", "cat", destination],
                                        timeout=30)
    if installed != output_receipt.read_bytes():
        raise RuntimeError("Repaired receipt read-back differs")
    save(repair / "receipt-installation.json", dict(run=run, sha256=SHA(installed), read_back=True))
    transcript = api("/api/runs/" + run + "/transcript")
    save(folder / "transcript-before-receipt.json", transcript)
    capture(folder, run, transcript)
    save(repair / "evaluation.json", api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
    save(repair / "result.json", api("/api/runs/" + run + "/result.json"))
    after = api("/api/runs/" + run + "/transcript")
    if after != transcript:
        raise RuntimeError("Repair evaluation changed transcript")
    print("Repaired embedded-anchor control and restored product for", run)


if __name__ == "__main__":
    main()
