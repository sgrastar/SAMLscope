#!/usr/bin/env python3
"""Add native signing capability controls to a complete same-Run intersection matrix.

The original matrix is copied unchanged. These controls configure the installed
product's signing algorithm explicitly; they make no claim about algorithm-list
consumption and never replace any matrix fixture. No verdict is assigned here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
from import_metadata_batch import api, save, flow, BASE
from configuration_batch import ConfigurationBatch
from importlib.util import spec_from_file_location, module_from_spec

_spec = spec_from_file_location("ssp_static_import", Path(__file__).with_name("import_metadata_batch.py"))
native = module_from_spec(_spec)
_spec.loader.exec_module(native)
CONTAINER = "samlscope-reference-ssp"
CONFIG = REPO / "build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php"
PRODUCT_CONFIG = "/var/simplesamlphp/metadata/saml20-sp-remote.php"
ALGORITHMS = [("sha256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
              ("sha384", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")]
READBACK = r'''
$metadata=[];require '/var/simplesamlphp/metadata/saml20-sp-remote.php';
$m=$metadata[$argv[1]]??null;
if($m===null)throw new \RuntimeException('Missing capability peer');
echo json_encode(['entity_id'=>$argv[1],'signature_algorithm'=>$m['signature.algorithm']??null,
 'assertion_encryption'=>$m['assertion.encryption']??null,'validate_authnrequest'=>$m['validate.authnrequest']??null],JSON_THROW_ON_ERROR);
'''


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def product_bytes():
    return subprocess.check_output(["docker", "exec", CONTAINER, "cat", PRODUCT_CONFIG], timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    shutil.copytree(source, out / "source")
    created = json.loads((source / "created.json").read_text())["run"]
    run, plan = created["id"], created["planId"]
    entity = BASE + "/p/" + plan
    entries_before = api("/api/runs/" + run + "/transcript")
    if entries_before != json.loads((source / "transcript.json").read_text()):
        raise ValueError("Original complete campaign transcript changed")
    save(out / "transcript-before.json", entries_before)
    save(out / "plan.json", json.loads((source / "plan.json").read_text()))
    save(out / "created.json", json.loads((source / "created.json").read_text()))
    configuration = ConfigurationBatch(CONFIG)
    configuration.container, configuration.container_path = CONTAINER, PRODUCT_CONFIG
    if b"?>" in configuration.original or entity.encode() in configuration.original:
        raise ValueError("Unexpected or existing capability peer")
    if product_bytes() != configuration.original:
        raise ValueError("Native initial metadata read-back differs")
    (out / "original-sp-config.php").write_bytes(configuration.original)
    # Pin the actual installed native signing implementation for later audit.
    raw = subprocess.check_output(["docker", "exec", CONTAINER, "cat",
        "/var/simplesamlphp/modules/saml/src/Message.php"], timeout=30)
    (out / "native-Message.php").write_bytes(raw)
    operations = []
    save(out / "operations.json", operations)
    try:
        for label, algorithm in ALGORITHMS:
            folder = out / ("capability-" + label)
            folder.mkdir()
            row = dict(label=label, algorithm=algorithm, run=run, status="incomplete")
            operations.append(row)
            save(out / "operations.json", operations)
            campaign = api("/api/runs/" + run + "/metadata-lab/automatic-polling",
                           dict(variants=["control"], pollingDelaySeconds=0))
            save(folder / "campaign.json", campaign)
            with urllib.request.urlopen(campaign["automaticStartUrl"], timeout=30) as response:
                if response.status != 202:
                    raise ValueError("Expected Suite metadata fetch gate")
            with urllib.request.urlopen(campaign["metadataUrl"], timeout=30) as response:
                fixture = response.read()
            (folder / "fixture.xml").write_bytes(fixture)
            parsed = subprocess.run(["docker", "exec", "-i", CONTAINER, "php", "-r", native.PHP, entity, "encrypt"],
                                    input=fixture, capture_output=True, timeout=40)
            (folder / "parser.stdout").write_bytes(parsed.stdout)
            (folder / "parser.stderr").write_bytes(parsed.stderr)
            row["parser_invoked"] = True
            row["parser_returncode"] = parsed.returncode
            if parsed.returncode:
                raise RuntimeError("Native capability metadata parser failed")
            data = json.loads(parsed.stdout)
            if data["entity_id"] != entity or data["validate_authnrequest"] is not True \
                    or data["assertion_encryption"] is not True:
                raise ValueError("Native capability metadata scope differs")
            overlay = data["php"] + "\n$metadata[" + repr(entity) + "][\"signature.algorithm\"] = " + repr(algorithm) + ";"
            (folder / "overlay.php").write_text(overlay + "\n")
            row["configuration_sha256"] = configuration.apply(overlay.encode())
            raw = product_bytes()
            (folder / "configuration-readback.php").write_bytes(raw)
            if raw != configuration.expected:
                raise ValueError("Native capability configuration read-back differs")
            readback_raw = subprocess.check_output(["docker", "exec", CONTAINER, "php", "-r", READBACK, entity], timeout=30)
            (folder / "native-readback.json").write_bytes(readback_raw)
            if json.loads(readback_raw) != dict(entity_id=entity, signature_algorithm=algorithm,
                    assertion_encryption=True, validate_authnrequest=True):
                raise ValueError("Native capability signing setting differs")
            row["configuration_read_back"] = True
            time.sleep(3)  # Installed OPcache revalidation, not a conformance threshold.
            row["protocol_attempted"] = True
            flow(run, folder / "flow.json", suite_signature_control=True)
            row["status"] = "recorded"
            save(out / "operations.json", operations)
            print(label, "native signing capability recorded", flush=True)
    finally:
        restoration = configuration.restore()
        final = product_bytes()
        (out / "final-sp-config.php").write_bytes(final)
        if final != configuration.original:
            restoration["restored"] = False
        save(out / "restoration.json", restoration)
        save(out / "operations.json", operations)
        save(out / "operation-counts.json", dict(run=run,
            configuration_apply_writes=configuration.applied_count,
            restoration_writes=configuration.restoration_writes,
            product_configuration_write_attempts=configuration.write_count,
            native_parser_invocations=sum(row.get("parser_invoked", False) for row in operations),
            protocol_operation_pairs_attempted=sum(row.get("protocol_attempted", False) for row in operations),
            product_restarts=0, human_operations=0, restored=restoration["restored"], verdict_adopted=False))
        entries = api("/api/runs/" + run + "/transcript")
        if entries[:len(entries_before)] != entries_before:
            raise RuntimeError("Original matrix transcript changed")
        save(out / "transcript.json", entries)
        sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
        from capture_run_originals import capture
        capture(out, run, entries)
        subprocess.run(["docker", "cp", "samlscope-reference-suite:/data/target-metadata/" + run + ".xml",
                        str(out / "target-metadata.xml")], check=True, capture_output=True, timeout=30)
        if (out / "target-metadata.xml").read_bytes() != (source / "target-metadata.xml").read_bytes():
            raise ValueError("Same-Run target metadata changed")
        if not restoration["restored"]:
            raise RuntimeError("Native restoration failed; no adoption permitted")
    print("Recorded two separate capability controls; original matrix unchanged; restored", flush=True)


if __name__ == "__main__":
    main()
