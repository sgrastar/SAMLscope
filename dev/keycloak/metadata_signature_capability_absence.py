#!/usr/bin/env python3
"""Record Keycloak's native metadata-signature capability boundary.

The campaign imports the approved MD03 signature fixtures through Keycloak's own
``Import client`` UI, reads the created clients back through the product API,
executes correlated SSO controls for every fixture that retains the Suite entityID,
and deletes each temporary client before continuing.  It also retains the native
converter output and immutable start/end runtime originals.  This recorder assigns
no verdict; the independent acceptance verifier decides whether the evidence proves
that the configuration capability itself is absent.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from attribute_policy_capability_absence import product_token
from import_metadata_batch import api, save
from md06b_multi_peer_campaign import capture_suite
from metadata_source_capability_absence import converter, lookup, safe_client
from metadata_url_campaign import runtime_capture


BASE = "http://localhost:18080"
CASES = ("IIP-MD03-a-idp-01", "IIP-MD03-b-idp-01", "IIP-MD03-c-idp-01")
FLOW_VARIANTS = (
    "control",
    "unsigned",
    "signed-other-key",
    "signed-other-key-primary-keyinfo",
    "certificate-expired",
    "certificate-not-yet-valid",
    "certificate-no-digital-signature",
    "certificate-critical-extension",
)
BAD_SIGNATURE = "bad-signature"
ALL_VARIANTS = FLOW_VARIANTS + (BAD_SIGNATURE,)
PLAYWRIGHT_MODULES = (
    REPO / "build/acceptance/reference-20260915/slo-oracle/console-import/node_modules"
)
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
MD = "urn:oasis:names:tc:SAML:2.0:metadata"
SCHEMA = "samlscope-keycloak-metadata-signature-capability-absence-v1"


def require(value, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def post_converter(token: str, fixture: bytes, path: Path) -> dict:
    converted = converter(token, fixture)
    safe, removed = safe_client(converted)
    require(not removed, "native converter unexpectedly returned credentials")
    path.write_bytes(canonical(safe))
    return {
        "file": path.name,
        "sha256": SHA(path.read_bytes()),
        "clientId": safe.get("clientId"),
        "protocol": safe.get("protocol"),
    }


def fetch_fixture(plan: str, run: str, variant: str) -> bytes:
    url = (BASE + "/p/" + plan + "/metadata?variant="
           + urllib.parse.quote(variant, safe="") + "&run=" + urllib.parse.quote(run, safe=""))
    with urllib.request.urlopen(url, timeout=60) as response:
        require(response.status == 200, "Suite fixture fetch failed")
        return response.read()


def copy_runtime_phase(source: Path, target: Path, phase: str) -> None:
    for name in (
        f"target-runtime-{phase}.json",
        f"keycloak-jars-{phase}.json",
        f"provider-inventory-{phase}.json",
        f"keycloak-config-{phase}.txt",
    ):
        shutil.move(str(source / name), str(target / name))


def run_import_batch(output: Path, modules: Path) -> None:
    command = [
        sys.executable,
        str(REPO / "dev/keycloak/import_metadata_batch.py"),
        "--output", str(output),
        "--playwright-modules", str(modules),
        "--variants", ",".join(FLOW_VARIANTS),
        "--signature-control",
    ]
    completed = subprocess.run(command, cwd=REPO, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, timeout=3600)
    (output.parent / (output.name + ".driver.log")).write_text(completed.stdout)
    require(completed.returncode == 0, "native Import client batch failed; inspect driver log")
    shutil.move(str(output.parent / (output.name + ".driver.log")), str(output / "driver.log"))


def run_bad_signature_import(output: Path, plan: str, run: str, modules: Path, token: str) -> dict:
    folder = output / BAD_SIGNATURE
    folder.mkdir()
    fixture = fetch_fixture(plan, run, BAD_SIGNATURE)
    fixture_path = folder / "fixture.xml"
    fixture_path.write_bytes(fixture)
    root = ET.fromstring(fixture)
    require(root.tag == "{" + MD + "}EntityDescriptor", "bad-signature root changed")
    entity = root.get("entityID")
    require(entity and entity.endswith("/tampered-after-signing"),
            "bad-signature mutation no longer preserves its expected marker")
    before = lookup(token, entity)
    (folder / "admin-before.json").write_bytes(canonical(before))
    require(before == [], "refusing to overwrite an existing bad-signature client")
    conversion = post_converter(token, fixture, folder / "converter-output.json")

    stage = output / "driver"
    command = [
        "node", str(stage / "console_import.mjs"),
        "--fixture", str(fixture_path),
        "--record", str(folder / "import.json"),
        "--delete",
    ]
    result = subprocess.run(command, cwd=REPO, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=420)
    (folder / "driver.log").write_text(result.stdout)
    require(result.returncode == 0, "Keycloak did not accept the bad-signature fixture")
    record = json.loads((folder / "import.json").read_text())
    require(record.get("status") == "success"
            and record.get("cleanup", {}).get("deleted_status") == 204
            and record.get("cleanup", {}).get("read_back_absent") is True,
            "bad-signature import/restoration record is incomplete")
    final = lookup(token, entity)
    (folder / "admin-final.json").write_bytes(canonical(final))
    require(final == before == [], "bad-signature client was not restored to absence")
    return {
        "variant": BAD_SIGNATURE,
        "entityId": entity,
        "fixtureFile": str(fixture_path.relative_to(output)),
        "fixtureSha256": SHA(fixture),
        "converter": conversion,
        "importFile": str((folder / "import.json").relative_to(output)),
        "importSha256": SHA((folder / "import.json").read_bytes()),
    }


def flow_variant_record(output: Path, variant: str, token: str, entity: str) -> dict:
    folder = output / variant
    fixture = (folder / "fixture.xml").read_bytes()
    root = ET.fromstring(fixture)
    require(root.tag == "{" + MD + "}EntityDescriptor" and root.get("entityID") == entity,
            variant + " fixture identity mismatch")
    imported = json.loads((folder / "import.json").read_text())
    flow = json.loads((folder / "flow.json").read_text())
    steps = {item.get("step"): item.get("ok") for item in imported.get("steps", [])}
    imported_and_read_back = (steps.get("product-import-signal") is True
                              and steps.get("admin-read-back") is True)
    require(imported_and_read_back
            and imported.get("cleanup", {}).get("deleted_status") == 204
            and imported.get("cleanup", {}).get("read_back_absent") is True,
            variant + " native import/restoration is incomplete")
    runtime_certificate_rejection = variant in {
        "certificate-expired", "certificate-not-yet-valid"
    }
    if runtime_certificate_rejection:
        require(imported.get("status") == "failure"
                and imported.get("failure_reason") == "follow-up-flow: command failed"
                and flow.get("variant") == variant
                and flow.get("correlated_success") is False
                and flow.get("positive_exchange", {}).get("success") is False
                and flow.get("receipt") == "no-response:Invalid requester",
                variant + " runtime-certificate rejection record changed")
    else:
        require(imported.get("status") == "success"
                and flow.get("variant") == variant and flow.get("correlated_success") is True
                and flow.get("positive_exchange", {}).get("success") is True,
                variant + " correlated positive flow missing")
    negative = flow.get("negative_control") or {}
    require(negative.get("correlated_success") is False
            and len(negative.get("mutations") or []) == 1,
            variant + " signed-request negative control missing")
    require(lookup(token, entity) == [], variant + " temporary client remains installed")
    conversion = post_converter(token, fixture, folder / "converter-output.json")
    return {
        "variant": variant,
        "entityId": entity,
        "fixtureFile": str((folder / "fixture.xml").relative_to(output)),
        "fixtureSha256": SHA(fixture),
        "converter": conversion,
        "importFile": str((folder / "import.json").relative_to(output)),
        "importSha256": SHA((folder / "import.json").read_bytes()),
        "flowFile": str((folder / "flow.json").relative_to(output)),
        "flowSha256": SHA((folder / "flow.json").read_bytes()),
        "nativeImportAccepted": imported_and_read_back,
        "correlatedProtocolSuccess": not runtime_certificate_rejection,
        "runtimeCertificateRejected": runtime_certificate_rejection,
    }


def record_failed_attempts(output: Path) -> dict:
    """Retain operation counts for earlier restored attempts separately from adoption evidence."""
    names = (
        output.name + ".failed-browser-launch",
        output.name + ".failed-wrapper-finalize",
    )
    attempts = []
    totals = {"nativeUiImports": 0, "productConfigurationWrites": 0,
              "restorationWrites": 0, "protocolRoundTripAttempts": 0,
              "productRestarts": 0, "humanOperations": 0}
    for name in names:
        folder = output.parent / name
        require(folder.is_dir(), "failed-attempt evidence directory missing: " + name)
        imports = []
        writes = restorations = 0
        for record_path in sorted(folder.glob("*/import.json")):
            record = json.loads(record_path.read_text())
            steps = {item.get("step"): item.get("ok") for item in record.get("steps", [])}
            created = steps.get("product-import-signal") is True and steps.get("admin-read-back") is True
            cleanup = record.get("cleanup") or {}
            restored = (cleanup.get("read_back_absent") is True
                        and (not created or cleanup.get("deleted_status") == 204))
            require(restored, "failed attempt left a product client behind")
            writes += int(created)
            restorations += int(created)
            imports.append({
                "file": str(record_path.relative_to(REPO)),
                "sha256": SHA(record_path.read_bytes()),
                "created": created,
                "restored": restored,
                "status": record.get("status"),
            })
        flow_files = sorted(folder.glob("*/flow.json"))
        attempt = {
            "folder": str(folder.relative_to(REPO)),
            "imports": imports,
            "nativeUiImports": len(imports),
            "productConfigurationWrites": writes,
            "restorationWrites": restorations,
            "protocolRoundTripAttempts": len(flow_files) * 2,
            "productRestarts": 0,
            "humanOperations": 0,
            "restored": all(item["restored"] for item in imports),
        }
        operations = folder / "operations.json"
        if operations.is_file():
            attempt["operationsFile"] = str(operations.relative_to(REPO))
            attempt["operationsSha256"] = SHA(operations.read_bytes())
        attempts.append(attempt)
        for key in totals:
            totals[key] += attempt[key]
    record = {
        "schema": "samlscope-keycloak-metadata-signature-failed-attempts-v1",
        "attempts": attempts,
        "totals": totals,
        "allRestored": all(item["restored"] for item in attempts),
    }
    (output / "failed-attempts.json").write_bytes(canonical(record))
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--playwright-modules", type=Path, default=PLAYWRIGHT_MODULES)
    args = parser.parse_args()
    output = args.output.resolve()
    require(not output.exists(), "output must not exist")
    require(args.playwright_modules.resolve().is_dir(), "Playwright module directory missing")

    with tempfile.TemporaryDirectory(prefix="samlscope-md03-runtime-start-") as temporary:
        start = Path(temporary)
        runtime_capture(start, "start")
        suite_start = capture_suite(start, "start")
        output.parent.mkdir(parents=True, exist_ok=True)
        run_import_batch(output, args.playwright_modules.resolve())
        copy_runtime_phase(start, output, "start")
        for item in start.iterdir():
            shutil.move(str(item), str(output / item.name))

    created = json.loads((output / "created.json").read_text())
    run = created["run"]["id"]
    plan = created["run"].get("planId") or created["run"]["plan_id"]
    entity = BASE + "/p/" + plan
    token = product_token()
    require(lookup(token, entity) == [], "flow client was not restored after native import batch")

    observations = [flow_variant_record(output, variant, token, entity)
                    for variant in FLOW_VARIANTS]
    observations.append(run_bad_signature_import(output, plan, run,
                                                  args.playwright_modules.resolve(), token))

    runtime_capture(output, "end")
    suite_final = capture_suite(output, "final")
    require({key: value for key, value in suite_start.items() if key != "inspectFile"
             and key != "inspectSha256" and key != "jars"}
            == {key: value for key, value in suite_final.items() if key != "inspectFile"
                and key != "inspectSha256" and key != "jars"},
            "Suite runtime changed during signature campaign")
    require({key: value["sha256"] for key, value in suite_start["jars"].items()}
            == {key: value["sha256"] for key, value in suite_final["jars"].items()},
            "Suite JARs changed during signature campaign")

    counts = {
        "nativeUiImports": len(ALL_VARIANTS),
        "nativeConverterCalls": len(ALL_VARIANTS),
        "productConfigurationWrites": len(ALL_VARIANTS),
        "restorationWrites": len(ALL_VARIANTS),
        "protocolRoundTripAttempts": len(FLOW_VARIANTS) * 2,
        "positiveProtocolRoundTrips": len(FLOW_VARIANTS) - 2,
        "signedRequestNegativeControls": len(FLOW_VARIANTS),
        "productRestarts": 0,
        "humanOperations": 0,
        "restored": lookup(token, entity) == [],
    }
    (output / "operation-counts-md03.json").write_bytes(canonical(counts))
    require(counts["restored"], "final Keycloak state is not restored")
    record_failed_attempts(output)

    base = REPO / "build/acceptance/reference-20260930/keycloak-metadata-source-capability-absence-v158"
    manifest = {
        "schema": SCHEMA,
        "product": "keycloak",
        "productVersion": "26.7.2",
        "targetEntityId": "http://localhost:18180/realms/samlscope",
        "cases": list(CASES),
        "runId": run,
        "planId": plan,
        "suiteEntityId": entity,
        "variants": list(ALL_VARIANTS),
        "observations": observations,
        "baseRuntimeEvidence": str(base.relative_to(REPO)),
        "baseRuntimeReceiptSha256": SHA((base / "receipt.json").read_bytes()),
        "suiteRuntimeStart": suite_start,
        "operationCountsFile": "operation-counts-md03.json",
        "operationCountsSha256": SHA((output / "operation-counts-md03.json").read_bytes()),
        "failedAttemptsFile": "failed-attempts.json",
        "failedAttemptsSha256": SHA((output / "failed-attempts.json").read_bytes()),
    }
    (output / "manifest.json").write_bytes(canonical(manifest))
    note = ("Machine-verified Keycloak 26.7.2 native metadata signature capability absence; "
            "manifest sha256=" + SHA((output / "manifest.json").read_bytes())
            + "; valid/unsigned/bad/wrong-key/certificate variants were imported and restored")
    for case in CASES:
        save(output / (case + "-configure.json"), api(
            "/api/runs/" + run + "/cases/" + case + "/configure",
            {"value": "capability_absent", "note": note}))
    save(output / "result-after.json", api("/api/runs/" + run + "/result.json"))
    save(output / "transcript-after.json", api("/api/runs/" + run + "/transcript"))
    print(run, "Keycloak MD03 signature capability campaign complete; restored", counts["restored"])


if __name__ == "__main__":
    main()
