#!/usr/bin/env python3
"""Create a Suite-only MD04.c capability-absence conclusion bound to native evidence.

The native Keycloak campaign has already proved and restored the product state.  Its protocol
result cannot be rewritten after the case is FINISHED, so this driver creates a minimal fresh Run,
verifies that it targets byte-identical metadata, and submits the approved
``capability_absent`` configuration event before any fixture-probe conclusion exists.  It performs
no Keycloak administration, product configuration write, restart, or browser interaction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse
import urllib.request

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))

from import_metadata_batch import BASE, api, save  # noqa: E402
from metadata_url_campaign import (  # noqa: E402
    SUITE, admin, admin_token, create_run, detail, lookup, suite_capture, write_json,
)
from metadata_validity_capability import product_admin, redact  # noqa: E402
from reference_flow import Client  # noqa: E402
from verify_keycloak_validity_capability_absence import verify_folder  # noqa: E402

CASE = "IIP-MD04-c-idp-01"
SCHEMA = "samlscope-keycloak-metadata-validity-capability-conclusion-v1"
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def require(value: object, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def case_map(result: dict) -> dict[str, dict]:
    return {case["id"]: case for requirement in result["requirements"]
            for case in requirement["cases"]}


def complete_initial_login(output: Path, plan: str, run: str) -> dict:
    """Create exactly one temporary client, complete the Suite prerequisite, then restore []."""
    entity = BASE + "/p/" + plan
    access = admin_token()
    before = lookup(access, entity)
    require(before == [], "refusing to replace an existing Keycloak client")
    (output / "baseline-admin-before.json").write_text(json.dumps(before, sort_keys=True) + "\n")
    fixture_url = BASE + "/p/" + urllib.parse.quote(plan, safe="") + "/metadata"
    with urllib.request.urlopen(fixture_url, timeout=30) as response:
        fixture = response.read()
    (output / "baseline-suite-metadata.xml").write_bytes(fixture)
    status, recipe = product_admin(access, "/client-description-converter", fixture,
                                   "POST", "application/xml")
    require(status == 200 and isinstance(recipe, dict)
            and recipe.get("clientId") == entity and recipe.get("protocol") == "saml",
            "Keycloak native converter did not produce the baseline client")
    recipe.setdefault("attributes", {})["saml.client.signature"] = "true"
    recipe["name"] = "SAMLscope MD04.c capability conclusion baseline"
    owned = None
    restored = False
    flow_receipt = None
    try:
        admin(access, "/clients", recipe, "POST")
        configured = detail(access, entity)
        owned = configured["id"]
        safe_configured, removed = redact(configured)
        require(set(removed) <= {"/secret", "/attributes/saml.signing.private.key"},
                "unexpected baseline credential inventory")
        (output / "baseline-admin-configured.json").write_text(
            json.dumps(safe_configured, indent=2, sort_keys=True) + "\n")
        write_json(output / "baseline-redaction.json", {
            "removedFields": removed,
            "credentialValuesPersisted": False,
            "fullRepresentationHeldInMemoryOnly": True,
        })
        flow_receipt = Client().flow(
            entity + "/start/m0-roundtrip?run=" + run,
            None,
            os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user"),
            os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password"))
        write_json(output / "baseline-flow.json", {"runId": run, "receipt": flow_receipt})
        require(flow_receipt == "recorded", "baseline SSO did not complete")
        state = api("/api/runs/" + run)
        save(output / "baseline-run-after.json", state)
        require(state.get("status") == "COMPLETED", "baseline SSO did not complete the Run")
    finally:
        access = admin_token()
        current = lookup(access, entity)
        require(len(current) <= 1, "temporary baseline client lookup became ambiguous")
        if current:
            identifier = current[0].get("id")
            require(owned is None or identifier == owned,
                    "temporary baseline client identity changed")
            admin(access, "/clients/" + identifier, method="DELETE")
        final = lookup(access, entity)
        (output / "baseline-admin-final.json").write_text(
            json.dumps(final, sort_keys=True) + "\n")
        restored = final == before
    require(restored, "temporary baseline client was not restored")
    return {
        "productConfigurationWrites": 2,
        "restorationWrites": 1,
        "productRestarts": 0,
        "protocolRoundTrips": 1,
        "humanOperations": 0,
        "restored": True,
        "temporaryRelayStarted": False,
        "temporaryRelayStopped": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output-name", default="md04c-capability-conclusion-v1")
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    output = evidence / args.output_name
    require(evidence.is_dir() and not output.exists(), "evidence/output directory state is invalid")

    # Replay every product-native prerequisite before creating a new formal conclusion.
    verify_folder(evidence, result=False)
    source_manifest = evidence / "manifest.json"
    source_manifest_sha = SHA(source_manifest.read_bytes())
    source = json.loads(source_manifest.read_text())
    source_counts = json.loads((evidence / "operation-counts.json").read_text())
    require(source_counts.get("restored") is True
            and (evidence / "admin-before.json").read_bytes()
                == (evidence / "admin-final.json").read_bytes() == b"[]\n",
            "source product restoration is not proven")

    output.mkdir()
    plan, run, _ = create_run(output, "validity-capability-conclusion", 12)
    suite_capture(output)

    target = output / "target-metadata.xml"
    subprocess.run([
        "docker", "cp", SUITE + ":/data/target-metadata/" + run + ".xml", str(target)
    ], check=True, stdout=subprocess.DEVNULL, timeout=60)
    require(target.read_bytes() == (evidence / "target-metadata.xml").read_bytes(),
            "fresh Run target metadata differs from native evidence Run")

    baseline_counts = complete_initial_login(output, plan, run)
    transcript_before = api("/api/runs/" + run + "/transcript")
    save(output / "transcript-before.json", transcript_before)
    save(output / "tests-start.json", api("/api/runs/" + run + "/tests/start", {}))
    note = (
        "Machine-verified Keycloak 26.7.2 evidence: native metadata URL and import paths used "
        "the approved near/far validUntil controls, while the installed provider/JAR originals "
        "expose cache expiry/reload controls but no configurable validity-rejection threshold. "
        "Evidence manifest sha256=" + source_manifest_sha
    )
    configured = api("/api/runs/" + run + "/cases/" + CASE + "/configure", {
        "value": "capability_absent", "note": note,
    })
    save(output / "configure.json", configured)
    result = api("/api/runs/" + run + "/result.json")
    save(output / "result.json", result)
    save(output / "run-after.json", api("/api/runs/" + run))
    save(output / "protocol-evidence.json", api("/api/runs/" + run + "/protocol-evidence"))
    transcript_after = api("/api/runs/" + run + "/transcript")
    save(output / "transcript-after.json", transcript_after)
    require(transcript_after == transcript_before, "configuration event changed protocol evidence")

    outcome = configured.get("outcome", {})
    row = case_map(result)[CASE]
    require(configured.get("runId") == run and configured.get("caseId") == CASE
            and configured.get("status") == "FINISHED"
            and outcome.get("outcome") == "VIOLATED"
            and outcome.get("reasonCode") == "capability_absent"
            and outcome.get("details", {}).get("configuration_note") == note,
            "configuration event did not produce capability_absent")
    require((row.get("outcome"), row.get("verdict"), row.get("reason_code"), row.get("attested"))
            == ("VIOLATED", "FAIL", "capability_absent", False),
            "formal MD04.c result is not capability_absent")

    counts = {
        **baseline_counts,
        "suiteConfigurationSubmissions": 1,
        "sourceEvidenceRestored": True,
    }
    write_json(output / "operation-counts.json", counts)
    manifest = {
        "schema": SCHEMA,
        "caseId": CASE,
        "runId": run,
        "planId": plan,
        "sourceEvidenceRunId": source["runId"],
        "sourceEvidenceManifestSha256": source_manifest_sha,
        "targetMetadataSha256": SHA(target.read_bytes()),
        "suiteRuntimeSha256": SHA((output / "suite-runtime.json").read_bytes()),
        "configureSha256": SHA((output / "configure.json").read_bytes()),
        "resultSha256": SHA((output / "result.json").read_bytes()),
        "runAfterSha256": SHA((output / "run-after.json").read_bytes()),
        "protocolEvidenceSha256": SHA((output / "protocol-evidence.json").read_bytes()),
        "transcriptBeforeSha256": SHA((output / "transcript-before.json").read_bytes()),
        "transcriptAfterSha256": SHA((output / "transcript-after.json").read_bytes()),
        "operationCountsSha256": SHA((output / "operation-counts.json").read_bytes()),
        "configurationNote": note,
    }
    for field, name in {
        "baselineAdminBeforeSha256": "baseline-admin-before.json",
        "baselineAdminConfiguredSha256": "baseline-admin-configured.json",
        "baselineAdminFinalSha256": "baseline-admin-final.json",
        "baselineRedactionSha256": "baseline-redaction.json",
        "baselineSuiteMetadataSha256": "baseline-suite-metadata.xml",
        "baselineFlowSha256": "baseline-flow.json",
        "baselineRunAfterSha256": "baseline-run-after.json",
        "planSha256": "plan.json",
        "createdSha256": "created.json",
        "preflightSha256": "preflight.json",
        "testsStartSha256": "tests-start.json",
    }.items():
        manifest[field] = SHA((output / name).read_bytes())
    write_json(output / "manifest.json", manifest)
    print(run, CASE, row["outcome"], row["verdict"], row["reason_code"])


if __name__ == "__main__":
    main()
