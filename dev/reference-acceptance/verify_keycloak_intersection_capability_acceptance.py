#!/usr/bin/env python3
"""Qualify native Keycloak full-intersection evidence with archived Reader replay.

Capability overrides are separate controls, never an assertion about the product's
default algorithm preference. No HTTP error/silence supplies a target conclusion.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import re
import urllib.request
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
FOLDER = "keycloak-intersection-capability-sha512-v167"
CASE = "IIP-MD05-e8-idp-01"
spec = importlib.util.spec_from_file_location("kc_intersection_runtime", Path(__file__).with_name("verify_ssp_intersection_capability_acceptance.py"))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
runtime.HELPER = "VerifyKeycloakMetadataIntersectionCapabilityEvidence"
sha, require, load, rows = runtime.sha, runtime.require, runtime.load, runtime.rows
REQUIRED = { {"algorithm-entity-sha384": "algorithm-entity-sha512", "algorithm-signing-256-keysize-excluded": "algorithm-signing-256-512-keysize-excluded",
             "algorithm-signing-384-keysize-excluded": "algorithm-signing-512-256-keysize-excluded"}.get(v, v) for v in runtime.REQUIRED }
verify_preparation = runtime.verify_preparation
P, S, DS = runtime.P, runtime.S, runtime.DS
STABLE = {"saml.client.signature": "true", "saml.encrypt": "true", "saml.assertion.signature": "true",
          "saml.server.signature": "true", "saml.signature.algorithm": "RSA_SHA256"}


def api(path, body=None):
    request = urllib.request.Request("http://localhost:18080" + path,
        data=None if body is None else json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=40) as response:
        return json.load(response)


def native_client_absent(entity):
    body = "client_id=admin-cli&username=admin&password=admin&grant_type=password".encode()
    request = urllib.request.Request("http://localhost:18180/realms/master/protocol/openid-connect/token", data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(request, timeout=30) as response:
        token = json.load(response)["access_token"]
    from urllib.parse import quote
    request = urllib.request.Request("http://localhost:18180/admin/realms/samlscope/clients?clientId=" + quote(entity, safe=""),
        headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response) == []


def verify_adoption(root, live=False, formal=True):
    folder = Path(root).resolve()
    if folder.name != FOLDER:
        folder = folder / FOLDER
    source = folder / "source"
    created = load(folder / "created.json")["run"]
    run, entity = created["id"], "http://localhost:18080/p/" + created["planId"]
    require(load(source / "created.json")["run"] == created, "Run identity differs")
    require(load(folder / "plan.json") == load(source / "plan.json"), "Plan differs")
    before, entries = load(folder / "transcript-before.json"), load(folder / "transcript.json")
    require(before == load(source / "transcript.json") and entries[:len(before)] == before, "Original matrix transcript changed")
    require(len(entries) - len(before) == 10, "Capability operation count differs")
    transcript = {row["id"]: row for row in entries}
    require(len(transcript) == len(entries) and all(row["runId"] == run for row in entries), "Foreign/ambiguous transcript")
    originals = {}
    for row in load(folder / "decoded-manifest.json"):
        path = (folder / row["file"]).resolve()
        require(path.parent == (folder / "decoded").resolve() and row["id"] not in originals, "Unsafe/duplicate original")
        raw = path.read_bytes()
        require(sha(raw) == row["sha256"] and len(raw) == transcript[row["id"]]["decodedSamlBytes"], "Original hash/length differs")
        originals[row["id"]] = raw
    for row in load(source / "decoded-manifest.json"):
        raw = (source / row["file"]).read_bytes()
        require(sha(raw) == row["sha256"] and originals[row["id"]] == raw, "Original matrix bytes changed")
    operations = load(source / "operations.json")
    require({row["variant"] for row in operations} == REQUIRED and len(operations) == len(REQUIRED), "Partial native matrix")
    database_ids = set()
    for variant in REQUIRED:
        verify_preparation(source, variant)
        receipt = load(source / variant / "import.json")
        require(receipt["fixture"]["entity_id"] == entity and receipt["cleanup"]["deleted_status"] == 204, "Matrix restoration differs")
        native = receipt["import"]["read_back"]["saml_attributes"]
        require(all(native.get(key) == value for key, value in STABLE.items())
                and "request_signature_policy" not in receipt["import"] and "signing_capability_policy" not in receipt["import"],
                "Original matrix policy was overridden or changed")
        require(receipt["client"]["database_id"] not in database_ids, "Client reused across fixtures")
        database_ids.add(receipt["client"]["database_id"])
        fixture = (source / variant / "fixture.xml").read_bytes()
        require(sha(fixture) == receipt["fixture"]["sha256"] and any(originals.get(row["id"]) == fixture
            and row["samlSummary"].get("type") == "MetadataPrepared" for row in before), "Original native fixture missing")
    require((folder / "target-metadata.xml").read_bytes() == (source / "target-metadata.xml").read_bytes(), "Target trust snapshot changed")
    preflight = load(folder / "native-capability-preflight.json")
    native_enum = subprocess.check_output(["javap", "-cp", str(folder / "native-saml-core.jar"),
                                          "org.keycloak.saml.SignatureAlgorithm"], timeout=30)
    require(native_enum == (folder / "native-signature-algorithms.javap.txt").read_bytes()
        and preflight["signature_algorithms"] == re.findall(r"public static final org\.keycloak\.saml\.SignatureAlgorithm ([A-Z0-9_]+);", native_enum.decode()),
        "Native enum original differs from binary")
    require(preflight["native_jar_sha256"] == sha((folder / "native-saml-core.jar").read_bytes())
        and preflight["required"] == ["RSA_SHA256", "RSA_SHA512"] and preflight["product_mutations"] == 0
        and {"RSA_SHA256", "RSA_SHA512"} <= set(preflight["signature_algorithms"]), "Native capability preflight differs")
    policy_writes = 0
    for label, native_algorithm, xml_algorithm in [("sha256", "RSA_SHA256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
            ("sha512", "RSA_SHA512", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")]:
        member = folder / ("capability-" + label)
        receipt = load(member / "import.json")
        require(receipt["status"] == "success" and receipt["fixture"]["entity_id"] == entity
            and receipt["fixture"]["sha256"] == sha((member / "fixture.xml").read_bytes())
            and receipt["import"]["save_clicked"] and receipt["import"]["ui_status"] == "client-settings-page"
            and receipt["client"]["database_id"] not in database_ids
            and receipt["import"]["final_url"].endswith("/clients/" + receipt["client"]["database_id"] + "/settings")
            and receipt["cleanup"] == {"deleted_status": 204, "read_back_absent": True}, "Capability native import/restoration differs")
        database_ids.add(receipt["client"]["database_id"])
        policy = receipt["import"]["signing_capability_policy"]
        original, effective = policy["original_saml_attributes"], receipt["import"]["read_back"]["saml_attributes"]
        require(all(original.get(key) == value for key, value in STABLE.items())
            and policy["requested_algorithm"] == native_algorithm and policy["read_back_verified"]
            and policy["key_material_modified"] is False
            and effective == {**original, "saml.signature.algorithm": native_algorithm}, "Native capability changed keys or other policy")
        require(policy["write_attempts"] == (0 if native_algorithm == "RSA_SHA256" else 1), "Native write count differs")
        if policy["write_attempts"]:
            require(policy["write_status"] == 204, "Native policy write failed")
        policy_writes += policy["write_attempts"]
        flow = load(member / "flow.json")
        require(flow["run"] == run and flow["variant"] == "control" and flow["correlated_success"]
            and flow["after_index"] == flow["before_index"] + 1, "Capability flow Success missing")
        request, response = [transcript[ref] for ref in flow["positive_exchange"]["transcript_ids"]]
        request_xml, response_xml = [ET.fromstring(originals[row["id"]]) for row in (request, response)]
        require(request_xml.tag == P + "AuthnRequest" and response_xml.tag == P + "Response"
            and response_xml.get("InResponseTo") == request_xml.get("ID")
            and response_xml.find(P + "Status/" + P + "StatusCode").get("Value") == "urn:oasis:names:tc:SAML:2.0:status:Success"
            and response_xml.find(DS + "Signature/" + DS + "SignedInfo/" + DS + "SignatureMethod").get("Algorithm") == xml_algorithm
            and len(response_xml.findall(S + "EncryptedAssertion")) > 0, "Native signed/encrypted capability differs")
        require(any(row["direction"] == "OUTBOUND" and row["samlSummary"].get("type") == "MetadataPrepared"
            and originals.get(row["id"]) == (member / "fixture.xml").read_bytes() and row["timestamp"] < request["timestamp"]
            for row in entries[len(before):]), "Capability preparation original absent")
        require(flow["negative_control"]["source"] == "suite" and flow["negative_control"]["correlated_success"] is False,
            "Corrupt signature diagnostic contradicted by Success")
    require(load(folder / "operation-counts.json") == dict(run=run, import_attempts=2, import_save_attempts=2,
        native_policy_write_attempts=policy_writes, temporary_clients_removed=2, protocol_operation_pairs_attempted=2,
        product_restarts=0, human_operations=0, restored=True, verdict_adopted=False), "Capability operation counts differ")
    require(load(folder / "batch-operation-counts.json") == dict(run=run, matrix_imports=13, capability_imports=2,
        import_save_attempts=15, native_policy_write_attempts=policy_writes, temporary_clients_removed=15,
        protocol_operation_pairs_attempted=15, product_restarts=0, human_operations=0, restored=True,
        verdict_adopted=False), "Complete native operation counts differ")
    require(len(database_ids) == 15, "Native matrix/capability client isolation differs")
    recorded = load(folder / "native-reader-replay.json")
    require(runtime.replay(folder) == recorded, "Archived production Reader replay differs")
    require(recorded["runId"] == run and recorded["outcome"] == "VIOLATED"
        and recorded["reasonCode"] == "metadata.algorithms.intersection-violated" and len(recorded["checks"]) == 12
        and recorded["checks"]["complete-native-campaign"] == "VIOLATED"
        and all(value == "NOT_VERIFIED" for name, value in recorded["checks"].items() if name != "complete-native-campaign")
        and recorded["privateKeyExported"] is False and recorded["plaintextPersisted"] is False, "Invalid evidence controls incomplete")
    details = recorded["details"]
    require(set(details["observed_variants"]) == REQUIRED and not details["missing_variants"] and not details["evidence_issues"]
        and details["signature_capability_controls_verified"] and len(details["campaigns"]) == 1, "Native matrix not qualified")
    if live:
        require(native_client_absent(entity), "Native temporary client not restored")
        require(api("/api/runs/" + run + "/transcript") == entries, "Live transcript differs")
    if not formal:
        return recorded
    result = load(folder / "evaluation/result.json")
    case = rows(result)[CASE]
    require(result["run"]["id"] == run and result["target"]["metadata_digest"] == "sha256:" + sha((folder / "target-metadata.xml").read_bytes()), "Formal target/Run differs")
    require((case["outcome"], case["verdict"], case["reason_code"], case["attested"]) ==
        ("VIOLATED", "FAIL", "metadata.algorithms.intersection-violated", False), "Formal outcome differs")
    execution = load(folder / "evaluation" / (CASE + "-configure.json"))
    require(execution["runId"] == run and execution["caseId"] == CASE and execution["status"] == "FINISHED"
        and execution["outcome"]["outcome"] == case["outcome"] and execution["outcome"]["details"].get("configuration_confirmed") is True
        and all(execution["outcome"]["details"].get(name) == value for name, value in details.items()), "Native preparation/formal reader differs")
    require(load(folder / "evaluation/transcript-before.json") == load(folder / "evaluation/transcript.json") == entries, "Formal evaluation changed originals")
    require({row["reference"] for row in recorded["evidence"]} <= {row["reference"] for row in case["evidence"]}, "Formal original references differ")
    return folder / "evaluation/result.json", {CASE: case}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--prepare-runtime", action="store_true")
    parser.add_argument("--record-replay", action="store_true")
    parser.add_argument("--diagnostic-only", action="store_true")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    folder = args.root.resolve()
    if folder.name != FOLDER:
        folder = folder / FOLDER
    if args.prepare_runtime:
        runtime.capture_runtime(folder)
    if args.record_replay:
        path = folder / "native-reader-replay.json"
        require(not path.exists(), "Immutable replay exists")
        path.write_text(json.dumps(runtime.replay(folder), indent=2) + "\n")
    verified = verify_adoption(folder, live=args.live, formal=not args.diagnostic_only)
    print("Verified Keycloak native intersection", verified["outcome"] if args.diagnostic_only else verified[1][CASE]["verdict"])
