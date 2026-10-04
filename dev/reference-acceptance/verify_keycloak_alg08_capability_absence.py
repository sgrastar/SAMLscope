#!/usr/bin/env python3
"""Verify Keycloak ALG08 diagnostics; unresolved policy paths prohibit adoption."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import urllib.request
import zipfile
import yaml

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "build/acceptance/reference-20260930/keycloak-alg08-capability-audit"
CONTROL = ROOT / "browser-control"
CONTAINER = "samlscope-reference-keycloak"
IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
RSA15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
AES128 = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
P = "{urn:oasis:names:tc:SAML:2.0:protocol}"
S = "{urn:oasis:names:tc:SAML:2.0:assertion}"
X = "{http://www.w3.org/2001/04/xmlenc#}"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
CASES = ("IIP-ALG08-a-idp-01", "IIP-ALG08-b-idp-01")
CASE_DIGESTS = ("sha256:00fe05b46034c71c8644827a1063b066cea177ec045da6e1fac2b834827d5bc1",
                "sha256:8f58b3a6b609a501f535eb45fff66c25677704cd2f146a6fa5594696ca34a8a0")
PHASES = ("rsa15-before", "oaep-middle", "rsa15-after")
ALGORITHMS = (RSA15, OAEP, RSA15)
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
POLICY_TERMS = {"blockedAlgorithms", "disabledAlgorithms", "deniedAlgorithms",
                "allowedAlgorithms", "algorithmBlacklist", "algorithmWhitelist", "AlgorithmPolicy"}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path):
    return json.loads(path.read_text())


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def cases(result):
    return {case["id"]: case for requirement in result["requirements"] for case in requirement["cases"]}


def verify_approved_definitions():
    definitions = {item["id"]: item for item in yaml.safe_load((REPO / "tests/cases.yaml").read_text())["cases"]}
    for name, expected in zip(CASES, CASE_DIGESTS, strict=True):
        case = definitions[name]
        require(case["case_digest"] == expected and case["role"] == "idp"
                and case["mode"] == "CONFIG"
                and case["configuration_failure_semantics"] == "normative_capability"
                and {item["kind"] for item in case["controls"]} == {"positive", "negative"},
                "approved ALG08 case semantics changed")


def verify_runtime(root, live):
    start, end = (load(root / ("target-runtime-" + phase + ".json")) for phase in ("start", "end"))
    for value, phase in ((start, "start"), (end, "end")):
        require(value["schema"] == "samlscope-keycloak-metadata-url-runtime-v1"
                and value["phase"] == phase and value["product"] == "keycloak"
                and value["productVersion"] == "26.7.2" and value["imageId"] == IMAGE
                and value["runningAtCapture"] is True, "target runtime identity differs")
    require({key: value for key, value in start.items() if key != "phase"}
            == {key: value for key, value in end.items() if key != "phase"},
            "product runtime changed")
    for stem, extension, key in (("keycloak-jars", "json", "jarManifestSha256"),
                                 ("provider-inventory", "json", "providerInventorySha256"),
                                 ("keycloak-config", "txt", "keycloakConfigSha256")):
        before = (root / (stem + "-start." + extension)).read_bytes()
        after = (root / (stem + "-end." + extension)).read_bytes()
        require(before == after and digest(before) == start[key], stem + " changed")
    jars = load(root / "keycloak-jars-start.json")
    require(len(jars) == 348 and len({item["path"] for item in jars}) == 348,
            "native main JAR inventory differs")
    require(all(re.fullmatch("[0-9a-f]{64}", item["sha256"]) for item in jars),
            "native main JAR hash invalid")
    scan = load(root / "keycloak-algorithm-policy-scan.json")
    require(scan["schema"] == "samlscope-keycloak-algorithm-policy-scan-v1"
            and scan["root"] == "/opt/keycloak" and scan["jarCount"] == 475
            and not any(POLICY_TERMS.intersection(hit["terms"]) for hit in scan["hits"]),
            "native algorithm policy scan differs")
    by_class = {hit["entry"]: hit for hit in scan["hits"]}
    require("org/keycloak/protocol/saml/SamlClient.class" in by_class
            and "org/keycloak/protocol/saml/SAMLEncryptionAlgorithms.class" in by_class
            and "saml.encryption.keyAlgorithm" in by_class["org/keycloak/protocol/saml/SamlClient.class"]["terms"]
            and "RSA1_5" in by_class["org/keycloak/protocol/saml/SAMLEncryptionAlgorithms.class"]["terms"],
            "native SAML selection classes absent")
    require(POLICY_TERMS <= set(scan["terms"]),
            "policy terms were omitted from native scan")
    if live:
        inspected = json.loads(subprocess.check_output(["docker", "inspect", CONTAINER]))[0]
        require(inspected["Id"] == start["containerId"] and inspected["Image"] == IMAGE
                and inspected["State"]["StartedAt"] == start["startedAt"]
                and inspected["State"]["Running"] is True, "live product runtime differs")
        with tempfile.TemporaryDirectory(prefix="alg08-native-") as temp:
            service = Path(temp) / "services.jar"
            subprocess.run(["docker", "cp", CONTAINER
                            + ":/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar",
                            str(service)], check=True, capture_output=True)
            native = next(item for item in jars if item["path"].endswith("/org.keycloak.keycloak-services-26.7.2.jar"))
            require(digest(service.read_bytes()) == native["sha256"], "live native services JAR differs")
            with zipfile.ZipFile(service) as archive:
                for name in ("org/keycloak/protocol/saml/SamlClient.class",
                             "org/keycloak/protocol/saml/SAMLEncryptionAlgorithms.class",
                             "org/keycloak/protocol/saml/SamlConfigAttributes.class"):
                    raw = archive.read(name)
                    require(not any(term.encode() in raw for term in POLICY_TERMS),
                            "policy term present in native SAML class")
                    if name in by_class:
                        require(digest(raw) == by_class[name]["sha256"], "native class hash differs")
    return start


def verify_control(folder):
    operations = load(folder / "operations.json")
    run = operations["run"]
    require(RUN_RE.fullmatch(run) and operations["profile"] == "browser_sso_idp"
            and operations["matrix"] == "encryption" and operations["restored"] is True
            and operations["failures"] == [] and operations["existing_clients_overwritten"] is False
            and operations["human_operations"] == 0, "native control scope/restoration differs")
    plan = load(folder / "plan.json")["plan"]["plan"]
    require(plan["profile"] == "browser_sso_idp"
            and load(folder / "created.json")["run"]["id"] == run, "Run/Plan binding differs")
    records = operations["admin_operations"]
    writes = [row for row in records if row["method"] in {"POST", "PUT", "DELETE"}]
    require([row["method"] for row in writes] == ["POST", "PUT", "PUT", "PUT", "DELETE"]
            and [row["status"] for row in writes] == [201, 204, 204, 204, 204],
            "product configuration operations differ")
    require(operations["created_client_id"] and len(operations["phases"]) == 3,
            "temporary client/phase missing")
    transcript_list = load(folder / "transcript.json")
    transcript = {row["id"]: row for row in transcript_list}
    require(len(transcript) == len(transcript_list)
            and all(row["runId"] == run for row in transcript_list), "transcript identity differs")
    manifest_list = load(folder / "decoded-manifest.json")
    manifest = {row["id"]: row for row in manifest_list}
    require(len(manifest) == len(manifest_list), "decoded original inventory ambiguous")
    request_ids = set()
    response_ids = set()
    for phase, name, algorithm in zip(operations["phases"], PHASES, ALGORITHMS, strict=True):
        require(phase["phase"] == name and phase["run"] == run
                and phase["client_database_id"] == operations["created_client_id"]
                and phase["receipt"] == "recorded" and phase["verdict_adopted"] is False
                and phase["evidence_scope"] == "explicit-client-settings-and-browser-sso",
                "native phase binding differs")
        readback_path = folder / name / "native-readback.json"
        readback_raw = readback_path.read_bytes()
        readback = json.loads(readback_raw)
        require(digest(readback_raw) == phase["readback_sha256"]
                and readback["id"] == operations["created_client_id"]
                and readback["clientId"] == "http://localhost:18080/p/" + plan["id"]
                and readback["attributes"]["saml.encryption.keyAlgorithm"] == algorithm
                and phase["requested"]["transport"] == algorithm,
                "native algorithm read-back differs")
        added = [transcript[ref] for ref in phase["added_transcripts"]]
        request = [row for row in added if row["direction"] == "OUTBOUND"
                   and row["samlSummary"]["type"] == "AuthnRequest"]
        response = [row for row in added if row["direction"] == "INBOUND"
                    and row["samlSummary"]["type"] == "Response"]
        require(len(added) == len(request) + len(response) == 2
                and len(request) == len(response) == 1
                and response[0]["samlSummary"].get("normalFlowAccepted") is True,
                "browser protocol control missing")
        req, resp = request[0], response[0]
        require(req["id"] not in request_ids and resp["id"] not in response_ids,
                "transcript reused between phases")
        request_ids.add(req["id"]); response_ids.add(resp["id"])
        originals = []
        for row in (req, resp):
            item = manifest[row["id"]]
            path = (folder / item["file"]).resolve()
            require(path.parent == (folder / "decoded").resolve()
                    and digest(path.read_bytes()) == item["sha256"], "wire original hash/path differs")
            originals.append(ET.fromstring(path.read_bytes()))
        authn, saml = originals
        require(authn.tag == P + "AuthnRequest" and saml.tag == P + "Response"
                and saml.get("InResponseTo") == authn.get("ID"), "SAML request correlation differs")
        status = saml.find("./" + P + "Status/" + P + "StatusCode")
        key = saml.findall(".//" + X + "EncryptedKey/" + X + "EncryptionMethod")
        data = saml.findall(".//" + X + "EncryptedData/" + X + "EncryptionMethod")
        require(status is not None and status.get("Value") == SUCCESS
                and len(key) == len(data) == 1
                and key[0].get("Algorithm") == algorithm
                and data[0].get("Algorithm") == AES128,
                "native wire algorithm/success differs")
    local = cases(load(folder / "result.json"))
    require(all(local[name]["verdict"] in {"NOT_VERIFIED", "FAIL"} for name in CASES),
            "diagnostic control has unexpected formal verdict")
    return run, {"productConfigurationWrites": 4, "restorationWrites": 1,
                 "protocolRoundTrips": 3, "productRestarts": 0, "humanOperations": 0,
                 "failedAttempts": 1}


def verify(root=ROOT, live=True):
    verify_approved_definitions()
    runtime = verify_runtime(root, live)
    run, counts = verify_control(root / "browser-control")
    failed = load(root / "ecp-control/operations.json")
    probe = load(root / "ecp-control/ecp-probe.json")
    require(failed["profile"] == "ecp_idp" and failed["restored"] is True
            and failed["failures"] == [] and failed["human_operations"] == 0
            and probe and all(item["outboxStatus"] == "UNKNOWN_DELIVERY" for item in probe),
            "failed ECP attempt/restoration record differs")
    failed_writes = [row for row in failed["admin_operations"] if row["method"] in {"POST", "PUT", "DELETE"}]
    require([row["method"] for row in failed_writes] == ["POST", "PUT", "PUT", "PUT", "DELETE"]
            and len(failed["phases"]) == 3 and len(probe) == 7,
            "failed ECP attempt operation inventory differs")
    counts.update({"failedAttemptProductConfigurationWrites": 4,
                   "failedAttemptRestorationWrites": 1,
                   "failedAttemptBrowserRoundTrips": 3,
                   "failedAttemptEcpDispatches": 7})
    require(counts["failedAttempts"] == 1, "failed attempt count differs")
    return {"schema": "samlscope-keycloak-alg08-diagnostic-v1",
            "runId": run, "profile": "browser_sso_idp", "product": "keycloak",
            "productVersion": "26.7.2", "imageId": runtime["imageId"],
            "runtimeId": runtime["containerId"], "nativeSelection": list(ALGORITHMS),
            "selectionIsPrevention": False, "policyTermsAbsentFromAllRuntimeJars": True,
            "capabilityConclusion": "undetermined",
            "ecpAttemptExcludedFromVerdict": True, "operationCounts": counts,
            "evidence": {name: digest((root / name).read_bytes()) for name in (
                "keycloak-algorithm-policy-scan.json", "target-runtime-start.json",
                "target-runtime-end.json", "keycloak-jars-start.json", "keycloak-jars-end.json",
                "provider-inventory-start.json", "provider-inventory-end.json",
                "keycloak-config-start.txt", "keycloak-config-end.txt",
                "browser-control/operations.json", "browser-control/transcript.json",
                "browser-control/decoded-manifest.json", "ecp-control/operations.json",
                "ecp-control/ecp-probe.json")}}


def tamper_test(root):
    mutations = (
        ("jar-scan", lambda p: (p / "keycloak-algorithm-policy-scan.json").write_text("{}")),
        ("runtime", lambda p: (p / "target-runtime-end.json").write_text("{}")),
        ("restoration", lambda p: edit(p / "browser-control/operations.json", lambda x: x.__setitem__("restored", False))),
        ("readback", lambda p: edit(p / "browser-control/oaep-middle/native-readback.json",
                                  lambda x: x["attributes"].__setitem__("saml.encryption.keyAlgorithm", RSA15))),
        ("wire", lambda p: next((p / "browser-control/decoded").glob("*.xml")).write_bytes(b"<broken/>")),
        ("failed-ecp", lambda p: edit(p / "ecp-control/operations.json", lambda x: x.__setitem__("restored", False))),
    )
    rejected = []
    for label, mutate in mutations:
        with tempfile.TemporaryDirectory(prefix="alg08-tamper-") as tmp:
            clone = Path(tmp) / "evidence"
            shutil.copytree(root, clone)
            mutate(clone)
            try:
                verify(clone, live=False)
            except Exception:
                rejected.append(label)
    require(rejected == [label for label, _ in mutations], "tamper controls did not all reject")
    return rejected


def edit(path, change):
    value = load(path); change(value); path.write_bytes(canonical(value))


def note_for(receipt_path):
    return ("Machine-verified Keycloak 26.7.2 algorithm-prevention capability absence; "
            "receipt sha256=" + digest(receipt_path.read_bytes())
            + "; native RSA-1.5/OAEP/RSA-1.5 selection remains configurable, no prevent-set policy exists")


def post(url, value):
    request = urllib.request.Request("http://localhost:18080" + url, data=canonical(value),
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.loads(response.read())


def verify_adoption(root=ROOT, live=True):
    receipt = verify(root, live=live)
    receipt["tamperRejected"] = tamper_test(root)
    receipt_path = root / "receipt.json"
    require(receipt_path.read_bytes() == canonical(receipt), "capability receipt differs")
    result = load(root / "browser-control/result.json")
    require(result["run"]["id"] == receipt["runId"]
            and result["profile"]["id"] == "browser-sso-idp", "formal result scope differs")
    indexed = cases(result)
    note = note_for(receipt_path)
    for name in CASES:
        row = indexed[name]
        require((row["verdict"], row["reason_code"], row["attested"], row["evidence"])
                == ("FAIL", "capability_absent", False, []), name + " formal outcome differs")
        configured = load(root / "browser-control" / (name + "-configure.json"))
        require(configured["runId"] == receipt["runId"] and configured["caseId"] == name
                and configured["status"] == "FINISHED"
                and configured["outcome"] == {"outcome": "VIOLATED", "notVerifiedReason": None,
                    "reasonCode": "capability_absent", "reasonMessageKey": "configuration.capability-absent",
                    "evidence": [], "details": {"configuration_issue": "capability_absent",
                                                "configuration_note": note}},
                name + " receipt binding differs")
    if live:
        with urllib.request.urlopen("http://localhost:18080/api/runs/"
                                    + receipt["runId"] + "/result.json", timeout=60) as response:
            current = json.loads(response.read())
        require(all(cases(current)[name] == indexed[name] for name in CASES),
                "live formal ALG08 outcome differs")
    return root / "browser-control/result.json", {name: indexed[name] for name in CASES}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    receipt = verify(args.root, live=not args.offline)
    receipt["tamperRejected"] = tamper_test(args.root)
    path = args.root / "receipt.json"
    path.write_bytes(canonical(receipt))
    print(receipt["runId"], "diagnostic only; formal result excluded",
          digest(path.read_bytes()))


if __name__ == "__main__":
    main()
