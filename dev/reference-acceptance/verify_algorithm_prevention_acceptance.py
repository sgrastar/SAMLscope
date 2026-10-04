#!/usr/bin/env python3
"""Fail-closed verifier for one Shibboleth ALG08 A/B/A campaign folder."""
import argparse
import base64
import hashlib
import importlib.util
import json
from functools import lru_cache
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request
import xml.etree.ElementTree as ET


BASE = "http://localhost:18080"
SUITE = "samlscope-reference-suite"
IMAGE = "sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a"
SUITE_IMAGE = "sha256:bfceeca3054d4c14aa0327be0e662782954ef5153325903a876a32a66effcd74"
SUITE_CLASSES = {
    "com/samlscope/runner/cases/AlgorithmPreventionEvidenceFile.class":
        "d52cfdda4b699b37dd5c3d589177d7308c99546237f2d6b4afdb93d78fd27964",
    "com/samlscope/runner/cases/AlgorithmPreventionConfigurationTestCase.class":
        "a2d9f2d8976efba16092550a1f3a0a94b4fc50edf1ed3fad5c31b91635e9d7ee",
    "com/samlscope/runner/cases/SuiteRunProfileLookup.class":
        "7b5d7862ea84c13dc034c3cde49e90ac1bd22fea451a67bff2d619fd3390f348",
}
OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
RSA15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
AES128 = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
P = "urn:oasis:names:tc:SAML:2.0:protocol"
S = "urn:oasis:names:tc:SAML:2.0:assertion"
X = "http://www.w3.org/2001/04/xmlenc#"
SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
PHASES = ("allowed-before", "blocked", "allowed-after")
FOLDER = "shibboleth-alg08-aes-v161"
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
PLAN_RE = re.compile(r"plan_[0-9A-HJKMNP-TV-Z]{26}")
REPO = Path(__file__).resolve().parents[2]
_campaign_spec = importlib.util.spec_from_file_location(
    "algorithm_prevention_campaign", REPO / "dev/shibboleth/algorithm_prevention_campaign.py")
campaign = importlib.util.module_from_spec(_campaign_spec)
_campaign_spec.loader.exec_module(campaign)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path):
    return json.loads(path.read_text())


def exact(value, fields, label):
    require(isinstance(value, dict) and set(value) == set(fields), label + " fields differ")


def unblob(value, label, limit=2_097_152):
    exact(value, ("base64", "sha256"), label)
    raw = base64.b64decode(value["base64"], validate=True)
    require(0 < len(raw) <= limit and sha(raw) == value["sha256"], label + " hash differs")
    return raw


def local_original(folder, manifest, reference):
    item = manifest.get(reference)
    require(item is not None and set(item) == {"id", "file", "sha256"}, "manifest entry absent")
    path = (folder / item["file"]).resolve()
    require(path.parent == (folder / "decoded").resolve() and path.is_file(), "unsafe original path")
    raw = path.read_bytes()
    require(sha(raw) == item["sha256"], "original hash differs")
    return raw


def runtime(value, previous=None):
    exact(value, ("inspect", "version"), "runtime")
    require(unblob(value["version"], "version", 4096).decode().strip() == "5.2.3", "version differs")
    inspected = json.loads(unblob(value["inspect"], "inspect", 262144))
    require(isinstance(inspected, list) and len(inspected) == 1, "inspect cardinality differs")
    item = inspected[0]
    require(item.get("Name") == "/samlscope-reference-shibboleth" and item.get("Image") == IMAGE,
            "runtime identity differs")
    require(item.get("State", {}).get("Running") is True, "runtime was not running")
    require(re.fullmatch(r"[0-9a-f]{64}", item.get("Id", "")), "container id invalid")
    started = item["State"].get("StartedAt", "")
    require(started.endswith("Z") and (previous is None or started > previous), "StartedAt is not increasing")
    return item["Id"], started


def suite_runtime(value):
    exact(value, ("inspect", "jars", "classes"), "Suite runtime")
    inspected = json.loads(unblob(value["inspect"], "Suite inspect", 262144))
    require(isinstance(inspected, list) and len(inspected) == 1, "Suite inspect cardinality differs")
    item = inspected[0]
    require(item.get("Name") == "/" + SUITE and item.get("Image") == SUITE_IMAGE,
            "Suite runtime identity differs")
    require(item.get("State", {}).get("Running") is True, "Suite runtime was not running")
    require(re.fullmatch(r"[0-9a-f]{64}", item.get("Id", "")), "Suite container id invalid")
    started = item.get("State", {}).get("StartedAt", "")
    require(isinstance(started, str) and started.endswith("Z"), "Suite StartedAt invalid")
    require(set(value["jars"]) == set(campaign.SUITE_JARS)
            and all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in value["jars"].values()),
            "Suite JAR hashes invalid")
    require(value["classes"] == SUITE_CLASSES, "Suite ALG08 class hashes differ")
    return item["Id"], started


def one(root, namespace, local):
    values = root.findall(".//{" + namespace + "}" + local)
    if root.tag == "{" + namespace + "}" + local:
        values.insert(0, root)
    require(len(values) == 1, local + " cardinality differs")
    return values[0]


def case_map(result):
    return {case["id"]: case for requirement in result["requirements"] for case in requirement["cases"]}


def verify(folder, live=True):
    initial_suite = load(folder / "suite-runtime-initial.json")
    final_suite = load(folder / "suite-runtime-final.json")
    suite_id, suite_started = suite_runtime(initial_suite)
    final_suite_id, final_suite_started = suite_runtime(final_suite)
    require((final_suite_id, final_suite_started) == (suite_id, suite_started),
            "Suite runtime envelope differs")
    require(final_suite["jars"] == initial_suite["jars"]
            and final_suite["classes"] == initial_suite["classes"],
            "Suite JAR/class hashes changed during campaign")
    receipt = load(folder / "algorithm-prevention-receipt.json")
    exact(receipt, ("schema", "runId", "profile", "targetEntityId", "targetMetadataSha256",
                    "suiteMetadata", "configuration", "runtime", "phases", "operationCounts"), "receipt")
    require(receipt["schema"] == "samlscope-shibboleth-algorithm-prevention-v2", "schema differs")
    run, profile = receipt["runId"], receipt["profile"]
    require(RUN_RE.fullmatch(run) and profile in {"browser_sso_idp", "ecp_idp"}, "scope invalid")
    plan_doc, created = load(folder / "plan.json"), load(folder / "created.json")
    plan = plan_doc["plan"]["plan"]
    require(PLAN_RE.fullmatch(plan["id"]) and plan["profile"] == profile, "Plan profile differs")
    require(created["run"]["id"] == run and created["run"]["planId"] == plan["id"], "Run binding differs")
    preflight = load(folder / "preflight.json")
    require(preflight.get("runId") == run, "preflight Run differs")
    checks = {check.get("code"): check for check in preflight.get("checks", [])}
    require(checks.get("target_metadata", {}).get("status") == "PASS",
            "target metadata preflight was not PASS")
    target = (folder / "target-metadata.xml").read_bytes()
    require(sha(target) == receipt["targetMetadataSha256"], "target metadata hash differs")
    target_root = ET.fromstring(target)
    require(target_root.get("entityID") == receipt["targetEntityId"], "target entity differs")
    suite_metadata = (folder / "suite-metadata.xml").read_bytes()
    require(unblob(receipt["suiteMetadata"], "suite metadata") == suite_metadata, "suite metadata differs")

    config = receipt["configuration"]
    exact(config, ("originalGlobal", "originalRelyingParty", "originalProviders", "providerConfiguredReadBack",
                   "fixtureReadBack", "restoredGlobal", "restoredRelyingParty", "restoredProviders",
                   "temporaryMetadataRemoved", "restored"), "configuration")
    originals = {name: (folder / ("original-" + name)).read_bytes()
                 for name in ("global", "relying", "providers")}
    require(unblob(config["originalGlobal"], "original global") == originals["global"], "global original differs")
    require(unblob(config["originalRelyingParty"], "original relying party") == originals["relying"], "relying party original differs")
    require(unblob(config["originalProviders"], "original providers") == originals["providers"], "providers original differs")
    require(unblob(config["restoredGlobal"], "restored global") == originals["global"], "global not restored")
    require(unblob(config["restoredRelyingParty"], "restored relying party") == originals["relying"], "relying party not restored")
    require(unblob(config["restoredProviders"], "restored providers") == originals["providers"], "providers not restored")
    require(unblob(config["fixtureReadBack"], "fixture") == suite_metadata, "fixture read-back differs")
    require(unblob(config["providerConfiguredReadBack"], "provider configured")
            == campaign.configured_providers(originals["providers"], run), "provider configuration differs")
    require(config["temporaryMetadataRemoved"] is True and config["restored"] is True, "restoration flags differ")
    restoration = load(folder / "restoration.json")
    require(restoration["run"] == run and restoration["restored"] is True
            and restoration["temporary_metadata_removed"] is True and not restoration["failures"],
            "restoration record is incomplete")

    exact(receipt["runtime"], ("initial", "restored"), "runtime envelope")
    container, started = runtime(receipt["runtime"]["initial"])
    algorithms, evidence = [], set()
    transcript_list = load(folder / "transcript.json")
    transcript = {entry["id"]: entry for entry in transcript_list}
    require(len(transcript) == len(transcript_list)
            and all(entry["runId"] == run for entry in transcript_list), "transcript scope differs")
    manifest_list = load(folder / "decoded-manifest.json")
    manifest = {entry["id"]: entry for entry in manifest_list}
    require(len(manifest) == len(manifest_list), "manifest ids are ambiguous")
    require(isinstance(receipt["phases"], list) and len(receipt["phases"]) == 3, "phase count differs")
    for index, phase in enumerate(receipt["phases"]):
        exact(phase, ("name", "globalReadBack", "relyingPartyReadBack", "runtime",
                      "requestReference", "responseReference"), "phase")
        require(phase["name"] == PHASES[index], "phase order differs")
        expected_global = campaign.configured_global(originals["global"], index == 1)
        expected_relying = campaign.configured_relying(originals["relying"])
        require(unblob(phase["globalReadBack"], "phase global") == expected_global,
                "phase global read-back differs")
        require(unblob(phase["relyingPartyReadBack"], "phase relying party") == expected_relying,
                "phase relying-party read-back differs")
        require((folder / phase["name"] / "global-readback.xml").read_bytes() == expected_global,
                "saved phase global differs")
        require((folder / phase["name"] / "relying-party-readback.xml").read_bytes() == expected_relying,
                "saved phase relying party differs")
        phase_container, started = runtime(phase["runtime"], started)
        require(phase_container == container, "container changed")
        for kind in ("requestReference", "responseReference"):
            require(phase[kind] not in evidence, "evidence reused")
            evidence.add(phase[kind])
        request, response = transcript.get(phase["requestReference"]), transcript.get(phase["responseReference"])
        require(request and response and request["direction"] == "OUTBOUND" and response["direction"] == "INBOUND",
                "exchange direction differs")
        request_raw = local_original(folder, manifest, request["id"])
        response_raw = local_original(folder, manifest, response["id"])
        request_root, response_root = ET.fromstring(request_raw), ET.fromstring(response_raw)
        authn, saml_response = one(request_root, P, "AuthnRequest"), one(response_root, P, "Response")
        require(authn.get("ID") and saml_response.get("InResponseTo") == authn.get("ID"), "correlation differs")
        require(saml_response.get("Destination"), "Destination absent")
        status = one(saml_response, P, "StatusCode")
        require(status.get("Value") == "urn:oasis:names:tc:SAML:2.0:status:Success",
                "SAML status is not Success")
        issuer = [node.text for node in authn.findall("./{" + S + "}Issuer")]
        require(issuer == [ET.fromstring(suite_metadata).get("entityID")], "request issuer differs")
        if profile == "browser_sso_idp":
            require(request_root is authn and response_root is saml_response, "browser originals are wrapped")
            require(request["samlSummary"].get("type") == "AuthnRequest"
                    and response["samlSummary"].get("type") == "Response"
                    and (response["samlSummary"].get("normalFlowAccepted") is True
                         or response["samlSummary"].get("activeProbeAccepted") is True), "browser oracle absent")
            require(response.get("url") == saml_response.get("Destination"), "browser Destination differs")
        else:
            require(request_root.tag == "{" + SOAP + "}Envelope" and response_root.tag == "{" + SOAP + "}Envelope",
                    "ECP SOAP envelope absent")
            require(request["samlSummary"].get("type") == "EcpSoapRequest"
                    and response["samlSummary"].get("type") == "EcpSoapResponse", "ECP summary differs")
            require(request.get("correlationId") == response.get("correlationId")
                    and request.get("url") == response.get("url") and response.get("status") == 200,
                    "ECP outbox correlation differs")
        encrypted = saml_response.findall(".//{" + S + "}EncryptedAssertion")
        data_methods = saml_response.findall(
            ".//{" + X + "}EncryptedData/{" + X + "}EncryptionMethod")
        key_methods = saml_response.findall(
            ".//{" + X + "}EncryptedKey/{" + X + "}EncryptionMethod")
        require(len(encrypted) == len(data_methods) == len(key_methods) == 1,
                "encrypted assertion cardinality differs")
        require(data_methods[0].get("Algorithm") == AES128, "unexpected data-encryption algorithm")
        algorithm = key_methods[0].get("Algorithm")
        require(algorithm in {RSA15, OAEP}, "unexpected key-transport algorithm")
        algorithms.append(algorithm)
    restored_container, started = runtime(receipt["runtime"]["restored"], started)
    require(restored_container == container, "restored container differs")
    require(algorithms == [RSA15, OAEP, RSA15], "A/B/A wire algorithms differ")
    exact(receipt["operationCounts"], ("productConfigurationWrites", "productRestarts", "metadataReloads",
                                       "protocolOperations", "humanOperations"), "operation counts")
    require(receipt["operationCounts"] == {"productConfigurationWrites": 9, "productRestarts": 4,
            "metadataReloads": 0, "protocolOperations": 3, "humanOperations": 0}, "operation counts differ")

    result = load(folder / "result.json")
    require(result["run"]["id"] == run and result["profile"]["id"] == profile.replace("_", "-"),
            "formal result scope differs")
    cases = case_map(result)
    for case_id in ("IIP-ALG08-a-idp-01", "IIP-ALG08-b-idp-01"):
        case = cases[case_id]
        require((case["verdict"], case["reason_code"], case["attested"]) ==
                ("PASS", "configuration.algorithm-prevention.observed", False), case_id + " not formally observed")
        refs = {item["reference"] for item in case["evidence"] if item["kind"] == "transcript"}
        require(refs == evidence, case_id + " evidence differs")

    if live:
        require(campaign.same_suite_runtime(campaign.suite_runtime_blob(), initial_suite),
                "live Suite runtime/JAR/class differs")
        with tempfile.TemporaryDirectory(prefix="alg08-receipt-") as temp:
            copied = Path(temp) / "receipt.json"
            subprocess.run(["docker", "cp", SUITE + ":/data/algorithm-prevention-evidence/" + run + ".json",
                            str(copied)], check=True, timeout=60, stdout=subprocess.DEVNULL)
            require(copied.read_bytes() == (folder / "algorithm-prevention-receipt.json").read_bytes(),
                    "installed Suite receipt differs")
        before = json.loads(urllib.request.urlopen(BASE + "/api/runs/" + run + "/transcript", timeout=60).read())
        request = urllib.request.Request(BASE + "/api/runs/" + run + "/protocol-evidence/evaluate",
                                         data=b"{}", headers={"Content-Type": "application/json"})
        urllib.request.urlopen(request, timeout=90).read()
        after = json.loads(urllib.request.urlopen(BASE + "/api/runs/" + run + "/transcript", timeout=60).read())
        require(before == transcript_list == after, "live cryptographic re-evaluation changed or lost evidence")
        live_result = json.loads(urllib.request.urlopen(BASE + "/api/runs/" + run + "/result.json", timeout=60).read())
        for case_id in ("IIP-ALG08-a-idp-01", "IIP-ALG08-b-idp-01"):
            require(case_map(live_result)[case_id]["verdict"] == "PASS", "live cryptographic recheck failed")
    return {"run": run, "profile": profile, "cases": 2, "algorithms": algorithms,
            "receipt_sha256": sha((folder / "algorithm-prevention-receipt.json").read_bytes()),
            "live_cryptographic_recheck": live}


def tamper_self_test(folder):
    # Use independent folder copies so every rejected mutation starts from known-valid bytes.
    recipes = []
    def add(name, action): recipes.append((name, action))
    def break_response(root):
        receipt = load(root / "algorithm-prevention-receipt.json")
        reference = receipt["phases"][0]["responseReference"]
        item = next(item for item in load(root / "decoded-manifest.json") if item["id"] == reference)
        (root / item["file"]).write_bytes(b"<broken/>")
    add("response-original", break_response)
    add("receipt-profile", lambda root: _mutate_json(root / "algorithm-prevention-receipt.json",
                                                     lambda value: value.__setitem__("profile", "ecp_idp")))
    add("restoration", lambda root: _mutate_json(root / "algorithm-prevention-receipt.json",
                                                  lambda value: value["configuration"].__setitem__("restored", False)))
    add("blocked-readback", lambda root: _mutate_json(root / "algorithm-prevention-receipt.json",
                                                       lambda value: value["phases"][1].__setitem__("globalReadBack", value["phases"][0]["globalReadBack"])))
    add("operation-count", lambda root: _mutate_json(root / "algorithm-prevention-receipt.json",
                                                      lambda value: value["operationCounts"].__setitem__("productRestarts", 3)))
    add("suite-runtime", lambda root: _mutate_json(root / "suite-runtime-final.json",
                                                    lambda value: value["classes"].__setitem__(next(iter(value["classes"])), "0" * 64)))
    rejected = []
    for name, action in recipes:
        with tempfile.TemporaryDirectory(prefix="alg08-tamper-") as temp:
            clone = Path(temp) / "campaign"
            subprocess.run(["cp", "-R", str(folder), str(clone)], check=True)
            action(clone)
            try:
                verify(clone, live=False)
            except Exception:
                rejected.append(name)
    require(rejected == [name for name, _ in recipes], "tamper self-test did not reject every mutation")
    return rejected


def _mutate_json(path, mutation):
    value = load(path); mutation(value); path.write_text(json.dumps(value, indent=2) + "\n")


def verify_saved_live_record(folder):
    runtime_path = folder / "suite-runtime-live-verification.json"
    report_path = folder / "acceptance-verification.json"
    runtime_value = load(runtime_path)
    live_id, live_started = suite_runtime(runtime_value)
    initial_value = load(folder / "suite-runtime-initial.json")
    initial_id, initial_started = suite_runtime(initial_value)
    require((live_id, live_started) == (initial_id, initial_started)
            and runtime_value["jars"] == initial_value["jars"]
            and runtime_value["classes"] == initial_value["classes"],
            "saved live Suite runtime differs from campaign runtime")
    report = load(report_path)
    exact(report, ("schema", "runId", "profile", "liveCryptographicRecheck",
                   "tamperRejections", "receiptSha256", "resultSha256",
                   "transcriptSha256", "suiteRuntimeSha256", "verifierSourceSha256"),
          "acceptance verification")
    receipt = load(folder / "algorithm-prevention-receipt.json")
    require(report == {
        "schema": "samlscope-algorithm-prevention-acceptance-v1",
        "runId": receipt["runId"],
        "profile": receipt["profile"],
        "liveCryptographicRecheck": True,
        "tamperRejections": ["response-original", "receipt-profile", "restoration",
                              "blocked-readback", "operation-count", "suite-runtime"],
        "receiptSha256": sha((folder / "algorithm-prevention-receipt.json").read_bytes()),
        "resultSha256": sha((folder / "result.json").read_bytes()),
        "transcriptSha256": sha((folder / "transcript.json").read_bytes()),
        "suiteRuntimeSha256": sha(runtime_path.read_bytes()),
        "verifierSourceSha256": sha(Path(__file__).read_bytes()),
    }, "saved live acceptance verification differs")
    return report


@lru_cache(maxsize=None)
def verify_adoption(root):
    folder = Path(root).resolve()
    if folder.name != FOLDER:
        folder = folder / FOLDER
    verified = verify(folder, live=False)
    require(verified["cases"] == 2 and verified["algorithms"] == [RSA15, OAEP, RSA15],
            "ALG08 adoption scope differs")
    require(tamper_self_test(folder) == [
        "response-original", "receipt-profile", "restoration", "blocked-readback",
        "operation-count", "suite-runtime",
    ], "ALG08 tamper rejection inventory differs")
    verify_saved_live_record(folder)
    result_path = folder / "result.json"
    cases = case_map(load(result_path))
    adopted = ("IIP-ALG08-a-idp-01", "IIP-ALG08-b-idp-01")
    return result_path, {case_id: cases[case_id] for case_id in adopted}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--tamper-self-test", action="store_true")
    args = parser.parse_args()
    result = verify(args.folder.resolve(), live=not args.offline)
    if args.tamper_self_test:
        result["tamper_rejections"] = tamper_self_test(args.folder.resolve())
    if not args.offline:
        folder = args.folder.resolve()
        require(result.get("live_cryptographic_recheck") is True,
                "live cryptographic recheck was not completed")
        rejected = result.get("tamper_rejections", [])
        require(rejected == ["response-original", "receipt-profile", "restoration",
                             "blocked-readback", "operation-count", "suite-runtime"],
                "live acceptance requires the full tamper self-test")
        runtime_path = folder / "suite-runtime-live-verification.json"
        runtime_path.write_text(json.dumps(campaign.suite_runtime_blob(), indent=2) + "\n")
        report = {
            "schema": "samlscope-algorithm-prevention-acceptance-v1",
            "runId": result["run"],
            "profile": result["profile"],
            "liveCryptographicRecheck": True,
            "tamperRejections": rejected,
            "receiptSha256": result["receipt_sha256"],
            "resultSha256": sha((folder / "result.json").read_bytes()),
            "transcriptSha256": sha((folder / "transcript.json").read_bytes()),
            "suiteRuntimeSha256": sha(runtime_path.read_bytes()),
            "verifierSourceSha256": sha(Path(__file__).read_bytes()),
        }
        (folder / "acceptance-verification.json").write_text(json.dumps(report, indent=2) + "\n")
        verify_saved_live_record(folder)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
