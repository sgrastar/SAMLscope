#!/usr/bin/env python3
"""Independent fail-closed verifier for Keycloak UI-feature nonuse evidence."""

import argparse
import base64
import copy
import hashlib
import json
import re
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import xml.etree.ElementTree as ET

if not __debug__:
    raise RuntimeError("UI feature absence verification must not run with Python optimization")

FOLDER = "keycloak-ui-feature-absence-v155"
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
CASES = {"IIP-MD05-fb-idp-01", "IIP-MD05-fj-idp-01"}
VARIANT = "ui-consumer-display-all"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
UI = "{urn:oasis:names:tc:SAML:metadata:ui}"
P = "{urn:oasis:names:tc:SAML:2.0:protocol}"
S = "{urn:oasis:names:tc:SAML:2.0:assertion}"
DISPLAY = "SAMLscope UI display candidate"
SERVICE = "SAMLscope service candidate"
IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
CLASS_HASHES = {
    "converterClass": "f12ac7fc23ddaec03f2b0d61c47368dae8038b478a4972a66d0ff7f3415de4ec",
    "samlProtocolClass": "4ad89b08f6d37e00a02e3cb0a4563883935f7d66b3f3bb717f9da8c316104100",
    "samlServiceClass": "9595db004ef39dfa3e560ae4817d30646c15d117dbff08737283d14f0fbc7f45",
}


def require(value, detail):
    if not value:
        raise ValueError(detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def fields(value, expected, detail):
    require(isinstance(value, dict) and set(value) == set(expected), detail)


def xml(raw):
    require(b"<!DOCTYPE" not in raw.upper() and b"<!ENTITY" not in raw.upper(), "unsafe XML original")
    return ET.fromstring(raw)


def inline_blob(value, expected_path=None):
    fields(value, {"path", "sha256", "base64"}, "blob fields differ")
    if expected_path is not None:
        require(value["path"] == expected_path, "blob source path differs")
    raw = base64.b64decode(value["base64"], validate=True)
    require(sha(raw) == value["sha256"], "blob hash differs")
    return raw


def artifact_blob(folder, value, expected_file):
    raw = inline_blob(value)
    require(value["path"] == expected_file, "artifact blob path differs")
    require((folder / expected_file).is_file() and (folder / expected_file).read_bytes() == raw,
            "artifact blob is not the captured original")
    return raw


def decoded(folder, transcript):
    by_id = {entry["id"]: entry for entry in transcript}
    require(len(by_id) == len(transcript), "duplicate transcript identifiers")
    values = {}
    manifest = read(folder / "decoded-manifest.json")
    for row in manifest:
        require(set(row) == {"id", "file", "sha256"} and row["id"] in by_id,
                "decoded manifest row differs")
        path = (folder / row["file"]).resolve()
        require(path.parent == (folder / "decoded").resolve(), "decoded path escapes evidence directory")
        raw = path.read_bytes()
        entry = by_id[row["id"]]
        require(entry.get("decodedSamlRef") == f"transcripts/{entry['runId']}/{entry['id']}.saml.xml",
                "decoded reference differs")
        require(sha(raw) == row["sha256"] and len(raw) == entry["decodedSamlBytes"],
                "decoded bytes differ")
        values[row["id"]] = raw
    require(set(values) == {entry["id"] for entry in transcript if entry.get("decodedSamlRef")},
            "decoded originals are incomplete")
    return by_id, values


def find_result_case(result, case_id):
    values = [case for requirement in result.get("requirements", [])
              for case in requirement.get("cases", []) if case.get("id") == case_id]
    require(len(values) == 1, "formal result case count differs")
    return values[0]


def verify_folder(folder, require_adoption=True, receipt_override=None):
    folder = Path(folder)
    receipt = copy.deepcopy(receipt_override if receipt_override is not None else read(folder / "receipt.json"))
    fields(receipt, {"schema", "runId", "targetEntityId", "targetMetadataSha256",
            "evidenceAdapter", "provenCases", "fixture", "exchange", "nativeImport",
            "runtime", "requestBoundDecision", "restoration", "operationCounts"},
           "receipt fields differ")
    run = receipt["runId"]
    require(receipt["schema"] == "samlscope-native-ui-feature-absence-v1"
            and RUN_RE.fullmatch(run) is not None
            and receipt["targetEntityId"] == "http://localhost:18180/realms/samlscope"
            and receipt["evidenceAdapter"] == "keycloak-native-client-import"
            and set(receipt["provenCases"]) == CASES
            and len(receipt["provenCases"]) == 2, "receipt identity differs")

    created = read(folder / "created.json")["run"]
    require(created["id"] == run, "receipt Run differs from created Run")
    target = (folder / "target-metadata.xml").read_bytes()
    require(sha(target) == receipt["targetMetadataSha256"], "target metadata hash differs")
    target_root = xml(target)
    require(target_root.tag == MD + "EntityDescriptor"
            and target_root.attrib.get("entityID") == receipt["targetEntityId"],
            "target metadata identity differs")

    transcript = read(folder / "transcript.json")
    require(transcript and all(entry.get("runId") == run for entry in transcript), "transcript Run differs")
    entries, originals = decoded(folder, transcript)
    fixture = receipt["fixture"]
    fields(fixture, {"variant", "fetchReference", "metadataReference", "metadataSha256"},
           "fixture binding differs")
    require(fixture["variant"] == VARIANT, "fixture variant differs")
    fetch = entries.get(fixture["fetchReference"])
    prepared = entries.get(fixture["metadataReference"])
    require(fetch and prepared and fetch["direction"] == "INBOUND" and prepared["direction"] == "OUTBOUND"
            and fetch["samlSummary"].get("type") == "MetadataFetch"
            and prepared["samlSummary"].get("type") == "MetadataPrepared"
            and fetch["samlSummary"].get("variant") == VARIANT
            and prepared["samlSummary"].get("variant") == VARIANT
            and prepared["samlSummary"].get("fetchTranscriptId") == fetch["id"],
            "fixture transcript binding differs")
    fixture_raw = originals[prepared["id"]]
    require(sha(fixture_raw) == fixture["metadataSha256"] == prepared["samlSummary"].get("metadataSha256"),
            "fixture original hash differs")
    fixture_root = xml(fixture_raw)
    role = fixture_root.findall(MD + "SPSSODescriptor")
    require(fixture_root.tag == MD + "EntityDescriptor" and len(role) == 1, "fixture role differs")
    display = role[0].find("./" + MD + "Extensions/" + UI + "UIInfo/" + UI + "DisplayName")
    service = role[0].find("./" + MD + "AttributeConsumingService/" + MD + "ServiceName")
    require(display is not None and display.text == DISPLAY and service is not None and service.text == SERVICE,
            "fixture candidates differ")
    entity = fixture_root.attrib["entityID"]

    exchange = receipt["exchange"]
    fields(exchange, {"requestReference", "responseReference", "requestSha256", "responseSha256"},
           "exchange fields differ")
    request = entries.get(exchange["requestReference"])
    response = entries.get(exchange["responseReference"])
    request_raw = originals.get(exchange["requestReference"])
    response_raw = originals.get(exchange["responseReference"])
    require(request and response and request_raw and response_raw
            and sha(request_raw) == exchange["requestSha256"]
            and sha(response_raw) == exchange["responseSha256"], "exchange originals differ")
    request_xml, response_xml = xml(request_raw), xml(response_raw)
    require(request["direction"] == "OUTBOUND" and response["direction"] == "INBOUND"
            and request["samlSummary"].get("variant") == VARIANT
            and response["samlSummary"].get("metadataProbeAccepted") is True
            and response["samlSummary"].get("statusCode") == SUCCESS
            and request_xml.tag == P + "AuthnRequest" and response_xml.tag == P + "Response"
            and response_xml.attrib.get("InResponseTo") == request_xml.attrib.get("ID")
            and response.get("correlationId") == request_xml.attrib.get("ID")
            and request_xml.find(S + "Issuer").text == entity
            and response_xml.find(S + "Issuer").text == receipt["targetEntityId"],
            "exchange semantic binding differs")
    query = parse_qs(urlparse(response["url"]).query)
    require(query == {"mdv": [VARIANT], "run": [run]}, "response URL correlation differs")

    native = receipt["nativeImport"]
    fields(native, {"uiImportRecord", "converterOutput", "configuredReadBack"}, "native import fields differ")
    import_record = json.loads(artifact_blob(folder, native["uiImportRecord"],
                                             VARIANT + "/import.json"))
    configured_raw = artifact_blob(folder, native["configuredReadBack"],
                                   VARIANT + "/configured-read-back.json")
    converter_raw = artifact_blob(folder, native["converterOutput"],
                                  VARIANT + "/converter-output.json")
    configured, converter = json.loads(configured_raw), json.loads(converter_raw)
    require(import_record["status"] == "success"
            and import_record["fixture"]["entity_id"] == entity
            and import_record["fixture"]["sha256"] == sha(fixture_raw)
            and import_record["import"]["ui_status"] == "client-settings-page"
            and import_record["client"]["database_id"] == configured["id"],
            "native import readback differs")
    require(configured["clientId"] == entity and configured["protocol"] == "saml"
            and any("mdv=" + VARIANT in value for value in configured["redirectUris"]),
            "configured client does not prove native metadata consumption")
    require(isinstance(converter, list) and len(converter) == 1
            and converter[0]["clientId"] == entity
            and converter[0]["attributes"]["saml_assertion_consumer_url_post"].find("mdv=" + VARIANT) >= 0,
            "native converter does not prove metadata consumption")
    forbidden = (DISPLAY, SERVICE, "UIInfo", "DisplayName", "OrganizationDisplayName",
                 "DiscoHints", "DomainHint", "GeolocationHint", "IPHint")
    require(all(value not in configured_raw.decode() and value not in converter_raw.decode()
                for value in forbidden), "a UI candidate survives product-native import")
    require(not configured.get("name") and not converter[0].get("name"), "display name survives import")

    runtime = receipt["runtime"]
    require(runtime["containerName"] == "samlscope-reference-keycloak"
            and re.fullmatch(r"[0-9a-f]{64}", runtime["containerId"])
            and runtime["imageId"] == IMAGE and runtime["productVersion"] == "26.7.2"
            and runtime["runningAtCapture"] is True, "runtime identity differs")
    for name, expected in CLASS_HASHES.items():
        require(sha(inline_blob(runtime[name])) == expected, "runtime class differs: " + name)

    decision = receipt["requestBoundDecision"]
    providers_raw = artifact_blob(folder, decision["identityProviderReadBack"],
                                  VARIANT + "/identity-provider-read-back.json")
    require(json.loads(providers_raw) == [] and decision["entityId"] == entity
            and decision["authenticatedFlowCompleted"] is True
            and decision["identityProviderAliases"] == []
            and decision["identityProviderLinks"] == []
            and re.fullmatch(r"[0-9a-f]{64}", decision["loginPageSha256"])
            and urlparse(decision["loginPageUrl"]).scheme == "http"
            and urlparse(decision["loginPageUrl"]).hostname == "localhost"
            and urlparse(decision["loginPageUrl"]).port == 18180
            and urlparse(decision["loginPageUrl"]).path == "/realms/samlscope/login-actions/authenticate"
            and decision["loginFormActionPath"] == "/realms/samlscope/login-actions/authenticate"
            and re.fullmatch(r"[0-9a-f]{64}", decision["loginFormActionSha256"]),
            "request-bound no-discovery decision differs")
    run_values = parse_qs(urlparse(decision["requestUrl"]).query).get("run", [])
    require(run_values == [run], "request-bound decision Run differs")

    restoration = receipt["restoration"]
    before = artifact_blob(folder, restoration["beforeReadBack"], "client-before.json")
    after = artifact_blob(folder, restoration["afterReadBack"], "client-final.json")
    require(before == after and json.loads(before) == [] and restoration["deletedClientId"] == entity
            and restoration["restored"] is True, "product state was not exactly restored")
    require(receipt["operationCounts"] == {"productConfigurationWrites": 4, "productRestarts": 0,
            "metadataImports": 2, "protocolRoundTrips": 2, "humanOperations": 0},
            "operation counts differ")
    operations = read(folder / "operations.json")
    require(len(operations) == 2 and [row["variant"] for row in operations] == ["control", VARIANT]
            and all(row["restored"] is True for row in operations), "campaign operation originals differ")

    cases = {}
    if require_adoption:
        result = read(folder / "result.json")
        for case_id in CASES:
            case = find_result_case(result, case_id)
            require(case["outcome"] == "SATISFIED_WITH_NOTE"
                    and case["reason_code"] == "browser.ui-native-feature.not-used",
                    "formal outcome differs for " + case_id)
            cases[case_id] = {"outcome": case["outcome"], "verdict": case["verdict"]}
    return {"runId": run, "cases": cases, "receiptSha256": sha((folder / "receipt.json").read_bytes()),
            "restored": True, "operationCounts": receipt["operationCounts"]}


def run_tamper_tests(folder):
    original = read(Path(folder) / "receipt.json")
    mutations = []
    mutations.append(lambda value: value.__setitem__("runId", "run_" + "0" * 26))
    mutations.append(lambda value: value.__setitem__("targetMetadataSha256", "0" * 64))
    mutations.append(lambda value: value["fixture"].__setitem__("metadataReference", "tx_" + "0" * 26))
    mutations.append(lambda value: value["exchange"].__setitem__("responseSha256", "0" * 64))
    mutations.append(lambda value: value["runtime"].__setitem__("imageId", "sha256:" + "0" * 64))
    mutations.append(lambda value: value["requestBoundDecision"]["identityProviderAliases"].append("broker"))
    mutations.append(lambda value: value["requestBoundDecision"].__setitem__("authenticatedFlowCompleted", False))
    mutations.append(lambda value: value["restoration"].__setitem__("restored", False))
    mutations.append(lambda value: value["operationCounts"].__setitem__("humanOperations", 1))
    mutations.append(lambda value: value.__setitem__("provenCases", ["IIP-MD05-fj-idp-01"]))
    rejected = 0
    for mutation in mutations:
        value = copy.deepcopy(original)
        mutation(value)
        try:
            verify_folder(folder, require_adoption=False, receipt_override=value)
        except (ValueError, KeyError, TypeError, IndexError):
            rejected += 1
    require(rejected == len(mutations), "one or more tamper mutations were accepted")
    return {"mutations": len(mutations), "rejected": rejected}


def verify_with_report(root):
    folder = Path(root) / FOLDER
    report = verify_folder(folder, require_adoption=True)
    report["tamper"] = run_tamper_tests(folder)
    return report


def verify(root):
    folder = Path(root) / FOLDER
    verify_with_report(root)
    path = folder / "result.json"
    result = read(path)
    return path, {case_id: find_result_case(result, case_id) for case_id in CASES}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--campaign-only", action="store_true")
    parser.add_argument("--tamper-tests", action="store_true")
    args = parser.parse_args()
    folder = args.root / FOLDER if (args.root / FOLDER).is_dir() else args.root
    report = verify_folder(folder, require_adoption=not args.campaign_only)
    if args.tamper_tests:
        report["tamper"] = run_tamper_tests(folder)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
