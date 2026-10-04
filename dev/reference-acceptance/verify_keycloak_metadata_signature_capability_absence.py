#!/usr/bin/env python3
"""Fail-closed verifier for Keycloak MD03.a/b/c capability-absence evidence."""
from __future__ import annotations

import argparse
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
from functools import lru_cache
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier

from verify_keycloak_metadata_source_capability_absence import verify_adoption as verify_base_adoption


REPO = Path(__file__).resolve().parents[2]
SCHEMA = "samlscope-keycloak-metadata-signature-capability-absence-v1"
FOLDER = "keycloak-md03-signature-capability-v160"
PRODUCT = "keycloak"
VERSION = "26.7.2"
TARGET = "http://localhost:18180/realms/samlscope"
TARGET_IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
BASE_FOLDER = "build/acceptance/reference-20260930/keycloak-metadata-source-capability-absence-v158"
BASE_RECEIPT_SHA = "80a204d7dde29685950d73d9b5a1934af901fe21450152f60553d6a438f34ba9"
CASES = ("IIP-MD03-a-idp-01", "IIP-MD03-b-idp-01", "IIP-MD03-c-idp-01")
CASE_DIGESTS = {
    "IIP-MD03-a-idp-01": "sha256:e71a48b1e44bd6ad473435e7472f51b3f444519e4e092bfcf6f0541141a83a52",
    "IIP-MD03-b-idp-01": "sha256:6a26d27008558854aff09e177ff1dfb1ed09323f80d32af44ed31b92d3da96b5",
    "IIP-MD03-c-idp-01": "sha256:f71d6283548a78b2d38aa4f918e350f1b18285c859753f8a57b1dba038d032ee",
}
FLOW_VARIANTS = (
    "control", "unsigned", "signed-other-key", "signed-other-key-primary-keyinfo",
    "certificate-expired", "certificate-not-yet-valid",
    "certificate-no-digital-signature", "certificate-critical-extension",
)
VARIANTS = FLOW_VARIANTS + ("bad-signature",)
RUNTIME_REJECTED = {"certificate-expired", "certificate-not-yet-valid"}
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
PLAN_RE = re.compile(r"plan_[0-9A-HJKMNP-TV-Z]{26}")
MD = "urn:oasis:names:tc:SAML:2.0:metadata"
DS = "http://www.w3.org/2000/09/xmldsig#"


def require(value, message="invalid Keycloak metadata-signature capability evidence"):
    if not value:
        raise ValueError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def inside(folder: Path, name: str) -> Path:
    path = (folder / name).resolve()
    require(path.is_relative_to(folder.resolve()) and path.is_file(), "evidence reference escaped folder")
    return path


def repo_file(name: str) -> Path:
    path = (REPO / name).resolve()
    require(path.is_relative_to(REPO) and path.is_file(), "repository evidence reference escaped")
    return path


def read(folder: Path, name: str):
    return json.loads(inside(folder, name).read_text())


def case_map(result: dict) -> dict:
    return {case["id"]: case for requirement in result["requirements"] for case in requirement["cases"]}


def verify_approved_definitions() -> None:
    document = yaml.safe_load((REPO / "tests/cases.yaml").read_text())
    definitions = {row["id"]: row for row in document["cases"]}
    for case in CASES:
        item = definitions[case]
        require(item["case_digest"] == CASE_DIGESTS[case]
                and item["role"] == "idp" and item["mode"] == "CONFIG"
                and item["configuration_failure_semantics"] == "normative_capability"
                and len(item["controls"]) == 2
                and {control["kind"] for control in item["controls"]} == {"positive", "negative"},
                "approved MD03 case semantics changed")


def verify_identity(folder: Path, manifest: dict) -> dict[str, dict]:
    require(manifest["schema"] == SCHEMA and manifest["product"] == PRODUCT
            and manifest["productVersion"] == VERSION and manifest["targetEntityId"] == TARGET
            and tuple(manifest["cases"]) == CASES and tuple(manifest["variants"]) == VARIANTS
            and RUN_RE.fullmatch(manifest["runId"]) and PLAN_RE.fullmatch(manifest["planId"])
            and manifest["suiteEntityId"] == "http://localhost:18080/p/" + manifest["planId"],
            "campaign identity mismatch")
    require(manifest["baseRuntimeEvidence"] == BASE_FOLDER
            and manifest["baseRuntimeReceiptSha256"] == BASE_RECEIPT_SHA,
            "base runtime evidence binding mismatch")
    observations = manifest["observations"]
    require(len(observations) == len(VARIANTS)
            and [row["variant"] for row in observations] == list(VARIANTS)
            and len({row["variant"] for row in observations}) == len(VARIANTS),
            "fixture observation inventory mismatch")
    return {row["variant"]: row for row in observations}


def verify_base_runtime(manifest: dict) -> None:
    base = REPO / manifest["baseRuntimeEvidence"]
    require(sha((base / "receipt.json").read_bytes()) == manifest["baseRuntimeReceiptSha256"],
            "base runtime receipt hash mismatch")
    path, cases = verify_base_adoption(base)
    require(path == base / "result.json" and set(cases) == {
        "IIP-MD06-b-idp-01", "IIP-MD03-d-idp-01"},
        "full-JAR/provider verifier did not cover the expected native path")


def verify_target_runtime(folder: Path) -> None:
    start = read(folder, "target-runtime-start.json")
    end = read(folder, "target-runtime-end.json")
    require(start["schema"] == end["schema"] == "samlscope-keycloak-metadata-url-runtime-v1"
            and start["phase"] == "start" and end["phase"] == "end"
            and start["product"] == end["product"] == PRODUCT
            and start["productVersion"] == end["productVersion"] == VERSION
            and start["imageId"] == end["imageId"] == TARGET_IMAGE
            and start["runningAtCapture"] is end["runningAtCapture"] is True,
            "target runtime identity mismatch")
    require({key: value for key, value in start.items() if key != "phase"}
            == {key: value for key, value in end.items() if key != "phase"},
            "target container changed during campaign")
    for stem in ("keycloak-jars", "provider-inventory"):
        require(inside(folder, stem + "-start.json").read_bytes()
                == inside(folder, stem + "-end.json").read_bytes(), stem + " changed")
    require(inside(folder, "keycloak-config-start.txt").read_bytes()
            == inside(folder, "keycloak-config-end.txt").read_bytes(),
            "Keycloak configuration changed during campaign")


def verify_suite(folder: Path, manifest: dict) -> None:
    start = read(folder, "suite-runtime-start.json")
    end = read(folder, "suite-runtime-final.json")
    require(start == manifest["suiteRuntimeStart"], "Suite manifest/start mismatch")
    for key in ("containerName", "containerId", "imageId", "startedAt", "configuredImage", "running"):
        require(start[key] == end[key], "Suite runtime changed")
    require(start["containerName"] == "samlscope-reference-suite" and start["running"] is True
            and set(start["jars"]) == set(end["jars"]) == {"core", "runner", "saml"},
            "Suite runtime inventory mismatch")
    for phase, record in (("start", start), ("final", end)):
        inspect = inside(folder, record["inspectFile"]).read_bytes()
        require(sha(inspect) == record["inspectSha256"], "Suite inspect hash mismatch")
        parsed = json.loads(inspect)
        require(len(parsed) == 1 and parsed[0]["Id"] == record["containerId"]
                and parsed[0]["Image"] == record["imageId"]
                and parsed[0]["State"]["StartedAt"] == record["startedAt"]
                and parsed[0]["State"]["Running"] is True,
                "Suite inspect identity mismatch")
        for name, item in record["jars"].items():
            require(item["file"] == f"suite-{name}-{phase}.jar"
                    and sha(inside(folder, item["file"]).read_bytes()) == item["sha256"],
                    "Suite JAR original mismatch")
    require({name: item["sha256"] for name, item in start["jars"].items()}
            == {name: item["sha256"] for name, item in end["jars"].items()},
            "Suite JARs changed during campaign")


def embedded_certificate(root: ET.Element) -> bytes:
    node = root.find("{" + DS + "}Signature/{" + DS + "}KeyInfo/{" + DS
                     + "}X509Data/{" + DS + "}X509Certificate")
    require(node is not None and node.text, "root signature certificate missing")
    return base64.b64decode("".join("".join(node.itertext()).split()), validate=True)


def public_key(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)


def independent_signature_results(documents: dict[str, bytes], certificates: dict[str, bytes]) -> None:
    base = REPO / BASE_FOLDER
    helper = base / "source-scoped-helper.java"
    material = json.loads((base / "key-material-manifest.json").read_text())
    require(sha(helper.read_bytes()) == material["helperSha256"], "signature helper binding mismatch")
    with tempfile.TemporaryDirectory(prefix="verify-keycloak-md03-") as temporary:
        temp = Path(temporary)
        source = temp / "SourceScopedMetadata.java"
        source.write_bytes(helper.read_bytes())
        subprocess.run(["javac", "--release", "21", "-d", str(temp), str(source)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)

        def verifies(label: str, document: bytes, certificate: bytes) -> bool:
            xml = temp / (label + ".xml")
            der = temp / (label + ".der")
            marker = temp / (label + ".verified")
            xml.write_bytes(document)
            der.write_bytes(certificate)
            result = subprocess.run(["java", "-cp", str(temp), "SourceScopedMetadata", "verify",
                                     str(xml), str(der), str(marker)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            return result.returncode == 0 and marker.is_file() and marker.read_text() == "verified\n"

        for variant in ("control", "signed-other-key", "certificate-expired",
                        "certificate-not-yet-valid", "certificate-no-digital-signature",
                        "certificate-critical-extension"):
            require(verifies(variant, documents[variant], certificates[variant]),
                    variant + " metadata signature is not independently valid")
        require(not verifies("bad-signature", documents["bad-signature"],
                             certificates["bad-signature"]),
                "bad-signature control unexpectedly verifies")
        require(not verifies("primary-keyinfo-embedded", documents["signed-other-key-primary-keyinfo"],
                             certificates["signed-other-key-primary-keyinfo"]),
                "out-of-band control unexpectedly verifies under embedded KeyInfo")
        require(verifies("primary-keyinfo-out-of-band",
                         documents["signed-other-key-primary-keyinfo"],
                         certificates["signed-other-key"]),
                "out-of-band control does not verify under the separate signer key")


def verify_fixtures(folder: Path, manifest: dict, observations: dict[str, dict]) -> None:
    documents: dict[str, bytes] = {}
    roots: dict[str, ET.Element] = {}
    certificates: dict[str, bytes] = {}
    entity = manifest["suiteEntityId"]
    for variant in VARIANTS:
        item = observations[variant]
        expected = f"{variant}/fixture.xml"
        require(item["fixtureFile"] == expected, "fixture path mismatch")
        raw = inside(folder, expected).read_bytes()
        require(sha(raw) == item["fixtureSha256"], "fixture hash mismatch")
        root = ET.fromstring(raw)
        expected_entity = entity + ("/tampered-after-signing" if variant == "bad-signature" else "")
        require(root.tag == "{" + MD + "}EntityDescriptor" and root.get("entityID") == expected_entity,
                "fixture identity mismatch")
        signatures = root.findall("{" + DS + "}Signature")
        require(len(signatures) == (0 if variant == "unsigned" else 1),
                "root signature inventory mismatch")
        documents[variant] = raw
        roots[variant] = root
        if variant != "unsigned":
            certificates[variant] = embedded_certificate(root)

    require(certificates["signed-other-key"]
            != certificates["signed-other-key-primary-keyinfo"],
            "out-of-band signer/embedded certificate control collapsed")
    independent_signature_results(documents, certificates)

    result = read(folder, "result-after.json")
    started = datetime.fromisoformat(result["run"]["started_at"].replace("Z", "+00:00"))
    parsed = {variant: x509.load_der_x509_certificate(certificates[variant])
              for variant in certificates}
    require(parsed["certificate-expired"].not_valid_after_utc < started
            and parsed["certificate-not-yet-valid"].not_valid_before_utc > started,
            "certificate validity controls are not decisive")
    usage = parsed["certificate-no-digital-signature"].extensions.get_extension_for_oid(
        ExtensionOID.KEY_USAGE).value
    require(usage.digital_signature is False and usage.key_encipherment is True,
            "KeyUsage negative control mismatch")
    extension = parsed["certificate-critical-extension"].extensions.get_extension_for_oid(
        ObjectIdentifier("1.3.6.1.4.1.57264.1.1"))
    require(extension.critical is True, "critical extension control mismatch")
    require(all(public_key(parsed[variant]) for variant in (
        "certificate-expired", "certificate-not-yet-valid",
        "certificate-no-digital-signature", "certificate-critical-extension")),
        "certificate controls lack public keys")


def verify_product_and_protocol(folder: Path, manifest: dict,
                                observations: dict[str, dict]) -> None:
    transcript = read(folder, "transcript-after.json")
    by_id = {item["id"]: item for item in transcript}
    require(len(by_id) == len(transcript)
            and all(item["runId"] == manifest["runId"] for item in transcript),
            "transcript identity mismatch")
    for variant in VARIANTS:
        item = observations[variant]
        imported = read(folder, item["importFile"])
        require(sha(inside(folder, item["importFile"]).read_bytes()) == item["importSha256"]
                and imported["fixture"]["sha256"] == item["fixtureSha256"]
                and imported["fixture"]["entity_id"] == item["entityId"],
                variant + " import original mismatch")
        steps = {row["step"]: row["ok"] for row in imported["steps"]}
        require(steps.get("file-selected") is True
                and steps.get("product-parsed-entity-id") is True
                and steps.get("product-import-signal") is True
                and steps.get("admin-read-back") is True
                and steps.get("cleanup-delete-verified") is True
                and imported["import"]["ui_status"] == "client-settings-page"
                and imported["import"]["read_back"]["client_id"] == item["entityId"]
                and imported["cleanup"] == {"deleted_status": 204, "read_back_absent": True},
                variant + " product import/read-back/restoration mismatch")
        if variant in RUNTIME_REJECTED:
            require(imported["status"] == "failure"
                    and imported["failure_reason"] == "follow-up-flow: command failed",
                    "runtime certificate rejection was misclassified as import failure")
        else:
            require(imported["status"] == "success", variant + " product import failed")

        converter_path = inside(folder, f"{variant}/{item['converter']['file']}")
        require(sha(converter_path.read_bytes()) == item["converter"]["sha256"],
                "converter original hash mismatch")
        converted = json.loads(converter_path.read_text())
        require(converted.get("clientId") == item["entityId"]
                and converted.get("protocol") == item["converter"]["protocol"] == "saml"
                and not any(token in json.dumps(converted).lower()
                            for token in ("trustanchor", "signaturevalidation")),
                "native converter result/configuration mismatch")

        prepared = [row for row in transcript
                    if row["direction"] == "OUTBOUND"
                    and row["samlSummary"].get("type") == "MetadataPrepared"
                    and row["samlSummary"].get("variant") == variant
                    and row["samlSummary"].get("metadataSha256") == item["fixtureSha256"]]
        require(len(prepared) == 1, "fixture is not uniquely correlated to Suite transcript")
        fetch = by_id.get(prepared[0]["correlationId"])
        require(fetch is not None and fetch["direction"] == "INBOUND"
                and fetch["samlSummary"].get("type") == "MetadataFetch"
                and fetch["samlSummary"].get("variant") == variant,
                "metadata fetch/preparation correlation mismatch")

        if variant == "bad-signature":
            require("flowFile" not in item and item["entityId"].endswith("/tampered-after-signing"),
                    "bad-signature control unexpectedly claims protocol success")
            continue
        require(item["nativeImportAccepted"] is True
                and item["runtimeCertificateRejected"] == (variant in RUNTIME_REJECTED)
                and item["correlatedProtocolSuccess"] == (variant not in RUNTIME_REJECTED),
                "protocol classification mismatch")
        flow_path = inside(folder, item["flowFile"])
        require(sha(flow_path.read_bytes()) == item["flowSha256"], "flow original hash mismatch")
        flow = json.loads(flow_path.read_text())
        negative = flow["negative_control"]
        require(flow["run"] == manifest["runId"] and flow["variant"] == variant
                and negative["correlated_success"] is False
                and len(negative["mutations"]) == 1
                and negative["mutations"][0]["original_request_sha256"]
                    != negative["mutations"][0]["mutated_request_sha256"],
                "signed-request negative control mismatch")
        exchange = flow["positive_exchange"]
        ids = exchange["transcript_ids"]
        require(ids and all(value in by_id for value in ids), "protocol transcript reference missing")
        request = by_id[ids[0]]
        require(request["direction"] == "OUTBOUND"
                and request["samlSummary"].get("type") == "AuthnRequest"
                and request["samlSummary"].get("variant") == variant
                and request["samlSummary"].get("id") == exchange["request_id"],
                "protocol request correlation mismatch")
        if variant in RUNTIME_REJECTED:
            require(exchange["success"] is False and flow["correlated_success"] is False
                    and flow["receipt"] == "no-response:Invalid requester" and len(ids) == 1,
                    "runtime certificate rejection evidence mismatch")
        else:
            require(exchange["success"] is True and flow["correlated_success"] is True
                    and exchange["status_codes"] == ["urn:oasis:names:tc:SAML:2.0:status:Success"]
                    and len(ids) == 2, "positive protocol control mismatch")
            response = by_id[ids[1]]
            require(response["direction"] == "INBOUND"
                    and response["samlSummary"].get("type") == "Response"
                    and response["samlSummary"].get("inResponseTo") == exchange["request_id"]
                    and response["samlSummary"].get("metadataProbeAccepted") is True,
                    "positive SAML response correlation mismatch")


def verify_operations(folder: Path, manifest: dict) -> None:
    counts = read(folder, manifest["operationCountsFile"])
    require(manifest["operationCountsFile"] == "operation-counts-md03.json"
            and sha(inside(folder, manifest["operationCountsFile"]).read_bytes())
                == manifest["operationCountsSha256"]
            and counts == {"nativeUiImports": 9, "nativeConverterCalls": 9,
                "productConfigurationWrites": 9, "restorationWrites": 9,
                "protocolRoundTripAttempts": 16, "positiveProtocolRoundTrips": 6,
                "signedRequestNegativeControls": 8, "productRestarts": 0,
                "humanOperations": 0, "restored": True},
            "successful campaign operation inventory mismatch")

    verify_failed_attempts(folder)


def verify_failed_attempts(folder: Path, failed: dict | None = None) -> None:
    failed = copy.deepcopy(read(folder, "failed-attempts.json") if failed is None else failed)
    require(failed["schema"] == "samlscope-keycloak-metadata-signature-failed-attempts-v1"
            and failed["allRestored"] is True and len(failed["attempts"]) == 2
            and failed["totals"] == {"nativeUiImports": 9, "productConfigurationWrites": 8,
                "restorationWrites": 8, "protocolRoundTripAttempts": 16,
                "productRestarts": 0, "humanOperations": 0},
            "failed-attempt operation inventory mismatch")
    for attempt in failed["attempts"]:
        require(attempt["restored"] is True and attempt["productRestarts"] == 0
                and attempt["humanOperations"] == 0, "failed attempt was not restored")
        for item in attempt["imports"]:
            path = repo_file(item["file"])
            record = json.loads(path.read_text())
            require(sha(path.read_bytes()) == item["sha256"]
                    and record["cleanup"].get("read_back_absent") is True
                    and item["restored"] is True,
                    "failed-attempt import original mismatch")
        if "operationsFile" in attempt:
            require(sha(repo_file(attempt["operationsFile"]).read_bytes())
                    == attempt["operationsSha256"], "failed-attempt operations hash mismatch")


def verify_formal(folder: Path, manifest: dict) -> None:
    manifest_sha = sha(inside(folder, "manifest.json").read_bytes())
    note = ("Machine-verified Keycloak 26.7.2 native metadata signature capability absence; "
            "manifest sha256=" + manifest_sha
            + "; valid/unsigned/bad/wrong-key/certificate variants were imported and restored")
    for case in CASES:
        configured = read(folder, case + "-configure.json")
        outcome = configured["outcome"]
        require(configured["runId"] == manifest["runId"] and configured["caseId"] == case
                and configured["status"] == "FINISHED"
                and outcome["outcome"] == "VIOLATED" and outcome["reasonCode"] == "capability_absent"
                and outcome["details"] == {"configuration_issue": "capability_absent",
                                            "configuration_note": note}
                and outcome["evidence"] == [], "formal configuration conclusion mismatch")
    result = read(folder, "result-after.json")
    require(result["run"]["id"] == manifest["runId"], "formal result Run mismatch")
    cases = case_map(result)
    for case in CASES:
        item = cases[case]
        require((item["outcome"], item["verdict"], item["mode"], item["reason_code"],
                 item["attested"], item["evidence_class"], item["evidence"]) ==
                ("VIOLATED", "FAIL", "CONFIG", "capability_absent", False,
                 "OPERATOR_ASSISTED", []), "formal product verdict mismatch")


def verify(folder: Path, manifest: dict | None = None, *, formal: bool = True) -> None:
    raw = inside(folder, "manifest.json").read_bytes()
    require(raw == canonical(json.loads(raw)), "manifest is not canonical")
    manifest = copy.deepcopy(json.loads(raw) if manifest is None else manifest)
    verify_approved_definitions()
    observations = verify_identity(folder, manifest)
    verify_base_runtime(manifest)
    verify_target_runtime(folder)
    verify_suite(folder, manifest)
    verify_operations(folder, manifest)
    verify_fixtures(folder, manifest, observations)
    verify_product_and_protocol(folder, manifest, observations)
    if formal:
        verify_formal(folder, manifest)


def tamper(folder: Path) -> list[str]:
    original = read(folder, "manifest.json")
    rejected: list[str] = []

    def reject(label, mutate):
        value = copy.deepcopy(original)
        mutate(value)
        try:
            verify(folder, value, formal=False)
        except (ValueError, KeyError, TypeError, ET.ParseError, json.JSONDecodeError,
                subprocess.CalledProcessError):
            rejected.append(label)
        else:
            raise AssertionError("tamper control accepted: " + label)

    reject("case-set", lambda value: value["cases"].pop())
    reject("base-receipt", lambda value: value.__setitem__("baseRuntimeReceiptSha256", "0" * 64))
    reject("suite-runner", lambda value: value["suiteRuntimeStart"]["jars"]["runner"].__setitem__("sha256", "0" * 64))
    reject("operation-counts", lambda value: value.__setitem__("operationCountsSha256", "0" * 64))
    reject("missing-bad-signature", lambda value: value["observations"].pop())
    reject("fixture-hash", lambda value: value["observations"][0].__setitem__("fixtureSha256", "0" * 64))
    reject("bad-fixture-substitution", lambda value: value["observations"][-1].update({
        "fixtureFile": "control/fixture.xml", "fixtureSha256": value["observations"][0]["fixtureSha256"]}))
    reject("out-of-band-substitution", lambda value: value["observations"][3].update({
        "fixtureFile": "signed-other-key/fixture.xml",
        "fixtureSha256": value["observations"][2]["fixtureSha256"]}))
    reject("expired-substitution", lambda value: value["observations"][4].update({
        "fixtureFile": "control/fixture.xml", "fixtureSha256": value["observations"][0]["fixtureSha256"]}))
    reject("converter-reference", lambda value: value["observations"][0]["converter"].__setitem__("file", "../manifest.json"))
    reject("import-reference", lambda value: value["observations"][0].__setitem__("importFile", "manifest.json"))
    reject("flow-reference", lambda value: value["observations"][0].__setitem__("flowFile", "manifest.json"))
    reject("runtime-rejection-as-success", lambda value: value["observations"][4].__setitem__("correlatedProtocolSuccess", True))
    reject("control-as-rejected", lambda value: value["observations"][0].__setitem__("correlatedProtocolSuccess", False))
    failed = read(folder, "failed-attempts.json")
    failed["allRestored"] = False
    try:
        verify_failed_attempts(folder, failed)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        rejected.insert(4, "failed-attempts")
    else:
        raise AssertionError("tamper control accepted: failed-attempts")
    require(len(rejected) == 15, "tamper rejection inventory mismatch")
    return rejected


@lru_cache(maxsize=None)
def verify_adoption(root: Path | str):
    folder = Path(root).resolve()
    if folder.name != FOLDER:
        folder = folder / FOLDER
    verify(folder)
    rejected = tamper(folder)
    require(rejected == [
        "case-set", "base-receipt", "suite-runner", "operation-counts", "failed-attempts",
        "missing-bad-signature", "fixture-hash", "bad-fixture-substitution",
        "out-of-band-substitution", "expired-substitution", "converter-reference",
        "import-reference", "flow-reference", "runtime-rejection-as-success", "control-as-rejected",
    ], "tamper rejection inventory mismatch")
    result_path = folder / "result-after.json"
    cases = case_map(json.loads(result_path.read_text()))
    return result_path, {case: cases[case] for case in CASES}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--tamper", action="store_true")
    args = parser.parse_args()
    folder = args.folder.resolve()
    verify(folder)
    rejected = tamper(folder) if args.tamper else []
    report = {"schema": "samlscope-keycloak-metadata-signature-capability-acceptance-v1",
              "folder": folder.name, "verified": True, "adoptedCases": list(CASES),
              "tamperControlsRejected": rejected, "formalReduction": 3}
    (folder / "acceptance-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(folder.name, "verified;", len(rejected), "tamper controls rejected")


if __name__ == "__main__":
    main()
