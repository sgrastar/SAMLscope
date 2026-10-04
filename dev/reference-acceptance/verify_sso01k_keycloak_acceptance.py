#!/usr/bin/env python3
"""Fail-closed adoption gate for Keycloak IIP-SSO01.k using the sealed EXT01.b Run.

The gate is deliberately read-only.  It accepts only the already captured
``ext01b-keycloak-v158/browser_sso_idp`` evidence and never contacts or changes the
reference product.  Encrypted assertion plaintext is not exported: the gate binds the
five signed wire originals to the formal result produced by the pinned Suite runtime
whose decryption and SSO01.k oracle classes are themselves pinned below.
"""

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
import zlib
from contextlib import contextmanager
from datetime import datetime
from functools import lru_cache
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from verify_ext01b_acceptance import ACCEPTED_SUITE_BY_PRODUCT, TARGET_IMAGES
from verify_terminal_http_acceptance import (
    EVALUATION,
    PRODUCT,
    _verify_configuration_restoration,
    _verify_suite_runtime,
    _verify_target_runtime,
    find_case,
)


CASE = "IIP-SSO01-k-idp-01"
OBLIGATION = "IIP-SSO01.k"
PROFILE = "browser_sso_idp"
PRODUCT_NAME = "keycloak"
EXPECTED_RUN = "run_3MZXNDWFZ62FNETRN75P79TVPT"
EXPECTED_PLAN = "plan_3HV35T28M9KGZKJBMGG5XAM2B5"
EXPECTED_CASE_DIGEST = "sha256:b3d72294149fa3bc17632c04bd34b3ff502fceaf69cfcaf4a39dcfda902657d0"
EXPECTED_OBLIGATION_DIGEST = "sha256:491b46eb762827f12f4180787e05665f22ed7ad7d28be844b619c2e02d5429e0"
EXPECTED_EVIDENCE = (
    "tx_95RBJVT8EB5JBRDYVC3EWZAAZ1",
    "tx_NYZCGT8CXW9Y4YM1FBXQZYS3R9",
    "tx_KAKKBJ4Z9N30JNYM1RX1V0EJEJ",
    "tx_18QQXV54F4VCD7MMFMCBZYMGQ6",
    "tx_73BYQ8XWGKY3CBWB7S5PM48YD0",
)
NORMAL_FLOW_RESPONSE = EXPECTED_EVIDENCE[0]
CORRELATED_FIXTURES = {
    EXPECTED_EVIDENCE[1]: ("IIP-IDP05-a-idp-01", "baseline-success", 0),
    EXPECTED_EVIDENCE[2]: ("IIP-IDP05-a-idp-01", "unsatisfiable-authn-context", 0),
    EXPECTED_EVIDENCE[3]: ("IIP-ALG01-a-idp-01", "valid", 0),
    EXPECTED_EVIDENCE[4]: ("IIP-ALG01-a-idp-01", "tampered-acs", 1),
}
EXPECTED_TAMPER_REJECTIONS = (
    "formal-verdict",
    "formal-reason",
    "five-evidence-set",
    "run-correlation",
    "normal-flow-control",
    "alternate-acs-control",
    "xml-correlation",
    "encrypted-assertion",
    "signed-ciphertext",
    "runtime-pin",
    "complete-restoration",
    "restoration-readback",
    "decryption-observation",
)
EXPECTED_ORACLE_CLASSES = {
    "com/samlscope/runner/cases/NormalFlowBrowserObservation.class": (
        "675dd75dba3738e978e74546abf71bc9e71b0ffe228a02f8de8c9ea5b8c12040",
        (
            b"IIP-SSO01-k-idp-01",
            b"browser.normal-flow.bearer-recipient-and-expiry-valid",
            b"browser.normal-flow.bearer-recipient-mismatch",
            b"browser.normal-flow.bearer-expiry-missing-or-not-later",
            b"distinct_acs_destinations",
            b"bearer_confirmations",
            b"EncryptedAssertion",
        ),
    ),
    "com/samlscope/runner/cases/AutoBrowserEvidenceTestCase.class": (
        "fbe60e2f5081a1328994bca7c7625e32fe83f7c7386008a703d1f83563d1051e",
        (b"EncryptedAssertion", b"SamlXmlDecrypter", b"normalFlowAccepted"),
    ),
}

P = "{urn:oasis:names:tc:SAML:2.0:protocol}"
A = "{urn:oasis:names:tc:SAML:2.0:assertion}"
DS = "{http://www.w3.org/2000/09/xmldsig#}"
X = "{http://www.w3.org/2001/04/xmlenc#}"
X11 = "{http://www.w3.org/2009/xmlenc11#}"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
AES256_GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
RSA_OAEP11 = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
MGF1_SHA256 = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
TX_RE = re.compile(r"tx_[0-9A-HJKMNP-TV-Z]{26}")


def require(value, detail):
    if not value:
        raise ValueError(detail)


def read(path):
    return json.loads(Path(path).read_text())


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def one(values, detail):
    values = list(values)
    require(len(values) == 1, detail)
    return values[0]


def direct(parent, tag):
    return [child for child in list(parent) if child.tag == tag]


def safe_xml(raw):
    upper = raw.upper()
    require(b"<!DOCTYPE" not in upper and b"<!ENTITY" not in upper,
            "DTD/entity in Recorder XML original")
    return ET.fromstring(raw)


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def verify_redirect_request(folder, entry, request_raw):
    raw_query = entry.get("rawQuery")
    require(entry.get("method") == "GET" and isinstance(raw_query, str),
            "normal-flow AuthnRequest lacks a raw Redirect query")
    pieces = raw_query.split("&")
    require(len(pieces) == 4
            and pieces[0].startswith("SAMLRequest=")
            and pieces[1].startswith("RelayState=")
            and pieces[2].startswith("SigAlg=")
            and pieces[3].startswith("Signature="),
            "Redirect signature input order/cardinality changed")
    saml_request = urllib.parse.unquote_to_bytes(pieces[0].split("=", 1)[1])
    inflated = zlib.decompress(base64.b64decode(saml_request), -15)
    require(inflated == request_raw, "raw Redirect SAMLRequest does not match Recorder XML original")
    sig_alg = urllib.parse.unquote(pieces[2].split("=", 1)[1])
    require(sig_alg == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "normal-flow Redirect request does not use RSA-SHA256")
    signature = base64.b64decode(urllib.parse.unquote_to_bytes(pieces[3].split("=", 1)[1]))

    metadata = safe_xml((folder / "suite-sp-metadata.xml").read_bytes())
    certificates = metadata.findall(
        ".//{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor/"
        "{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor[@use='signing']"
        "/{http://www.w3.org/2000/09/xmldsig#}KeyInfo/"
        "{http://www.w3.org/2000/09/xmldsig#}X509Data/"
        "{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
    encoded = {"".join(value.text.split()) for value in certificates}
    require(len(encoded) == 1, "Suite metadata must contain one SP signing certificate")
    certificate = x509.load_der_x509_certificate(base64.b64decode(encoded.pop()))
    try:
        certificate.public_key().verify(
            signature, "&".join(pieces[:3]).encode(), padding.PKCS1v15(), hashes.SHA256())
    except Exception as error:
        raise ValueError("normal-flow Redirect request signature is invalid") from error
    return sha(certificate.public_bytes(serialization.Encoding.DER))


def verify_approved_definition(repo):
    catalog = yaml.safe_load((repo / "tests/cases.yaml").read_text())
    case = one((value for value in catalog.get("cases", []) if value.get("id") == CASE),
               "approved case definition must occur exactly once")
    canonical_case = {name: value for name, value in case.items()
                      if name not in ("case_digest", "review")}
    computed_case_digest = "sha256:" + sha(json.dumps(
        canonical_case, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode())
    require(case.get("obligation") == OBLIGATION
            and case.get("obligation_digest") == EXPECTED_OBLIGATION_DIGEST
            and case.get("case_digest") == EXPECTED_CASE_DIGEST
            and computed_case_digest == EXPECTED_CASE_DIGEST
            and case.get("role") == "idp" and case.get("mode") == "BROWSER"
            and case.get("baseline") == "idp-core-no-ecp",
            "approved SSO01.k case identity changed")
    variants = (
        "IIP-SSO01.k#v-0623be5814",
        "IIP-SSO01.k#v-3c2ce78583",
        "IIP-SSO01.k#v-ef4635cfc0",
        "IIP-SSO01.k#v-fb00db5594",
    )
    require(tuple(case.get("covers_variants") or ()) == variants,
            "approved SSO01.k variant set/order changed")
    plan = case.get("variant_plan") or []
    require(tuple(value.get("reference") for value in plan) == variants
            and all(value.get("applicability") == "owner_condition"
                    and value.get("treatment") == "verdict" for value in plan),
            "approved SSO01.k variant plan changed")
    instructions = tuple(value.get("instruction_en") for value in plan)
    require(instructions == (
        "Recipient exactly matches the ACS URL to which the <Response> was actually delivered.",
        "NotOnOrAfter is present and is later than the response time.",
        "In the variant that switches the ACS, Recipient follows the selected ACS and is not fixed to a default value.",
        "The Address attribute MAY be present or absent. Do not mark this as FAIL.",
    ), "approved SSO01.k instructions changed")
    groups = case.get("variant_groups") or []
    require(len(groups) == 1 and groups[0].get("id") == "default-all-of"
            and groups[0].get("kind") == "all_of"
            and tuple(groups[0].get("members") or ()) == variants,
            "approved SSO01.k all-of group changed")
    controls = case.get("controls") or []
    require([(value.get("id"), value.get("kind"), value.get("fixture"), value.get("on_failure"))
             for value in controls] == [
                 ("iip-sso01-k-idp-01-positive", "positive", "idp-core-no-ecp", "control_failed"),
                 ("iip-sso01-k-idp-01-negative", "negative", "mut-iip-sso01-k-idp", "control_failed"),
             ] and case.get("detected_by_mutants") == ["mut-iip-sso01-k-idp"],
            "approved SSO01.k positive/negative controls changed")
    constraints = case.get("interpretation_constraints") or []
    require(len(constraints) == 2
            and "two ACS endpoints" in constraints[0]
            and "relative size" in constraints[1],
            "approved SSO01.k interpretation constraints changed")

    approval_record = yaml.safe_load((repo / "tests/approvals/g2.yaml").read_text())
    approval = one((value for value in approval_record.get("approvals", [])
                    if value.get("case") == CASE),
                   "canonical G2 approval must occur exactly once")
    require(approval.get("case_digest") == EXPECTED_CASE_DIGEST
            and approval.get("reviewer") and approval.get("approved_at"),
            "canonical G2 approval is missing or does not match")
    return case


def decoded_originals(folder, transcript):
    by_id = {entry.get("id"): entry for entry in transcript}
    require(len(by_id) == len(transcript) and None not in by_id,
            "duplicate/missing transcript identity")
    originals = {}
    rows = read(folder / "decoded-manifest.json")
    for row in rows:
        entry_id = row.get("id")
        require(TX_RE.fullmatch(entry_id or "") and entry_id in by_id
                and entry_id not in originals,
                "invalid decoded-original identity")
        require(row.get("file") == f"decoded/{entry_id}.xml",
                "decoded original has unexpected path")
        path = folder / row["file"]
        raw = path.read_bytes()
        require(path.resolve().is_relative_to((folder / "decoded").resolve()),
                "decoded original escaped evidence directory")
        require(row.get("sha256") == sha(raw)
                and by_id[entry_id].get("decodedSamlBytes") == len(raw),
                "decoded original hash/length mismatch")
        originals[entry_id] = (path, raw)
    return by_id, originals


def verify_oracle_runtime(folder):
    runtime = read(folder / "suite-runtime-terminal-http.json")
    runner_path = folder / runtime["jars"]["runner"]["file"]
    with zipfile.ZipFile(runner_path) as archive:
        for name, (expected_hash, needles) in EXPECTED_ORACLE_CLASSES.items():
            raw = archive.read(name)
            require(sha(raw) == expected_hash and all(needle in raw for needle in needles),
                    "pinned Suite lacks the approved encrypted-assertion SSO01.k oracle: " + name)


@contextmanager
def compiled_signature_verifier():
    source = Path(__file__).with_name("VerifySso01kResponseSignatures.java")
    with tempfile.TemporaryDirectory(prefix="sso01k-signatures-") as temporary:
        subprocess.run(["javac", "-d", temporary, str(source)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        yield Path(temporary)


def verify_response_signatures(folder, paths, classes):
    command = ["java", "-cp", str(classes), "VerifySso01kResponseSignatures", "--responses",
               str(folder / "target-metadata.xml"), *(str(path) for path in paths)]
    try:
        completed = subprocess.run(command, check=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as error:
        raise ValueError("independent Response signature verification failed") from error
    result = json.loads(completed.stdout)
    require(result.get("entityId") == PRODUCT[PRODUCT_NAME]["target_entity"]
            and result.get("responses") == len(paths)
            and re.fullmatch(r"[0-9a-f]{64}", result.get("certificateSha256", "")),
            "unexpected Response signature verification result")
    return result


def verify_folder(folder, repo=None, signature_classes=None):
    folder = Path(folder).resolve()
    repo = Path(repo or Path(__file__).resolve().parents[2]).resolve()
    approved = verify_approved_definition(repo)

    plan = read(folder / "plan.json")["plan"]
    created = read(folder / "created.json")["run"]
    require(plan["plan"]["id"] == EXPECTED_PLAN
            and plan["plan"]["profile"] == PROFILE
            and plan["plan"]["target"] == {
                "kind": "IDP", "entityId": PRODUCT[PRODUCT_NAME]["target_entity"],
                "connectionId": None, "metadataRevisionId": None}
            and plan["plan"]["requestSigningMode"] == "REQUIRED",
            "wrong Plan/profile/target")
    require(created.get("id") == EXPECTED_RUN and created.get("planId") == EXPECTED_PLAN,
            "wrong sealed Run/Plan binding")
    run_created_at = float(created["createdAt"])

    pins = ACCEPTED_SUITE_BY_PRODUCT[PRODUCT_NAME]
    _verify_target_runtime(folder, PRODUCT_NAME, run_created_at)
    require(read(folder / "target-runtime-start.json")["binding"]["image_id"]
            == TARGET_IMAGES[PRODUCT_NAME], "untrusted Keycloak image")
    _verify_suite_runtime(folder, EXPECTED_RUN, run_created_at, pins)
    verify_oracle_runtime(folder)
    counts = _verify_configuration_restoration(folder, PRODUCT_NAME)

    result_path = folder / EVALUATION / "result.json"
    result = read(result_path)
    original_result = read(folder / "result.json")
    require(result.get("run", {}).get("id") == EXPECTED_RUN
            and original_result.get("run", {}).get("id") == EXPECTED_RUN,
            "formal result is not bound to the sealed Run")
    require(result.get("suite", {}).get("image_digest") == pins["image_id"]
            and original_result.get("suite", {}).get("image_digest") == pins["image_id"],
            "formal result is not bound to the pinned Suite")
    target_metadata_raw = (folder / "target-metadata.xml").read_bytes()
    expected_metadata_digest = "sha256:" + sha(target_metadata_raw)
    require(result.get("target", {}).get("metadata_digest") == expected_metadata_digest
            and original_result.get("target", {}).get("metadata_digest") == expected_metadata_digest,
            "formal result is not bound to the target metadata original")
    case = find_case(result, CASE)
    original_case = find_case(original_result, CASE)
    require(case == original_case, "initial and formal SSO01.k result disagree")
    require((case.get("obligation"), case.get("outcome"), case.get("verdict"),
             case.get("reason_code"), case.get("attested"), case.get("evidence_class")) == (
                OBLIGATION, "SATISFIED", "PASS",
                "browser.normal-flow.bearer-recipient-and-expiry-valid", False,
                "PROTOCOL_OBSERVED"),
            "formal SSO01.k result is not an un-attested protocol PASS")
    evidence = case.get("evidence") or []
    require(tuple(value.get("reference", "").removeprefix("transcript:") for value in evidence)
            == EXPECTED_EVIDENCE
            and all(value.get("kind") == "transcript"
                    and value.get("reference", "").startswith("transcript:tx_") for value in evidence),
            "formal SSO01.k result does not bind the exact five evidence references")

    transcript = read(folder / "transcript.json")
    require(transcript == read(folder / EVALUATION / "transcript-before.json")
            == read(folder / EVALUATION / "transcript.json"),
            "formal re-evaluation transcript differs from Recorder evidence")
    require(all(entry.get("runId") == EXPECTED_RUN for entry in transcript),
            "transcript contains an entry from another Run")
    by_id, originals = decoded_originals(folder, transcript)
    acs = tuple(read(folder / "native-configuration.json").get("registered_acs") or ())
    require(acs == (
        f"http://localhost:18080/p/{EXPECTED_PLAN}/sp/acs/0",
        f"http://localhost:18080/p/{EXPECTED_PLAN}/sp/acs/1",
    ), "native read-back does not bind ACS /0 and /1")

    request_by_id = {}
    for entry in transcript:
        if entry.get("direction") != "OUTBOUND" or entry.get("id") not in originals:
            continue
        root = safe_xml(originals[entry["id"]][1])
        if root.tag == P + "AuthnRequest":
            request_id = root.get("ID")
            require(request_id and request_id not in request_by_id,
                    "duplicate/missing AuthnRequest ID")
            request_by_id[request_id] = (entry, root, originals[entry["id"]][0])

    response_paths = []
    request_signatures = []
    destinations = []
    encrypted = 0
    correlated = 0
    normal = 0
    redirect_certificate = None
    for response_id in EXPECTED_EVIDENCE:
        entry = by_id.get(response_id)
        require(entry is not None and entry.get("direction") == "INBOUND"
                and entry.get("method") == "POST" and entry.get("status") == 200,
                "evidence is not a successful inbound POST")
        path, raw = originals.get(response_id, (None, None))
        require(path is not None, "evidence lacks a decoded Recorder original")
        root = safe_xml(raw)
        require(root.tag == P + "Response" and root.get("ID") == entry.get("samlSummary", {}).get("id")
                and root.get("InResponseTo") == entry.get("correlationId")
                and root.get("Destination") == entry.get("url")
                and root.get("Destination") in acs,
                "Response XML/Transcript correlation mismatch")
        require(abs(parse_time(root.get("IssueInstant")) - float(entry["timestamp"])) < 60,
                "Response timestamp is not correlated to its Recorder entry")
        issuer = one(direct(root, A + "Issuer"), "Response must contain one direct Issuer")
        status = one(direct(root, P + "Status"), "Response must contain one Status")
        status_code = one(direct(status, P + "StatusCode"), "Response must contain one StatusCode")
        require(issuer.text == PRODUCT[PRODUCT_NAME]["target_entity"]
                and status_code.get("Value") == SUCCESS
                and entry.get("samlSummary", {}).get("statusCode") == SUCCESS,
                "evidence is not a successful target-issued Response")
        wrappers = direct(root, A + "EncryptedAssertion")
        require(len(wrappers) == 1 and not direct(root, A + "Assertion"),
                "each SSO01.k evidence Response must contain one encrypted and no plaintext Assertion")
        data = one(direct(wrappers[0], X + "EncryptedData"),
                   "EncryptedAssertion must contain one EncryptedData")
        data_method = one(direct(data, X + "EncryptionMethod"),
                          "EncryptedData must contain one EncryptionMethod")
        keys = data.findall(".//" + X + "EncryptedKey")
        require(len(keys) == 1, "EncryptedAssertion must contain one EncryptedKey")
        key_method = one(direct(keys[0], X + "EncryptionMethod"),
                         "EncryptedKey must contain one EncryptionMethod")
        digest = one(direct(key_method, DS + "DigestMethod"),
                     "RSA-OAEP11 evidence must state one DigestMethod")
        mgf = one(direct(key_method, X11 + "MGF"),
                  "RSA-OAEP11 evidence must state one MGF")
        require((data_method.get("Algorithm"), key_method.get("Algorithm"),
                 digest.get("Algorithm"), mgf.get("Algorithm")) == (
                    AES256_GCM, RSA_OAEP11, SHA256, MGF1_SHA256),
                "unexpected encrypted Assertion algorithm tuple")
        encrypted += 1
        destinations.append(root.get("Destination"))
        response_paths.append(path)

        if response_id == NORMAL_FLOW_RESPONSE:
            summary = entry.get("samlSummary", {})
            request_entry, request, request_path = request_by_id.get(
                root.get("InResponseTo"), (None, None, None))
            require(summary.get("normalFlowAccepted") is True
                    and summary.get("activeProbeAccepted") is None
                    and root.get("Destination") == acs[0]
                    and root.get("InResponseTo", "").startswith("_saml_")
                    and request_entry is not None
                    and request_entry.get("timestamp") <= entry.get("timestamp")
                    and request_entry.get("correlationId") == request.get("ID")
                    and request.get("AssertionConsumerServiceURL") == acs[0]
                    and request.get("ProtocolBinding") == POST
                    and request.get("Destination") == PRODUCT[PRODUCT_NAME]["sso"]
                    and one(direct(request, A + "Issuer"),
                            "normal-flow request must have one Issuer").text == plan["entityId"],
                    "normal-flow positive control is missing or misclassified")
            redirect_certificate = verify_redirect_request(
                folder, request_entry, originals[request_entry["id"]][1])
            normal += 1
            continue

        expected_case, expected_fixture, expected_index = CORRELATED_FIXTURES[response_id]
        request_entry, request, request_path = request_by_id.get(root.get("InResponseTo"), (None, None, None))
        require(request_entry is not None and request_entry.get("timestamp") <= entry.get("timestamp")
                and request.get("AssertionConsumerServiceURL") == acs[expected_index]
                and request.get("ProtocolBinding") == POST
                and request.get("Destination") == PRODUCT[PRODUCT_NAME]["sso"]
                and one(direct(request, A + "Issuer"),
                        "active request must have one Issuer").text == plan["entityId"]
                and root.get("Destination") == acs[expected_index],
                "request/Response XML and ACS correlation mismatch")
        summary = request_entry.get("samlSummary", {})
        require(summary.get("scenario_case_id") == expected_case
                and summary.get("fixture_id") == expected_fixture
                and "_" + summary.get("action_id", "") == request.get("ID")
                and request_entry.get("correlationId") == summary.get("action_id"),
                "response is not correlated to the expected approved control fixture")
        request_signatures.append((request_path, response_id != EXPECTED_EVIDENCE[-1]))
        correlated += 1

    require((normal, correlated, encrypted) == (1, 4, 5)
            and destinations.count(acs[0]) == 4 and destinations.count(acs[1]) == 1,
            "normal flow, five encrypted Assertions, and ACS /0-/1 control are incomplete")

    protocol = read(folder / "protocol-evidence")
    alg = one((value for value in protocol.get("cases", [])
               if value.get("caseId") == "IIP-ALG04-a-idp-01"),
              "decryption capability observation missing")
    details = alg.get("details", {})
    require(details.get("decrypted_assertions") == details.get("encrypted_assertions_observed") == 17
            and details.get("observed_content_algorithms") == ["aes256-gcm"]
            and details.get("observed_key_transport_algorithms") == ["rsa-oaep"],
            "pinned Suite did not record successful decryption of this Run's encrypted Assertions")

    own_classes = signature_classes is None
    if own_classes:
        manager = compiled_signature_verifier()
        signature_classes = manager.__enter__()
    try:
        signatures = verify_response_signatures(folder, response_paths, signature_classes)
        command = ["java", "-cp", str(signature_classes),
                   "VerifySso01kResponseSignatures", "--requests",
                   str(folder / "suite-sp-metadata.xml")]
        for path, expected_valid in request_signatures:
            command.extend([str(expected_valid).lower(), str(path)])
        request_result = json.loads(subprocess.run(
            command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True).stdout)
        require(request_result == {"valid": 3, "invalid": 1},
                "unexpected active-control AuthnRequest signature matrix")
    except subprocess.CalledProcessError as error:
        raise ValueError("independent AuthnRequest signature verification failed") from error
    finally:
        if own_classes:
            manager.__exit__(None, None, None)

    return {
        "schema": "samlscope-sso01k-keycloak-acceptance-v1",
        "product": PRODUCT_NAME,
        "profile": PROFILE,
        "case": CASE,
        "approved_case_digest": approved["case_digest"],
        "run": EXPECTED_RUN,
        "plan": EXPECTED_PLAN,
        "verdict": "PASS",
        "reason_code": case["reason_code"],
        "evidence": list(EXPECTED_EVIDENCE),
        "normal_flow_responses": normal,
        "correlated_request_responses": correlated,
        "encrypted_assertions": encrypted,
        "acs_destinations": list(dict.fromkeys(destinations)),
        "signed_responses": signatures["responses"],
        "signed_redirect_requests": 1 if redirect_certificate else 0,
        "valid_signed_post_requests": request_result["valid"],
        "intentionally_invalid_signed_post_requests": request_result["invalid"],
        "suite_image": pins["image_id"],
        "target_image": TARGET_IMAGES[PRODUCT_NAME],
        "configuration_restored": counts["restored"],
        "human_operations": counts["human_operations"],
        "verdict_adopted": False,
    }


def tamper_self_test(folder, repo=None, signature_classes=None):
    folder = Path(folder).resolve()
    repo = Path(repo or Path(__file__).resolve().parents[2]).resolve()

    def rejected(label, mutate):
        with tempfile.TemporaryDirectory(prefix="sso01k-tamper-") as temporary:
            trial = Path(temporary) / "evidence"
            shutil.copytree(folder, trial)
            mutate(trial)
            try:
                verify_folder(trial, repo, signature_classes)
            except (ValueError, KeyError, FileNotFoundError, ET.ParseError,
                    zipfile.BadZipFile, json.JSONDecodeError, yaml.YAMLError):
                return label
            raise AssertionError("tamper was accepted: " + label)

    def write_json(path, value):
        path.write_text(json.dumps(value, indent=2) + "\n")

    def update_all_transcripts(trial, mutate):
        for path in (trial / "transcript.json", trial / EVALUATION / "transcript-before.json",
                     trial / EVALUATION / "transcript.json"):
            value = read(path)
            mutate(value)
            write_json(path, value)

    def update_xml(trial, entry_id, mutate):
        manifest_path = trial / "decoded-manifest.json"
        manifest = read(manifest_path)
        row = one((value for value in manifest if value.get("id") == entry_id),
                  "tamper target missing")
        path = trial / row["file"]
        raw = mutate(path.read_bytes())
        path.write_bytes(raw)
        row["sha256"] = sha(raw)
        write_json(manifest_path, manifest)

    def formal_verdict(trial):
        path = trial / EVALUATION / "result.json"
        value = read(path)
        find_case(value, CASE)["verdict"] = "NOT_VERIFIED"
        write_json(path, value)

    def formal_reason(trial):
        for path in (trial / "result.json", trial / EVALUATION / "result.json"):
            value = read(path)
            find_case(value, CASE)["reason_code"] = "tampered"
            write_json(path, value)

    def evidence_count(trial):
        for path in (trial / "result.json", trial / EVALUATION / "result.json"):
            value = read(path)
            find_case(value, CASE)["evidence"].pop()
            write_json(path, value)

    def cross_run(trial):
        def mutate(entries):
            next(value for value in entries if value["id"] == EXPECTED_EVIDENCE[0])["runId"] = (
                "run_00000000000000000000000000")
        update_all_transcripts(trial, mutate)

    def normal_flow(trial):
        def mutate(entries):
            next(value for value in entries if value["id"] == NORMAL_FLOW_RESPONSE)[
                "samlSummary"]["normalFlowAccepted"] = False
        update_all_transcripts(trial, mutate)

    def alternate_acs(trial):
        def mutate(entries):
            next(value for value in entries if value["id"] == EXPECTED_EVIDENCE[-1])["url"] = (
                f"http://localhost:18080/p/{EXPECTED_PLAN}/sp/acs/0")
        update_all_transcripts(trial, mutate)

    def xml_correlation(trial):
        update_xml(trial, EXPECTED_EVIDENCE[1],
                   lambda raw: raw.replace(b"_action_48ccee040bf8a4195a4f3ba446869210",
                                           b"_action_48ccee040bf8a4195a4f3ba446869211", 1))

    def encrypted_wrapper(trial):
        def mutate(raw):
            require(raw.count(b"EncryptedAssertion") == 2, "tamper wrapper count changed")
            return raw.replace(b"EncryptedAssertion", b"EncryptedAssertiox")
        update_xml(trial, EXPECTED_EVIDENCE[2], mutate)

    def signed_ciphertext(trial):
        def mutate(raw):
            marker = b"<xenc:CipherValue>"
            start = raw.index(marker) + len(marker)
            replacement = b"A" if raw[start:start + 1] != b"A" else b"B"
            return raw[:start] + replacement + raw[start + 1:]
        update_xml(trial, EXPECTED_EVIDENCE[3], mutate)

    def runtime_pin(trial):
        path = trial / "suite-runtime-terminal-http.json"
        value = read(path)
        value["container"]["image_id"] = "sha256:" + "0" * 64
        write_json(path, value)

    def restoration(trial):
        path = trial / "restoration.json"
        value = read(path)
        value["restored"] = False
        write_json(path, value)

    def restoration_readback(trial):
        path = trial / "main-client-restored-readback.json"
        value = read(path)
        value["clientId"] += "-tampered"
        write_json(path, value)

    def decryption_observation(trial):
        path = trial / "protocol-evidence"
        value = read(path)
        case = next(item for item in value["cases"] if item["caseId"] == "IIP-ALG04-a-idp-01")
        case["details"]["decrypted_assertions"] = 0
        write_json(path, value)

    mutations = (
        ("formal-verdict", formal_verdict),
        ("formal-reason", formal_reason),
        ("five-evidence-set", evidence_count),
        ("run-correlation", cross_run),
        ("normal-flow-control", normal_flow),
        ("alternate-acs-control", alternate_acs),
        ("xml-correlation", xml_correlation),
        ("encrypted-assertion", encrypted_wrapper),
        ("signed-ciphertext", signed_ciphertext),
        ("runtime-pin", runtime_pin),
        ("complete-restoration", restoration),
        ("restoration-readback", restoration_readback),
        ("decryption-observation", decryption_observation),
    )
    rejected_labels = [rejected(label, mutate) for label, mutate in mutations]
    require(tuple(rejected_labels) == EXPECTED_TAMPER_REJECTIONS,
            "tamper rejection inventory mismatch")
    return rejected_labels


def verify(root):
    root = Path(root).resolve()
    folder = root / "browser_sso_idp" if root.name == "ext01b-keycloak-v158" else root
    with compiled_signature_verifier() as classes:
        return verify_folder(folder, signature_classes=classes)


@lru_cache(maxsize=None)
def verify_adoption(root: Path | str):
    """Replay the complete gate and all tamper controls once for ledger adoption."""
    root = Path(root).resolve()
    folder = root / "browser_sso_idp" if root.name == "ext01b-keycloak-v158" else root
    with compiled_signature_verifier() as classes:
        accepted = verify_folder(folder, signature_classes=classes)
        rejected = tamper_self_test(folder, signature_classes=classes)
    require(tuple(rejected) == EXPECTED_TAMPER_REJECTIONS,
            "adoption tamper rejection inventory mismatch")

    result_path = folder / EVALUATION / "result.json"
    result = read(result_path)
    case = find_case(result, CASE)
    evidence = tuple(value.get("reference", "").removeprefix("transcript:")
                     for value in case.get("evidence", []))
    require(accepted.get("verdict_adopted") is False
            and result.get("run", {}).get("id") == accepted.get("run")
            and case.get("verdict") == accepted.get("verdict")
            and case.get("reason_code") == accepted.get("reason_code")
            and evidence == tuple(accepted.get("evidence", [])),
            "accepted gate/formal result binding mismatch")
    return result_path, {CASE: case}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--tamper-self-test", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    folder = root / "browser_sso_idp" if root.name == "ext01b-keycloak-v158" else root
    with compiled_signature_verifier() as classes:
        result = verify_folder(folder, signature_classes=classes)
        if args.tamper_self_test:
            result["tamper_rejected"] = tamper_self_test(folder, signature_classes=classes)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
