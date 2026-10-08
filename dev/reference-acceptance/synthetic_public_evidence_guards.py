"""Offline public-response and selected-original guards for synthetic collectors."""
import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

CASE = "IIP-IDP12-f-idp-01"
CASE_DIGEST = "sha256:1ef44e75e3fb37fc82a1a240b477490e15a5ecadc6471015f684e62cb12409d1"
P = "urn:oasis:names:tc:SAML:2.0:protocol"
POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
FIXTURES = ["post-binding-control", "redirect-binding", "unsupported-binding", "artifact-binding"]
VARIANTS = {"IIP-IDP12.f#v-506e90c9bf", "IIP-IDP12.f#v-5d97fd0b51", "IIP-IDP12.f#v-d52d921b7f", "IIP-IDP12.f#v-d7fa7792d4"}
SENSITIVE_KEYS = {"managementurl", "token", "accesstoken", "refreshtoken", "idtoken", "clientsecret",
                  "privatekey", "password", "passwd", "authorization", "proxyauthorization", "cookie",
                  "setcookie", "credential", "credentials", "bearertoken", "apikey", "apisecret"}
MAX_ORIGINAL = 8 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def assert_public_json(value):
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.replace("_", "").replace("-", "").lower()
            require(normalized not in SENSITIVE_KEYS or child is None, "Non-public API JSON omitted")
            assert_public_json(child)
    elif isinstance(value, list):
        for child in value:
            assert_public_json(child)


def public_json_document(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Malformed API JSON omitted")
            result[key] = value
        return result
    def invalid_constant(_):
        raise ValueError("Malformed API JSON omitted")
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (ValueError, UnicodeError):
        raise ValueError("Malformed or non-public API JSON omitted") from None
    require(isinstance(value, (dict, list)), "Non-public API JSON omitted")
    assert_public_json(value)
    return value


def persist_public_json(raw, destination):
    """Validate before creating a raw-body file or exposing a created document."""
    value = public_json_document(raw)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(raw)
    return value


def no_symlinks(path):
    current = Path(path).absolute()
    for part in [current, *current.parents]:
        require(not part.is_symlink(), "Portable original contains a symlink")


def verify_part(original, field, declared_size, declared_hash, path):
    size = original.get(declared_size)
    require(type(size) is int and 0 <= size <= MAX_ORIGINAL, "Portable original declared size invalid")
    value = original.get(field)
    require(isinstance(value, str), "Portable original bytes absent")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        raise ValueError("Portable original base64 invalid") from None
    require(len(raw) == size, "Portable original size differs")
    digest = hashlib.sha256(raw).hexdigest()
    require(original.get(declared_hash) == digest, "Portable original declared SHA differs")
    summary = original["summary"]
    if field == "bodyBase64":
        for recorded in (original.get("storedBodySha256"), summary.get("body_sha256")):
            require(recorded is None or recorded == digest, "Portable original Recorder body SHA differs")
    else:
        for name in ("decodedSha256", "decoded_sha256"):
            require(name not in summary or summary[name] == digest, "Portable original Recorder SAML SHA differs")
    no_symlinks(path)
    if size:
        require(path.is_file() and path.stat().st_size == size, "Portable original physical size differs")
        with path.open("rb") as stream:
            physical = stream.read(MAX_ORIGINAL + 1)
        require(physical == raw and hashlib.sha256(physical).hexdigest() == digest, "Portable original physical bytes differ")
    else:
        require(not path.exists(), "Unexpected file for an empty original")
    return raw, digest


def validate_selected_export(native, mode_folder):
    """Require the real case's ten references and its two original M0 references."""
    require(native.get("runtimeProofVerified") is True, "Original-backed Artifact proof unavailable")
    run, plan = native["runId"], native["planId"]
    require(re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", run) and re.fullmatch(r"plan_[0-9A-HJKMNP-TV-Z]{26}", plan), "Foreign selected Run/Plan")
    approved, execution, proof = native["approvedCase"], native["caseExecution"], native["runtimeProof"]
    require(approved["id"] == CASE and approved["caseDigest"] == CASE_DIGEST and set(approved["coversVariants"]) == VARIANTS, "Approved selected scope differs")
    require({c["id"] for c in approved["controls"]} == {"iip-idp12-f-idp-01-positive", "iip-idp12-f-idp-01-negative"} and len(approved["controls"]) == 2, "Approved controls differ")
    require(execution["runId"] == run and execution["caseId"] == CASE and execution["status"] == "FINISHED" and execution["outcome"]["outcome"] == "SATISFIED", "Actual selected case did not finish")
    require(execution["outcome"]["details"].get("completed_binding_fixtures") == FIXTURES, "Approved four-fixture proof incomplete")
    evidence = execution["outcome"]["evidence"]
    require(len(evidence) == 10 and all(e["kind"] == "transcript" for e in evidence), "Exact ten CaseOutcome references required")
    case_refs = {e["reference"] for e in evidence}
    require(len(case_refs) == 10, "Duplicate selected CaseOutcome reference")
    originals = {}
    for original in native["transcriptOriginals"]:
        require(original["runId"] == run and original["id"] not in originals, "Duplicate or foreign original")
        require(re.fullmatch(r"tx_[0-9A-HJKMNP-TV-Z]{26}", original["id"]), "Unsafe original reference")
        originals[original["id"]] = original
    require(case_refs <= originals.keys(), "Selected B or Artifact original missing")
    require(proof["normalResponseReference"] in originals, "M0 response original missing")
    normal = originals[proof["normalResponseReference"]]
    normal_requests = [e for e in originals.values() if e["direction"] == "OUTBOUND" and e["summary"].get("type") == "AuthnRequest" and e["correlationId"] == normal["summary"].get("inResponseTo")]
    require(len(normal_requests) == 1, "Unique M0 request original missing")
    selected = case_refs | {normal["id"], normal_requests[0]["id"]}
    require(len(selected) == 12, "Selected case and M0 must have twelve distinct references")
    decoded, exports = {}, []
    root = Path(mode_folder).absolute()
    no_symlinks(root)
    for reference in sorted(selected):
        original = originals[reference]
        parts = []
        for field, size, digest_field, suffix in [("bodyBase64", "bodyBytes", "computedBodySha256", ".body"), ("decodedSamlBase64", "decodedSamlBytes", "computedDecodedSha256", ".saml.xml")]:
            raw, digest = verify_part(original, field, size, digest_field, root / "originals" / (reference + suffix))
            if raw:
                parts.append({"suffix": suffix, "bytes": len(raw), "sha256": digest})
            if field == "decodedSamlBase64":
                decoded[reference] = raw
        require(parts, "Selected original has no portable bytes")
        exports.append({"reference": reference, "parts": parts})
    requests = [originals[r] for r in case_refs if originals[r]["direction"] == "OUTBOUND" and originals[r]["summary"].get("type") == "AuthnRequest"]
    require(len(requests) == 4 and {e["summary"].get("fixture_id") for e in requests} == set(FIXTURES), "Four approved request originals required")
    for request in requests:
        fixture = request["summary"]["fixture_id"]
        require(request["summary"].get("scenario_case_id") == CASE, "Foreign fixture owner")
        xml = ET.fromstring(decoded[request["id"]])
        require(xml.tag == f"{{{P}}}AuthnRequest" and xml.attrib.get("ID") == "_" + request["correlationId"], "Fixture correlation differs")
        binding = xml.attrib.get("ProtocolBinding")
        require(binding == {"post-binding-control": POST, "redirect-binding": REDIRECT, "artifact-binding": ARTIFACT}.get(fixture, binding) and (fixture != "unsupported-binding" or binding not in {POST, REDIRECT, ARTIFACT}), "Approved fixture binding differs")
        if fixture != "artifact-binding":
            replies = [originals[r] for r in case_refs if originals[r]["direction"] == "INBOUND" and originals[r]["summary"].get("type") == "Response" and originals[r]["summary"].get("inResponseTo") == xml.attrib["ID"]]
            require(len(replies) == 1 and replies[0]["method"] == "POST", "Selected B response original missing")
            response = ET.fromstring(decoded[replies[0]["id"]])
            require(response.tag == f"{{{P}}}Response" and response.attrib.get("InResponseTo") == xml.attrib["ID"] and response.attrib.get("Destination") == xml.attrib.get("AssertionConsumerServiceURL"), "B response context differs")
            status = response.find(f"{{{P}}}Status/{{{P}}}StatusCode")
            allowed = {"urn:oasis:names:tc:SAML:2.0:status:Success"} if fixture == "post-binding-control" else {"urn:oasis:names:tc:SAML:2.0:status:" + s for s in ("Requester", "Responder", "VersionMismatch")}
            require(status is not None and status.attrib.get("Value") in allowed, "Approved B response observation absent")
    require({proof[k] for k in ("artifactAuthnRequestReference", "artifactDeliveryReference", "requestSoapReference", "responseSoapReference")} <= case_refs, "Artifact originals are outside case evidence")
    for field in ("normalAuthnRequestRedirectSignatureVerified", "normalResponseOuterSignatureVerified", "suiteCertificateMatchesPlanPublicMetadata", "outerAndInnerCorrelationIssuerAcsVerified", "requestPayloadEqualsBothRecorderOriginals", "responseBodyEqualsDecodedOriginal", "tlsReceiptVerified"):
        require(proof.get(field) is True, "Required original proof flag absent")
    return {"schema": "synthetic-selected-portable-original-gate-v1", "runId": run, "caseId": CASE,
            "caseEvidenceReferences": sorted(case_refs), "normalEvidenceReferences": [normal_requests[0]["id"], normal["id"]],
            "requiredOriginals": exports, "approvedFixtures": FIXTURES,
            "requiredSelectedOriginalsExported": True, "wholeRunExportClaimed": False,
            "globalOriginalExportComplete": native.get("originalExportComplete"), "productEvidenceAdoption": False}
