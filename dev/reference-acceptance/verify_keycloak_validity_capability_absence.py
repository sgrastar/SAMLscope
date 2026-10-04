#!/usr/bin/env python3
"""Fail-closed adoption gate for Keycloak metadata-validity observations.

The source campaign proves MD04.a/b from protocol behavior, MD04.c from a separate
capability-absence conclusion, and MD05.as from use of an expired metadata signing
key.  Each conclusion remains gated by its own approved definition and controls.
"""

from __future__ import annotations

from datetime import datetime
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
import yaml

REPO = Path(__file__).resolve().parents[2]
FOLDER = "keycloak-validity-capability-v158"
CAPABILITY_FOLDER = "md04c-capability-conclusion-v1"
CASES = ("IIP-MD04-a-idp-01", "IIP-MD04-b-idp-01", "IIP-MD04-c-idp-01")
MD05_AS = "IIP-MD05-as-idp-01"
ADOPTED_CASES = CASES + (MD05_AS,)
VARIANTS = ("control", "no-valid-until", "expired", "valid-until-near", "valid-until-far")
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
PLAN_RE = re.compile(r"plan_[0-9A-HJKMNP-TV-Z]{26}")
TX_RE = re.compile(r"tx_[0-9A-HJKMNP-TV-Z]{26}")
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
P = "{urn:oasis:names:tc:SAML:2.0:protocol}"
A = "{urn:oasis:names:tc:SAML:2.0:assertion}"
DS = "{http://www.w3.org/2000/09/xmldsig#}"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
JAR_HASHES = {
    "services": "213c45bb357e0881ead8284f12308e3c9fd8e09e7f0b6ec816f95f8b0921bea9",
    "storage": "63ba0e2133e3a5a65f5a4b7944018d3ae7b524aecbcaeacadcdfc7a004fb76d6",
    "saml": "191794d8be9289121c628f5e69380771b67f72ea869207248c2bbda253979e84",
    "saml-public": "e1262687b87e92edb759b02d568fed8518d5e00b32a70749bee61a787178bbb2",
    "server-spi-private": "a9541ffb99d572a487afdbd0ce112f3038f8d58119857219306e14d3af400afa",
}
CASE_DIGESTS = {
    "IIP-MD04-a-idp-01": "sha256:3a1b3ee7a55ba424dba77c01c52b2caab9ecd332f49f6fb63aa0d34ef4543fec",
    "IIP-MD04-b-idp-01": "sha256:759849eb8944f0695399cf30836d28b5f7514e2abf9ee7be572d67656ed7c6d4",
    "IIP-MD04-c-idp-01": "sha256:ff942df4a1dd959e35d3bdbe63e121d114f67a5048dfc8f1b8df33c693e67e12",
    "IIP-MD05-as-idp-01": "sha256:e16c5223202cf19d68977ed7bf914d13d6ed1946b943b25882b2cda66bd32ef8",
}
SUITE_IMAGE = "sha256:846083123e759f24e88a89f9badba50c4e4cd110b3b13563e8295c9829886cdb"
SUITE_JAR_HASHES = {
    "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe",
    "runner": "94dca2c3c134cf2ad3c30fb4a271448b729c7327b464bff0070a83b45b157dae",
    "saml": "cbfdb79f54ed967f58c8153eb8d0dda350016030c552d0aaee3fc30988d3bf73",
}


def require(value: object, detail: str) -> None:
    if not value:
        raise AssertionError(detail)


def read(folder: Path, name: str):
    return json.loads((folder / name).read_text())


def sensitive_paths(value, path="") -> list[str]:
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = path + "/" + key
            lowered = key.lower()
            if (lowered in {"secret", "registrationaccesstoken", "accesstoken", "password"}
                    or "private.key" in lowered or "privatekey" in lowered):
                found.append(child_path)
            found.extend(sensitive_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(sensitive_paths(child, path + "/" + str(index)))
    return found


def one(values, detail: str):
    values = list(values)
    require(len(values) == 1, detail)
    return values[0]


def safe_xml(raw: bytes) -> ET.Element:
    upper = raw.upper()
    require(b"<!DOCTYPE" not in upper and b"<!ENTITY" not in upper, "DTD/entity in XML original")
    return ET.fromstring(raw)


def parse_time(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def require_scoped_signature(root: ET.Element, expected_id: str, detail: str) -> None:
    direct = [child for child in root if child.tag == DS + "Signature"]
    all_signatures = root.findall(".//" + DS + "Signature")
    require(len(direct) == len(all_signatures) == 1, detail + " signature placement mismatch")
    references = direct[0].findall("./" + DS + "SignedInfo/" + DS + "Reference")
    require(len(references) == 1 and references[0].get("URI") == "#" + expected_id,
            detail + " signature Reference mismatch")


def request_without_signature(root: ET.Element) -> bytes:
    normalized = copy.deepcopy(root)
    normalized.set("ID", "_CONTROL_ID_")
    normalized.set("IssueInstant", "_CONTROL_TIME_")
    for child in list(normalized):
        if child.tag == DS + "Signature":
            normalized.remove(child)
    return ET.tostring(normalized, encoding="utf-8")


def decoded_originals(folder: Path, transcript: list[dict]) -> dict[str, bytes]:
    manifest = read(folder, "decoded-manifest.json")
    require(len({row.get("id") for row in manifest}) == len(manifest), "duplicate decoded original")
    by_id = {row["id"]: row for row in transcript}
    originals = {}
    for row in manifest:
        entry = by_id.get(row.get("id"))
        path = (folder / row.get("file", "missing")).resolve()
        require(path.parent == (folder / "decoded").resolve(), "decoded original escaped folder")
        raw = path.read_bytes()
        require(entry is not None and TX_RE.fullmatch(entry["id"]), "decoded entry is unknown")
        require(SHA(raw) == row.get("sha256") and len(raw) == entry.get("decodedSamlBytes"),
                "decoded original hash/size mismatch")
        require(entry.get("decodedSamlRef") == f"transcripts/{entry['runId']}/{entry['id']}.saml.xml",
                "decoded source reference mismatch")
        originals[entry["id"]] = raw
    require(set(originals) == {row["id"] for row in transcript if row.get("decodedSamlRef")},
            "decoded original inventory is incomplete")
    return originals


def verify_approved_definitions() -> None:
    rows = yaml.safe_load((REPO / "tests/cases.yaml").read_text())["cases"]
    by_id = {row["id"]: row for row in rows}
    approvals = yaml.safe_load((REPO / "tests/approvals/g2.yaml").read_text())["approvals"]
    approved_by_id = {row["case"]: row for row in approvals}
    for case, digest in CASE_DIGESTS.items():
        row = by_id[case]
        approval = approved_by_id.get(case)
        require(row["case_digest"] == digest and row["mode"] == "CONFIG"
                and row["role"] == "idp" and approval is not None
                and approval.get("case_digest") == digest
                and approval.get("reviewer") == "hoshina@gmail.com"
                and approval.get("approved_at") == "2026-09-22T05:58:38+09:00",
                case + " approved digest/identity changed")
    require(all(by_id[case]["configuration_failure_semantics"] == "normative_capability"
                for case in CASES), "MD04 configuration failure semantics changed")
    require([row["instruction_en"] for row in by_id[CASES[0]]["variant_plan"]]
            == ["variant=no-validuntil"], "MD04.a variants changed")
    require([row["instruction_en"] for row in by_id[CASES[1]]["variant_plan"]]
            == ["variant=expired (now-24h)"], "MD04.b variants changed")
    require([row["instruction_en"] for row in by_id[CASES[2]]["variant_plan"]]
            == ["now+T+δ (should be rejected)",
                "Have the target configure threshold T, then use now+T-δ (should be accepted)"],
            "MD04.c variants changed")
    constraints = by_id[CASES[2]]["interpretation_constraints"]
    require(any("no absolute threshold" in value for value in constraints)
            and any("no configuration capability" in value and "capability_absent" in value
                    for value in constraints), "MD04.c capability semantics changed")
    md05 = by_id[MD05_AS]
    require(md05["configuration_failure_semantics"] == "test_precondition"
            and md05["obligation"] == "IIP-MD05.as"
            and md05["covers_variants"] == ["IIP-MD05.as#v-0080ee6fd9"]
            and md05["variant_scopes"] == {
                "IIP-MD05.as#v-0080ee6fd9": "owner_condition"}
            and md05["variant_plan"] == [{
                "reference": "IIP-MD05.as#v-0080ee6fd9",
                "applicability": "owner_condition",
                "treatment": "verdict",
                "instruction_en": (
                    "Do not use the endpoints, signing key, or encryption key from expired metadata")
            }]
            and md05["variant_groups"] == [{
                "id": "default-all-of", "kind": "all_of",
                "members": ["IIP-MD05.as#v-0080ee6fd9"],
                "rationale_en": (
                    "Exercise each remaining applicable variant; informational and control "
                    "variants do not independently determine the target outcome.")
            }], "MD05.as approved variant definition changed")
    require([{key: control.get(key) for key in ("id", "kind", "fixture", "on_failure")}
             for control in md05["controls"]] == [
                {"id": "iip-md05-as-idp-01-positive", "kind": "positive",
                 "fixture": "idp-core-no-ecp", "on_failure": "control_failed"},
                {"id": "iip-md05-as-idp-01-negative", "kind": "negative",
                 "fixture": "mut-iip-md05-as-idp", "on_failure": "control_failed"},
             ] and md05["baseline"] == "idp-core-no-ecp"
             and md05["detected_by_mutants"] == ["mut-iip-md05-as-idp"]
             and md05["interpretation_constraints"] == [
                "Metadata that is merely stale because cacheDuration has elapsed is not invalid. "
                "Pair this with the MAY in IIP-MD05.at"],
             "MD05.as approved controls/constraint changed")


def verify_hashes(folder: Path, manifest: dict) -> None:
    fixed = {
        "adminBeforeSha256": "admin-before.json",
        "adminConfiguredSha256": "admin-configured.json",
        "adminFinalSha256": "admin-final.json",
        "adminRedactionSha256": "admin-redaction.json",
        "operationCountsSha256": "operation-counts.json",
        "relaySourceSha256": "KeycloakMetadataUrlRelay.java",
        "relayRequestsSha256": "relay-requests.jsonl",
        "targetRuntimeStartSha256": "target-runtime-start.json",
        "targetRuntimeEndSha256": "target-runtime-end.json",
        "validityRuntimeSha256": "validity-runtime.json",
        "converterObservationsSha256": "converter-observations.json",
        "transcriptSha256": "transcript.json",
        "decodedManifestSha256": "decoded-manifest.json",
        "targetMetadataSha256": "target-metadata.xml",
    }
    for field, name in fixed.items():
        require(manifest.get(field) == SHA((folder / name).read_bytes()), name + " hash mismatch")


def verify_run_and_suite(folder: Path, manifest: dict) -> None:
    """Bind the protocol evidence to one real Suite Run and its captured runtime."""
    suite = read(folder, "suite-runtime.json")
    require(suite.get("schema") == "samlscope-keycloak-metadata-url-suite-runtime-v1"
            and suite.get("imageId") == SUITE_IMAGE
            and suite.get("configuredImage") == "samlscope:reference-combined-v158"
            and suite.get("runningAtCapture") is True,
            "Suite runtime identity mismatch")
    require(set(suite.get("jars", {})) == set(SUITE_JAR_HASHES),
            "Suite runtime JAR inventory mismatch")
    for label, expected in SUITE_JAR_HASHES.items():
        record = suite["jars"][label]
        path = (folder / record.get("file", "missing")).resolve()
        require(path.parent == folder.resolve()
                and record.get("sha256") == expected == SHA(path.read_bytes()),
                label + " Suite JAR mismatch")

    plan = read(folder, "plan.json")["plan"]
    definition = plan["plan"]
    created = read(folder, "created.json")["run"]
    preflight = read(folder, "preflight.json")
    require(definition.get("id") == manifest["planId"]
            and definition.get("profile") == "metadata_idp"
            and definition.get("requestSigningMode") == "REQUIRED"
            and definition.get("target") == {
                "kind": "IDP", "entityId": manifest["targetEntityId"],
                "connectionId": None, "metadataRevisionId": None}
            and plan.get("entityId") == manifest["entityId"]
            and created.get("id") == manifest["runId"]
            and created.get("planId") == manifest["planId"]
            and preflight.get("runId") == manifest["runId"]
            and preflight.get("observations", {}).get("targetEntityId")
                == manifest["targetEntityId"]
            and not any(check.get("status") == "FAIL"
                        for check in preflight.get("checks", []))
            and read(folder, "tests-start.json") == {"ecpProbesRequired": False},
            "Plan/Run/preflight binding mismatch")

    target = (folder / "target-metadata.xml").read_bytes()
    target_root = safe_xml(target)
    require(SHA(target) == manifest["targetMetadataSha256"]
            and target_root.get("entityID") == manifest["targetEntityId"],
            "target metadata identity mismatch")


def verify_restoration(folder: Path, manifest: dict) -> None:
    before = (folder / "admin-before.json").read_bytes()
    after = (folder / "admin-final.json").read_bytes()
    require(before == after == b"[]\n", "temporary client was not restored exactly")
    configured = read(folder, "admin-configured.json")
    require(configured.get("clientId") == manifest["entityId"] and configured.get("protocol") == "saml"
            and configured.get("attributes", {}).get("saml.useMetadataDescriptorUrl") == "true"
            and configured.get("attributes", {}).get("saml.metadataDescriptorUrl") == manifest["relayUrl"],
            "native metadata URL configuration read-back mismatch")
    expected_redirects = [manifest["entityId"] + "/sp/acs/0"] + [
        manifest["entityId"] + "/sp/acs/0?mdv=" + variant + "&run=" + manifest["runId"]
        for variant in VARIANTS
    ]
    actual_redirects = configured.get("redirectUris", [])
    require(len(actual_redirects) == len(expected_redirects)
            and set(actual_redirects) == set(expected_redirects),
            "Run-correlated callback allowlist read-back mismatch")
    require(sensitive_paths(configured) == [], "credential value was persisted")
    redaction = read(folder, "admin-redaction.json")
    removed = redaction.get("removedFields")
    require(redaction == {"removedFields": removed,
                          "credentialValuesPersisted": False,
                          "fullRepresentationHeldInMemoryOnly": True}
            and "/attributes/saml.signing.private.key" in removed
            and set(removed) <= {"/secret", "/attributes/saml.signing.private.key"},
            "credential redaction mismatch")
    counts = read(folder, "operation-counts.json")
    require(counts.get("restored") is True and counts.get("productConfigurationWrites") == 2
            and counts.get("restorationWrites") == 1 and counts.get("protocolRoundTrips") == 10
            and counts.get("metadataFetches") == 5 and counts.get("metadataConverterCalls") == 5
            and counts.get("productRestarts") == 0 and counts.get("humanOperations") == 0
            and counts.get("temporaryRelayStopped") is True, "operation counts mismatch")


def verify_runtime(folder: Path, manifest: dict) -> None:
    start = read(folder, "target-runtime-start.json")
    end = read(folder, "target-runtime-end.json")
    for phase, value in (("start", start), ("end", end)):
        require(value.get("schema") == "samlscope-keycloak-metadata-url-runtime-v1"
                and value.get("phase") == phase and value.get("product") == "keycloak"
                and value.get("productVersion") == "26.7.2" and value.get("imageId") == IMAGE
                and value.get("runningAtCapture") is True, "target runtime identity mismatch")
    require((start["containerId"], start["imageId"], start["startedAt"])
            == (end["containerId"], end["imageId"], end["startedAt"]),
            "target runtime changed during campaign")
    for name in ("keycloak-jars", "provider-inventory", "keycloak-config"):
        suffix = ".json" if name != "keycloak-config" else ".txt"
        require((folder / f"{name}-start{suffix}").read_bytes()
                == (folder / f"{name}-end{suffix}").read_bytes(), name + " changed during campaign")

    runtime = read(folder, "validity-runtime.json")
    require(runtime.get("schema") == "samlscope-keycloak-validity-runtime-v1"
            and runtime.get("imageId") == IMAGE and runtime.get("containerId") == start["containerId"]
            and runtime.get("containerStartedAt") == start["startedAt"]
            and runtime.get("productConfigurationWrites") == runtime.get("productRestarts")
            == runtime.get("humanOperations") == 0, "capability runtime binding mismatch")
    require((folder / "providers-inventory.txt").read_bytes() == b"./README.md\n"
            and runtime["providersInventorySha256"]
                == SHA((folder / "providers-inventory.txt").read_bytes())
            and runtime["providersReadmeSha256"]
                == SHA((folder / "providers-README.md").read_bytes()), "custom provider inventory mismatch")

    server = read(folder, "serverinfo-validity-providers.json")["providers"]
    require(set(server["client-description-converter"]["providers"])
            == {"keycloak", "openid-connect", "saml2-entity-descriptor"}
            and set(server["client-registration"]["providers"])
            == {"default", "install", "openid-connect", "saml2-entity-descriptor"}
            and set(server["login-protocol"]["providers"]) == {"openid-connect", "saml"}
            and set(server["publicKeyCache"]["providers"]) == {"infinispan"}
            and set(server["publicKeyStorage"]["providers"]) == {"infinispan"},
            "installed native provider inventory changed")

    for label, expected in JAR_HASHES.items():
        record = runtime["jars"][label]
        path = (folder / record["file"]).resolve()
        require(path.parent == (folder / "product-jars").resolve()
                and record["sha256"] == expected == SHA(path.read_bytes()), label + " JAR mismatch")
    classes = runtime["classes"]
    for label, record in classes.items():
        jar = folder / runtime["jars"][record["jar"]]["file"]
        with zipfile.ZipFile(jar) as archive:
            raw = archive.read(record["jarEntry"])
        class_path = folder / record["classFile"]
        javap_path = folder / record["javapFile"]
        require(raw == class_path.read_bytes() and SHA(raw) == record["classSha256"]
                and SHA(javap_path.read_bytes()) == record["javapSha256"], label + " class original mismatch")

    texts = {label: (folder / row["javapFile"]).read_text(errors="replace")
             for label, row in classes.items()}
    class_bytes = {label: (folder / row["classFile"]).read_bytes()
                   for label, row in classes.items()}
    abstract = texts["abstract-metadata-loader"]
    require("getExpirationTime" in abstract and "java/lang/Math.min" in abstract
            and "PublicKeysWrapper" in abstract
            and b"getValidUntil" in class_bytes["abstract-metadata-loader"]
            and b"getCacheDuration" in class_bytes["abstract-metadata-loader"],
            "metadata expiry-to-cache path changed")
    storage = texts["key-storage"] + texts["key-storage-factory"]
    require("minTimeBetweenRequests" in storage and "maxCacheTime" in storage
            and "reloadKeys" in storage and "getExpirationTime" in storage
            and "Maximum interval in seconds that keys are cached" in storage,
            "public-key cache semantics changed")
    require(all(term not in class_bytes["metadata-converter"] for term in
                (b"getValidUntil", b"getCacheDuration", b"maxValidity", b"requiredValid")),
            "native import gained unreviewed validity semantics")
    require("saml.useMetadataDescriptorUrl" in texts["saml-client"]
            and "saml.metadataDescriptorUrl" in texts["saml-client"]
            and all(term not in (texts["saml-client"] + texts["saml-config"]) for term in
                    ("maxValidity", "requiredValidUntil", "validityInterval")),
            "SAML client validity configuration inventory changed")

    scan_raw = (folder / "all-jars-scan.json").read_bytes()
    require(runtime["allJarsScanSha256"] == SHA(scan_raw)
            and runtime["scanSourceSha256"] == SHA((folder / "scan_keycloak_jars.py").read_bytes()),
            "exhaustive JAR scan binding mismatch")
    scan = json.loads(scan_raw)
    current = read(folder, "keycloak-jars-start.json")
    require(scan["jar_count"] == len(scan["jars"]) == len(current) == 348,
            "full JAR inventory size mismatch")
    current_by_name = {Path(row["path"]).name: (row["sha256"], row["size"]) for row in current}
    require({row["name"]: (row["sha256"], row["size"]) for row in scan["jars"]} == current_by_name,
            "exhaustive scan does not match the running product")
    require(scan["pattern_hits"]["mdq_literal_lower"] == []
            and scan["pattern_hits"]["metadata_query_protocol"] == [],
            "unreviewed native metadata query path appeared")
    validity_hits = {(row["jar"], row["entry"]) for row in scan["pattern_hits"]["valid_until"]}
    require(("org.keycloak.keycloak-services-26.7.2.jar",
             "org/keycloak/protocol/saml/SamlAbstractMetadataPublicKeyLoader.class") in validity_hits
            and all("MetadataValidity" not in entry and "ValidityInterval" not in entry
                    for _, entry in validity_hits), "validUntil implementation inventory changed")


def verify_protocol(folder: Path, manifest: dict) -> None:
    transcript = read(folder, "transcript.json")
    require(transcript == read(folder, "transcript-after.json")
            and transcript and all(row.get("runId") == manifest["runId"] for row in transcript)
            and len({row["id"] for row in transcript}) == len(transcript),
            "transcript changed, mixed Runs, or contains duplicate IDs")
    entries = {row["id"]: row for row in transcript}
    originals = decoded_originals(folder, transcript)
    decoded_paths = {row["id"]: folder / row["file"] for row in read(folder, "decoded-manifest.json")}
    relay = [json.loads(line) for line in (folder / "relay-requests.jsonl").read_text().splitlines() if line]
    require(len(relay) == 5 and len({row["sequence"] for row in relay}) == 5,
            "native relay fetch count/identity mismatch")
    campaign = read(folder, "campaign.json")
    require(campaign.get("campaignVariants") == list(VARIANTS)
            and campaign.get("pollingDelaySeconds") == 12, "Suite campaign definition mismatch")
    conversions = read(folder, "converter-observations.json")
    require(conversions == manifest["conversions"]
            and [row["variant"] for row in conversions] == list(VARIANTS),
            "native converter inventory mismatch")
    signature_args = []
    response_args = []
    valid_until = {}
    metadata_certificates = {}

    for variant, phase, conversion in zip(VARIANTS, manifest["phases"], conversions, strict=True):
        require(phase.get("variant") == variant and conversion.get("variant") == variant,
                "phase variant order mismatch")
        metadata_path = folder / ("metadata-" + variant + ".xml")
        metadata = metadata_path.read_bytes()
        require(SHA(metadata) == phase["fixtureSha256"] == conversion["fixtureSha256"],
                "metadata original hash mismatch")
        root = safe_xml(metadata)
        require(root.tag == MD + "EntityDescriptor" and root.get("entityID") == manifest["entityId"],
                "metadata identity mismatch")
        valid_until[variant] = root.get("validUntil")
        certificates = {
            re.sub(r"\s+", "", certificate.text or "")
            for descriptor in root.findall(
                "./" + MD + "SPSSODescriptor/" + MD + "KeyDescriptor")
            if descriptor.get("use", "") in {"", "signing"}
            for certificate in descriptor.findall(
                "./" + DS + "KeyInfo/" + DS + "X509Data/" + DS + "X509Certificate")
        }
        require(len(certificates) == 1, "metadata signing-certificate inventory mismatch")
        metadata_certificates[variant] = next(iter(certificates))
        if variant == "expired":
            require(root.get("cacheDuration") is None,
                    "MD05.as expired fixture was replaced by cache staleness")
        converted_path = folder / ("converter-" + variant + ".json")
        converted_raw = converted_path.read_bytes()
        converted = json.loads(converted_raw)
        require(SHA(converted_raw) == phase["converterOutputSha256"]
                == conversion["converterOutputSha256"] and conversion["httpStatus"] == 200
                and converted.get("clientId") == manifest["entityId"]
                and converted.get("protocol") == "saml"
                and "validUntil" not in json.dumps(converted)
                and "cacheDuration" not in json.dumps(converted),
                "native converter validity behavior mismatch")

        fetch = entries.get(phase.get("fetchReference"))
        prepared = entries.get(phase.get("preparedReference"))
        request = entries.get(phase.get("requestReference"))
        response = entries.get(phase.get("responseReference"))
        control = entries.get(phase.get("controlRequestReference"))
        require(all(row is not None for row in (fetch, prepared, request, response, control)),
                "phase transcript reference missing")
        require(fetch["direction"] == "INBOUND"
                and fetch.get("samlSummary") == {"type": "MetadataFetch", "variant": variant, "feed": "live"},
                "target metadata fetch mismatch")
        prepared_summary = prepared.get("samlSummary", {})
        require(prepared["direction"] == "OUTBOUND"
                and prepared_summary.get("type") == "MetadataPrepared"
                and prepared_summary.get("variant") == variant
                and prepared_summary.get("fetchTranscriptId") == fetch["id"]
                and prepared_summary.get("metadataSha256") == SHA(metadata)
                and originals[prepared["id"]] == metadata, "prepared metadata original mismatch")
        request_summary = request.get("samlSummary", {})
        control_summary = control.get("samlSummary", {})
        require(request["direction"] == control["direction"] == "OUTBOUND"
                and request_summary.get("type") == control_summary.get("type") == "AuthnRequest"
                and request_summary.get("variant") == control_summary.get("variant") == variant
                and request_summary.get("metadataSignatureControl") == "valid"
                and control_summary.get("metadataSignatureControl") == "invalid",
                "signed request control mismatch")
        request_xml = safe_xml(originals[request["id"]])
        control_xml = safe_xml(originals[control["id"]])
        request_id = request_xml.get("ID")
        expected_acs = (manifest["entityId"] + "/sp/acs/0?mdv=" + variant
                        + "&run=" + manifest["runId"])
        require(request_xml.tag == control_xml.tag == P + "AuthnRequest"
                and request_id == request_summary.get("id")
                and control_xml.get("ID") == control_summary.get("id")
                and request_xml.get("AssertionConsumerServiceURL") == expected_acs
                and control_xml.get("AssertionConsumerServiceURL") == expected_acs
                and request_xml.get("Destination") == control_xml.get("Destination")
                    == manifest["targetEntityId"] + "/protocol/saml",
                "request original/variant-specific ACS mismatch")
        require_scoped_signature(request_xml, request_id, variant + " valid request")
        require_scoped_signature(control_xml, control_summary.get("id"),
                                 variant + " invalid-signature control")
        require(request_without_signature(request_xml) == request_without_signature(control_xml),
                "valid/invalid signature controls differ semantically")
        request_issuer = request_xml.find("./" + A + "Issuer")
        control_issuer = control_xml.find("./" + A + "Issuer")
        require(request_issuer is not None and control_issuer is not None
                and request_issuer.text == control_issuer.text == manifest["entityId"],
                "AuthnRequest Issuer mismatch")
        response_summary = response.get("samlSummary", {})
        response_xml = safe_xml(originals[response["id"]])
        require(response["direction"] == "INBOUND" and response_summary.get("type") == "Response"
                and response_summary.get("inResponseTo") == request_id
                and response_summary.get("statusCode") == SUCCESS
                and response_summary.get("metadataProbeAccepted") is True
                and response_xml.tag == P + "Response" and response_xml.get("InResponseTo") == request_id
                and response_xml.get("Destination") == expected_acs,
                "correlated Success response mismatch")
        status = response_xml.find("./" + P + "Status/" + P + "StatusCode")
        require(status is not None and status.get("Value") == SUCCESS, "SAML Status is not Success")
        response_issuer = response_xml.find("./" + A + "Issuer")
        confirmations = response_xml.findall(
            ".//" + A + "SubjectConfirmationData")
        audiences = response_xml.findall(".//" + A + "Audience")
        require(response_issuer is not None and response_issuer.text == manifest["targetEntityId"]
                and any(node.get("InResponseTo") == request_id
                        and node.get("Recipient") == expected_acs for node in confirmations)
                and len(audiences) == 1 and audiences[0].text == manifest["entityId"],
                "Response issuer/recipient/audience mismatch")
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(response["url"]).query, strict_parsing=True)
        require(query == {"mdv": [variant], "run": [manifest["runId"]]},
                "callback URL correlation mismatch")
        require(not any(row["direction"] == "INBOUND"
                        and row.get("samlSummary", {}).get("inResponseTo") == control_summary.get("id")
                        for row in transcript), "invalid signature produced a SAML response")

        control_record = folder / phase["invalidControlRecordFile"]
        control_body = folder / phase["invalidControlResponseFile"]
        evidence = json.loads(control_record.read_text())
        body = control_body.read_bytes()
        require(SHA(control_record.read_bytes()) == phase["invalidControlRecordSha256"]
                and SHA(body) == phase["invalidControlResponseSha256"]
                and evidence.get("requestId") == control_summary.get("id")
                and evidence.get("requestSha256") == SHA(originals[control["id"]])
                and evidence.get("responseStatus") == 400
                and evidence.get("responseBodySha256") == SHA(body)
                and evidence.get("samlResponseFormPresent") is False,
                "product-owned invalid-signature rejection mismatch")
        native = one((row for row in relay if row["sequence"] == phase["relaySequence"]),
                     "native relay sequence mismatch")
        require(native.get("httpStatus") == 200 and native.get("failure") == ""
                and native.get("mode") == "fetch" and native.get("sourceUrl") == manifest["sourceUrl"]
                and native.get("entityId") == manifest["entityId"]
                and native.get("upstreamSha256") == native.get("servedSha256") == SHA(metadata)
                and (folder / native["servedFile"]).read_bytes() == metadata,
                "native relay original mismatch")
        require(float(control["timestamp"]) < parse_time(native["startedAt"])
                <= float(fetch["timestamp"]) <= float(prepared["timestamp"])
                <= parse_time(native["completedAt"]) < float(request["timestamp"])
                < float(response["timestamp"]),
                "product fetch/request/response event order mismatch")
        signature_args.extend((str(metadata_path), str(decoded_paths[request["id"]]),
                               str(decoded_paths[control["id"]])))
        response_args.append(str(decoded_paths[response["id"]]))

    require(valid_until["no-valid-until"] is None and valid_until["control"] is not None,
            "missing-validUntil control mismatch")
    expired = parse_time(valid_until["expired"])
    near = parse_time(valid_until["valid-until-near"])
    far = parse_time(valid_until["valid-until-far"])
    created = parse_time(manifest["createdAt"])
    require(expired < created and 18 * 86400 <= near - created <= 20 * 86400
            and 20 * 86400 <= far - created <= 22 * 86400
            and 47 * 3600 <= far - near <= 49 * 3600, "validUntil boundary fixtures changed")
    require(len(set(metadata_certificates.values())) == len(VARIANTS),
            "fixture signing keys are not pairwise disjoint")
    expired_certificate = metadata_certificates["expired"]
    for name in ("admin-before.json", "admin-configured.json", "admin-final.json",
                 "target-metadata.xml"):
        require(expired_certificate not in re.sub(
            r"\s+", "", (folder / name).read_text(errors="replace")),
            "expired fixture key leaked into static configuration: " + name)

    source = REPO / "dev/reference-acceptance/VerifyMetadataValiditySignatures.java"
    with tempfile.TemporaryDirectory(prefix="keycloak-validity-signatures-") as temporary:
        subprocess.run(["javac", "-d", temporary, str(source)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = subprocess.run(["java", "-cp", temporary, "VerifyMetadataValiditySignatures",
                                 *signature_args], check=True, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    signature_result = json.loads(result.stdout)
    require(len(signature_result.get("fixtures", [])) == 5
            and len({row.get("key") for row in signature_result["fixtures"]}) == 5
            and all(row == {"key": row["key"], "valid": True, "invalid": False}
                    and re.fullmatch(r"[0-9a-f]{64}", row["key"])
                    for row in signature_result["fixtures"]), "cryptographic controls mismatch")

    response_source = REPO / "dev/reference-acceptance/VerifyMetadataValidityResponseSignatures.java"
    with tempfile.TemporaryDirectory(prefix="keycloak-validity-responses-") as temporary:
        subprocess.run(["javac", "-d", temporary, str(response_source)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        response_result = subprocess.run(
            ["java", "-cp", temporary, "VerifyMetadataValidityResponseSignatures",
             str(folder / "target-metadata.xml"), *response_args],
            check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    verified_responses = json.loads(response_result.stdout)
    require(verified_responses.get("entityId") == manifest["targetEntityId"]
            and re.fullmatch(r"[0-9a-f]{64}",
                             verified_responses.get("certificateSha256", ""))
            and verified_responses.get("responses") == len(VARIANTS),
            "target Response signature verification mismatch")


def case_map(result: dict) -> dict[str, dict]:
    return {case["id"]: case for requirement in result["requirements"] for case in requirement["cases"]}


def verify_capability_conclusion(folder: Path, source: dict) -> dict:
    conclusion = folder / CAPABILITY_FOLDER
    manifest = read(conclusion, "manifest.json")
    require(manifest.get("schema")
            == "samlscope-keycloak-metadata-validity-capability-conclusion-v1"
            and manifest.get("caseId") == CASES[2]
            and RUN_RE.fullmatch(manifest.get("runId", ""))
            and PLAN_RE.fullmatch(manifest.get("planId", ""))
            and manifest.get("sourceEvidenceRunId") == source["runId"]
            and manifest.get("sourceEvidenceManifestSha256")
                == SHA((folder / "manifest.json").read_bytes()),
            "MD04.c capability conclusion identity mismatch")
    fixed = {
        "suiteRuntimeSha256": "suite-runtime.json",
        "configureSha256": "configure.json",
        "resultSha256": "result.json",
        "runAfterSha256": "run-after.json",
        "protocolEvidenceSha256": "protocol-evidence.json",
        "transcriptBeforeSha256": "transcript-before.json",
        "transcriptAfterSha256": "transcript-after.json",
        "operationCountsSha256": "operation-counts.json",
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
    }
    for field, name in fixed.items():
        require(manifest.get(field) == SHA((conclusion / name).read_bytes()),
                "MD04.c " + name + " hash mismatch")
    target = (conclusion / "target-metadata.xml").read_bytes()
    require(manifest.get("targetMetadataSha256") == SHA(target)
            and target == (folder / "target-metadata.xml").read_bytes(),
            "MD04.c target metadata differs from native evidence")
    require((conclusion / "suite-runtime.json").read_bytes()
            == (folder / "suite-runtime.json").read_bytes(),
            "MD04.c conclusion used a different Suite runtime")
    suite = read(conclusion, "suite-runtime.json")
    for record in suite["jars"].values():
        require(SHA((conclusion / record["file"]).read_bytes()) == record["sha256"],
                "MD04.c Suite JAR hash mismatch")

    plan = read(conclusion, "plan.json")["plan"]["plan"]
    created = read(conclusion, "created.json")["run"]
    preflight = read(conclusion, "preflight.json")
    entity = "http://localhost:18080/p/" + manifest["planId"]
    require(plan.get("id") == manifest["planId"] and plan.get("profile") == "metadata_idp"
            and plan.get("requestSigningMode") == "REQUIRED"
            and plan.get("target") == {"kind": "IDP",
                "entityId": "http://localhost:18180/realms/samlscope",
                "connectionId": None, "metadataRevisionId": None}
            and created.get("id") == manifest["runId"]
            and created.get("planId") == manifest["planId"]
            and preflight.get("runId") == manifest["runId"]
            and not any(row.get("status") == "FAIL" for row in preflight.get("checks", []))
            and read(conclusion, "tests-start.json") == {"ecpProbesRequired": False},
            "MD04.c Plan/Run/preflight mismatch")

    before = (conclusion / "baseline-admin-before.json").read_bytes()
    final = (conclusion / "baseline-admin-final.json").read_bytes()
    require(before == final == b"[]\n", "MD04.c temporary baseline client was not restored")
    configured = read(conclusion, "baseline-admin-configured.json")
    require(configured.get("clientId") == entity and configured.get("protocol") == "saml"
            and configured.get("enabled") is True
            and entity + "/sp/acs/0" in configured.get("redirectUris", [])
            and configured.get("attributes", {}).get("saml.client.signature") == "true"
            and sensitive_paths(configured) == [], "MD04.c baseline read-back mismatch")
    redaction = read(conclusion, "baseline-redaction.json")
    require(redaction.get("credentialValuesPersisted") is False
            and redaction.get("fullRepresentationHeldInMemoryOnly") is True
            and set(redaction.get("removedFields", [])) <= {
                "/secret", "/attributes/saml.signing.private.key"},
            "MD04.c baseline credential redaction mismatch")
    baseline_metadata = safe_xml((conclusion / "baseline-suite-metadata.xml").read_bytes())
    require(any(row.get("entityID") == entity for row in baseline_metadata.iter()),
            "MD04.c baseline metadata entity mismatch")
    require(read(conclusion, "baseline-flow.json")
            == {"runId": manifest["runId"], "receipt": "recorded"}
            and read(conclusion, "baseline-run-after.json").get("status") == "COMPLETED",
            "MD04.c initial login prerequisite is unproven")

    before_transcript = read(conclusion, "transcript-before.json")
    after_transcript = read(conclusion, "transcript-after.json")
    require(before_transcript == after_transcript and len(before_transcript) == 2
            and all(row.get("runId") == manifest["runId"] for row in before_transcript),
            "MD04.c configuration changed or mixed protocol evidence")
    request = one((row for row in before_transcript
                   if row.get("direction") == "OUTBOUND"
                   and row.get("samlSummary", {}).get("type") == "AuthnRequest"),
                  "MD04.c baseline request mismatch")
    response = one((row for row in before_transcript
                    if row.get("direction") == "INBOUND"
                    and row.get("samlSummary", {}).get("type") == "Response"),
                   "MD04.c baseline response mismatch")
    require(response.get("samlSummary", {}).get("inResponseTo")
            == request.get("samlSummary", {}).get("id")
            and response.get("samlSummary", {}).get("statusCode") == SUCCESS,
            "MD04.c baseline SSO is not a correlated Success")

    expected_note = (
        "Machine-verified Keycloak 26.7.2 evidence: native metadata URL and import paths used "
        "the approved near/far validUntil controls, while the installed provider/JAR originals "
        "expose cache expiry/reload controls but no configurable validity-rejection threshold. "
        "Evidence manifest sha256=" + manifest["sourceEvidenceManifestSha256"]
    )
    configure = read(conclusion, "configure.json")
    outcome = configure.get("outcome", {})
    require(manifest.get("configurationNote") == expected_note
            and configure.get("runId") == manifest["runId"]
            and configure.get("caseId") == CASES[2] and configure.get("status") == "FINISHED"
            and outcome.get("outcome") == "VIOLATED"
            and outcome.get("reasonCode") == "capability_absent"
            and outcome.get("reasonMessageKey") == "configuration.capability-absent"
            and outcome.get("evidence") == []
            and outcome.get("details") == {"configuration_issue": "capability_absent",
                                            "configuration_note": expected_note},
            "MD04.c configuration outcome mismatch")
    result = read(conclusion, "result.json")
    row = case_map(result)[CASES[2]]
    require(result["run"]["id"] == manifest["runId"]
            and result["run"]["conformance"] == "NON_CONFORMANT"
            and result["target"]["metadata_digest"] == "sha256:" + SHA(target)
            and (row["outcome"], row["verdict"], row["reason_code"], row["reason"],
                 row["attested"], row["evidence_class"], row["evidence"])
                == ("VIOLATED", "FAIL", "capability_absent",
                    "configuration.capability-absent", False, "OPERATOR_ASSISTED", []),
            "MD04.c formal capability-absence result mismatch")
    run_after = read(conclusion, "run-after.json")
    require(run_after.get("id") == manifest["runId"] and run_after.get("status") == "COMPLETED",
            "MD04.c conclusion Run is incomplete")
    counts = read(conclusion, "operation-counts.json")
    require(counts == {
        "productConfigurationWrites": 2, "restorationWrites": 1,
        "productRestarts": 0, "protocolRoundTrips": 1, "humanOperations": 0,
        "restored": True, "temporaryRelayStarted": False,
        "temporaryRelayStopped": True, "suiteConfigurationSubmissions": 1,
        "sourceEvidenceRestored": True,
    }, "MD04.c operation counts mismatch")
    return row


def verify_result(folder: Path, manifest: dict) -> dict[str, dict]:
    before_result = read(folder, "result-before.json")
    result = read(folder, "result-after.json")
    # The native protocol observations already demonstrate each mismatch.  The later
    # capability-absence submission must not replace, manufacture, or otherwise alter those
    # formal conclusions; the retained runtime originals independently prove why MD04.c had no
    # configurable T with which the target could reject the far-side control.
    require(result == before_result, "capability submission changed the formal protocol result")
    require(result["run"]["id"] == manifest["runId"]
            and result["run"]["conformance"] == "NON_CONFORMANT"
            and result["suite"]["image_digest"] == SUITE_IMAGE
            and result["target"]["metadata_digest"] == "sha256:" + manifest["targetMetadataSha256"],
            "result Run/target mismatch")
    cases = case_map(result)
    expected = {
        CASES[0]: ({"control", "no-valid-until"}, {"no-valid-until"}),
        CASES[1]: ({"control", "expired"}, {"expired"}),
    }
    for case, (variants, fixtures) in expected.items():
        row = cases[case]
        require((row["outcome"], row["verdict"], row["reason_code"], row["attested"])
                == ("VIOLATED", "FAIL", "metadata.fixture-probe.violated", False)
                and set(row["diagnostics"].get("used_variants", [])) == variants
                and set(row["diagnostics"].get("fetched_variants", [])) == variants
                and set(row["diagnostics"].get("fixtures", [])) == fixtures
                and row.get("evidence"), case + " native protocol result mismatch")
    md05 = cases[MD05_AS]
    require((md05["outcome"], md05["verdict"], md05["reason_code"], md05["reason"],
             md05["attested"], md05["evidence_class"])
            == ("VIOLATED", "FAIL", "metadata.fixture-probe.violated",
                "metadata.fixture-probe.violated", False, "OPERATOR_ASSISTED")
            and set(md05.get("diagnostics", {}).get("used_variants", []))
                == {"control", "expired"}
            and set(md05.get("diagnostics", {}).get("fetched_variants", []))
                == {"control", "expired"}
            and set(md05.get("diagnostics", {}).get("fixtures", [])) == {"expired"},
            "MD05.as formal expired-metadata result mismatch")
    phases = {phase["variant"]: phase for phase in manifest["phases"]}
    required_references = {
        phases[variant][field]
        for variant in ("control", "expired")
        for field in ("fetchReference", "requestReference", "responseReference")
    }
    evidence_references = {
        item.get("reference", "").removeprefix("transcript:")
        for item in md05.get("evidence", []) if item.get("kind") == "transcript"
    }
    require(len(evidence_references) == len(md05.get("evidence", []))
            and required_references <= evidence_references,
            "MD05.as formal evidence omits the control/expired chain")
    control_until = parse_time(safe_xml((folder / "metadata-control.xml").read_bytes())
                               .get("validUntil"))
    expired_until = parse_time(safe_xml((folder / "metadata-expired.xml").read_bytes())
                               .get("validUntil"))
    transcript = {row["id"]: row for row in read(folder, "transcript.json")}
    control_request_at = float(transcript[phases["control"]["requestReference"]]["timestamp"])
    expired_fetch_at = float(transcript[phases["expired"]["fetchReference"]]["timestamp"])
    require(control_until > control_request_at and expired_until < expired_fetch_at
            and control_until - control_request_at >= 13 * 86400
            and expired_fetch_at - expired_until >= 23 * 3600,
            "MD05.as control/expired validUntil boundary mismatch")
    # The historical source Run reached MD04.c through the fixture oracle first.  It is retained as
    # capability evidence, but that reason is not an approved formal conclusion when T cannot be
    # configured; only the separate configuration.capability-absent Run is adopted below.
    old_c = cases[CASES[2]]
    require(old_c.get("reason_code") == "metadata.fixture-probe.violated",
            "MD04.c source evidence history changed")
    conclusions = read(folder, "capability-conclusions.json")
    require(set(conclusions) == set(CASES), "configuration conclusion inventory mismatch")
    for case, record in conclusions.items():
        outcome = record.get("outcome", {})
        require(record.get("runId") == manifest["runId"] and record.get("caseId") == case
                and record.get("status") == "FINISHED"
                and outcome.get("outcome") == "VIOLATED"
                and outcome.get("reasonCode") == "metadata.fixture-probe.violated",
                case + " capability submission did not preserve native result")
    capability_c = verify_capability_conclusion(folder, manifest)
    return {CASES[0]: cases[CASES[0]], CASES[1]: cases[CASES[1]], CASES[2]: capability_c,
            MD05_AS: md05}


def verify_folder(folder: Path, result: bool = True) -> dict[str, dict] | None:
    verify_approved_definitions()
    manifest = read(folder, "manifest.json")
    require(manifest.get("schema") == "samlscope-keycloak-metadata-validity-capability-v1"
            and manifest.get("adapter") == "keycloak-native-metadata-validity-capability-v1"
            and RUN_RE.fullmatch(manifest.get("runId", ""))
            and PLAN_RE.fullmatch(manifest.get("planId", ""))
            and manifest.get("entityId") == "http://localhost:18080/p/" + manifest["planId"]
            and manifest.get("targetEntityId") == "http://localhost:18180/realms/samlscope"
            and manifest.get("variants") == list(VARIANTS)
            and manifest.get("refreshWaitSeconds") == 12
            and manifest.get("configuredThresholdSeconds") is None
            and manifest.get("configurationConclusion") == "capability-absent"
            and len(manifest.get("phases", [])) == len(manifest.get("conversions", [])) == 5,
            "manifest identity/configuration mismatch")
    verify_hashes(folder, manifest)
    verify_run_and_suite(folder, manifest)
    verify_restoration(folder, manifest)
    verify_runtime(folder, manifest)
    verify_protocol(folder, manifest)
    return verify_result(folder, manifest) if result else None


def tamper_self_test(folder: Path) -> list[str]:
    checks = []
    with tempfile.TemporaryDirectory(prefix="keycloak-validity-tamper-") as temporary:
        base = Path(temporary) / "base"
        shutil.copytree(folder, base)

        def rejected(name, mutate):
            candidate = Path(temporary) / name
            shutil.copytree(base, candidate)
            mutate(candidate)
            try:
                verify_folder(candidate)
            except Exception:
                checks.append(name)
                shutil.rmtree(candidate)
                return
            raise AssertionError("tamper accepted: " + name)

        def mutate_json(path: Path, name: str, change):
            value = read(path, name)
            change(value)
            (path / name).write_text(json.dumps(value, indent=2) + "\n")

        def update_manifest_hash(path: Path, field: str, name: str):
            manifest = read(path, "manifest.json")
            manifest[field] = SHA((path / name).read_bytes())
            (path / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

        def drop_transcript(path: Path, reference: str, decoded: bool = False):
            manifest = read(path, "manifest.json")
            phase = next(row for row in manifest["phases"] if row["variant"] == "expired")
            transcript_id = phase[reference]
            transcript = read(path, "transcript.json")
            transcript = [row for row in transcript if row["id"] != transcript_id]
            (path / "transcript.json").write_text(json.dumps(transcript, indent=2) + "\n")
            (path / "transcript-after.json").write_text(
                json.dumps(transcript, indent=2) + "\n")
            manifest["transcriptSha256"] = SHA((path / "transcript.json").read_bytes())
            if decoded:
                decoded_manifest = read(path, "decoded-manifest.json")
                decoded_manifest = [row for row in decoded_manifest if row["id"] != transcript_id]
                (path / "decoded-manifest.json").write_text(
                    json.dumps(decoded_manifest, indent=2) + "\n")
                manifest["decodedManifestSha256"] = SHA(
                    (path / "decoded-manifest.json").read_bytes())
            (path / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

        def expired_to_future(path: Path):
            metadata_path = path / "metadata-expired.xml"
            root = safe_xml(metadata_path.read_bytes())
            root.set("validUntil", "2099-12-31T23:59:59Z")
            metadata = ET.tostring(root, encoding="utf-8", xml_declaration=True)
            metadata_path.write_bytes(metadata)
            digest = SHA(metadata)
            manifest = read(path, "manifest.json")
            phase = next(row for row in manifest["phases"] if row["variant"] == "expired")
            phase["fixtureSha256"] = digest
            conversion = next(row for row in manifest["conversions"]
                              if row["variant"] == "expired")
            conversion["fixtureSha256"] = digest
            observations = read(path, "converter-observations.json")
            next(row for row in observations if row["variant"] == "expired")[
                "fixtureSha256"] = digest
            (path / "converter-observations.json").write_text(
                json.dumps(observations, indent=2) + "\n")
            manifest["converterObservationsSha256"] = SHA(
                (path / "converter-observations.json").read_bytes())

            transcript = read(path, "transcript.json")
            prepared = next(row for row in transcript if row["id"] == phase["preparedReference"])
            prepared["samlSummary"]["metadataSha256"] = digest
            (path / "transcript.json").write_text(json.dumps(transcript, indent=2) + "\n")
            (path / "transcript-after.json").write_text(
                json.dumps(transcript, indent=2) + "\n")
            manifest["transcriptSha256"] = SHA((path / "transcript.json").read_bytes())
            decoded_manifest = read(path, "decoded-manifest.json")
            decoded_record = next(row for row in decoded_manifest
                                  if row["id"] == phase["preparedReference"])
            (path / decoded_record["file"]).write_bytes(metadata)
            decoded_record["sha256"] = digest
            decoded_record["bytes"] = len(metadata)
            prepared["decodedSamlBytes"] = len(metadata)
            # Persist the byte-count update made after the first transcript write.
            (path / "transcript.json").write_text(json.dumps(transcript, indent=2) + "\n")
            (path / "transcript-after.json").write_text(
                json.dumps(transcript, indent=2) + "\n")
            manifest["transcriptSha256"] = SHA((path / "transcript.json").read_bytes())
            (path / "decoded-manifest.json").write_text(
                json.dumps(decoded_manifest, indent=2) + "\n")
            manifest["decodedManifestSha256"] = SHA(
                (path / "decoded-manifest.json").read_bytes())

            relay_rows = [json.loads(line) for line in (path / "relay-requests.jsonl")
                          .read_text().splitlines() if line]
            relay = next(row for row in relay_rows if row["sequence"] == phase["relaySequence"])
            (path / relay["servedFile"]).write_bytes(metadata)
            relay["upstreamSha256"] = relay["servedSha256"] = digest
            (path / "relay-requests.jsonl").write_text(
                "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in relay_rows))
            manifest["relayRequestsSha256"] = SHA((path / "relay-requests.jsonl").read_bytes())
            (path / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

        def expired_request_other_run(path: Path):
            manifest = read(path, "manifest.json")
            phase = next(row for row in manifest["phases"] if row["variant"] == "expired")
            transcript = read(path, "transcript.json")
            next(row for row in transcript if row["id"] == phase["requestReference"])[
                "runId"] = "run_00000000000000000000000000"
            (path / "transcript.json").write_text(json.dumps(transcript, indent=2) + "\n")
            (path / "transcript-after.json").write_text(
                json.dumps(transcript, indent=2) + "\n")
            update_manifest_hash(path, "transcriptSha256", "transcript.json")

        def remove_control_diagnostic(path: Path):
            for name in ("result-before.json", "result-after.json"):
                result = read(path, name)
                case = case_map(result)[MD05_AS]
                case["diagnostics"]["used_variants"] = ["expired"]
                case["diagnostics"]["fetched_variants"] = ["expired"]
                (path / name).write_text(json.dumps(result, indent=2) + "\n")

        def replace_md04c_with_fixture_reason(path: Path):
            conclusion = path / CAPABILITY_FOLDER
            result = read(conclusion, "result.json")
            row = case_map(result)[CASES[2]]
            row["reason_code"] = "metadata.fixture-probe.violated"
            row["reason"] = "metadata.fixture-probe.violated"
            (conclusion / "result.json").write_text(json.dumps(result, indent=2) + "\n")
            configure = read(conclusion, "configure.json")
            configure["outcome"]["reasonCode"] = "metadata.fixture-probe.violated"
            configure["outcome"]["reasonMessageKey"] = "metadata.fixture-probe.violated"
            (conclusion / "configure.json").write_text(json.dumps(configure, indent=2) + "\n")
            manifest = read(conclusion, "manifest.json")
            manifest["resultSha256"] = SHA((conclusion / "result.json").read_bytes())
            manifest["configureSha256"] = SHA((conclusion / "configure.json").read_bytes())
            (conclusion / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

        rejected("wrong-run", lambda path: mutate_json(path, "manifest.json",
                 lambda value: value.__setitem__("runId", "run_00000000000000000000000000")))
        rejected("phase-reference", lambda path: mutate_json(path, "manifest.json",
                 lambda value: value["phases"][1].__setitem__("requestReference",
                                                              value["phases"][0]["requestReference"])))
        rejected("metadata", lambda path: (path / "metadata-expired.xml").write_bytes(b"<x/>"))
        rejected("converter", lambda path: (path / "converter-control.json").write_text("{}\n"))
        rejected("restoration", lambda path: (path / "admin-final.json").write_text("[{}]\n"))
        rejected("operations", lambda path: mutate_json(path, "operation-counts.json",
                 lambda value: value.__setitem__("productRestarts", 1)))
        rejected("class-original", lambda path: (path / "product-originals/key-storage.javap.txt")
                 .write_text("changed\n"))
        rejected("jar-scan", lambda path: mutate_json(path, "all-jars-scan.json",
                 lambda value: value["pattern_hits"].__setitem__("valid_until", [])))
        rejected("invalid-control", lambda path: (path / "signature-control-control-response.html")
                 .write_text("changed"))
        rejected("result", lambda path: mutate_json(path, "result-after.json",
                 lambda value: next(case for requirement in value["requirements"]
                                    for case in requirement["cases"] if case["id"] == CASES[0])
                 .__setitem__("outcome", "SATISFIED")))
        rejected("md04c-old-fixture-reason", replace_md04c_with_fixture_reason)
        rejected("md05as-expired-to-future", expired_to_future)
        rejected("md05as-fetch-missing", lambda path: drop_transcript(
            path, "fetchReference"))
        rejected("md05as-success-missing", lambda path: drop_transcript(
            path, "responseReference", decoded=True))
        rejected("md05as-invalid-control-missing", lambda path: (
            path / "signature-control-expired.json").unlink())
        rejected("md05as-other-run", expired_request_other_run)
        rejected("md05as-control-missing", remove_control_diagnostic)
    require(len(checks) == 17, "tamper self-test count mismatch")
    return checks


def verify(root: Path | str, case: str):
    require(case in ADOPTED_CASES, "unsupported case")
    folder = Path(root) / FOLDER
    cases = verify_folder(folder)
    result = (folder / CAPABILITY_FOLDER / "result.json") if case == CASES[2] \
        else (folder / "result-after.json")
    return result, {case: cases[case]}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--tamper", action="store_true")
    args = parser.parse_args()
    adopted = verify_folder(args.folder)
    print("verified", ",".join(adopted), "source-run", read(args.folder, "manifest.json")["runId"],
          "md04c-run", read(args.folder / CAPABILITY_FOLDER, "manifest.json")["runId"])
    if args.tamper:
        print("tamper", len(tamper_self_test(args.folder)), "of 17 rejected")
