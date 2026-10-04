#!/usr/bin/env python3
"""Fail-closed verifier for Keycloak IIP-EXT01.c across four independent profiles."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
import zipfile

from verify_terminal_http_acceptance import (
    EVALUATION, _verify_configuration_restoration, _verify_suite_runtime,
    _verify_target_runtime, find_case,
)


CASE = "IIP-EXT01-c-idp-01"
PROFILES = ("browser_sso_idp", "ecp_idp", "metadata_idp", "single_logout_idp")
ACTIVE = ("baseline-success", "unknown-any-attribute", "unknown-attribute-any-attribute")
VARIANTS = (
    "control",
    "foreign-attribute-entity",
    "foreign-attribute-organization",
    "foreign-attribute-contact",
    "foreign-attribute-role",
    "foreign-attribute-single-logout",
    "foreign-attribute-single-sign-on",
    "foreign-attribute-manage-nameid",
    "foreign-attribute-nameid-mapping",
    "foreign-attribute-assertion-id",
    "foreign-attribute-authn-query",
    "foreign-attribute-authz",
    "foreign-attribute-attribute-service",
    "foreign-attribute-affiliation",
)
METADATA_PLACEMENTS = {
    "foreign-attribute-entity": "EntityDescriptor",
    "foreign-attribute-organization": "Organization",
    "foreign-attribute-contact": "ContactPerson",
    "foreign-attribute-role": "RoleDescriptor",
    "foreign-attribute-single-logout": "SingleLogoutService",
    "foreign-attribute-single-sign-on": "SingleSignOnService",
    "foreign-attribute-manage-nameid": "ManageNameIDService",
    "foreign-attribute-nameid-mapping": "NameIDMappingService",
    "foreign-attribute-assertion-id": "AssertionIDRequestService",
    "foreign-attribute-authn-query": "AuthnQueryService",
    "foreign-attribute-authz": "AuthzService",
    "foreign-attribute-attribute-service": "AttributeService",
    "foreign-attribute-affiliation": "AffiliationDescriptor",
}
ACCEPTED_SUITE = {
    "image_id": "sha256:f22f1b4ef9ba489fb7b7e52ad7d7f7da0b49a99a3ca6ef14722559713f6408bc",
    "jars": {
        "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe",
        "runner": "f3ce984cb077bc020b9a429d4ab4452d2bc435eaa270fe50fb73fd564dbac51c",
        "saml": "cbfdb79f54ed967f58c8153eb8d0dda350016030c552d0aaee3fc30988d3bf73",
    },
}
TARGET_IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
TX_RE = re.compile(r"tx_[0-9A-HJKMNP-TV-Z]{26}")
ACTION_RE = re.compile(r"action_[0-9a-f]{32}")
P = "{urn:oasis:names:tc:SAML:2.0:protocol}"
A = "{urn:oasis:names:tc:SAML:2.0:assertion}"
MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
FOREIGN_ACTIVE = "{urn:samlscope:probe:unknown-attribute}fixture"
FOREIGN_METADATA = "{urn:samlscope:fixture:foreign-attribute}undefined"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
TARGET_ENTITY = "http://localhost:18180/realms/samlscope"


def require(value, detail):
    if not value:
        raise ValueError(detail)


def read(path):
    return json.loads(Path(path).read_text())


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_xml(raw):
    require(b"<!DOCTYPE" not in raw.upper() and b"<!ENTITY" not in raw.upper(),
            "DTD/entity in XML original")
    return ET.fromstring(raw)


def direct(parent, tag):
    return [child for child in list(parent) if child.tag == tag]


def originals(folder, transcript):
    manifest = read(folder / "decoded-manifest.json")
    expected = {entry["id"] for entry in transcript if entry.get("decodedSamlRef")}
    require(isinstance(manifest, list) and {item.get("id") for item in manifest} == expected,
            "decoded manifest does not cover exact Recorder originals")
    result = {}
    for item in manifest:
        require(set(item) == {"id", "file", "sha256"} and TX_RE.fullmatch(item["id"] or ""),
                "invalid decoded manifest item")
        path = folder / item["file"]
        require(path.resolve().is_relative_to((folder / "decoded").resolve()),
                "decoded original escaped evidence directory")
        raw = path.read_bytes()
        require(sha(raw) == item["sha256"] and item["id"] not in result,
                "decoded original hash/identity mismatch")
        result[item["id"]] = raw
    return result


def response_for(transcript, decoded, request_id, expected_url=None):
    candidates = [entry for entry in transcript
                  if entry.get("direction") == "INBOUND"
                  and (entry.get("samlSummary") or {}).get("inResponseTo") == request_id]
    require(len(candidates) == 1, "request lacks one unique correlated response")
    entry = candidates[0]
    require(entry["id"] in decoded and entry.get("decodedSamlBytes") == len(decoded[entry["id"]]),
            "correlated response original is missing")
    root = safe_xml(decoded[entry["id"]])
    require(root.tag == P + "Response" and root.get("InResponseTo") == request_id,
            "response original correlation mismatch")
    status = direct(root, P + "Status")
    codes = direct(status[0], P + "StatusCode") if len(status) == 1 else []
    require(len(codes) == 1 and codes[0].get("Value") == SUCCESS,
            "correlated response is not SAML Success")
    require(direct(root, A + "Assertion") or direct(root, A + "EncryptedAssertion"),
            "Success response has no assertion")
    require(root.get("Destination") == entry.get("url"), "response Destination/Recorder mismatch")
    if expected_url is not None:
        require(entry.get("url") == expected_url, "response used another metadata variant/Run URL")
    return entry


def verify_active_request(fixture, root):
    require(root.tag == P + "AuthnRequest" and root.get("ID"), "active fixture is not AuthnRequest")
    marked = [element for element in root.iter() if FOREIGN_ACTIVE in element.attrib]
    if fixture == "baseline-success":
        require(not marked, "active baseline contains foreign attribute")
        return
    require(len(marked) == 1, "active foreign attribute cardinality mismatch")
    expected = "SubjectConfirmationData" if fixture == "unknown-any-attribute" else "Attribute"
    require(marked[0].tag == A + expected, "active foreign attribute is on wrong assertion element")
    require(marked[0].attrib[FOREIGN_ACTIVE] == root.get("ID").removeprefix("_"),
            "active foreign attribute token is not request-bound")


def verify_metadata_fixture(variant, raw, entity):
    root = safe_xml(raw)
    entities = ([root] if root.tag == MD + "EntityDescriptor" else
                list(root.iter(MD + "EntityDescriptor")))
    require(sum(value.get("entityID") == entity for value in entities) == 1,
            "metadata fixture does not contain exactly one target entity")
    marked = [element for element in root.iter() if FOREIGN_METADATA in element.attrib]
    if variant == "control":
        require(not marked, "metadata control contains foreign attribute")
        return
    require(len(marked) == 1 and marked[0].attrib[FOREIGN_METADATA] == "ignored-content",
            "metadata foreign attribute cardinality/value mismatch")
    require(marked[0].tag == MD + METADATA_PLACEMENTS[variant],
            "metadata foreign attribute is on wrong schema extension point")


def verify_runtime_code(folder):
    runtime = read(folder / "suite-runtime-terminal-http.json")
    with zipfile.ZipFile(folder / runtime["jars"]["runner"]["file"]) as archive:
        value = archive.read(
            "com/samlscope/runner/cases/IdpExecutableBrowserFixtureScenarioTestCase.class")
        require(all(needle in value for needle in (
            b"IIP-EXT01-c-idp-01", b"UNKNOWN_ANY_ATTRIBUTE",
            b"UNKNOWN_ATTRIBUTE_ANY_ATTRIBUTE", b"metadata_attribute_matrix_complete",
            b"foreign-attribute-", b"browser_fixture_satisfied")),
            "running Runner lacks complete EXT01.c all-of oracle")
        partial = archive.read(
            "com/samlscope/runner/cases/IdpExecutableBrowserFixtureScenarioTestCase$PartialFixture.class")
        require(b"partial-observation-v8" in partial,
                "running Runner lacks the evidence-bound active fixture implementation")
    with zipfile.ZipFile(folder / runtime["jars"]["saml"]["file"]) as archive:
        request = archive.read("com/samlscope/saml/normal/SamlErrorProbeRequestFactory.class")
        metadata = archive.read("com/samlscope/saml/metadata/MetadataExtensionAttributeFixtures.class")
        require(b"urn:samlscope:probe:unknown-attribute" in request
                and b"SubjectConfirmationData" in request and b"Attribute" in request,
                "running SAML module lacks active attribute fixtures")
        require(b"urn:samlscope:fixture:foreign-attribute" in metadata
                and all(name.encode() in metadata for name in METADATA_PLACEMENTS.values()),
                "running SAML module lacks complete metadata attribute matrix")


def verify_active(folder, profile):
    plan = read(folder / "plan.json")["plan"]["plan"]
    created = read(folder / "created.json")["run"]
    run = created["id"]
    require(RUN_RE.fullmatch(run or "") and created["planId"] == plan["id"],
            "active Plan/Run mismatch")
    require(plan["profile"] == profile and plan["target"]["kind"] == "IDP"
            and plan["target"]["entityId"] == TARGET_ENTITY
            and plan.get("requestSigningMode") == "REQUIRED", "wrong active target/profile")
    _verify_target_runtime(folder, "keycloak", float(created["createdAt"]))
    require(read(folder / "target-runtime-start.json")["binding"]["image_id"] == TARGET_IMAGE,
            "untrusted Keycloak image")
    _verify_configuration_restoration(folder, "keycloak")

    transcript = read(folder / "transcript.json")
    require(all(entry.get("runId") == run for entry in transcript), "foreign Run in active transcript")
    decoded = originals(folder, transcript)
    outbound = [entry for entry in transcript if entry.get("direction") == "OUTBOUND"
                and (entry.get("samlSummary") or {}).get("scenario_case_id") == CASE]
    require(len(outbound) == len(ACTIVE), "wrong active EXT01.c fixture count")
    responses = []
    seen = []
    for entry in outbound:
        summary = entry.get("samlSummary") or {}
        fixture = summary.get("fixture_id")
        require(fixture in ACTIVE and fixture not in seen, "duplicate/unknown active fixture")
        action = summary.get("action_id")
        require(ACTION_RE.fullmatch(action or "") and entry.get("correlationId") == action,
                "active action correlation mismatch")
        require(entry["id"] in decoded and entry.get("decodedSamlBytes") == len(decoded[entry["id"]]),
                "active request original missing")
        request = safe_xml(decoded[entry["id"]])
        verify_active_request(fixture, request)
        responses.append(response_for(transcript, decoded, request.get("ID"))["id"])
        seen.append(fixture)
    require(tuple(seen) == ACTIVE, "active fixture order changed")
    partial = find_case(read(folder / "result.json"), CASE)
    require(partial.get("outcome") == "NOT_VERIFIED"
            and partial.get("verdict") == "NOT_VERIFIED"
            and partial.get("reason_code") == "browser_fixture_partial",
            "active-only case did not remain fail-closed partial")
    evidence = {item.get("reference") for item in partial.get("evidence", [])
                if item.get("kind") == "transcript"}
    require(evidence == set(responses), "active partial evidence does not bind exact responses")
    require((folder / "target-metadata.xml").is_file(), "active target metadata original missing")
    return plan, created, transcript, responses


def verify_supplemental(profile_folder, plan, created, active_transcript, active_responses, pins):
    metadata = profile_folder / "metadata"
    runtime = profile_folder / "supplemental-runtime"
    run = created["id"]
    entity = "http://localhost:18080/p/" + plan["id"]
    _verify_target_runtime(runtime, "keycloak", float(created["createdAt"]))
    require(read(runtime / "target-runtime-start.json")["binding"]["image_id"] == TARGET_IMAGE,
            "untrusted supplemental Keycloak image")
    before = read(profile_folder / "supplemental-before.json")
    after = read(profile_folder / "supplemental-after.json")
    require(before == after and before.get("run") == run and before.get("entity_id") == entity
            and before.get("client_query") == []
            and before.get("canonical_sha256") == sha(b"[]"),
            "supplemental Keycloak state was not exactly restored")

    _verify_suite_runtime(metadata, run, float(created["createdAt"]), pins)
    verify_runtime_code(metadata)
    transcript = read(metadata / "transcript.json")
    evaluation = metadata / EVALUATION
    require(transcript == read(evaluation / "transcript-before.json")
            == read(evaluation / "transcript.json"), "formal re-evaluation changed transcript")
    require(transcript[:len(active_transcript)] == active_transcript,
            "supplemental campaign changed active transcript prefix")
    require(all(entry.get("runId") == run for entry in transcript), "foreign Run in final transcript")
    decoded = originals(metadata, transcript)
    operations = read(metadata / "operations.json")
    require([item.get("variant") for item in operations] == list(VARIANTS)
            and all(item.get("driver_exit") == 0 for item in operations),
            "metadata operation list is incomplete/failed/reordered")

    response_ids = []
    evidence_ids = []
    database_ids = set()
    for variant, operation in zip(VARIANTS, operations, strict=True):
        member = metadata / variant
        fixture_raw = (member / "fixture.xml").read_bytes()
        fixture_hash = sha(fixture_raw)
        require(operation.get("fixture_sha256") == fixture_hash,
                "operation/fixture hash mismatch: " + variant)
        verify_metadata_fixture(variant, fixture_raw, entity)

        imports = read(member / "import.json")
        expected_steps = ["file-selected", "product-parsed-entity-id", "product-import-signal",
                          "admin-read-back", "follow-up-flow", "cleanup-delete-verified"]
        require(imports.get("status") == "success"
                and [item.get("step") for item in imports.get("steps", [])] == expected_steps
                and all(item.get("ok") is True for item in imports["steps"]),
                "native console import did not fully succeed: " + variant)
        require(imports.get("fixture", {}).get("sha256") == fixture_hash
                and imports["fixture"].get("bytes") == len(fixture_raw)
                and imports["fixture"].get("entity_id") == entity,
                "native import fixture identity mismatch: " + variant)
        database_id = imports.get("client", {}).get("database_id")
        require(str(uuid.UUID(database_id)) == database_id and database_id not in database_ids,
                "native import database identity is invalid/reused")
        database_ids.add(database_id)
        readback = imports.get("import", {}).get("read_back", {})
        require(readback.get("client_id") == entity
                and imports.get("import", {}).get("ui_status") == "client-settings-page"
                and imports.get("cleanup") == {"deleted_status": 204, "read_back_absent": True},
                "native import/delete read-back mismatch: " + variant)

        fetches = [entry for entry in transcript
                   if entry.get("direction") == "INBOUND"
                   and (entry.get("samlSummary") or {}).get("type") == "MetadataFetch"
                   and (entry.get("samlSummary") or {}).get("variant") == variant]
        require(len(fetches) == 1, "metadata variant lacks unique fetch: " + variant)
        fetch = fetches[0]
        prepared = [entry for entry in transcript
                    if entry.get("direction") == "OUTBOUND"
                    and (entry.get("samlSummary") or {}).get("type") == "MetadataPrepared"
                    and (entry.get("samlSummary") or {}).get("variant") == variant
                    and (entry.get("samlSummary") or {}).get("fetchTranscriptId") == fetch["id"]]
        require(len(prepared) == 1 and prepared[0].get("correlationId") == fetch["id"],
                "metadata prepared/fetch correlation mismatch: " + variant)
        prepared_entry = prepared[0]
        require(prepared_entry["id"] in decoded
                and decoded[prepared_entry["id"]] == fixture_raw
                and prepared_entry.get("decodedSamlBytes") == len(fixture_raw)
                and prepared_entry.get("bodyBytes") == len(fixture_raw)
                and (prepared_entry.get("samlSummary") or {}).get("metadataSha256") == fixture_hash,
                "metadata prepared original mismatch: " + variant)

        flow = read(member / "flow.json")
        exchange = flow.get("positive_exchange") or {}
        require(flow.get("run") == run and flow.get("variant") == variant
                and flow.get("correlated_success") is True and exchange.get("success") is True,
                "native post-import flow is not a correlated success: " + variant)
        request_id = exchange.get("request_id")
        request_entries = [entry for entry in transcript
                           if entry.get("direction") == "OUTBOUND"
                           and (entry.get("samlSummary") or {}).get("id") == request_id]
        require(len(request_entries) == 1 and request_entries[0]["id"] in decoded,
                "metadata flow request original missing: " + variant)
        expected_url = (entity + "/sp/acs/0?mdv=" + urllib.parse.quote(variant)
                        + "&run=" + urllib.parse.quote(run))
        response = response_for(transcript, decoded, request_id, expected_url)
        require((response.get("samlSummary") or {}).get("metadataProbeAccepted") is True,
                "metadata response lacks Suite acceptance marker: " + variant)
        require(exchange.get("transcript_ids") == [request_entries[0]["id"], response["id"]],
                "flow receipt/transcript mismatch: " + variant)
        response_ids.append(response["id"])
        evidence_ids.extend([fetch["id"], response["id"]])

    result = read(evaluation / "result.json")
    case = find_case(result, CASE)
    require(case.get("outcome") == "SATISFIED" and case.get("verdict") == "PASS"
            and case.get("reason_code") == "browser_fixture_satisfied"
            and case.get("attested") is False and case.get("evidence_class") == "PROTOCOL_OBSERVED",
            "formal EXT01.c result is not protocol-observed PASS")
    evidence = [item.get("reference") for item in case.get("evidence", [])
                if item.get("kind") == "transcript"]
    require(set(evidence) == set(active_responses + evidence_ids)
            and len(evidence) == len(active_responses) + len(evidence_ids),
            "formal result does not bind exact active and metadata all-of evidence")
    require((metadata / "target-metadata.xml").read_bytes()
            == (profile_folder / "active" / "target-metadata.xml").read_bytes(),
            "target metadata changed between active and supplemental capture")

    counts = read(profile_folder / "operation-counts.json")
    require(counts == {
        "restored": True, "human_operations": 0, "product_restarts": 0,
        "active_configuration_apply_writes": 3, "active_restoration_writes": 3,
        "metadata_console_import_writes": len(VARIANTS),
        "metadata_delete_writes": len(VARIANTS),
        "active_protocol_roundtrips": len(ACTIVE),
        "metadata_protocol_roundtrips": len(VARIANTS), "verdict_adopted": False,
    }, "operation counts are not exact")
    return {"run": run, "responses": active_responses + response_ids,
            "active_fixtures": list(ACTIVE), "metadata_variants": list(VARIANTS)}


def verify_profile(folder, profile, pins=ACCEPTED_SUITE):
    folder = Path(folder)
    plan, created, active_transcript, active_responses = verify_active(folder / "active", profile)
    result = verify_supplemental(folder, plan, created, active_transcript, active_responses, pins)
    return {"profile": profile, **result}


def verify_batch(root, pins=ACCEPTED_SUITE):
    root = Path(root)
    batch = read(root / "batch.json")
    require(batch == {
        "schema": "samlscope-ext01c-keycloak-batch-v1", "product": "keycloak",
        "profiles": list(PROFILES), "case": CASE, "metadata_variants": list(VARIANTS),
        "completed": batch.get("completed"), "verdict_adopted": False,
    }, "invalid EXT01.c batch manifest")
    require([item.get("profile") for item in batch["completed"]] == list(PROFILES),
            "four-profile EXT01.c campaign is incomplete")
    observations = [verify_profile(root / profile, profile, pins) for profile in PROFILES]
    require([item.get("run") for item in batch["completed"]]
            == [item["run"] for item in observations]
            and len({item["run"] for item in observations}) == len(PROFILES),
            "profiles are not bound to four independent Runs")
    return {"schema": "samlscope-ext01c-keycloak-acceptance-v1", "product": "keycloak",
            "case": CASE, "observations": observations, "count": len(observations)}


def diagnose_affiliation_profile(folder, profile, pins=ACCEPTED_SUITE):
    """Prove the observed blocker without converting it into a product verdict."""
    folder = Path(folder)
    plan, created, active_transcript, _ = verify_active(folder / "active", profile)
    run = created["id"]
    entity = "http://localhost:18080/p/" + plan["id"]
    metadata = folder / "metadata"
    runtime = folder / "supplemental-runtime"
    _verify_target_runtime(runtime, "keycloak", float(created["createdAt"]))
    _verify_suite_runtime(metadata, run, float(created["createdAt"]), pins)
    verify_runtime_code(metadata)
    before = read(folder / "supplemental-before.json")
    after = read(folder / "supplemental-after.json")
    require(before == after and before.get("client_query") == []
            and before.get("canonical_sha256") == sha(b"[]"),
            "diagnostic campaign was not restored")
    transcript = read(metadata / "transcript.json")
    require(transcript[:len(active_transcript)] == active_transcript
            and transcript == read(metadata / EVALUATION / "transcript-before.json")
            == read(metadata / EVALUATION / "transcript.json"),
            "diagnostic transcript was changed during formal evaluation")
    decoded = originals(metadata, transcript)
    operations = read(metadata / "operations.json")
    require([item.get("variant") for item in operations] == list(VARIANTS)
            and all(item.get("driver_exit") == 0 for item in operations[:-1])
            and operations[-1].get("driver_exit") != 0
            and operations[-1].get("continued_without_verdict") is True,
            "blocker is not isolated to affiliation")
    # The other twelve foreign-attribute locations and the baseline all imported, produced a
    # correlated Success, and were deleted. This prevents a generic browser/import outage from
    # being mislabeled as the affiliation blocker.
    for variant in VARIANTS[:-1]:
        record = read(metadata / variant / "import.json")
        flow = read(metadata / variant / "flow.json")
        require(record.get("status") == "success"
                and record.get("cleanup") == {"deleted_status": 204, "read_back_absent": True}
                and flow.get("run") == run and flow.get("variant") == variant
                and flow.get("correlated_success") is True,
                "non-affiliation control failed: " + variant)

    variant = VARIANTS[-1]
    member = metadata / variant
    fixture_raw = (member / "fixture.xml").read_bytes()
    require(operations[-1].get("fixture_sha256") == sha(fixture_raw),
            "affiliation operation/fixture hash mismatch")
    verify_metadata_fixture(variant, fixture_raw, entity)
    root = safe_xml(fixture_raw)
    entities = list(root.iter(MD + "EntityDescriptor"))
    require(root.tag == MD + "EntitiesDescriptor" and len(entities) == 2
            and sum(value.get("entityID") == entity for value in entities) == 1,
            "affiliation fixture is not the approved two-entity aggregate")
    record = read(member / "import.json")
    require(record.get("status") == "failure"
            and record.get("fixture", {}).get("sha256") == sha(fixture_raw)
            and record.get("fixture", {}).get("entity_id") == entity
            and record.get("steps", [{}])[0] == {"step": "file-selected", "ok": True, "detail": ""}
            and record.get("cleanup") == {"no_save_attempted": True, "read_back_absent": True}
            and "page.waitForFunction: Timeout" in record.get("failure_reason", "")
            and (not (member / "flow.json").exists()
                 or not (member / "flow.json").read_bytes()),
            "affiliation did not fail at the native pre-save parse boundary")
    fetches = [entry for entry in transcript
               if (entry.get("samlSummary") or {}).get("type") == "MetadataFetch"
               and (entry.get("samlSummary") or {}).get("variant") == variant]
    require(len(fetches) == 1, "affiliation fixture was not fetched exactly once")
    prepared = [entry for entry in transcript
                if (entry.get("samlSummary") or {}).get("type") == "MetadataPrepared"
                and (entry.get("samlSummary") or {}).get("variant") == variant]
    require(len(prepared) == 1 and prepared[0].get("correlationId") == fetches[0]["id"]
            and (prepared[0].get("samlSummary") or {}).get("fetchTranscriptId") == fetches[0]["id"]
            and prepared[0]["id"] in decoded and decoded[prepared[0]["id"]] == fixture_raw,
            "Suite did not prepare the exact affiliation original")
    urls = [entry.get("url", "") for entry in transcript
            if entry.get("direction") == "INBOUND" and entry.get("decodedSamlBytes", 0) > 0]
    require(not any("mdv=" + variant in value and "run=" + run in value for value in urls),
            "affiliation unexpectedly reached a protocol response")
    case = find_case(read(metadata / EVALUATION / "result.json"), CASE)
    require(case.get("outcome") == "NOT_VERIFIED" and case.get("verdict") == "NOT_VERIFIED"
            and case.get("reason_code") == "browser_fixture_partial",
            "incomplete affiliation was not retained as NOT_VERIFIED")
    return {
        "profile": profile, "run": run,
        "classification": "keycloak-native-import-multiple-entity-constraint",
        "category": "product-native-import-constraint",
        "suite_fixture_prepared": True, "native_save_attempted": False,
        "protocol_observation_available": False, "restored": True,
        "adoptable": False,
    }


def diagnose_affiliation(root, pins=ACCEPTED_SUITE):
    root = Path(root)
    batch = read(root / "batch.json")
    require([item.get("profile") for item in batch.get("completed", [])] == list(PROFILES),
            "diagnostic batch is incomplete")
    observations = [diagnose_affiliation_profile(root / profile, profile, pins)
                    for profile in PROFILES]
    require([item["run"] for item in observations]
            == [item["run"] for item in batch["completed"]], "diagnostic Run binding mismatch")
    return {
        "schema": "samlscope-ext01c-keycloak-affiliation-diagnosis-v1",
        "case": CASE, "variant": VARIANTS[-1], "classification": "product-native-import-constraint",
        "reason": ("Keycloak Import client does not select the requested entity from the approved "
                   "two-EntityDescriptor aggregate. Parsing stops before save; therefore no protocol "
                   "observation exists and the target outcome remains NOT_VERIFIED."),
        "observations": observations, "adopted": 0,
    }


def tamper_self_test(root, pins=ACCEPTED_SUITE):
    root = Path(root)
    source = root / PROFILES[0]

    def rejected(label, mutate, trial_pins=None):
        with tempfile.TemporaryDirectory(prefix="samlscope-ext01c-tamper-") as temporary:
            trial = Path(temporary) / "profile"
            shutil.copytree(source, trial)
            mutate(trial)
            try:
                verify_profile(trial, PROFILES[0], pins if trial_pins is None else trial_pins)
            except (ValueError, KeyError, OSError, ET.ParseError, zipfile.BadZipFile):
                return label
            raise AssertionError("tamper accepted: " + label)

    def write(path, value):
        Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

    def active_placement(folder):
        transcript = read(folder / "active/transcript.json")
        entry = next(item for item in transcript
                     if (item.get("samlSummary") or {}).get("scenario_case_id") == CASE
                     and (item.get("samlSummary") or {}).get("fixture_id") == "unknown-any-attribute")
        manifest = read(folder / "active/decoded-manifest.json")
        item = next(value for value in manifest if value["id"] == entry["id"])
        path = folder / "active" / item["file"]
        raw = path.read_bytes().replace(b"SubjectConfirmationData", b"SubjectConfirmationDatz", 2)
        path.write_bytes(raw)
        item["sha256"] = sha(raw)
        write(folder / "active/decoded-manifest.json", manifest)

    def metadata_placement(folder):
        member = folder / "metadata/foreign-attribute-entity"
        fixture = member / "fixture.xml"
        raw = fixture.read_bytes().replace(b"foreign:undefined", b"foreign:undefineX", 1)
        fixture.write_bytes(raw)
        operation = read(folder / "metadata/operations.json")
        target = next(item for item in operation if item["variant"] == "foreign-attribute-entity")
        target["fixture_sha256"] = sha(raw)
        write(folder / "metadata/operations.json", operation)

    def cleanup(folder):
        path = folder / "metadata/control/import.json"
        value = read(path); value["cleanup"]["read_back_absent"] = False; write(path, value)

    def run_swap(folder):
        path = folder / "metadata/control/flow.json"
        value = read(path); value["run"] = "run_00000000000000000000000000"; write(path, value)

    def transcript(folder):
        for path in (folder / "metadata/transcript.json",
                     folder / "metadata" / EVALUATION / "transcript-before.json",
                     folder / "metadata" / EVALUATION / "transcript.json"):
            value = read(path)
            value = [item for item in value
                     if (item.get("samlSummary") or {}).get("variant") != "foreign-attribute-entity"]
            write(path, value)

    def formal_result(folder):
        path = folder / "metadata" / EVALUATION / "result.json"
        value = read(path); case = find_case(value, CASE)
        case["outcome"] = case["verdict"] = "NOT_VERIFIED"; write(path, value)

    def restoration(folder):
        path = folder / "supplemental-after.json"
        value = read(path); value["client_query"] = [{"id": "remaining"}]; write(path, value)

    def profile(folder):
        path = folder / "active/plan.json"
        value = read(path); value["plan"]["plan"]["profile"] = "metadata_idp"; write(path, value)

    def response(folder):
        transcript_value = read(folder / "metadata/transcript.json")
        entry = next(item for item in transcript_value
                     if (item.get("samlSummary") or {}).get("metadataProbeAccepted") is True)
        manifest = read(folder / "metadata/decoded-manifest.json")
        item = next(value for value in manifest if value["id"] == entry["id"])
        path = folder / "metadata" / item["file"]
        raw = path.read_bytes().replace(b"Success", b"Failure", 1)
        path.write_bytes(raw); item["sha256"] = sha(raw)
        write(folder / "metadata/decoded-manifest.json", manifest)

    bad_pins = json.loads(json.dumps(pins))
    bad_pins["jars"]["runner"] = "0" * 64
    return [
        rejected("active-placement", active_placement),
        rejected("metadata-placement", metadata_placement),
        rejected("native-delete-readback", cleanup),
        rejected("Run-binding", run_swap),
        rejected("transcript-original", transcript),
        rejected("formal-result", formal_result),
        rejected("exact-restoration", restoration),
        rejected("profile-binding", profile),
        rejected("response-original", response),
        rejected("Suite-pin", lambda _: None, bad_pins),
    ]


def diagnostic_tamper_self_test(root, pins=ACCEPTED_SUITE):
    """Show that the blocker classification is also fail-closed."""
    source = Path(root) / PROFILES[0]

    def write(path, value):
        Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

    def rejected(label, mutate, trial_pins=None):
        with tempfile.TemporaryDirectory(prefix="samlscope-ext01c-diagnostic-tamper-") as temporary:
            trial = Path(temporary) / "profile"
            shutil.copytree(source, trial)
            mutate(trial)
            try:
                diagnose_affiliation_profile(
                    trial, PROFILES[0], pins if trial_pins is None else trial_pins)
            except (ValueError, KeyError, OSError, ET.ParseError, zipfile.BadZipFile):
                return label
            raise AssertionError("diagnostic tamper accepted: " + label)

    def cleanup(folder):
        path = folder / "metadata/foreign-attribute-affiliation/import.json"
        value = read(path); value["cleanup"]["read_back_absent"] = False; write(path, value)

    def fixture(folder):
        path = folder / "metadata/foreign-attribute-affiliation/fixture.xml"
        path.write_bytes(path.read_bytes().replace(b"foreign:undefined", b"foreign:undefineX", 1))

    def restoration(folder):
        path = folder / "supplemental-after.json"
        value = read(path); value["client_query"] = [{"id": "remaining"}]; write(path, value)

    def prepared_correlation(folder):
        for path in (folder / "metadata/transcript.json",
                     folder / "metadata" / EVALUATION / "transcript-before.json",
                     folder / "metadata" / EVALUATION / "transcript.json"):
            value = read(path)
            entry = next(item for item in value
                         if (item.get("samlSummary") or {}).get("type") == "MetadataPrepared"
                         and (item.get("samlSummary") or {}).get("variant") == VARIANTS[-1])
            entry["samlSummary"]["fetchTranscriptId"] = "tx_00000000000000000000000000"
            write(path, value)

    def false_conclusion(folder):
        path = folder / "metadata" / EVALUATION / "result.json"
        value = read(path); case = find_case(value, CASE)
        case["outcome"] = "SATISFIED"; case["verdict"] = "PASS"; write(path, value)

    bad_pins = json.loads(json.dumps(pins)); bad_pins["jars"]["saml"] = "0" * 64
    return [
        rejected("native-absence-readback", cleanup),
        rejected("fixture-original", fixture),
        rejected("exact-restoration", restoration),
        rejected("prepared-fetch-correlation", prepared_correlation),
        rejected("false-product-conclusion", false_conclusion),
        rejected("Suite-pin", lambda _: None, bad_pins),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--tamper-self-test", action="store_true")
    parser.add_argument("--diagnose-affiliation", action="store_true")
    args = parser.parse_args()
    result = (diagnose_affiliation(args.root.resolve()) if args.diagnose_affiliation
              else verify_batch(args.root.resolve()))
    if args.tamper_self_test:
        result["tamper_rejected"] = (diagnostic_tamper_self_test(args.root.resolve())
                                     if args.diagnose_affiliation
                                     else tamper_self_test(args.root.resolve()))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
