#!/usr/bin/env python3
"""Fail-closed verifier for the four-profile Shibboleth IIP-EXT01.c campaign."""

import argparse
import json
from pathlib import Path
import re
import shutil
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile

from verify_ext01c_keycloak_acceptance import (
    ACTION_RE, ACTIVE, CASE, MD, METADATA_PLACEMENTS, PROFILES, VARIANTS,
    originals, read, require, response_for, safe_xml, sha, verify_active_request,
    verify_metadata_fixture, verify_runtime_code,
)
from verify_terminal_http_acceptance import (
    EVALUATION, _verify_configuration_restoration, _verify_suite_runtime,
    _verify_target_runtime, find_case,
)


ACCEPTED_SUITE = {
    "image_id": "sha256:846083123e759f24e88a89f9badba50c4e4cd110b3b13563e8295c9829886cdb",
    "jars": {
        "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe",
        "runner": "94dca2c3c134cf2ad3c30fb4a271448b729c7327b464bff0070a83b45b157dae",
        "saml": "cbfdb79f54ed967f58c8153eb8d0dda350016030c552d0aaee3fc30988d3bf73",
    },
}
TARGET_IMAGE = "sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a"
TARGET_ENTITY = "http://localhost:18280/idp/shibboleth"
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
XSI = "{http://www.w3.org/2001/XMLSchema-instance}"
SHIB_MD = "{urn:mace:shibboleth:2.0:metadata}"


def verify_active(folder, profile):
    plan = read(folder / "plan.json")["plan"]["plan"]
    created = read(folder / "created.json")["run"]
    run = created["id"]
    require(RUN_RE.fullmatch(run or "") and created["planId"] == plan["id"],
            "active Plan/Run mismatch")
    require(plan["profile"] == profile and plan["target"]["kind"] == "IDP"
            and plan["target"]["entityId"] == TARGET_ENTITY
            and plan.get("requestSigningMode") == "REQUIRED", "wrong active target/profile")
    _verify_target_runtime(folder, "shibboleth", float(created["createdAt"]))
    require(read(folder / "target-runtime-start.json")["binding"]["image_id"] == TARGET_IMAGE,
            "untrusted Shibboleth image")
    _verify_configuration_restoration(folder, "shibboleth")

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
            "active-only result did not remain fail-closed partial")
    evidence = {item.get("reference") for item in partial.get("evidence", [])
                if item.get("kind") == "transcript"}
    require(evidence == set(responses), "active partial evidence does not bind exact responses")
    require((folder / "target-metadata.xml").is_file(), "active target metadata original missing")
    return plan, created, transcript, responses


def verify_provider_configuration(metadata, run):
    original = (metadata / "original-providers.xml").read_bytes()
    configured = (metadata / "configured-providers.xml").read_bytes()
    configured_readback = (metadata / "configured-providers-readback.xml").read_bytes()
    final = (metadata / "final-providers.xml").read_bytes()
    require(configured == configured_readback, "provider configuration read-back mismatch")
    require(original == final, "provider configuration bytes were not restored")
    restoration = read(metadata / "restoration.json")
    require(restoration == {
        "restored": True,
        "temporary_file_removed": True,
        "signature_certificate_removed": True,
        "original_sha256": sha(original),
        "final_sha256": sha(final),
    }, "metadata restoration receipt mismatch")

    root = safe_xml(configured)
    providers = [child for child in list(root)
                 if child.tag == SHIB_MD + "MetadataProvider"
                 and child.get("id") == "Algorithm" + run]
    require(len(providers) == 1, "temporary filesystem provider identity mismatch")
    expected_path = "/opt/reference-idp/metadata/algorithm-" + run + ".xml"
    require(providers[0].get(XSI + "type") == "FilesystemMetadataProvider"
            and providers[0].get("metadataFile") == expected_path,
            "campaign did not use the native FilesystemMetadataProvider path")
    return original, expected_path


def verify_native_operations(metadata, expected_path):
    operations = read(metadata / "native-operations.json")
    expected = []
    for index, variant in enumerate(VARIANTS):
        expected.append(("write", "fixture-" + variant, expected_path))
        if index == 0:
            expected.append(("write", "provider-apply",
                             "/opt/reference-idp/conf/metadata-providers.xml"))
        expected.append(("reload", "import-" + variant, None))
    expected.extend((
        ("write", "restore-provider", "/opt/reference-idp/conf/metadata-providers.xml"),
        ("reload", "restore", None),
    ))
    require(len(operations) == len(expected), "native operation count mismatch")
    for record, (kind, label, path) in zip(operations, expected, strict=True):
        require(record.get("operation") == kind and record.get("label") == label,
                "native operation order/label mismatch")
        if kind == "write":
            require(record.get("path") == path and record.get("read_back") is True
                    and record.get("sha256") == record.get("read_back_sha256")
                    and re.fullmatch(r"[0-9a-f]{64}", record.get("sha256", ""))
                    and record.get("bytes", 0) > 0,
                    "native write lacks exact read-back")
            if label.startswith("fixture-"):
                variant = label.removeprefix("fixture-")
                member = metadata / variant
                raw = (member / "fixture.xml").read_bytes()
                require((member / "fixture-readback.xml").read_bytes() == raw
                        and record.get("sha256") == sha(raw)
                        and record.get("read_back_file") == variant + "/fixture-readback.xml",
                        "fixture native read-back mismatch: " + variant)
        else:
            require(record.get("completed") is True, "metadata resolver reload was not completed")
    return operations


def verify_supplemental(folder, plan, created, active_transcript, active_responses, pins):
    metadata = folder / "metadata"
    runtime = folder / "supplemental-runtime"
    run = created["id"]
    entity = "http://localhost:18080/p/" + plan["id"]

    _verify_target_runtime(runtime, "shibboleth", float(created["createdAt"]))
    require(read(runtime / "target-runtime-start.json")["binding"]["image_id"] == TARGET_IMAGE,
            "untrusted supplemental Shibboleth image")
    require(read(folder / "active/target-runtime-start.json")["binding"]
            == read(runtime / "target-runtime-start.json")["binding"],
            "Shibboleth runtime identity changed between active and metadata phases")
    before = read(folder / "supplemental-before.json")
    after = read(folder / "supplemental-after.json")
    require(before == after and before.get("run") == run
            and before.get("configuration_path") == "/opt/reference-idp/conf/metadata-providers.xml"
            and before.get("temporary_path") == "/opt/reference-idp/metadata/algorithm-" + run + ".xml"
            and before.get("temporary_path_absent") is True,
            "supplemental product state was not exactly restored")

    _verify_suite_runtime(metadata, run, float(created["createdAt"]), pins)
    verify_runtime_code(metadata)
    require(read(metadata / "created.json") == {
        "run": {"id": run, "planId": plan["id"], "createdAt": created["createdAt"]},
        "reused": True,
    }, "metadata campaign was not attached to the exact active Run")
    original, expected_path = verify_provider_configuration(metadata, run)
    require(before.get("configuration_sha256") == sha(original)
            and before.get("configuration_bytes") == len(original),
            "external restoration read-back differs from provider original")
    native_operations = verify_native_operations(metadata, expected_path)

    confirmation = read(metadata / "attempt-confirmation.json")
    confirmed = [item for item in confirmation.get("completed", []) if item.get("caseId") == CASE]
    require(confirmed == [{"caseId": CASE, "outcome": "SATISFIED"}],
            "attempt confirmation did not derive exactly one EXT01.c satisfaction")
    require(all(item.get("caseId") == CASE or item.get("outcome") == "NOT_VERIFIED"
                for item in confirmation.get("completed", [])),
            "attempt confirmation concluded an unrelated case")

    transcript = read(metadata / "transcript.json")
    evaluation = metadata / EVALUATION
    require(transcript == read(evaluation / "transcript-before.json")
            == read(evaluation / "transcript.json"), "formal re-evaluation changed transcript")
    require(transcript[:len(active_transcript)] == active_transcript,
            "supplemental campaign changed the active transcript prefix")
    require(all(entry.get("runId") == run for entry in transcript), "foreign Run in final transcript")
    decoded = originals(metadata, transcript)
    operations = read(metadata / "operations.json")
    require([item.get("variant") for item in operations] == list(VARIANTS)
            and all(item.get("status") == "success" and item.get("restored") is True
                    for item in operations),
            "metadata operation list is incomplete, failed, or reordered")

    response_ids = []
    evidence_ids = []
    for variant, operation in zip(VARIANTS, operations, strict=True):
        member = metadata / variant
        fixture = (member / "fixture.xml").read_bytes()
        fixture_hash = sha(fixture)
        require(operation == read(member / "import.json"), "operation/member record mismatch")
        require(operation.get("product") == "shibboleth"
                and operation.get("import_path") == "native-filesystem-provider"
                and operation.get("run") == run and operation.get("entity_id") == entity
                and operation.get("fixture_sha256") == fixture_hash
                and operation.get("configuration_read_back") is True
                and operation.get("provider_reloaded") is True,
                "native import record is incomplete: " + variant)
        require((member / "fixture-readback.xml").read_bytes() == fixture,
                "native fixture read-back differs: " + variant)
        require((member / ("import-" + variant + "-reload.log")).is_file(),
                "resolver reload original is missing: " + variant)
        verify_metadata_fixture(variant, fixture, entity)

        fetches = [entry for entry in transcript
                   if entry.get("direction") == "INBOUND"
                   and (entry.get("samlSummary") or {}).get("type") == "MetadataFetch"
                   and (entry.get("samlSummary") or {}).get("variant") == variant]
        require(len(fetches) == 1, "metadata variant lacks one unique fetch: " + variant)
        fetch = fetches[0]
        prepared = [entry for entry in transcript
                    if entry.get("direction") == "OUTBOUND"
                    and (entry.get("samlSummary") or {}).get("type") == "MetadataPrepared"
                    and (entry.get("samlSummary") or {}).get("variant") == variant
                    and (entry.get("samlSummary") or {}).get("fetchTranscriptId") == fetch["id"]]
        require(len(prepared) == 1 and prepared[0].get("correlationId") == fetch["id"],
                "metadata prepared/fetch correlation mismatch: " + variant)
        prepared_entry = prepared[0]
        require(prepared_entry["id"] in decoded and decoded[prepared_entry["id"]] == fixture
                and prepared_entry.get("decodedSamlBytes") == len(fixture)
                and prepared_entry.get("bodyBytes") == len(fixture)
                and (prepared_entry.get("samlSummary") or {}).get("metadataSha256") == fixture_hash,
                "prepared metadata original mismatch: " + variant)

        flow = read(member / "flow.json")
        exchange = flow.get("positive_exchange") or {}
        require(flow.get("run") == run and flow.get("variant") == variant
                and flow.get("correlated_success") is True and exchange.get("success") is True,
                "native post-import flow is not a correlated Success: " + variant)
        negative = flow.get("negative_control") or {}
        require(negative.get("source") == "suite"
                and negative.get("correlated_success") is False
                and (negative.get("exchange") or {}).get("success") is False,
                "signature control advanced or produced a correlated Success: " + variant)
        request_id = exchange.get("request_id")
        requests = [entry for entry in transcript if entry.get("direction") == "OUTBOUND"
                    and (entry.get("samlSummary") or {}).get("id") == request_id]
        require(len(requests) == 1 and requests[0]["id"] in decoded,
                "metadata flow request original missing: " + variant)
        expected_url = (entity + "/sp/acs/0?mdv=" + urllib.parse.quote(variant)
                        + "&run=" + urllib.parse.quote(run))
        response = response_for(transcript, decoded, request_id, expected_url)
        require((response.get("samlSummary") or {}).get("metadataProbeAccepted") is True,
                "metadata response lacks Suite acceptance marker: " + variant)
        require(exchange.get("transcript_ids") == [requests[0]["id"], response["id"]],
                "flow receipt/transcript mismatch: " + variant)
        response_ids.append(response["id"])
        evidence_ids.extend([fetch["id"], requests[0]["id"], response["id"]])

    case = find_case(read(evaluation / "result.json"), CASE)
    require(case.get("outcome") == "SATISFIED" and case.get("verdict") == "PASS"
            and case.get("reason_code") == "browser_fixture_satisfied"
            and case.get("attested") is False and case.get("evidence_class") == "OPERATOR_ASSISTED",
            "formal EXT01.c result is not the non-attested browser PASS")
    evidence = [item.get("reference") for item in case.get("evidence", [])
                if item.get("kind") == "transcript"]
    normalized_evidence = [value.removeprefix("transcript:") for value in evidence]
    require(set(normalized_evidence) == set(active_responses + evidence_ids)
            and len(evidence) == len(active_responses) + len(evidence_ids),
            "formal result does not bind exact active and metadata all-of evidence")

    metadata_counts = read(metadata / "operation-counts.json")
    require(metadata_counts == {
        "restored": True, "human_operations": 0, "product_restarts": 0,
        "metadata_fixture_writes": len(VARIANTS), "provider_apply_writes": 1,
        "restoration_writes": 1, "reloads": len(VARIANTS) + 1,
        "protocol_roundtrips": len(VARIANTS), "verdict_adopted": False,
    }, "metadata operation counts are not exact")
    counts = read(folder / "operation-counts.json")
    require(counts == {
        "restored": True, "human_operations": 0, "product_restarts": 0,
        "active_configuration_writes": 3, "active_restoration_writes": 1,
        "active_reloads": 2, "active_protocol_roundtrips": len(ACTIVE),
        "metadata_fixture_writes": len(VARIANTS), "metadata_provider_apply_writes": 1,
        "metadata_restoration_writes": 1, "metadata_reloads": len(VARIANTS) + 1,
        "metadata_protocol_roundtrips": len(VARIANTS), "verdict_adopted": False,
        "protocol_attempt_confirmation_calls": 1,
    }, "combined operation counts are not exact")
    require(len(native_operations) == len(VARIANTS) * 2 + 3,
            "unexpected native operation cardinality")
    return {"run": run, "responses": active_responses + response_ids,
            "active_fixtures": list(ACTIVE), "metadata_variants": list(VARIANTS)}


def verify_profile(folder, profile, pins=ACCEPTED_SUITE):
    folder = Path(folder)
    plan, created, transcript, responses = verify_active(folder / "active", profile)
    return {"profile": profile,
            **verify_supplemental(folder, plan, created, transcript, responses, pins)}


def verify_batch(root, pins=ACCEPTED_SUITE):
    root = Path(root)
    batch = read(root / "batch.json")
    require(batch == {
        "schema": "samlscope-ext01c-shibboleth-batch-v1", "product": "shibboleth",
        "profiles": list(PROFILES), "case": CASE, "metadata_variants": list(VARIANTS),
        "completed": batch.get("completed"), "verdict_adopted": False,
    }, "invalid EXT01.c Shibboleth batch manifest")
    require([item.get("profile") for item in batch["completed"]] == list(PROFILES),
            "four-profile campaign is incomplete")
    observations = [verify_profile(root / profile, profile, pins) for profile in PROFILES]
    require([item.get("run") for item in batch["completed"]]
            == [item["run"] for item in observations]
            and len({item["run"] for item in observations}) == len(PROFILES),
            "profiles are not bound to four independent Runs")
    return {"schema": "samlscope-ext01c-shibboleth-acceptance-v1",
            "product": "shibboleth", "case": CASE,
            "observations": observations, "count": len(observations)}


def tamper_self_test(root, pins=ACCEPTED_SUITE):
    source = Path(root) / PROFILES[0]

    def write(path, value):
        Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

    def rejected(label, mutate, trial_pins=None):
        with tempfile.TemporaryDirectory(prefix="samlscope-ext01c-shib-tamper-") as temporary:
            trial = Path(temporary) / "profile"
            shutil.copytree(source, trial)
            mutate(trial)
            try:
                verify_profile(trial, PROFILES[0], pins if trial_pins is None else trial_pins)
            except (ValueError, KeyError, OSError, ET.ParseError, zipfile.BadZipFile):
                return label
            raise AssertionError("tamper accepted: " + label)

    def active_placement(folder):
        transcript = read(folder / "active/transcript.json")
        entry = next(item for item in transcript
                     if (item.get("samlSummary") or {}).get("scenario_case_id") == CASE
                     and (item.get("samlSummary") or {}).get("fixture_id") == "unknown-any-attribute")
        manifest = read(folder / "active/decoded-manifest.json")
        item = next(value for value in manifest if value["id"] == entry["id"])
        path = folder / "active" / item["file"]
        raw = path.read_bytes().replace(b"SubjectConfirmationData", b"SubjectConfirmationDatz", 2)
        path.write_bytes(raw); item["sha256"] = sha(raw)
        write(folder / "active/decoded-manifest.json", manifest)

    def metadata_placement(folder):
        path = folder / "metadata/foreign-attribute-entity/fixture.xml"
        raw = path.read_bytes().replace(b"foreign:undefined", b"foreign:undefineX", 1)
        path.write_bytes(raw)
        (folder / "metadata/foreign-attribute-entity/fixture-readback.xml").write_bytes(raw)
        records = read(folder / "metadata/operations.json")
        next(item for item in records if item["variant"] == "foreign-attribute-entity")["fixture_sha256"] = sha(raw)
        write(folder / "metadata/operations.json", records)
        write(folder / "metadata/foreign-attribute-entity/import.json",
              next(item for item in records if item["variant"] == "foreign-attribute-entity"))

    def readback(folder):
        path = folder / "metadata/foreign-attribute-affiliation/fixture-readback.xml"
        path.write_bytes(path.read_bytes() + b"\n")

    def restoration(folder):
        path = folder / "supplemental-after.json"
        value = read(path); value["configuration_sha256"] = "0" * 64; write(path, value)

    def run_binding(folder):
        path = folder / "metadata/control/flow.json"
        value = read(path); value["run"] = "run_00000000000000000000000000"; write(path, value)

    def transcript(folder):
        for path in (folder / "metadata/transcript.json",
                     folder / "metadata" / EVALUATION / "transcript-before.json",
                     folder / "metadata" / EVALUATION / "transcript.json"):
            value = [item for item in read(path)
                     if (item.get("samlSummary") or {}).get("variant") != "foreign-attribute-affiliation"]
            write(path, value)

    def result(folder):
        path = folder / "metadata" / EVALUATION / "result.json"
        value = read(path); case = find_case(value, CASE)
        case["outcome"] = case["verdict"] = "NOT_VERIFIED"; write(path, value)

    def reload(folder):
        path = folder / "metadata/native-operations.json"
        value = read(path); next(item for item in value if item.get("operation") == "reload")["completed"] = False
        write(path, value)

    bad_pins = json.loads(json.dumps(pins)); bad_pins["jars"]["runner"] = "0" * 64
    return [
        rejected("active-placement", active_placement),
        rejected("metadata-placement", metadata_placement),
        rejected("native-readback", readback),
        rejected("exact-restoration", restoration),
        rejected("Run-binding", run_binding),
        rejected("transcript-original", transcript),
        rejected("formal-result", result),
        rejected("resolver-reload", reload),
        rejected("Suite-pin", lambda _: None, bad_pins),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--tamper-self-test", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    result = verify_batch(root)
    if args.tamper_self_test:
        result["tamper_rejected"] = tamper_self_test(root)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
