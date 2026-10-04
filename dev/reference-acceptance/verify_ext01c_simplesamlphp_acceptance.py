#!/usr/bin/env python3
"""Fail-closed verifier for SimpleSAMLphp IIP-EXT01.c in four profiles."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile

from verify_ext01c_keycloak_acceptance import (
    ACTION_RE, ACTIVE, CASE, VARIANTS, originals, response_for, safe_xml,
    verify_active_request, verify_metadata_fixture, verify_runtime_code,
)
from verify_terminal_http_acceptance import (
    EVALUATION, _verify_configuration_restoration, _verify_suite_runtime,
    _verify_target_runtime, find_case,
)


PROFILES = ("browser_sso_idp", "ecp_idp", "metadata_idp", "single_logout_idp")
TARGET_ENTITY = "http://localhost:18380/idp"
TARGET_IMAGE = "sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa"
ACCEPTED_SUITE = {
    "image_id": "sha256:846083123e759f24e88a89f9badba50c4e4cd110b3b13563e8295c9829886cdb",
    "jars": {
        "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe",
        "runner": "94dca2c3c134cf2ad3c30fb4a271448b729c7327b464bff0070a83b45b157dae",
        "saml": "cbfdb79f54ed967f58c8153eb8d0dda350016030c552d0aaee3fc30988d3bf73",
    },
}
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")


def require(value, detail):
    if not value:
        raise ValueError(detail)


def read(path):
    return json.loads(Path(path).read_text())


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_active(folder, profile):
    plan = read(folder / "plan.json")["plan"]["plan"]
    created = read(folder / "created.json")["run"]
    run = created["id"]
    require(RUN_RE.fullmatch(run or "") and created["planId"] == plan["id"],
            "active Plan/Run mismatch")
    require(plan["profile"] == profile and plan["target"]["kind"] == "IDP"
            and plan["target"]["entityId"] == TARGET_ENTITY
            and plan.get("requestSigningMode") == "REQUIRED", "wrong active target/profile")
    _verify_target_runtime(folder, "simplesamlphp", float(created["createdAt"]))
    require(read(folder / "target-runtime-start.json")["binding"]["image_id"] == TARGET_IMAGE,
            "untrusted SimpleSAMLphp image")
    _verify_configuration_restoration(folder, "simplesamlphp")

    transcript = read(folder / "transcript.json")
    require(all(entry.get("runId") == run for entry in transcript), "foreign Run in active transcript")
    decoded = originals(folder, transcript)
    outbound = [entry for entry in transcript if entry.get("direction") == "OUTBOUND"
                and (entry.get("samlSummary") or {}).get("scenario_case_id") == CASE]
    require(len(outbound) == len(ACTIVE), "wrong active EXT01.c fixture count")
    responses, seen = [], []
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


def verify_state(profile_folder, profile, run):
    before = read(profile_folder / "supplemental-before.json")
    after = read(profile_folder / "supplemental-after.json")
    require(before == after == {
        "profile": profile, "run": run,
        "host_sha256": before.get("host_sha256"),
        "product_sha256": before.get("product_sha256"),
        "bytes": before.get("bytes"), "host_product_equal": True,
    }, "supplemental SimpleSAMLphp state was not exactly restored")
    require(re.fullmatch(r"[0-9a-f]{64}", before["host_sha256"] or "")
            and before["host_sha256"] == before["product_sha256"]
            and isinstance(before["bytes"], int) and before["bytes"] > 0,
            "supplemental state digest is invalid")


def verify_native_record(metadata, variant, operation, entity, original):
    member = metadata / variant
    fixture_raw = (member / "fixture.xml").read_bytes()
    fixture_hash = sha(fixture_raw)
    require(operation.get("variant") == variant and operation.get("fixture_sha256") == fixture_hash,
            "operation/fixture hash mismatch: " + variant)
    verify_metadata_fixture(variant, fixture_raw, entity)
    record = read(member / "import.json")
    require(record.get("variant") == variant and record.get("product") == "simplesamlphp"
            and record.get("import_path") == "native-parser-cli"
            and record.get("fixture_sha256") == fixture_hash
            and record.get("restored") is True and record.get("restoration_pending") is False,
            "native parser record identity/restoration mismatch: " + variant)
    stderr = (member / "parser.stderr").read_bytes()
    stdout = (member / "parser.stdout").read_bytes()
    require(record.get("parser_stderr_sha256") == sha(stderr)
            and record.get("parser_stderr_bytes") == len(stderr),
            "parser stderr original mismatch: " + variant)
    if record.get("status") != "success":
        return record, None, fixture_raw

    parsed_raw = (member / "parser-output.json").read_bytes()
    require(parsed_raw == stdout and record.get("parser_returncode") == 0
            and record.get("parser_output_sha256") == sha(parsed_raw)
            and record.get("parser_output_bytes") == len(parsed_raw),
            "parser output original mismatch: " + variant)
    parsed = json.loads(parsed_raw)
    require(parsed.get("entity_id") == entity and parsed.get("validate_authnrequest") is True
            and record.get("entity_id") == entity and record.get("validate_authnrequest") is True,
            "native parser did not select the expected signed SP: " + variant)
    configured = (member / "configuration-readback.php").read_bytes()
    expected = original + b"\n" + parsed["php"].encode() + b"\n"
    require(configured == expected
            and record.get("configuration_sha256") == sha(configured)
            and record.get("configuration_read_back_sha256") == sha(configured)
            and record.get("configuration_read_back_bytes") == len(configured)
            and record.get("configuration_written") is True
            and record.get("configuration_read_back") is True,
            "native configuration read-back mismatch: " + variant)
    return record, parsed, fixture_raw


def verify_prepared(transcript, decoded, variant, fixture_raw):
    fetches = [entry for entry in transcript if entry.get("direction") == "INBOUND"
               and (entry.get("samlSummary") or {}).get("type") == "MetadataFetch"
               and (entry.get("samlSummary") or {}).get("variant") == variant]
    require(len(fetches) == 1, "metadata variant lacks unique fetch: " + variant)
    fetch = fetches[0]
    prepared = [entry for entry in transcript if entry.get("direction") == "OUTBOUND"
                and (entry.get("samlSummary") or {}).get("type") == "MetadataPrepared"
                and (entry.get("samlSummary") or {}).get("variant") == variant
                and (entry.get("samlSummary") or {}).get("fetchTranscriptId") == fetch["id"]]
    require(len(prepared) == 1 and prepared[0].get("correlationId") == fetch["id"],
            "metadata prepared/fetch correlation mismatch: " + variant)
    item = prepared[0]
    require(item["id"] in decoded and decoded[item["id"]] == fixture_raw
            and item.get("decodedSamlBytes") == len(fixture_raw)
            and item.get("bodyBytes") == len(fixture_raw)
            and (item.get("samlSummary") or {}).get("metadataSha256") == sha(fixture_raw),
            "metadata prepared original mismatch: " + variant)
    return fetch, item


def verify_success_flow(metadata, variant, run, entity, transcript, decoded):
    flow = read(metadata / variant / "flow.json")
    exchange = flow.get("positive_exchange") or {}
    require(flow.get("run") == run and flow.get("variant") == variant
            and flow.get("correlated_success") is True and exchange.get("success") is True,
            "post-import flow is not a correlated success: " + variant)
    request_id = exchange.get("request_id")
    requests = [entry for entry in transcript if entry.get("direction") == "OUTBOUND"
                and (entry.get("samlSummary") or {}).get("id") == request_id]
    require(len(requests) == 1 and requests[0]["id"] in decoded,
            "metadata flow request original missing: " + variant)
    expected_url = (entity + "/sp/acs/0?mdv=" + urllib.parse.quote(variant)
                    + "&run=" + urllib.parse.quote(run))
    response = response_for(transcript, decoded, request_id, expected_url)
    require((response.get("samlSummary") or {}).get("metadataProbeAccepted") is True
            and exchange.get("transcript_ids") == [requests[0]["id"], response["id"]],
            "flow receipt/transcript mismatch: " + variant)
    return response["id"]


def verify_supplemental(profile_folder, profile, plan, created, active_transcript,
                        active_responses, pins):
    metadata = profile_folder / "metadata"
    runtime = profile_folder / "supplemental-runtime"
    run = created["id"]
    entity = "http://localhost:18080/p/" + plan["id"]
    verify_state(profile_folder, profile, run)
    _verify_target_runtime(runtime, "simplesamlphp", float(created["createdAt"]))
    require(read(runtime / "target-runtime-start.json")["binding"]["image_id"] == TARGET_IMAGE,
            "untrusted supplemental SimpleSAMLphp image")
    _verify_suite_runtime(metadata, run, float(created["createdAt"]), pins)
    verify_runtime_code(metadata)

    transcript = read(metadata / "transcript.json")
    evaluation = metadata / EVALUATION
    require(transcript == read(evaluation / "transcript-before.json")
            == read(evaluation / "transcript.json"), "formal re-evaluation changed transcript")
    require(transcript[:len(active_transcript)] == active_transcript
            and all(entry.get("runId") == run for entry in transcript),
            "supplemental campaign changed the active prefix or mixed Runs")
    decoded = originals(metadata, transcript)
    operations = read(metadata / "operations.json")
    require([item.get("variant") for item in operations] == list(VARIANTS),
            "metadata operation list is incomplete/reordered")
    original = (metadata / "original-sp-config.php").read_bytes()
    final = (metadata / "final-sp-config.php").read_bytes()
    restoration = read(metadata / "restoration.json")
    require(original == final
            and restoration.get("restored") is True
            and restoration.get("original_sha256") == restoration.get("final_sha256") == sha(original)
            and restoration.get("product_original_sha256")
                == restoration.get("product_final_sha256") == sha(original),
            "metadata batch did not restore exact SimpleSAMLphp bytes")

    success_responses, evidence_ids, failures = [], [], []
    for variant, operation in zip(VARIANTS, operations, strict=True):
        record, _, fixture_raw = verify_native_record(metadata, variant, operation, entity, original)
        fetch, _ = verify_prepared(transcript, decoded, variant, fixture_raw)
        if record.get("status") == "success":
            response_id = verify_success_flow(metadata, variant, run, entity, transcript, decoded)
            success_responses.append(response_id)
            evidence_ids.extend([fetch["id"], response_id])
        else:
            failures.append(variant)
            require(record.get("parser_returncode") not in {None, 0}
                    and record.get("reason") == "Product native parser rejected fixture"
                    and record.get("continued_without_verdict") is True
                    and not (metadata / variant / "flow.json").exists()
                    and not (metadata / variant / "configuration-readback.php").exists(),
                    "parser failure was promoted or mutated product state: " + variant)

    counts = read(profile_folder / "operation-counts.json")
    metadata_counts = read(metadata / "operation-counts.json")
    require(counts == {
        "restored": True, "human_operations": 0, "product_restarts": 0,
        "active_configuration_write_attempts": 2,
        "active_restoration_write_attempts": 1,
        "active_protocol_roundtrips": 3,
        "metadata_native_parser_invocations": len(VARIANTS),
        "metadata_configuration_apply_writes": len(VARIANTS) - len(failures),
        "metadata_restoration_writes": 1,
        "metadata_protocol_roundtrips": len(VARIANTS) - len(failures),
        "verdict_adopted": False,
    } and metadata_counts.get("native_parser_invocations") == len(VARIANTS)
      and metadata_counts.get("configuration_apply_writes") == len(VARIANTS) - len(failures)
      and metadata_counts.get("protocol_roundtrips") == len(VARIANTS) - len(failures)
      and metadata_counts.get("restoration_writes") == 1
      and metadata_counts.get("product_restarts") == metadata_counts.get("human_operations") == 0
      and metadata_counts.get("restored") is True,
      "operation counts are not exact")
    require((metadata / "target-metadata.xml").read_bytes()
            == (profile_folder / "active/target-metadata.xml").read_bytes(),
            "target metadata changed between active and supplemental capture")

    case = find_case(read(evaluation / "result.json"), CASE)
    evidence = [item.get("reference") for item in case.get("evidence", [])
                if item.get("kind") == "transcript"]
    if not failures:
        expected_evidence = set(active_responses + evidence_ids)
        require(set(evidence) == expected_evidence and len(evidence) == len(expected_evidence),
                "formal PASS does not bind exact completed all-of evidence")
        require(case.get("outcome") == "SATISFIED" and case.get("verdict") == "PASS"
                and case.get("reason_code") == "browser_fixture_satisfied"
                and case.get("attested") is False and case.get("evidence_class") == "PROTOCOL_OBSERVED",
                "complete EXT01.c result is not protocol-observed PASS")
        classification = "adopted"
    else:
        require(failures == ["foreign-attribute-authz"],
                "unexpected native parser failure set")
        stderr = (metadata / failures[0] / "parser.stderr").read_text(errors="replace")
        require("PDPDescriptor" in stderr
                and "Must have at least one AuthzService in PDPDescriptor" in stderr,
                "AuthzService parser blocker is not the observed native failure")
        # A native-parser stop provides no correlated protocol behavior for this member.  It is
        # therefore an observation precondition blocker for the all-of case, never a target FAIL.
        require(case.get("outcome") == "NOT_VERIFIED"
                and case.get("verdict") == "NOT_VERIFIED"
                and case.get("reason_code") == "browser_fixture_partial",
                "incomplete native parser matrix was not retained as NOT_VERIFIED")
        # A partial parent-case result is deliberately not allowed to adopt the independently
        # collected native-parser successes.  Its formal evidence therefore remains the exact
        # three active responses.  The verifier above still proves every successful metadata
        # fetch/fixture/response from originals, but none of those observations can replace the
        # missing AuthzService member of the approved all-of matrix.
        require(set(evidence) == set(active_responses) and len(evidence) == len(active_responses),
                "partial formal result adopted incomplete metadata evidence")
        diagnostics = case.get("diagnostics") or {}
        expected_missing = ["control", *sorted(VARIANTS[1:])]
        require(diagnostics.get("metadata_attribute_fixtures") == sorted(VARIANTS[1:])
                and diagnostics.get("metadata_attribute_missing_fetches") == expected_missing
                and diagnostics.get("metadata_attribute_missing_acceptance") == expected_missing,
                "partial formal diagnostics do not retain the complete missing matrix")
        classification = "native-parser-precondition"
    return {"run": run, "classification": classification, "failed_variants": failures,
            "responses": active_responses + success_responses,
            "active_fixtures": list(ACTIVE), "metadata_variants": list(VARIANTS)}


def verify_profile(folder, profile, pins=ACCEPTED_SUITE):
    folder = Path(folder)
    plan, created, active_transcript, active_responses = verify_active(folder / "active", profile)
    result = verify_supplemental(
        folder, profile, plan, created, active_transcript, active_responses, pins)
    return {"profile": profile, **result}


def verify_batch(root, pins=ACCEPTED_SUITE):
    root = Path(root)
    batch = read(root / "batch.json")
    require(batch == {
        "schema": "samlscope-ext01c-simplesamlphp-batch-v1", "product": "simplesamlphp",
        "profiles": list(PROFILES), "case": CASE, "metadata_variants": list(VARIANTS),
        "completed": batch.get("completed"), "verdict_adopted": False,
    }, "invalid EXT01.c SimpleSAMLphp batch manifest")
    require([item.get("profile") for item in batch["completed"]] == list(PROFILES),
            "four-profile EXT01.c campaign is incomplete")
    observations = [verify_profile(root / profile, profile, pins) for profile in PROFILES]
    require([item.get("run") for item in batch["completed"]]
            == [item["run"] for item in observations]
            and len({item["run"] for item in observations}) == len(PROFILES),
            "profiles are not bound to four independent Runs")
    count = sum(item["classification"] == "adopted" for item in observations)
    return {"schema": "samlscope-ext01c-simplesamlphp-acceptance-v1",
            "product": "simplesamlphp", "case": CASE,
            "observations": observations, "count": count}


def tamper_self_test(root, pins=ACCEPTED_SUITE):
    source = Path(root) / PROFILES[0]

    def write(path, value):
        Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

    def rejected(label, mutate, trial_pins=None):
        with tempfile.TemporaryDirectory(prefix="samlscope-ext01c-ssp-tamper-") as temporary:
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
        member = folder / "metadata/foreign-attribute-entity"
        fixture = member / "fixture.xml"
        raw = fixture.read_bytes().replace(b"foreign:undefined", b"foreign:undefineX", 1)
        fixture.write_bytes(raw)
        operations = read(folder / "metadata/operations.json")
        target = next(item for item in operations if item["variant"] == "foreign-attribute-entity")
        target["fixture_sha256"] = sha(raw); write(folder / "metadata/operations.json", operations)

    def parser_output(folder):
        path = folder / "metadata/control/parser-output.json"
        value = read(path); value["validate_authnrequest"] = False; write(path, value)
        (folder / "metadata/control/parser.stdout").write_bytes(path.read_bytes())
        record_path = folder / "metadata/control/import.json"; record = read(record_path)
        raw = path.read_bytes(); record["parser_output_sha256"] = sha(raw)
        record["parser_output_bytes"] = len(raw); write(record_path, record)

    def config_readback(folder):
        path = folder / "metadata/control/configuration-readback.php"
        path.write_bytes(path.read_bytes() + b"\n# tampered\n")

    def run_binding(folder):
        path = folder / "metadata/control/flow.json"; value = read(path)
        value["run"] = "run_00000000000000000000000000"; write(path, value)

    def restoration(folder):
        path = folder / "metadata/restoration.json"; value = read(path)
        value["restored"] = False; write(path, value)

    def response(folder):
        transcript = read(folder / "metadata/transcript.json")
        entry = next(item for item in transcript
                     if (item.get("samlSummary") or {}).get("metadataProbeAccepted") is True)
        manifest = read(folder / "metadata/decoded-manifest.json")
        item = next(value for value in manifest if value["id"] == entry["id"])
        path = folder / "metadata" / item["file"]
        path.write_bytes(path.read_bytes().replace(b"Success", b"Failure", 1))

    def failure_promotion(folder):
        path = folder / "metadata/foreign-attribute-authz/import.json"; value = read(path)
        value["status"] = "success"; write(path, value)

    def false_conclusion(folder):
        path = folder / "metadata" / EVALUATION / "result.json"; value = read(path)
        case = find_case(value, CASE); case["outcome"] = "SATISFIED"; case["verdict"] = "PASS"
        write(path, value)

    bad_pins = copy.deepcopy(pins); bad_pins["jars"]["runner"] = "0" * 64
    return [rejected(label, mutation, trial_pins) for label, mutation, trial_pins in (
        ("active-placement", active_placement, None),
        ("metadata-placement", metadata_placement, None),
        ("parser-output", parser_output, None),
        ("configuration-readback", config_readback, None),
        ("Run-binding", run_binding, None),
        ("exact-restoration", restoration, None),
        ("response-original", response, None),
        ("parser-failure-promotion", failure_promotion, None),
        ("false-product-conclusion", false_conclusion, None),
        ("Suite-pin", lambda _: None, bad_pins),
    )]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--tamper-self-test", action="store_true")
    args = parser.parse_args()
    result = verify_batch(args.root.resolve())
    if args.tamper_self_test:
        result["tamper_rejected"] = tamper_self_test(args.root.resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
