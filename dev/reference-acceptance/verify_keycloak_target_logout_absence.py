#!/usr/bin/env python3
"""Fail-closed adoption verifier for Keycloak's native target-logout campaign."""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import shutil
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

CASES = {"IIP-IDP17-n-idp-01", "IIP-IDP17-u-idp-01"}
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
EXPECTED = {
    "IIP-IDP17-n-idp-01": (
        "SATISFIED", "PASS", "slo.logout-request.identifier-strong-match.satisfied"),
    "IIP-IDP17-u-idp-01": (
        "VIOLATED", "WARNING", "slo.logout-request.not-on-or-after-bound.violated"),
}
FOLDER = "keycloak-target-logout-absence-v158-r7"
SUITE_IMAGE = "sha256:846083123e759f24e88a89f9badba50c4e4cd110b3b13563e8295c9829886cdb"
SUITE_JARS = {
    "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe",
    "runner": "94dca2c3c134cf2ad3c30fb4a271448b729c7327b464bff0070a83b45b157dae",
    "saml": "cbfdb79f54ed967f58c8153eb8d0dda350016030c552d0aaee3fc30988d3bf73",
}
TARGET_IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
TARGET_VERSION_PREFIX = "Keycloak 26.7.2\n"
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read(folder: Path, name: str):
    return json.loads((folder / name).read_text())


def cases(result):
    return {row["id"]: row for requirement in result["requirements"]
            for row in requirement["cases"]}


def parse_time(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, "logout time is not timezone-aware")
    return parsed


def verify(root, folder_name=FOLDER):
    folder = Path(root) / folder_name
    created = read(folder, "created.json")
    result = read(folder, "evaluation-terminal-http-v1/result.json")
    run = created["run"]["id"]
    require(result["run"]["id"] == run, "result/run mismatch")
    require(read(folder, "result.json") == result, "formal re-evaluation changed the result")
    require(result["profile"]["id"] == "single-logout-idp", "wrong profile")
    require(result["target"]["entity_id"] == "redacted:internal-target", "unexpected target export")
    require(read(folder, "initial-login.json") == {"run": run, "receipt": "recorded"},
            "initial SSO did not complete")

    plan_response = read(folder, "plan.json")["plan"]
    plan = plan_response["plan"]
    request = read(folder, "plan-request.json")
    entity = plan_response["entityId"]
    require(entity == "http://localhost:18080/p/" + plan["id"], "Suite entity mismatch")
    require(plan["profile"] == "single_logout_idp", "plan profile mismatch")
    require(plan["target"]["entityId"] == "http://localhost:18180/realms/samlscope",
            "target entity mismatch")
    require(request["interaction"] == {"allowBrowserSteps": True, "allowAttestation": False,
                                        "preset": "quick"}, "interaction policy mismatch")
    require(request["authorizedTarget"] is True and request["profile"] == "single_logout_idp"
            and request["targetEntityId"] == plan["target"]["entityId"], "plan request mismatch")

    metadata = (folder / "suite-sp-metadata.xml").read_bytes()
    require(result["target"]["metadata_digest"].startswith("sha256:"), "missing target digest")
    imported = read(folder, "imported-client-readback.json")
    require(imported["clientId"] == entity and imported["protocol"] == "saml" and imported["enabled"],
            "native imported client identity mismatch")
    attributes = imported.get("attributes") or {}
    require(attributes.get("saml_single_logout_service_url_post") == entity + "/sp/slo",
            "native import did not retain POST SLO endpoint")
    require(attributes.get("saml_single_logout_service_url_redirect") == entity + "/sp/slo",
            "native import did not retain Redirect SLO endpoint")
    require(attributes.get("saml_single_logout_service_url_soap") == entity + "/sp/slo/soap",
            "native import did not retain SOAP SLO endpoint")
    require("[REDACTED]" == imported.get("secret"), "client secret was not redacted")
    require(b"SingleLogoutService" in metadata and entity.encode() in metadata,
            "Suite metadata does not advertise the observed SLO endpoint")

    require(read(folder, "initial-client-absence.json") == [], "client was not initially absent")
    require(read(folder, "final-client-absence.json") == [], "client remained after restoration")
    cleanup = read(folder, "cleanup.json")
    require(cleanup == {"attempted": True, "initially_absent": True, "deleted": True,
                        "final_absence": True}, "cleanup/read-back incomplete")
    operations = read(folder, "operation-counts.json")
    require(operations == {
        "product_configuration_writes": 1,
        "product_configuration_restorations": 1,
        "product_restarts": 0,
        "product_session_reads": operations["product_session_reads"],
        "browser_logins": 1,
        "browser_logouts": 1,
        "human_operations": 0,
    }, "unexpected operation counts")
    require(operations["product_session_reads"] >= 2, "missing product session read-back")

    start_runtime = read(folder, "target-runtime-start.json")
    end_runtime = read(folder, "target-runtime-end.json")
    require(start_runtime["product"] == end_runtime["product"] == "keycloak", "wrong runtime product")
    require(start_runtime["runtime_version"]["value"] == end_runtime["runtime_version"]["value"],
            "product version changed")
    require(start_runtime["runtime_version"]["value"].startswith(TARGET_VERSION_PREFIX),
            "unreviewed Keycloak version")
    require(start_runtime["binding"]["image_id"] == end_runtime["binding"]["image_id"],
            "product image changed")
    require(start_runtime["binding"]["image_id"] == TARGET_IMAGE,
            "unreviewed Keycloak image")
    require(start_runtime["binding"]["container_id"] == end_runtime["binding"]["container_id"],
            "product container changed")
    require(start_runtime["binding"]["running_at_capture"]
            and end_runtime["binding"]["running_at_capture"], "product was not running")
    require(start_runtime["binding"]["host_port_bound"]
            and end_runtime["binding"]["host_port_bound"], "product port binding changed")
    suite_runtime = read(folder, "suite-runtime-terminal-http.json")
    require(suite_runtime["run"] == run and suite_runtime["container"]["running_at_capture"],
            "Suite runtime/run binding mismatch")
    require(result["suite"]["image_digest"] == suite_runtime["container"]["image_id"],
            "Suite result/image mismatch")
    require(suite_runtime["container"]["image_id"] == SUITE_IMAGE,
            "unreviewed Suite image")
    require(set(suite_runtime["jars"]) == {"core", "runner", "saml"}
            and all(len(value["sha256"]) == 64 for value in suite_runtime["jars"].values()),
            "Suite JAR originals are incomplete")
    for name, expected in SUITE_JARS.items():
        item = suite_runtime["jars"][name]
        jar = folder / item["file"]
        require(jar.is_file() and SHA(jar.read_bytes()) == item["sha256"] == expected,
                name + " running JAR pin mismatch")
    with zipfile.ZipFile(folder / suite_runtime["jars"]["runner"]["file"]) as archive:
        profile_case = archive.read(
            "com/samlscope/runner/cases/LogoutTranscriptProfileCase.class")
        browser_case = archive.read(
            "com/samlscope/runner/cases/LogoutBrowserEvidenceTestCase.class")
    require(all(value in profile_case for value in (
                b"slo.logout-request.identifier-strong-match",
                b"slo.logout-request.not-on-or-after-bound",
                b"slo.identifier.strong-match-unobservable")),
            "running Runner lacks the reviewed logout oracle")
    require(all(value in browser_case for value in (
                b"IIP-IDP17-n-idp-01", b"IIP-IDP17-u-idp-01")),
            "running Runner lacks the reviewed case registration")

    before_sessions = read(folder, "sessions-before.json")
    after_sessions = read(folder, "sessions-after.json")
    require(before_sessions and any(row["imported_client_present"] for row in before_sessions),
            "no authenticated Suite SP session before logout")
    before_ids = {row["session_id_sha256"] for row in before_sessions
                  if row["imported_client_present"]}
    after_ids = {row["session_id_sha256"] for row in after_sessions}
    require(before_ids and before_ids.isdisjoint(after_ids), "same product session survived logout")
    require(not any(row["imported_client_present"] for row in after_sessions),
            "Suite SP session remained after logout")
    for row in before_sessions + after_sessions:
        require(len(row["session_id_sha256"]) == 64, "invalid hashed session identity")
        require(all(len(value) == 64 for value in row["client_internal_ids_sha256"]),
                "invalid hashed client identity")

    logout = read(folder, "logout-browser.json")
    started = parse_time(logout["started_at"])
    completed = parse_time(logout["completed_at"])
    absent = parse_time(logout["session_absence_observed_at"])
    require(started <= completed <= absent, "logout evidence time order invalid")
    require(logout["confirmation_submitted"], "native logout confirmation was not submitted")
    require(logout["initial"]["status"] < 400 and logout["final"]["status"] < 400,
            "native logout browser path failed")
    require(logout["initial"]["url"].startswith(
            "http://localhost:18180/realms/samlscope/protocol/openid-connect/logout"),
            "logout did not start at the target")
    require(len(logout["initial"]["body_sha256"]) == 64
            and len(logout["final"]["body_sha256"]) == 64, "browser bodies not hash-bound")
    require(logout["initial"]["diagnostics"]["has_logout_confirm_form"],
            "native confirmation page was not observed")
    continuation = logout["saml_continuation"]
    require([row["message_kind"] for row in continuation] == ["SAMLRequest", "SAMLResponse"],
            "native SAML logout continuation was incomplete")
    require(continuation[0]["action_origin_path"] == entity + "/sp/slo",
            "LogoutRequest was not delivered to the Suite SLO endpoint")
    require(continuation[1]["action_origin_path"] ==
            "http://localhost:18180/realms/samlscope/protocol/saml",
            "LogoutResponse was not returned to Keycloak")
    require(all(row["response_status"] < 400
                and len(row["action_url_sha256"]) == 64
                and len(row["response_body_sha256"]) == 64 for row in continuation),
            "native SAML logout continuation failed")
    require({"KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"}
            <= set(logout["cookie_names_before"]), "authenticated cookie state was not observed")
    require(not ({"KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"}
                 & set(logout["cookie_names_after"])), "authenticated cookies survived logout")

    intent = read(folder, "target-intent.json")
    require(intent["runId"] == run and intent["kind"] == "TARGET_LOGOUT", "target intent mismatch")
    concluded = read(folder, "target-conclude.json")
    require(concluded.get("concluded", 0) >= len(CASES), "target campaign was not concluded")

    before_transcript = read(folder, "transcript-before-logout.json")
    transcript = read(folder, "transcript.json")
    require(transcript[:len(before_transcript)] == before_transcript,
            "transcript prefix changed across native logout")
    require(len({row["id"] for row in transcript}) == len(transcript), "duplicate transcript ids")
    require(all(row["runId"] == run for row in transcript), "mixed Run transcript")
    initial_success = [row for row in before_transcript
                       if row["direction"] == "INBOUND"
                       and row.get("samlSummary", {}).get("type") == "Response"
                       and row.get("samlSummary", {}).get("statusCode") == SUCCESS
                       and row.get("samlSummary", {}).get("normalFlowAccepted") is True]
    require(initial_success, "missing accepted initial SAML session response")
    inbound_logout = [row for row in transcript if row["direction"] == "INBOUND"
                      and row.get("samlSummary", {}).get("type") == "LogoutRequest"]
    require(len(inbound_logout) == 1, "expected exactly one target-issued LogoutRequest")
    require(not any(row.get("samlSummary", {}).get("type") == "LogoutRequest"
                    for row in before_transcript), "LogoutRequest preceded the native logout")
    outbound_logout_response = [row for row in transcript if row["direction"] == "OUTBOUND"
                                and row.get("samlSummary", {}).get("type") == "LogoutResponse"]
    require(len(outbound_logout_response) == 1, "Suite LogoutResponse was not recorded")

    manifest_rows = read(folder, "decoded-manifest.json")
    manifest = {row["id"]: row for row in manifest_rows}
    require(len(manifest) == len(manifest_rows), "duplicate decoded manifest ids")
    assertion_seen = False
    for response in initial_success:
        original = manifest.get(response["id"])
        require(original is not None, "initial response original missing")
        raw = (folder / original["file"]).read_bytes()
        require(SHA(raw) == original["sha256"], "initial response original hash mismatch")
        root = ET.fromstring(raw)
        assertion_seen = assertion_seen or bool(root.findall(".//{" + ASSERTION + "}Assertion")) \
            or bool(root.findall(".//{" + ASSERTION + "}EncryptedAssertion"))
    require(assertion_seen, "initial SAML response had no assertion")
    logout_entry = inbound_logout[0]
    logout_original = manifest.get(logout_entry["id"])
    require(logout_original is not None, "LogoutRequest original missing")
    logout_raw = (folder / logout_original["file"]).read_bytes()
    require(SHA(logout_raw) == logout_original["sha256"], "LogoutRequest original hash mismatch")
    logout_root = ET.fromstring(logout_raw)
    require(logout_root.tag.endswith("}LogoutRequest"), "wrong target logout original")
    name_ids = logout_root.findall("./{" + ASSERTION + "}NameID")
    session_indexes = logout_root.findall("./{urn:oasis:names:tc:SAML:2.0:protocol}SessionIndex")
    require(len(name_ids) == 1 and len(session_indexes) == 1,
            "target LogoutRequest lacked one principal/session identifier")
    require(not logout_root.get("NotOnOrAfter"),
            "recorded product WARNING no longer matches the LogoutRequest")
    response_entry = outbound_logout_response[0]
    response_original = manifest.get(response_entry["id"])
    require(response_original is not None, "LogoutResponse original missing")
    response_raw = (folder / response_original["file"]).read_bytes()
    require(SHA(response_raw) == response_original["sha256"], "LogoutResponse original hash mismatch")
    response_root = ET.fromstring(response_raw)
    require(response_root.get("InResponseTo") == logout_root.get("ID"),
            "LogoutResponse was not correlated to the target request")
    target_metadata = (folder / "target-metadata.xml").read_bytes()
    require(SHA(target_metadata) == result["target"]["metadata_digest"].removeprefix("sha256:"),
            "target metadata/result digest mismatch")

    selected = cases(result)
    adopted = {}
    for case_id in CASES:
        row = selected[case_id]
        expected = EXPECTED[case_id]
        require((row["outcome"], row["verdict"], row["reason_code"], row["attested"]) ==
                (*expected, False),
                case_id + " formal outcome mismatch")
        require(row["evidence"] == [{"kind": "transcript",
                                      "reference": "transcript:" + logout_entry["id"]}],
                case_id + " formal evidence mismatch")
        adopted[case_id] = row
    evaluation = read(folder, "evaluation-terminal-http-v1/transcript.json")
    require(evaluation == transcript
            and read(folder, "evaluation-terminal-http-v1/transcript-before.json") == transcript,
            "formal re-evaluation changed the transcript")
    return folder / "evaluation-terminal-http-v1/result.json", adopted


def write(path: Path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def tamper_self_test(root: Path):
    source = root / FOLDER
    mutations = {
        "session-survives": lambda d: write(d / "sessions-after.json",
                                             read(d, "sessions-before.json")),
        "logout-not-submitted": lambda d: mutate(d, "logout-browser.json",
                                                   lambda value: value.update(confirmation_submitted=False)),
        "human-operation": lambda d: mutate(d, "operation-counts.json",
                                             lambda value: value.update(human_operations=1)),
        "cleanup-missing": lambda d: mutate(d, "cleanup.json",
                                             lambda value: value.update(final_absence=False)),
        "slo-endpoint-missing": lambda d: mutate(d, "imported-client-readback.json",
                                                  lambda value: value["attributes"].pop(
                                                      "saml_single_logout_service_url_redirect")),
        "target-logout-removed": remove_logout,
        "continuation-broken": lambda d: mutate(d, "logout-browser.json",
                                                  lambda value: value["saml_continuation"].pop()),
        "logout-original-corrupt": corrupt_logout_original,
        "suite-pin-changed": lambda d: mutate(d, "suite-runtime-terminal-http.json",
                                                lambda value: value["container"].update(
                                                    image_id="sha256:" + "0" * 64)),
        "target-pin-changed": lambda d: mutate(d, "target-runtime-start.json",
                                                 lambda value: value["binding"].update(
                                                     image_id="sha256:" + "0" * 64)),
        "formal-result-not-verified": tamper_result,
    }
    passed = []
    for name, mutation in mutations.items():
        with tempfile.TemporaryDirectory(prefix="samlscope-target-logout-") as temporary:
            destination = Path(temporary) / FOLDER
            shutil.copytree(source, destination, symlinks=True)
            mutation(destination)
            try:
                verify(Path(temporary))
            except (AssertionError, KeyError, ValueError, ET.ParseError):
                passed.append(name)
            else:
                raise AssertionError("tamper accepted: " + name)
    return passed


def mutate(folder: Path, name: str, change):
    value = read(folder, name)
    change(value)
    write(folder / name, value)


def remove_logout(folder: Path):
    value = read(folder, "transcript.json")
    value = [row for row in value if row.get("samlSummary", {}).get("type") != "LogoutRequest"]
    write(folder / "transcript.json", value)


def corrupt_logout_original(folder: Path):
    transcript = read(folder, "transcript.json")
    identifier = next(row["id"] for row in transcript
                      if row.get("samlSummary", {}).get("type") == "LogoutRequest")
    original = next(row for row in read(folder, "decoded-manifest.json")
                    if row["id"] == identifier)
    path = folder / original["file"]
    path.write_bytes(path.read_bytes() + b" ")


def tamper_result(folder: Path):
    value = read(folder, "evaluation-terminal-http-v1/result.json")
    selected = cases(value)["IIP-IDP17-n-idp-01"]
    selected.update(outcome="NOT_VERIFIED", verdict="NOT_VERIFIED", reason_code="case.pending-interaction")
    write(folder / "evaluation-terminal-http-v1/result.json", value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--folder", default=FOLDER)
    parser.add_argument("--tamper-self-test", action="store_true")
    args = parser.parse_args()
    path, adopted = verify(args.root, args.folder)
    report = {"result": str(path), "adopted": {key: value["verdict"] for key, value in adopted.items()}}
    if args.tamper_self_test:
        require(args.folder == FOLDER, "tamper self-test requires the canonical folder")
        report["tamper_rejections"] = tamper_self_test(args.root)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
