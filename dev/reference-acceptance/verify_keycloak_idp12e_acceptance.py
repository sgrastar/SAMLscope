#!/usr/bin/env python3
"""Fail-closed adoption check for Keycloak's IIP-IDP12.e ACS-URL run.

The campaign deliberately retains Keycloak's native console import, then adds
only the metadata-published secondary ACS to the temporary client's accepted
redirect URI list.  This verifier proves that change was read back, that the
client was restored/deleted, and that the two approved URL fixtures produced
correlated successful Responses at ACS 0 and ACS 1.  It refuses to turn a
terminal browser page or an uncorrelated response into a conclusion.
"""
import hashlib
import json
import re
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

if not __debug__:
    raise RuntimeError("Keycloak IDP12.e acceptance verification must not run with Python optimization")

FOLDER_PREFIX = "keycloak-idp12e-v"
CASE = "IIP-IDP12-e-idp-01"
TARGET = "samlscope-reference-keycloak"
VERSION = "26.7.2"
SUITE = "samlscope-reference-suite"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
P = "{urn:oasis:names:tc:SAML:2.0:protocol}"


def canonical(value): return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
def sha(raw): return hashlib.sha256(raw).hexdigest()
def read(path):
    path = Path(path)
    require(path.is_file(), f"missing evidence original: {path.name}")
    return json.loads(path.read_text())
def require(ok, detail):
    if not ok: raise ValueError(detail)
def time(value): return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
def xml(raw):
    require(b"<!DOCTYPE" not in raw.upper() and b"<!ENTITY" not in raw.upper(), "XML DTD/entity is forbidden")
    return ET.fromstring(raw)
def one(values, detail):
    require(len(values) == 1, detail); return values[0]


def evidence_folder(root):
    """Resolve exactly one explicitly named campaign folder.

    Requiring either the leaf evidence directory or an unambiguous parent avoids
    accidentally adopting a previous campaign when several retry folders exist.
    """
    root = Path(root)
    if (root / "created.json").is_file():
        folder = root
    else:
        candidates = [path for path in root.iterdir() if path.is_dir()
                      and re.fullmatch(r"keycloak-idp12e-v[0-9]+", path.name)]
        require(len(candidates) == 1, "pass one Keycloak IDP12.e evidence folder")
        folder = candidates[0]
    require(re.fullmatch(r"keycloak-idp12e-v[0-9]+", folder.name) is not None,
            "invalid Keycloak IDP12.e evidence folder")
    return folder


def target_runtime(folder, phase, created):
    raw = (folder / f"target-container-inspect-{phase}.json").read_bytes()
    version_raw = (folder / f"target-version-runtime-{phase}.txt").read_bytes()
    summary = read(folder / f"target-runtime-{phase}.json")
    records = json.loads(raw)
    require(isinstance(records, list) and len(records) == 1, "invalid target inspect original")
    item = records[0]; state = item.get("State", {})
    ports = item.get("NetworkSettings", {}).get("Ports", {}).get("8080/tcp") or []
    require(item.get("Name") == "/" + TARGET and state.get("Running") is True, "wrong/stopped target")
    require(re.fullmatch(r"[0-9a-f]{64}", item.get("Id", "")) is not None, "invalid target id")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", item.get("Image", "")) is not None, "invalid target image")
    require(any(x.get("HostIp") == "127.0.0.1" and x.get("HostPort") == "18180" for x in ports), "target port binding absent")
    for mount in item.get("Mounts", []):
        dest = mount.get("Destination", "")
        require(not any(dest == root or dest.startswith(root + "/") for root in (
            "/opt/keycloak/bin", "/opt/keycloak/lib", "/opt/keycloak/providers", "/opt/keycloak/quarkus-app")),
            "target executable tree is mounted")
    require(item.get("Config", {}).get("Labels", {}).get("org.opencontainers.image.version") == VERSION,
            "target version label differs")
    binding = {"container_name": TARGET, "container_id": item["Id"], "image_id": item["Image"],
               "container_started_at": state["StartedAt"], "running_at_capture": True,
               "host_port": 18180, "host_port_bound": True}
    require(summary == {"binding": binding, "docker_inspect_sha256": sha(raw),
                        "runtime_version": {"file": f"target-version-runtime-{phase}.txt", "sha256": sha(version_raw),
                                            "value": version_raw.decode().strip()}}, "target runtime summary mismatch")
    require(re.search(rf"^Keycloak {re.escape(VERSION)}(?:$|\n)", version_raw.decode()) is not None,
            "target runtime version mismatch")
    require(time(binding["container_started_at"]) < float(created), "target started after Run")
    return binding


def originals(folder, transcript, run):
    manifest = read(folder / "decoded-manifest.json")
    entries = {x["id"]: x for x in transcript}
    require(len(entries) == len(transcript), "duplicate transcript IDs")
    decoded_root = (folder / "decoded").resolve(); values = {}
    for row in manifest:
        require(set(row) == {"id", "file", "sha256"} and row["id"] in entries, "invalid decoded manifest row")
        entry = entries[row["id"]]
        require(entry.get("runId") == run and entry.get("decodedSamlRef") == f"transcripts/{run}/{entry['id']}.saml.xml",
                "decoded original has wrong Run or source")
        path = (folder / row["file"]).resolve()
        require(path.parent == decoded_root and path.is_file(), "decoded file escapes evidence directory")
        raw = path.read_bytes()
        require(sha(raw) == row["sha256"] and len(raw) == entry.get("decodedSamlBytes"), "decoded original hash mismatch")
        values[row["id"]] = raw
    require(set(values) == {x["id"] for x in transcript if x.get("decodedSamlRef")}, "manifest incomplete")
    return entries, values


def case(result):
    return one([c for r in result["requirements"] for c in r["cases"] if c["id"] == CASE], "IDP12.e case missing/duplicated")


def verify_with_report(root):
    folder = evidence_folder(root)
    run_record = read(folder / "created.json")["run"]; run = run_record["id"]
    require(re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", run) is not None, "malformed Run")
    plan = read(folder / "plan.json")["plan"]; definition = plan["plan"]
    require(definition["id"] == run_record["planId"] and definition["profile"] == "browser_sso_idp"
            and definition["target"] == {"kind": "IDP", "entityId": "http://localhost:18180/realms/samlscope", "connectionId": None, "metadataRevisionId": None}
            and definition["requestSigningMode"] == "REQUIRED", "wrong plan binding")
    entity = plan["entityId"]
    require(entity == f"http://localhost:18080/p/{definition['id']}", "wrong Suite entity")
    start = target_runtime(folder, "start", run_record["createdAt"])
    end = target_runtime(folder, "end", run_record["createdAt"])
    require(start == end, "target changed during campaign")

    fixture = (folder / "suite-sp-metadata.xml").read_bytes()
    imported = read(folder / "import.json")
    require(imported.get("status") == "success" and imported.get("fixture") == {
        "path": str((folder / "suite-sp-metadata.xml").resolve()), "sha256": sha(fixture), "bytes": len(fixture), "entity_id": entity},
        "native console import not bound to fixture")
    require([x.get("step") for x in imported.get("steps", [])] == ["file-selected", "product-parsed-entity-id", "product-import-signal", "admin-read-back"],
            "native console import lacks required signals")
    source = (folder / "driver" / "console_import.mjs").read_text()
    require(all(token in source for token in ("getByText('Import client'", "setInputFiles(fixturePath)", "product-import-signal", "admin-read-back")),
            "captured driver lacks console-import path")
    require("fetch(`${ADMIN}/clients`, { method: 'POST'" not in source, "driver directly creates target client")

    original = read(folder / "client-original.json")
    configured = read(folder / "client-configured-readback.json")
    configuration = read(folder / "client-configuration.json")
    primary, secondary = entity + "/sp/acs/0", entity + "/sp/acs/1"
    require(configuration == {"entity_id": entity, "client_database_id": original.get("id"),
        "original_sha256": sha(canonical(original)),
        "original_redirect_uris": original.get("redirectUris"), "configured_redirect_uris": configured.get("redirectUris"),
        "configured_readback_sha256": sha(canonical(configured)),
        "added_redirect_uri": secondary, "configuration_scope": "temporary existing console-imported client redirectUris only"}, "configuration record is altered")
    require(primary in original.get("redirectUris", []) and secondary not in original.get("redirectUris", []),
            "native imported client baseline does not distinguish secondary ACS")
    require(configured.get("id") == original.get("id") and configured.get("clientId") == entity
            and configured.get("attributes") == original.get("attributes"), "configured client read-back identity/attributes mismatch")
    require(set(configured.get("redirectUris", [])) == set(original["redirectUris"]) | {secondary},
            "temporary configuration changed more than the secondary ACS")
    operations = read(folder / "admin-operations.json")
    require(isinstance(operations, list) and all(isinstance(row, dict) for row in operations),
            "admin operation record is malformed")
    path = "/clients/" + original["id"]
    configured_sha, original_sha = sha(canonical(configured)), sha(canonical(original))
    # Keycloak may normalize its returned client representation (for example,
    # list ordering) after a PUT.  Bind the request to the deterministic
    # allowed mutation reconstructed from the imported original, and bind the
    # subsequent GET separately to the full raw read-back.
    configured_request = json.loads(canonical(original))
    configured_request["redirectUris"] = sorted(set(original["redirectUris"]) | {secondary})
    configured_request_sha = sha(canonical(configured_request))
    configure_put = one([i for i, row in enumerate(operations)
                         if row.get("method") == "PUT" and row.get("path") == path and row.get("status") == 204
                         and row.get("request_json_sha256") == configured_request_sha],
                        "temporary configuration PUT is absent or ambiguous")
    restore_put = one([i for i, row in enumerate(operations)
                       if row.get("method") == "PUT" and row.get("path") == path and row.get("status") == 204
                       and row.get("request_json_sha256") == original_sha],
                      "restore PUT is absent or ambiguous")
    require(configure_put < restore_put, "restore occurs before temporary configuration")
    configured_gets = [i for i, row in enumerate(operations)
                       if row.get("method") == "GET" and row.get("path") == path and row.get("status") == 200
                       and row.get("response_json_sha256") == configured_sha and configure_put < i < restore_put]
    require(configured_gets, "temporary configuration lacks a bound read-back")
    configured_get = configured_gets[0]
    restored_get = one([i for i, row in enumerate(operations)
                        if row.get("method") == "GET" and row.get("path") == path and row.get("status") == 200
                        and row.get("response_json_sha256") == original_sha and i > restore_put],
                       "restore lacks a bound read-back")
    require(configure_put < configured_get < restore_put < restored_get,
            "temporary configuration/read-back/restore order is invalid")
    delete = one([i for i, row in enumerate(operations)
                  if row.get("method") == "DELETE" and row.get("path") == path and row.get("status") == 204],
                 "temporary client delete is absent or ambiguous")
    require(restored_get < delete, "temporary client is deleted before restoration read-back")
    restoration = read(folder / "client-restoration.json")
    require(restoration == {"original_sha256": original_sha, "restored_sha256": original_sha,
                            "redirect_uris_restored": True, "attributes_restored": True, "restored": True},
            "restoration original is altered or incomplete")
    cleanup = read(folder / "cleanup.json")
    require(cleanup == {"restore_attempted": True, "delete_attempted": True, "redirect_uris_restored": True,
                        "attributes_restored": True, "read_back_absent": True, "restored": True}, "client restore/delete unproven")

    steps = read(folder / "steps.json")
    relevant = [row for row in steps if row.get("caseId") == CASE and "actionId" in row]
    require(len(relevant) == 2 and [row.get("receipt") for row in relevant] == ["recorded", "recorded"],
            "IDP12.e did not execute exactly two recorded fixtures")
    require(relevant[0].get("nextCaseId") == CASE and relevant[1].get("nextCaseId") != CASE,
            "IDP12.e fixture order is incomplete")
    actions = ["_" + row["actionId"] for row in relevant]

    transcript = read(folder / "transcript.json")
    require(all(x.get("runId") == run for x in transcript), "mixed Run transcript")
    entries, decoded = originals(folder, transcript, run)
    capture = read(folder / "original-capture.json")
    metadata = (folder / "target-metadata.xml").read_bytes()
    require(capture == {"run": run, "originals": len(decoded), "target_metadata_sha256": sha(metadata)}, "original capture mismatch")
    # The native Suite metadata must publish both POST ACS endpoints before the client is configured.
    MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
    metadata_root = xml(fixture)
    require(metadata_root.tag == MD + "EntityDescriptor" and metadata_root.get("entityID") == entity,
            "Suite metadata identity mismatch")
    published = [x.attrib for x in metadata_root.findall(".//" + MD + "AssertionConsumerService")]
    require({"Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "Location": primary, "index": "0", "isDefault": "true"}.items() <= published[0].items()
            and any(x.get("Binding") == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" and x.get("Location") == secondary and x.get("index") == "1" for x in published),
            "Suite metadata does not publish ACS 0 and ACS 1")
    responses = []
    for expected_index, action in enumerate(actions):
        request = one([x for x in transcript if x.get("direction") == "OUTBOUND" and x.get("samlSummary", {}).get("action_id") == action.removeprefix("_")],
                      "each action requires one outbound request original")
        request_summary = request.get("samlSummary", {})
        require(request_summary == {"scenario_case_id": CASE, "fixture_id": ("default-control" if expected_index == 0 else "non-default-url"),
                                    "active_probe": True, "action_id": action.removeprefix("_"), "type": "AuthnRequest"},
                "outbound request has wrong IDP12.e fixture identity")
        request_xml = xml(decoded[request["id"]])
        require(request_xml.tag == P + "AuthnRequest" and request_xml.get("ID") == action and request_xml.get("Destination") == "http://localhost:18180/realms/samlscope/protocol/saml",
                "outbound request original identity/destination mismatch")
        if expected_index == 0:
            require(not any(key in request_xml.attrib for key in ("AssertionConsumerServiceURL", "AssertionConsumerServiceIndex", "ProtocolBinding")),
                    "control request contains ACS URL/index/binding")
        else:
            require(request_xml.get("AssertionConsumerServiceURL") == secondary
                    and "AssertionConsumerServiceIndex" not in request_xml.attrib and "ProtocolBinding" not in request_xml.attrib,
                    "non-default request is not URL-only ACS 1")
        response = one([x for x in transcript if x.get("direction") == "INBOUND" and x.get("correlationId") == action],
                       "each action requires one inbound correlated response")
        summary = response.get("samlSummary", {})
        expected_url = f"{entity}/sp/acs/{expected_index}"
        require(request["timestamp"] < response["timestamp"], "request is not before its response")
        require(response.get("url") == expected_url and response.get("status") == 200 and summary == {
            "statusCode": SUCCESS, "type": "Response", "id": summary.get("id"), "destination": expected_url,
            "inResponseTo": action, "issuer": "http://localhost:18180/realms/samlscope", "activeProbeAccepted": True},
            "response transcript is not a correlated Success at the expected ACS")
        require(re.fullmatch(r"ID_[0-9a-f-]{36}", summary["id"]) is not None, "malformed response identifier")
        root_xml = xml(decoded[response["id"]])
        require(root_xml.tag == P + "Response" and root_xml.get("InResponseTo") == action and root_xml.get("Destination") == expected_url,
                "response original does not bind action/destination")
        status = one(root_xml.findall(".//" + P + "StatusCode"), "response requires one status")
        require(status.get("Value") == SUCCESS, "response original is not Success")
        responses.append((request, response))
    require(responses[0][1]["timestamp"] < responses[1][1]["timestamp"], "fixtures are out of order")

    runtime = read(folder / "suite-runtime.json"); inspect = (folder / "suite-container-inspect.json").read_bytes(); jar = (folder / "suite-runner-0.1.0.jar").read_bytes()
    inspected = json.loads(inspect); require(isinstance(inspected, list) and len(inspected) == 1, "invalid Suite inspect")
    require(runtime == {"run": run, "container": {"name": SUITE, "id": inspected[0]["Id"], "image": inspected[0]["Image"], "started_at": inspected[0]["State"]["StartedAt"]},
                        "runner_jar": {"path": "/opt/samlscope/lib/runner-0.1.0.jar", "sha256": sha(jar)}, "docker_inspect_sha256": sha(inspect)},
            "Suite runtime mismatch")
    require(time(runtime["container"]["started_at"]) < float(run_record["createdAt"]), "Suite started after Run")
    with zipfile.ZipFile(folder / "suite-runner-0.1.0.jar") as archive:
        cls = archive.read("com/samlscope/runner/cases/IdpAcsSelectionScenarioTestCase.class")
    saml_jar = (folder / "suite-saml-0.1.0.jar").read_bytes()
    require(read(folder / "suite-saml-runtime.json") == {"path": "/opt/samlscope/lib/saml-0.1.0.jar", "sha256": sha(saml_jar)},
            "Suite SAML runtime summary mismatch")
    with zipfile.ZipFile(folder / "suite-saml-0.1.0.jar") as archive:
        factory = archive.read("com/samlscope/saml/normal/SamlAcsSelectionRequestFactory.class")
    require(all(value.encode() in cls + factory for value in (CASE, "default-control", "non-default-url", "SUCCESS_AT_DEFAULT", "SUCCESS_AT_SECONDARY", "URL_ONE", "AssertionConsumerServiceURL", "ProtocolBinding")),
            "running Suite JAR lacks approved IDP12.e fixture mapping")
    before = read(folder / "evaluation-v139" / "transcript-before.json"); after = read(folder / "evaluation-v139" / "transcript.json")
    result = read(folder / "result.json"); reeval = read(folder / "evaluation-v139" / "result.json")
    observed = case(result)
    require(before == after == transcript and observed == case(reeval), "formal re-evaluation changed Run evidence/result")
    require((observed.get("outcome"), observed.get("verdict"), observed.get("reason_code"), observed.get("attested"), observed.get("evidence_class")) ==
            ("SATISFIED", "PASS", "idp.acs-probe.satisfied", False, "PROTOCOL_OBSERVED"), "Suite did not produce an un-attested ACS URL pass")
    # The Runner's case evidence intentionally retains the observed Responses.  The paired
    # outbound originals are independently required above, even though they are not case EvidenceRefs.
    refs = {"transcript:" + response["id"] for _, response in responses}
    require({item.get("kind") + ":" + item.get("reference", "") for item in observed.get("evidence", [])} == refs,
            "case evidence escapes the independently replayed response set")
    require(reeval["target"]["metadata_digest"] == "sha256:" + sha(metadata), "result target metadata mismatch")
    report = {"run": run, "case": CASE, "verdict": observed["verdict"], "reason_code": observed["reason_code"],
              "target": {"container": TARGET, "version": VERSION}, "responses": [{"action": a, "request": request["id"], "url": response["url"], "transcript": response["id"]} for a, (request, response) in zip(actions, responses, strict=True)],
              "operations": {"product_configuration_writes": 2, "temporary_client_restored_and_deleted": 1,
                             "product_restarts": 0, "human_operations": 0}}
    return folder / "evaluation-v139" / "result.json", {CASE: observed}, report


def verify(root):
    result, cases, _ = verify_with_report(root); return result, cases


def negative_validation(root):
    source = evidence_folder(root)
    results = []
    with tempfile.TemporaryDirectory() as temporary:
        copied = Path(temporary) / source.name; shutil.copytree(source, copied)
        # Raw SAML modification is rejected through the decoded-manifest hash.
        evidence = read(copied / "evaluation-v139" / "result.json"); rid = case(evidence)["evidence"][0]["reference"]
        path = copied / "decoded" / (rid + ".xml"); path.write_bytes(path.read_bytes() + b" ")
        try: verify_with_report(copied)
        except ValueError: results.append("response-original-tamper-rejected")
        else: raise RuntimeError("response original tamper was accepted")
    with tempfile.TemporaryDirectory() as temporary:
        copied = Path(temporary) / source.name; shutil.copytree(source, copied)
        path = copied / "target-version-runtime-end.txt"; path.write_text("Keycloak 0.0.0\n")
        try: verify_with_report(copied)
        except ValueError: results.append("target-version-tamper-rejected")
        else: raise RuntimeError("target version tamper was accepted")
    with tempfile.TemporaryDirectory() as temporary:
        copied = Path(temporary) / source.name; shutil.copytree(source, copied)
        config = read(copied / "client-configuration.json"); config["added_redirect_uri"] = "http://invalid.example/"; (copied / "client-configuration.json").write_text(json.dumps(config))
        try: verify_with_report(copied)
        except ValueError: results.append("configuration-tamper-rejected")
        else: raise RuntimeError("configuration tamper was accepted")
    return results

if __name__ == "__main__":
    root = Path(sys.argv[1])
    result, cases, report = verify_with_report(root)
    if "--negative-validation" in sys.argv:
        report["negative_validation"] = negative_validation(root)
    folder = evidence_folder(root)
    (result.parent.parent / f"acceptance-{folder.name.removeprefix('keycloak-')}.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"result": str(result), "verdicts": {key: value["verdict"] for key, value in cases.items()}, **({"negative_validation": report["negative_validation"]} if "--negative-validation" in sys.argv else {})}))
