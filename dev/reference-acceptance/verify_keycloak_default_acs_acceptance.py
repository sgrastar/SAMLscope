#!/usr/bin/env python3
"""Fail-closed adoption check for Keycloak's native default-ACS import result.

This is deliberately narrower than a general metadata importer.  It accepts one
Run only when the four G2-approved MD05.av fixtures were given to Keycloak's own
``Import client`` console flow, each temporary client was read back and deleted,
and the raw Run originals prove the resulting SSO behavior.  It never turns an
unobserved rejection into a product result.
"""
import hashlib
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import xml.etree.ElementTree as ET


# Assertions disappear under ``python -O``.  This module guards an adoption
# decision, so reject that execution mode before it can read evidence.
if not __debug__:
    raise RuntimeError("Keycloak default-ACS acceptance verification must not run with Python optimization")


CASE = "IIP-MD05-av-idp-01"
FOLDER = "keycloak-default-acs-v139"
TARGET_CONTAINER = "samlscope-reference-keycloak"
TARGET_VERSION = "26.7.2"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
P = "{urn:oasis:names:tc:SAML:2.0:protocol}"
DS = "{http://www.w3.org/2000/09/xmldsig#}"
POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
PAOS = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"
REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
VARIANTS = (
    "control",
    "default-acs-first",
    "default-acs-first-omitted",
    "default-acs-all-false",
    "default-acs-duplicate-index",
)
EXPECTED_INDEX = {
    "control": 0,
    "default-acs-first": 0,
    "default-acs-first-omitted": 1,
    "default-acs-all-false": 0,
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def read(path):
    return json.loads(Path(path).read_text())


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def xml(raw):
    require(b"<!DOCTYPE" not in raw.upper() and b"<!ENTITY" not in raw.upper(),
            "evidence XML must not use DTDs or entities")
    return ET.fromstring(raw)


def target_binding(inspect):
    require(isinstance(inspect, list) and len(inspect) == 1,
            "target inspect must contain exactly one container")
    item = inspect[0]
    state = item.get("State", {})
    ports = item.get("NetworkSettings", {}).get("Ports", {}).get("8080/tcp") or []
    require(state.get("Running") is True, "target was not running")
    require(item.get("Name") == "/" + TARGET_CONTAINER,
            "wrong target container")
    require(re.fullmatch(r"[0-9a-f]{64}", item.get("Id", "")) is not None,
            "target container id is invalid")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", item.get("Image", "")) is not None,
            "target image id is invalid")
    require(any(value.get("HostIp") == "127.0.0.1" and value.get("HostPort") == "18180"
                for value in ports), "target localhost port binding is absent")
    # The reference realm import is intentionally mounted under data/import.  Reject
    # overlays of executable/runtime code, while retaining the actual inspect record
    # for the realm configuration that was exercised.
    protected = ("/opt/keycloak/bin", "/opt/keycloak/lib", "/opt/keycloak/providers",
                 "/opt/keycloak/quarkus-app")
    for mount in item.get("Mounts", []):
        destination = mount.get("Destination", "")
        require(not any(destination == root or destination.startswith(root + "/") for root in protected),
                "target executable tree is covered by a mount")
    labels = item.get("Config", {}).get("Labels", {})
    require(labels.get("org.opencontainers.image.version") == TARGET_VERSION,
            "target image version label is unexpected")
    return {
        "container_name": TARGET_CONTAINER,
        "container_id": item["Id"],
        "image_id": item["Image"],
        "container_started_at": state["StartedAt"],
        "running_at_capture": True,
        "host_port": 18180,
        "host_port_bound": True,
    }


def verify_target_runtime(folder, run_created_at):
    observed = []
    for phase in ("start", "end"):
        inspect_raw = (folder / f"target-container-inspect-{phase}.json").read_bytes()
        version_raw = (folder / f"target-version-runtime-{phase}.txt").read_bytes()
        summary = read(folder / f"target-runtime-{phase}.json")
        binding = target_binding(json.loads(inspect_raw))
        version = version_raw.decode().strip()
        require(re.search(rf"^Keycloak {re.escape(TARGET_VERSION)}(?:$|\n)", version) is not None,
                "target runtime version is unexpected")
        require(summary == {
            "binding": binding,
            "docker_inspect_sha256": sha(inspect_raw),
            "runtime_version": {
                "file": f"target-version-runtime-{phase}.txt",
                "sha256": sha(version_raw),
                "value": version,
            },
        }, "target runtime summary does not bind its originals")
        observed.append((binding, version_raw))
    require(observed[0] == observed[1], "target identity or runtime version changed during campaign")
    require(parse_time(observed[0][0]["container_started_at"]) < float(run_created_at),
            "target started after the measured Run")
    return observed[0][0]


def expected_services(entity, run, variant):
    values = [
        {"Binding": POST, "Location": f"{entity}/sp/acs/0?mdv={variant}&run={run}", "index": "0"},
        {"Binding": POST, "Location": f"{entity}/sp/acs/1?mdv={variant}&run={run}", "index": "1"},
        {"Binding": PAOS, "Location": f"{entity}/sp/paos?mdv={variant}&run={run}", "index": "2"},
        {"Binding": REDIRECT, "Location": f"{entity}/sp/acs/3?mdv={variant}&run={run}", "index": "3"},
    ]
    if variant in {"control", "default-acs-first"}:
        values[0]["isDefault"] = "true"
    elif variant == "default-acs-first-omitted":
        values[0]["isDefault"] = "false"
    elif variant in {"default-acs-all-false", "default-acs-duplicate-index"}:
        for value in values:
            value["isDefault"] = "false"
    if variant == "default-acs-duplicate-index":
        values[1]["index"] = "0"
    return values


def fixture_services(raw):
    root = xml(raw)
    require(root.tag == MD + "EntityDescriptor", "fixture root is not EntityDescriptor")
    descriptors = root.findall(MD + "SPSSODescriptor")
    require(len(descriptors) == 1, "fixture has an unexpected number of SPSSODescriptor values")
    services = [element.attrib.copy() for element in descriptors[0].findall(MD + "AssertionConsumerService")]
    require(len(services) == 4, "fixture must contain exactly four ACS endpoints")
    return root.attrib.get("entityID"), services


def response_path(entry, entity, run, variant, index):
    parsed = urlparse(entry["url"])
    return (parsed.scheme == "http" and parsed.netloc == "localhost:18080"
            and parsed.path == f"{urlparse(entity).path}/sp/acs/{index}"
            and parse_qs(parsed.query) == {"mdv": [variant], "run": [run]})


def original_bytes(folder, transcript):
    manifest = read(folder / "decoded-manifest.json")
    by_id = {entry["id"]: entry for entry in transcript}
    require(len(by_id) == len(transcript), "transcript has duplicate identifiers")
    decoded_root = (folder / "decoded").resolve()
    values = {}
    for row in manifest:
        require(set(row) == {"id", "file", "sha256"} and row["id"] in by_id,
                "decoded manifest row is malformed")
        entry = by_id[row["id"]]
        require(entry.get("runId") == transcript[0]["runId"], "decoded entry has a mixed Run")
        expected_ref = f"transcripts/{entry['runId']}/{entry['id']}.saml.xml"
        require(entry.get("decodedSamlRef") == expected_ref, "decoded entry source is unexpected")
        path = (folder / row["file"]).resolve()
        require(path.parent == decoded_root and path.is_file(), "decoded original path escapes the evidence folder")
        raw = path.read_bytes()
        require(sha(raw) == row["sha256"] and len(raw) == entry.get("decodedSamlBytes"),
                "decoded original hash or length does not match transcript")
        values[entry["id"]] = raw
    require(set(values) == {entry["id"] for entry in transcript if entry.get("decodedSamlRef")},
            "decoded manifest does not cover every decoded transcript entry")
    return by_id, values


def one(items, detail):
    require(len(items) == 1, detail)
    return items[0]


def case_in(result):
    return one([case for requirement in result["requirements"] for case in requirement["cases"]
                if case["id"] == CASE], "result has an unexpected MD05.av case count")


def verify_driver(folder):
    raw = (folder / "driver" / "console_import.mjs").read_bytes()
    require(len(raw) > 1000, "console-import driver is missing")
    source = raw.decode()
    required = (
        "getByText('Import client'", "setInputFiles(fixturePath)",
        "product-import-signal", "admin-read-back", "cleanup-delete-verified",
        "method: 'DELETE'",
    )
    require(all(value in source for value in required),
            "captured driver does not use the product console import path")
    require("fetch(`${ADMIN}/clients`, { method: 'POST'" not in source,
            "captured driver directly creates a client through the Admin API")
    return sha(raw)


def verify_with_report(root):
    folder = Path(root) / FOLDER
    run_record = read(folder / "created.json")["run"]
    run = run_record["id"]
    require(re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", run) is not None,
            "Run id is malformed")
    plan = read(folder / "plan.json")["plan"]
    plan_data = plan["plan"]
    require(plan_data["id"] == run_record["planId"], "Run is not bound to its plan")
    require(plan_data["profile"] == "metadata_idp" and plan_data["target"]["kind"] == "IDP",
            "plan has the wrong role or profile")
    require(plan_data["target"]["entityId"] == "http://localhost:18180/realms/samlscope",
            "plan has the wrong Keycloak target")
    entity = plan["entityId"]
    require(entity == f"http://localhost:18080/p/{plan_data['id']}",
            "Suite metadata entity is not bound to the plan")
    verify_target_runtime(folder, run_record["createdAt"])

    campaign = read(folder / "campaign.json")
    require(campaign["runId"] == run and campaign["planId"] == plan_data["id"],
            "campaign does not bind Run and plan")
    require(campaign["ingestionMode"] == "AUTOMATIC_POLLING"
            and tuple(campaign["campaignVariants"]) == VARIANTS
            and campaign["operatorContinuationActions"] == 0,
            "campaign did not execute the complete unattended fixture sequence")
    require(read(folder / "final-state.json")["campaignIndex"] == len(VARIANTS),
            "campaign did not consume every fixture")
    driver_sha = verify_driver(folder)

    transcript = read(folder / "transcript.json")
    require(len(transcript) == 20 and all(entry.get("runId") == run for entry in transcript),
            "transcript is incomplete or mixed")
    entries, decoded = original_bytes(folder, transcript)
    capture = read(folder / "original-capture.json")
    target_metadata = (folder / "target-metadata.xml").read_bytes()
    require(capture == {"run": run, "originals": len(decoded),
                        "target_metadata_sha256": sha(target_metadata)},
            "original capture record does not bind target metadata")

    runtime = read(folder / "suite-runtime.json")
    inspect_raw = (folder / "suite-container-inspect.json").read_bytes()
    inspected = json.loads(inspect_raw)
    require(isinstance(inspected, list) and len(inspected) == 1, "Suite inspect is malformed")
    jar = (folder / "suite-runner-0.1.0.jar").read_bytes()
    require(runtime == {
        "run": run,
        "container": {"name": inspected[0]["Name"].removeprefix("/"), "id": inspected[0]["Id"],
                      "image": inspected[0]["Image"], "started_at": inspected[0]["State"]["StartedAt"]},
        "runner_jar": {"path": "/opt/samlscope/lib/runner-0.1.0.jar", "sha256": sha(jar)},
        "docker_inspect_sha256": sha(inspect_raw),
    }, "Suite runtime summary does not bind its originals")
    require(parse_time(runtime["container"]["started_at"]) < float(run_record["createdAt"]),
            "Suite started after the measured Run")
    with zipfile.ZipFile(folder / "suite-runner-0.1.0.jar") as archive:
        factory = archive.read("com/samlscope/runner/cases/MetadataConfigCaseFactory.class")
    require(all(value.encode() in factory for value in (
        "IIP-MD05.av", "default-acs-first", "default-acs-first-omitted",
        "default-acs-all-false", "default-acs-duplicate-index")),
        "running Suite JAR lacks the approved MD05.av fixture mapping")

    operations = read(folder / "operations.json")
    require(len(operations) == len(VARIANTS), "operation record count is wrong")
    refs = set()
    conclusions = {}
    for ordinal, variant in enumerate(VARIANTS):
        operation = operations[ordinal]
        require(operation == {
            "variant": variant,
            "fixture_sha256": sha((folder / variant / "fixture.xml").read_bytes()),
            "driver_exit": 0,
            "record": str((folder / variant / "import.json").resolve()),
        }, "operation record is not bound to its fixture and native import receipt")
        fixture = (folder / variant / "fixture.xml").read_bytes()
        fixture_entity, services = fixture_services(fixture)
        require(fixture_entity == entity and services == expected_services(entity, run, variant),
                "fixture is not the approved default-ACS input")

        imported = read(folder / variant / "import.json")
        flow = read(folder / variant / "flow.json")
        require(imported["status"] == "success" and imported["fixture"] == {
            "path": str((folder / variant / "fixture.xml").resolve()),
            "sha256": sha(fixture), "bytes": len(fixture), "entity_id": entity,
        }, "native import receipt is not bound to its original fixture")
        require(imported["import"]["save_clicked"] is True
                and imported["import"]["ui_status"] == "client-settings-page"
                and re.fullmatch(r"[0-9a-f-]{36}", imported["client"]["database_id"] or "") is not None,
                "Keycloak console did not positively confirm client import")
        steps = [step["step"] for step in imported["steps"]]
        require(steps == ["file-selected", "product-parsed-entity-id", "product-import-signal",
                          "admin-read-back", "follow-up-flow", "cleanup-delete-verified"],
                "import receipt is missing a required native step")
        readback = imported["import"]["read_back"]
        require(readback["client_id"] == entity and readback["saml_attributes"].get("saml.client.signature") == "true",
                "Keycloak Admin API read-back is not for the imported client")
        require(imported["flow"].get("ok") is True and imported["cleanup"] == {
            "deleted_status": 204, "read_back_absent": True},
                "temporary client was not followed by a verified deletion")
        require(flow["run"] == run and flow["variant"] == variant
                and flow["correlated_success"] is True
                and flow["before_index"] == ordinal and flow["after_index"] == ordinal + 1,
                "follow-up flow is not the expected Run-correlated fixture operation")
        exchange = flow["positive_exchange"]
        require(exchange["success"] is True and exchange["status_codes"] == [SUCCESS]
                and len(exchange["transcript_ids"]) == 2,
                "follow-up flow lacks one successful request/response exchange")
        request_id, response_id = exchange["transcript_ids"]
        request = entries.get(request_id)
        response = entries.get(response_id)
        require(request is not None and response is not None, "flow references unknown transcript entries")
        require(request["direction"] == "OUTBOUND" and request["url"] == "http://localhost:18180/realms/samlscope/protocol/saml",
                "request does not target the bound Keycloak IdP")
        require(request["samlSummary"] == {
            "attributeConsumingServiceIndex": "absent", "type": "AuthnRequest", "id": exchange["request_id"],
            "campaign": "metadata-polling", "variant": variant,
            "metadataSignatureGroup": request["samlSummary"]["metadataSignatureGroup"],
            "metadataSignatureControl": "valid",
        }, "request transcript is not the expected valid metadata fixture request")
        require(response["direction"] == "INBOUND" and response["samlSummary"].get("type") == "Response"
                and response["samlSummary"].get("inResponseTo") == exchange["request_id"]
                and response["samlSummary"].get("statusCode") == SUCCESS
                and response["samlSummary"].get("metadataProbeAccepted") is True,
                "response lacks a correlated successful metadata probe")
        request_xml = xml(decoded[request_id])
        response_xml = xml(decoded[response_id])
        require(request_xml.tag == P + "AuthnRequest" and request_xml.attrib.get("ID") == exchange["request_id"],
                "request original does not match transcript")
        require(response_xml.tag == P + "Response" and response_xml.attrib.get("InResponseTo") == exchange["request_id"],
                "response original does not match request")
        status = one(response_xml.findall(".//" + P + "StatusCode"), "response must have one StatusCode")
        require(status.attrib.get("Value") == SUCCESS and response_xml.attrib.get("Destination") == response["url"],
                "response original is not a successful response for the observed endpoint")
        if variant == "control":
            require(request_xml.attrib.get("AssertionConsumerServiceURL") == services[0]["Location"],
                    "control request did not bind the baseline ACS")
        else:
            require(not any(name in request_xml.attrib for name in (
                "AssertionConsumerServiceURL", "AssertionConsumerServiceIndex", "ProtocolBinding")),
                    "fixture request bypassed metadata ACS selection")
        prepared = one([entry for entry in transcript if entry["samlSummary"].get("type") == "MetadataPrepared"
                        and entry["samlSummary"].get("variant") == variant],
                       "fixture must have one prepared metadata original")
        fetched = one([entry for entry in transcript if entry["samlSummary"].get("type") == "MetadataFetch"
                       and entry["samlSummary"].get("variant") == variant],
                      "fixture must have one metadata fetch")
        require(decoded[prepared["id"]] == fixture and prepared["samlSummary"].get("metadataSha256") == sha(fixture),
                "prepared Suite metadata does not equal uploaded fixture")
        require(prepared["samlSummary"].get("fetchTranscriptId") == fetched["id"]
                and fetched["timestamp"] < prepared["timestamp"] < request["timestamp"] < response["timestamp"],
                "metadata fetch, import-driven flow, and response ordering is invalid")
        observed_url = response["url"]
        require(readback["saml_attributes"].get("saml_assertion_consumer_url_post") == observed_url,
                "Keycloak read-back ACS does not match the actual response endpoint")
        if variant in EXPECTED_INDEX:
            expected = EXPECTED_INDEX[variant]
            conclusions[variant] = {
                "expected_index": expected,
                "observed_index": int(urlparse(observed_url).path.rsplit("/", 1)[-1]),
            }
            if variant != "default-acs-first-omitted":
                require(response_path(response, entity, run, variant, expected),
                        "positive default-ACS control reached the wrong endpoint")
            else:
                require(response_path(response, entity, run, variant, 0)
                        and not response_path(response, entity, run, variant, expected),
                        "first-omitted control did not demonstrate the observed wrong default")
        else:
            require(variant == "default-acs-duplicate-index", "unexpected fixture category")
            require(response_path(response, entity, run, variant, 0),
                    "duplicate-index fixture did not reach the imported product endpoint")
            conclusions[variant] = {"expected": "reject", "observed": "imported-and-successful"}
        refs.update({f"transcript:{fetched['id']}", f"transcript:{prepared['id']}",
                     f"transcript:{request_id}", f"transcript:{response_id}"})

    original = read(folder / "result.json")
    reevaluated = read(folder / "evaluation-v139" / "result.json")
    observed = case_in(original)
    require(observed == case_in(reevaluated), "formal re-evaluation changed the MD05.av result")
    require((observed["outcome"], observed["verdict"], observed["reason_code"], observed["attested"]) == (
        "VIOLATED", "FAIL", "metadata.fixture-probe.violated", False),
        "Suite did not produce the expected un-attested product violation")
    require(all(item["kind"] == "transcript" and item["reference"] in refs for item in observed["evidence"]),
            "Suite case evidence is outside the independently replayed Run scope")
    before = read(folder / "evaluation-v139" / "transcript-before.json")
    after = read(folder / "evaluation-v139" / "transcript.json")
    require(before == after == transcript, "formal re-evaluation altered the transcript")
    require(reevaluated["target"]["metadata_digest"] == "sha256:" + sha(target_metadata),
            "result is not bound to captured target metadata")
    return folder / "evaluation-v139" / "result.json", {CASE: observed}, {
        "run": run,
        "case": CASE,
        "verdict": observed["verdict"],
        "reason_code": observed["reason_code"],
        "driver_sha256": driver_sha,
        "target": {"container": TARGET_CONTAINER, "version": TARGET_VERSION},
        "conclusions": conclusions,
        "operations": {
            "product_configuration_writes": len(VARIANTS),
            "temporary_clients_deleted_and_read_back_absent": len(VARIANTS),
            "product_restarts": 0,
            "human_operations": 0,
            "protocol_exchanges": len(VARIANTS),
        },
    }


def verify(root):
    """Return the immutable re-evaluation result in the generator's standard shape."""
    result, cases, _ = verify_with_report(root)
    return result, cases


if __name__ == "__main__":
    import sys
    result, cases, report = verify_with_report(sys.argv[1])
    report_path = result.parent.parent / "acceptance-v139.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(result, {name: value["verdict"] for name, value in cases.items()})
