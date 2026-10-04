#!/usr/bin/env python3
"""Fail-closed adoption verifier for Shibboleth's native default-ACS campaign."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from urllib.parse import parse_qs, urlparse
import xml.etree.ElementTree as ET
import zipfile


if not __debug__:
    raise RuntimeError("Shibboleth default-ACS acceptance verification must not run with Python optimization")


CASE = "IIP-MD05-av-idp-01"
FOLDER = "shibboleth-default-acs-v138"
TARGET = "samlscope-reference-shibboleth"
TARGET_VERSION = "5.2.3"
TARGET_VERSION_SOURCE = "/opt/reference-idp/dist/idp.installed.version"
TARGET_VERSION_COMMAND = "/opt/reference-idp/bin/version.sh"
SUITE = "samlscope-reference-suite"
RUNNER_JAR = "/opt/samlscope/lib/runner-0.1.0.jar"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
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


def read(folder, name):
    return json.loads((folder / name).read_text())


def case(result):
    matches = [item for requirement in result["requirements"] for item in requirement["cases"]
               if item["id"] == CASE]
    require(len(matches) == 1, "result must contain one default-ACS case")
    return matches[0]


def safe_xml(raw):
    require(b"<!DOCTYPE" not in raw.upper() and b"<!ENTITY" not in raw.upper(),
            "captured XML original contains DTD or entity declaration")
    return ET.fromstring(raw)


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def parse_time(value):
    if isinstance(value, (int, float)):
        return float(value)
    require(isinstance(value, str), "timestamp is not a number or ISO timestamp")
    from datetime import datetime
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def target_binding(inspect):
    require(isinstance(inspect, list) and len(inspect) == 1,
            "target container inspection must contain exactly one value")
    value = inspect[0]
    state = value.get("State", {})
    require(state.get("Running") is True, "target was not running at capture")
    container_id = value.get("Id", "")
    image_id = value.get("Image", "")
    started_at = state.get("StartedAt", "")
    require(len(container_id) == 64 and image_id.startswith("sha256:") and started_at,
            "target identity is incomplete")
    protected_roots = ("/opt/reference-idp", "/usr/local/tomcat/webapps/idp")
    for mount in value.get("Mounts", []):
        destination = mount.get("Destination", "")
        require(not any(destination == root or destination.startswith(root + "/")
                        for root in protected_roots),
                "target executable or configuration root is mounted from outside the image")
    ports = value.get("NetworkSettings", {}).get("Ports", {}).get("8080/tcp") or []
    require(any(item.get("HostIp") == "127.0.0.1" and item.get("HostPort") == "18280"
                for item in ports), "target localhost port binding differs")
    return {
        "container_name": TARGET,
        "container_id": container_id,
        "image_id": image_id,
        "container_started_at": started_at,
        "running_at_capture": True,
        "host_port": 18280,
        "protected_roots_mounted": False,
    }


def target_runtime(folder, label):
    summary = read(folder, f"target-runtime-{label}.json")
    inspect_raw = (folder / f"target-container-inspect-{label}.json").read_bytes()
    source_raw = (folder / f"target-version-source-{label}.properties").read_bytes()
    runtime_raw = (folder / f"target-version-runtime-{label}.txt").read_bytes()
    source_values = [line.split("=", 1)[1].strip() for line in source_raw.decode("utf-8").splitlines()
                     if line.startswith("idp.installed.version=")]
    require(source_values == [TARGET_VERSION], "target version source is not Shibboleth 5.2.3")
    runtime_value = runtime_raw.decode("utf-8").strip()
    require(runtime_value == TARGET_VERSION, "target runtime version is not Shibboleth 5.2.3")
    expected = {
        "captured_at": summary.get("captured_at"),
        "binding": target_binding(json.loads(inspect_raw)),
        "docker_inspect_sha256": sha(inspect_raw),
        "version_source": {
            "path": TARGET_VERSION_SOURCE,
            "file": f"target-version-source-{label}.properties",
            "sha256": sha(source_raw),
            "value": TARGET_VERSION,
        },
        "runtime_version": {
            "command": TARGET_VERSION_COMMAND,
            "file": f"target-version-runtime-{label}.txt",
            "value": TARGET_VERSION,
        },
    }
    require(isinstance(summary.get("captured_at"), (int, float)), "target capture time is absent")
    require(summary == expected, "target runtime summary does not match its originals")
    return summary


def suite_runtime(folder, label):
    summary = read(folder, f"suite-runtime-{label}.json")
    inspect_raw = (folder / f"suite-container-inspect-{label}.json").read_bytes()
    inspect = json.loads(inspect_raw)
    require(isinstance(inspect, list) and len(inspect) == 1 and inspect[0].get("State", {}).get("Running") is True,
            "Suite was not running at capture")
    jar_raw = (folder / f"suite-runner-{label}.jar").read_bytes()
    expected = {
        "captured_at": summary.get("captured_at"),
        "container": {
            "name": inspect[0]["Name"].removeprefix("/"),
            "id": inspect[0]["Id"],
            "image": inspect[0]["Image"],
            "started_at": inspect[0]["State"]["StartedAt"],
        },
        "docker_inspect_sha256": sha(inspect_raw),
        "runner_jar": {"path": RUNNER_JAR, "sha256": sha(jar_raw)},
    }
    require(isinstance(summary.get("captured_at"), (int, float)), "Suite capture time is absent")
    require(summary == expected, "Suite runtime summary does not match its originals")
    with zipfile.ZipFile(folder / f"suite-runner-{label}.jar") as archive:
        factory = archive.read("com/samlscope/runner/cases/MetadataConfigCaseFactory.class")
        observer = archive.read("com/samlscope/runner/cases/MetadataFixtureObservationTestCase.class")
    for value in ("IIP-MD05.av", *VARIANTS[1:]):
        require(value.encode("utf-8") in factory, "Runner lacks an approved default-ACS fixture")
    require(b"wrong_default_acs" in observer and b"expected_rejection" in observer,
            "Runner lacks the default-ACS observation paths")
    return summary


def expected_services(entity, run, variant):
    services = [
        {"Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
         "Location": f"{entity}/sp/acs/0?mdv={variant}&run={run}", "index": "0"},
        {"Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
         "Location": f"{entity}/sp/acs/1?mdv={variant}&run={run}", "index": "1"},
        {"Binding": "urn:oasis:names:tc:SAML:2.0:bindings:PAOS",
         "Location": f"{entity}/sp/paos?mdv={variant}&run={run}", "index": "2"},
        {"Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
         "Location": f"{entity}/sp/acs/3?mdv={variant}&run={run}", "index": "3"},
    ]
    if variant in {"control", "default-acs-first"}:
        services[0]["isDefault"] = "true"
    elif variant == "default-acs-first-omitted":
        services[0]["isDefault"] = "false"
    elif variant in {"default-acs-all-false", "default-acs-duplicate-index"}:
        for service in services:
            service["isDefault"] = "false"
    if variant == "default-acs-duplicate-index":
        services[1]["index"] = "0"
    return services


def fixture_services(raw):
    root = safe_xml(raw)
    require(local_name(root.tag) == "EntityDescriptor", "fixture root is not EntityDescriptor")
    descriptors = [value for value in root.iter() if local_name(value.tag) == "SPSSODescriptor"]
    require(len(descriptors) == 1, "fixture must contain one SPSSODescriptor")
    services = [value.attrib.copy() for value in descriptors[0]
                if local_name(value.tag) == "AssertionConsumerService"]
    require(len(services) == 4, "fixture must contain four AssertionConsumerService endpoints")
    return root.attrib.get("entityID"), services


def response_path(entry, entity, run, variant, index):
    expected_entity = urlparse(entity)
    parsed = urlparse(entry["url"])
    return (parsed.scheme == expected_entity.scheme == "http"
            and parsed.netloc == expected_entity.netloc == "localhost:18080"
            and parsed.path == expected_entity.path + f"/sp/acs/{index}"
            and not parsed.params and not parsed.fragment
            and parse_qs(parsed.query, keep_blank_values=True) == {"mdv": [variant], "run": [run]})


def decoded_originals(folder, transcript):
    manifest = read(folder, "decoded-manifest.json")
    require(isinstance(manifest, list), "decoded original manifest is not a list")
    entries = {entry["id"]: entry for entry in transcript}
    require(len(entries) == len(transcript), "transcript includes a duplicate identifier")
    decoded = {}
    root = (folder / "decoded").resolve()
    for row in manifest:
        require(set(row) == {"id", "file", "sha256"} and row["id"] in entries,
                "invalid decoded original manifest record")
        path = (folder / row["file"]).resolve()
        require(path.parent == root and path.is_file(), "decoded original escapes its evidence directory")
        raw = path.read_bytes()
        require(sha(raw) == row["sha256"], "decoded original digest mismatch")
        require(entries[row["id"]].get("decodedSamlBytes") == len(raw),
                "decoded original size does not match transcript")
        decoded[row["id"]] = raw
    require({entry["id"] for entry in transcript if entry.get("decodedSamlBytes", 0) > 0} == set(decoded),
            "not every decoded transcript original was captured")
    return entries, decoded


def one(items, detail):
    require(len(items) == 1, detail)
    return items[0]


def validate_variant(folder, entries, decoded, entity, run, variant):
    fixture = (folder / variant / "fixture.xml").read_bytes()
    fixture_entity, services = fixture_services(fixture)
    require(fixture_entity == entity and services == expected_services(entity, run, variant),
            f"{variant} fixture does not match the approved default-ACS input")
    record = read(folder / variant, "import.json")
    require(record == {
        "product": "shibboleth",
        "import_path": "native-filesystem-provider",
        "variant": variant,
        "run": run,
        "status": "success",
        "entity_id": entity,
        "fixture_sha256": sha(fixture),
        "configuration_read_back": True,
        "provider_reloaded": True,
        "restored": True,
    }, f"{variant} native import record is incomplete")
    flow = read(folder / variant, "flow.json")
    require(flow.get("run") == run and flow.get("variant") == variant
            and flow.get("correlated_success") is True
            and flow.get("positive_exchange", {}).get("success") is True,
            f"{variant} lacks a correlated normal exchange")
    control = flow.get("negative_control")
    require(isinstance(control, dict) and control.get("source") == "suite"
            and control.get("correlated_success") is False,
            f"{variant} invalid-signature control is missing or accepted")
    matching = [entry for entry in entries.values()
                if entry.get("samlSummary", {}).get("variant") == variant]
    fetch = one([entry for entry in matching if entry.get("direction") == "INBOUND"
                 and entry["samlSummary"].get("type") == "MetadataFetch"],
                f"{variant} must have one metadata fetch")
    prepared = one([entry for entry in matching if entry.get("direction") == "OUTBOUND"
                    and entry["samlSummary"].get("type") == "MetadataPrepared"],
                   f"{variant} must have one prepared metadata original")
    require(decoded.get(prepared["id"]) == fixture
            and prepared["samlSummary"].get("metadataSha256") == sha(fixture)
            and prepared["samlSummary"].get("fetchTranscriptId") == fetch["id"],
            f"{variant} prepared metadata is not the fetched fixture")
    request = one([entry for entry in matching if entry.get("direction") == "OUTBOUND"
                   and entry["samlSummary"].get("type") == "AuthnRequest"
                   and entry["samlSummary"].get("metadataSignatureControl") == "valid"],
                  f"{variant} must have one valid AuthnRequest")
    request_root = safe_xml(decoded[request["id"]])
    require(local_name(request_root.tag) == "AuthnRequest"
            and request_root.attrib.get("ID") == request["samlSummary"].get("id")
            and request_root.attrib.get("Destination") == "http://localhost:18280/idp/profile/SAML2/POST/SSO",
            f"{variant} AuthnRequest is not bound to the target")
    if variant == "control":
        require(request_root.attrib.get("AssertionConsumerServiceURL") == services[0]["Location"],
                "control request does not bind its known ACS")
    else:
        require("AssertionConsumerServiceURL" not in request_root.attrib
                and "AssertionConsumerServiceIndex" not in request_root.attrib,
                f"{variant} request bypasses metadata default selection")
    response = one([entry for entry in entries.values() if entry.get("direction") == "INBOUND"
                    and entry.get("samlSummary", {}).get("type") == "Response"
                    and entry["samlSummary"].get("inResponseTo") == request["samlSummary"].get("id")],
                   f"{variant} lacks one response correlated to the normal request")
    summary = response["samlSummary"]
    require(summary.get("metadataProbeAccepted") is True and summary.get("statusCode") == SUCCESS,
            f"{variant} response is not a recorded SAML Success")
    require(response.get("url") in {service["Location"] for service in services},
            f"{variant} response destination is not an endpoint in the imported fixture")
    response_root = safe_xml(decoded[response["id"]])
    require(local_name(response_root.tag) == "Response"
            and response_root.attrib.get("InResponseTo") == request["samlSummary"].get("id")
            and response_root.attrib.get("Destination") == response.get("url"),
            f"{variant} response XML is not tied to its recorded destination")
    status_codes = [element.attrib.get("Value") for element in response_root.iter()
                    if local_name(element.tag) == "StatusCode"]
    require(SUCCESS in status_codes, f"{variant} response XML lacks Success status")
    require(fetch["timestamp"] < prepared["timestamp"] < request["timestamp"] < response["timestamp"],
            f"{variant} operation timestamps are not ordered")
    return fixture, services, request, response


def verify(root, folder_name=FOLDER):
    folder = Path(root) / folder_name
    require(folder.is_dir(), "default-ACS evidence directory is absent")
    run_record = read(folder, "created.json")["run"]
    run = run_record["id"]
    created_at = parse_time(run_record["createdAt"])
    plan = read(folder, "plan.json")["plan"]
    plan_data = plan["plan"]
    require(plan_data["profile"] == "metadata_idp" and plan_data["target"]["kind"] == "IDP"
            and plan_data["target"]["entityId"] == "http://localhost:18280/idp/shibboleth"
            and plan_data["requestSigningMode"] == "REQUIRED",
            "plan is not the approved Shibboleth metadata campaign")
    entity = plan["entityId"]
    input_record = read(folder, "campaign-input.json")
    driver_raw = (folder / "native-filesystem-driver.py").read_bytes()
    require(input_record == {
        "variants": list(VARIANTS), "driver": "dev/shibboleth/import_metadata_batch.py",
        "driver_sha256": sha(driver_raw), "human_operations": 0,
    }, "campaign input is not bound to the executed native driver")
    campaign = read(folder, "campaign.json")
    require(campaign["runId"] == run and campaign["planId"] == plan_data["id"]
            and campaign["ingestionMode"] == "AUTOMATIC_POLLING"
            and tuple(campaign["campaignVariants"]) == VARIANTS
            and campaign["operatorContinuationActions"] == 0,
            "automatic polling campaign differs from the approved fixture set")

    target_start = target_runtime(folder, "start")
    target_end = target_runtime(folder, "end")
    require(target_start["binding"] == target_end["binding"]
            and {key: value for key, value in target_start["version_source"].items() if key != "file"}
                == {key: value for key, value in target_end["version_source"].items() if key != "file"}
            and {key: value for key, value in target_start["runtime_version"].items() if key != "file"}
                == {key: value for key, value in target_end["runtime_version"].items() if key != "file"},
            "target identity or version changed during campaign")
    require(target_start["captured_at"] < created_at < target_end["captured_at"]
            and parse_time(target_start["binding"]["container_started_at"]) < created_at,
            "target runtime is not temporally bound to this Run")
    public_start = (folder / "target-public-metadata-start.xml").read_bytes()
    public_end = (folder / "target-public-metadata-end.xml").read_bytes()
    target_metadata = (folder / "target-metadata.xml").read_bytes()
    require(public_start == public_end == target_metadata,
            "target metadata changed or does not match the Suite-pinned original")
    target_root = safe_xml(target_metadata)
    require(local_name(target_root.tag) == "EntityDescriptor"
            and target_root.attrib.get("entityID") == "http://localhost:18280/idp/shibboleth",
            "pinned target metadata does not identify Shibboleth")

    suite_start = suite_runtime(folder, "start")
    suite_end = suite_runtime(folder, "end")
    require(suite_start["container"] == suite_end["container"]
            and suite_start["runner_jar"] == suite_end["runner_jar"]
            and suite_start["captured_at"] < created_at < suite_end["captured_at"],
            "Suite runtime changed or is not temporally bound to this Run")

    original = (folder / "original-providers.xml").read_bytes()
    configured = (folder / "configured-providers.xml").read_bytes()
    final = (folder / "final-providers.xml").read_bytes()
    restoration = read(folder, "restoration.json")
    require(original != configured and original == final
            and restoration == {
                "restored": True,
                "temporary_file_removed": True,
                "signature_certificate_removed": True,
                "original_sha256": sha(original),
                "final_sha256": sha(final),
            }, "Shibboleth provider configuration was not restored exactly")
    provider_root = safe_xml(configured)
    providers = [value for value in provider_root if local_name(value.tag) == "MetadataProvider"]
    require(providers and providers[0].attrib.get("id") == "Algorithm" + run
            and providers[0].attrib.get("metadataFile") == "/opt/reference-idp/metadata/algorithm-" + run + ".xml"
            and providers[0].attrib.get("{http://www.w3.org/2001/XMLSchema-instance}type") == "FilesystemMetadataProvider",
            "configured provider does not point to the Run-specific native fixture")
    counts = read(folder, "operation-counts.json")
    require(counts == {
        "run": run, "human_operations": 0, "product_configuration_writes": 2,
        "product_configuration_restoration_writes": 1, "temporary_fixture_writes": len(VARIANTS),
        "metadata_resolver_reloads": len(VARIANTS) + 1, "normal_protocol_flows": len(VARIANTS),
        "suite_signature_controls": len(VARIANTS), "product_restarts": 0,
        "operator_continuations": 0, "operations_recorded": len(VARIANTS), "restored": True,
    }, "operation count record is incomplete")

    transcript = read(folder, "transcript.json")
    require(all(entry.get("runId") == run for entry in transcript), "transcript mixes Runs")
    entries, decoded = decoded_originals(folder, transcript)
    capture = read(folder, "original-capture.json")
    require(capture == {"run": run, "originals": len(decoded), "target_metadata_sha256": sha(target_metadata)},
            "original capture record is incomplete")
    validations = {}
    for variant in VARIANTS:
        validations[variant] = validate_variant(folder, entries, decoded, entity, run, variant)
    omitted_response = validations["default-acs-first-omitted"][3]
    require(response_path(omitted_response, entity, run, "default-acs-first-omitted", 0)
            and not response_path(omitted_response, entity, run, "default-acs-first-omitted", 1),
            "explicit false was not observed to win over the omitted default")
    duplicate_services = validations["default-acs-duplicate-index"][1]
    duplicate_response = validations["default-acs-duplicate-index"][3]
    require(duplicate_services[0]["index"] == duplicate_services[1]["index"] == "0"
            and duplicate_response["url"] in {service["Location"] for service in duplicate_services},
            "duplicate-index fixture was not actually used by the target")

    original_result = read(folder, "result.json")
    replayed_result = read(folder, "evaluation-v138/result.json")
    observed = case(original_result)
    require(observed == case(replayed_result), "formal re-evaluation changed the default-ACS conclusion")
    require((observed["outcome"], observed["verdict"], observed["reason_code"], observed["attested"]) == (
        "VIOLATED", "FAIL", "metadata.fixture-probe.violated", False),
        "Run did not reach the expected product violation")
    diagnostics = observed.get("diagnostics", {})
    require("default-acs-first-omitted" in diagnostics.get("wrong_endpoint_variants", [])
            and "default-acs-first-omitted" in diagnostics.get("missing_acceptance", [])
            and set(diagnostics.get("fetched_variants", [])) == set(VARIANTS),
            "Runner diagnostics do not identify the default-selection failure")
    evidence_refs = {(item.get("kind"), item.get("reference")) for item in observed.get("evidence", [])}
    for variant in ("control", "default-acs-first", "default-acs-first-omitted", "default-acs-all-false"):
        request, response = validations[variant][2:]
        require(("transcript", "transcript:" + request["id"]) in evidence_refs
                and ("transcript", "transcript:" + response["id"]) in evidence_refs,
                f"Runner result lacks the decisive {variant} evidence references")
    before = read(folder, "evaluation-v138/transcript-before.json")
    after = read(folder, "evaluation-v138/transcript.json")
    require(before == after == transcript and read(folder, "evaluation-v138/evaluation.json").get("completed") == [],
            "formal re-evaluation did not preserve the recorded transcript")
    return folder / "evaluation-v138/result.json", {CASE: observed}


def negative_validation(root):
    source = Path(root)
    checks = []
    with tempfile.TemporaryDirectory() as temporary:
        temp_root = Path(temporary)
        copied = temp_root / FOLDER
        shutil.copytree(source / FOLDER, copied)
        fixture = copied / "default-acs-first-omitted/fixture.xml"
        fixture.write_bytes(fixture.read_bytes().replace(b'isDefault="false"', b'isDefault="true"', 1))
        try:
            verify(temp_root)
        except Exception:
            checks.append("fixture-tamper-rejected")
        else:
            raise RuntimeError("fixture tamper was accepted")
        shutil.rmtree(copied)
        shutil.copytree(source / FOLDER, copied)
        source_file = copied / "target-version-source-end.properties"
        source_file.write_bytes(source_file.read_bytes().replace(b"5.2.3", b"5.2.4", 1))
        try:
            verify(temp_root)
        except Exception:
            checks.append("target-version-tamper-rejected")
        else:
            raise RuntimeError("target-version tamper was accepted")
        shutil.rmtree(copied)
        shutil.copytree(source / FOLDER, copied)
        response = copied / "decoded/tx_PKG3K5FPEC66TRHAACC3176670.xml"
        # The transcript ID is stable for this evidence set and the body replacement breaks the
        # manifest digest before any conclusion can be selected.
        require(response.exists(), "expected decisive response original is absent")
        response.write_bytes(response.read_bytes() + b" ")
        try:
            verify(temp_root)
        except Exception:
            checks.append("response-original-tamper-rejected")
        else:
            raise RuntimeError("response-original tamper was accepted")
    return checks


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--negative-validation", action="store_true")
    parser.add_argument("--record-negative-validation", action="store_true")
    args = parser.parse_args()
    require(not args.record_negative_validation or args.negative_validation,
            "--record-negative-validation requires --negative-validation")
    path, cases = verify(args.root)
    output = {"result": str(path), "verdicts": {case_id: value["verdict"] for case_id, value in cases.items()}}
    if args.negative_validation:
        output["negative_validation"] = negative_validation(args.root)
    if args.record_negative_validation:
        record = Path(args.root) / FOLDER / "negative-validation.json"
        require(not record.exists(), "negative validation record already exists")
        record.write_text(json.dumps({"checks": output["negative_validation"]}, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
