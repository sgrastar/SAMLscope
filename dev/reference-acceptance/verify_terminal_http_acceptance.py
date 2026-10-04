#!/usr/bin/env python3
"""Fail-closed adoption gate for SSO01.d/ak/em browser-terminal campaigns.

This verifier independently replays every adopted fixture from Recorder-owned originals.  It
never turns a timeout, missing callback, cross-origin page, or uncorrelated result into evidence.
The command-line entry point remains disabled until the exact deployed Suite image/JAR hashes are
filled into ``ACCEPTED_SUITE`` after the shared image build is stable.
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from pathlib import Path


P = "{urn:oasis:names:tc:SAML:2.0:protocol}"
A = "{urn:oasis:names:tc:SAML:2.0:assertion}"
DS = "{http://www.w3.org/2000/09/xmldsig#}"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
EVALUATION = "evaluation-terminal-http-v1"
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
TX_RE = re.compile(r"tx_[0-9A-HJKMNP-TV-Z]{26}")
ACTION_RE = re.compile(r"action_[0-9a-f]{32}")

CASES = {
    "IIP-SSO01-d-idp-01": {
        "fixtures": ("baseline-success", "unrecognized-subject"),
        "satisfied_reason": "idp.error-assertion.satisfied",
        "violated_reason": "error_response_contains_assertion",
        "inconclusive_reason": "idp.error-assertion.inconclusive",
        "violated_verdict": "FAIL",
    },
    "IIP-SSO01-ak-idp-01": {
        "fixtures": ("valid", "tampered-acs", "bad-reference", "bad-signature-value"),
        "satisfied_reason": "idp.signed-request.satisfied",
        "violated_reason": "signed_request_validation_violated",
        "inconclusive_reason": "idp.signed-request.inconclusive",
        "violated_verdict": "WARNING",
    },
    "IIP-SSO01-em-idp-01": {
        "fixtures": ("baseline-success", "version-1-1", "version-3-0"),
        "satisfied_reason": "idp.version.satisfied",
        "violated_reason": "unsupported_major_version_accepted",
        "inconclusive_reason": "idp.version.inconclusive",
        "violated_verdict": "FAIL",
    },
}
PRODUCT_CASES = {
    "keycloak": tuple(CASES),
    # SSO01.d is already adopted for Shibboleth and must not be counted twice.
    "shibboleth": ("IIP-SSO01-ak-idp-01", "IIP-SSO01-em-idp-01"),
    "simplesamlphp": tuple(CASES),
}
EVIDENCE_FOLDERS = {
    "keycloak": "terminal-http-keycloak-v151b",
    "shibboleth": "terminal-http-shibboleth-v151b",
    "simplesamlphp": "terminal-http-ssp-v151",
}
PRODUCT = {
    "keycloak": {
        "target_entity": "http://localhost:18180/realms/samlscope",
        "sso": "http://localhost:18180/realms/samlscope/protocol/saml",
        "container": "samlscope-reference-keycloak",
        "container_port": "8080/tcp",
        "host_port": 18180,
        "version": "26.7.2",
    },
    "shibboleth": {
        "target_entity": "http://localhost:18280/idp/shibboleth",
        "sso": "http://localhost:18280/idp/profile/SAML2/POST/SSO",
        "container": "samlscope-reference-shibboleth",
        "container_port": "8080/tcp",
        "host_port": 18280,
        "version": "5.2.3",
    },
    "simplesamlphp": {
        "target_entity": "http://localhost:18380/idp",
        "sso": "http://localhost:18380/simplesaml/module.php/saml/idp/singleSignOnService",
        "container": "samlscope-reference-ssp",
        "container_port": "80/tcp",
        "host_port": 18380,
        "version": "2.5.0",
    },
}

# Exact identity of the shared v151 image that produced this campaign.  The verifier also reads
# every JAR back from the running container, hashes it, and checks the required oracle classes.
ACCEPTED_SUITE = {
    "image_id": "sha256:10e1bb41fc8fc6eec74df4eb201c190d2397c372a8b7e906d1178050addd009e",
    "jars": {
        "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe",
        "runner": "4e5f75e0238df5b93f3bf1443180d2b97c96366ef82eaafa0eb76bdc8183eeb5",
        "saml": "83c92fc2277830aacc5d79deac74428c3cbf57707c9a919313362260a2c0e7a3",
    },
}


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def one(values, detail):
    values = list(values)
    require(len(values) == 1, detail)
    return values[0]


def safe_xml(raw):
    upper = raw.upper()
    require(b"<!DOCTYPE" not in upper and b"<!ENTITY" not in upper, "DTD/entity in XML original")
    return ET.fromstring(raw)


def origin(value):
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme.lower() in {"http", "https"} and parsed.hostname, "invalid origin URL")
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80
    return parsed.scheme.lower(), parsed.hostname.lower(), port


def parsed_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def find_case(result, case_id):
    return one((case for requirement in result.get("requirements", [])
                for case in requirement.get("cases", []) if case.get("id") == case_id),
               "result must contain exactly one " + case_id)


def _verify_target_runtime(folder, product, run_created_at):
    expected = PRODUCT[product]
    captures = []
    for phase in ("start", "end"):
        summary = read(folder / f"target-runtime-{phase}.json")
        inspect_raw = (folder / f"target-container-inspect-{phase}.json").read_bytes()
        image_raw = (folder / f"target-image-inspect-{phase}.json").read_bytes()
        version_raw = (folder / f"target-version-runtime-{phase}.txt").read_bytes()
        require(summary.get("schema") == "samlscope-terminal-http-target-runtime-v1",
                "wrong target runtime schema")
        require(summary.get("product") == product and summary.get("phase") == phase,
                "target runtime product/phase mismatch")
        require(summary.get("docker_inspect_sha256") == sha(inspect_raw),
                "target inspect hash mismatch")
        require(summary.get("image_inspect_sha256") == sha(image_raw),
                "target image inspect hash mismatch")
        require(summary.get("runtime_version", {}).get("sha256") == sha(version_raw),
                "target version hash mismatch")
        inspected = read_bytes_json(inspect_raw, "target inspect")
        item = one(inspected, "target inspect must contain one container")
        image = one(read_bytes_json(image_raw, "target image inspect"),
                    "target image inspect must contain one image")
        binding = summary.get("binding", {})
        ports = item.get("NetworkSettings", {}).get("Ports", {}).get(expected["container_port"]) or []
        require(binding == {
            "container_name": item["Name"].removeprefix("/"),
            "container_id": item["Id"],
            "configured_image": item["Config"]["Image"],
            "image_id": item["Image"],
            "repo_digests": sorted(image.get("RepoDigests") or []),
            "container_started_at": item["State"]["StartedAt"],
            "running_at_capture": item["State"]["Running"],
            "container_port": expected["container_port"],
            "host_port": expected["host_port"],
            "host_port_bound": any(row.get("HostIp") == "127.0.0.1"
                                   and row.get("HostPort") == str(expected["host_port"])
                                   for row in ports),
        }, "target binding does not replay from inspect")
        require(binding["container_name"] == expected["container"]
                and binding["running_at_capture"] is True and binding["host_port_bound"] is True,
                "wrong or unavailable target container")
        require(image.get("Id") == binding["image_id"], "target image/container identity mismatch")
        require(len(binding["container_id"]) == 64 and binding["image_id"].startswith("sha256:"),
                "incomplete target container identity")
        require(parsed_time(binding["container_started_at"]) < run_created_at,
                "target container started after the Run")
        version = version_raw.decode().strip()
        if product == "keycloak":
            require(version.startswith("Keycloak " + expected["version"]), "wrong Keycloak version")
        else:
            require(version == expected["version"], "wrong target runtime version")
            source = summary.get("version_source", {})
            source_raw = (folder / source.get("file", "missing")).read_bytes()
            require(source.get("sha256") == sha(source_raw)
                    and source.get("value") == expected["version"], "version source mismatch")
        if product == "simplesamlphp":
            protected = ("/var/simplesamlphp/src", "/var/simplesamlphp/vendor",
                         "/var/simplesamlphp/public/module.php")
            for mount in item.get("Mounts", []):
                destination = mount.get("Destination", "")
                require(not any(destination == root or destination.startswith(root + "/")
                                for root in protected), "SimpleSAMLphp executable source is mounted")
        captures.append(summary)
    start, end = captures
    require(start["binding"] == end["binding"], "target identity changed during campaign")
    require(start["runtime_version"] | {"file": None} == end["runtime_version"] | {"file": None},
            "target runtime version changed during campaign")
    if product != "keycloak":
        require(start["version_source"] | {"file": None} == end["version_source"] | {"file": None},
                "target version source changed during campaign")


def read_bytes_json(raw, detail):
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("invalid " + detail) from error


def _verify_suite_runtime(folder, run, run_created_at, pins):
    require(pins.get("image_id", "").startswith("sha256:")
            and set(pins.get("jars", {})) == {"core", "runner", "saml"}
            and all(re.fullmatch(r"[0-9a-f]{64}", value or "")
                    for value in pins.get("jars", {}).values()),
            "trusted Suite image/JAR pins are not configured")
    runtime = read(folder / "suite-runtime-terminal-http.json")
    inspect_raw = (folder / "suite-container-inspect-terminal-http.json").read_bytes()
    item = one(read_bytes_json(inspect_raw, "Suite inspect"), "Suite inspect must contain one container")
    require(runtime.get("schema") == "samlscope-terminal-http-suite-runtime-v1"
            and runtime.get("run") == run, "wrong Suite runtime schema/Run")
    require(runtime.get("docker_inspect_sha256") == sha(inspect_raw), "Suite inspect hash mismatch")
    expected_container = {
        "name": item["Name"].removeprefix("/"),
        "id": item["Id"],
        "configured_image": item["Config"]["Image"],
        "image_id": item["Image"],
        "started_at": item["State"]["StartedAt"],
        "running_at_capture": item["State"]["Running"],
    }
    require(runtime.get("container") == expected_container, "Suite container summary mismatch")
    require(expected_container["name"] == "samlscope-reference-suite"
            and expected_container["running_at_capture"] is True
            and expected_container["image_id"] == pins["image_id"], "untrusted Suite image")
    require(parsed_time(expected_container["started_at"]) < run_created_at,
            "Suite container started after the Run")
    for name, trusted in pins["jars"].items():
        record = runtime.get("jars", {}).get(name, {})
        path = folder / record.get("file", "missing")
        raw = path.read_bytes()
        require(record.get("sha256") == sha(raw) == trusted, "untrusted Suite " + name + " JAR")
        require(record.get("path") == f"/opt/samlscope/lib/{name}-0.1.0.jar",
                "wrong Suite JAR source path")
    with zipfile.ZipFile(folder / runtime["jars"]["runner"]["file"]) as archive:
        required = {
            "com/samlscope/runner/scenario/TargetHttpObservation.class":
                (b"httpStatus", b"isSameOriginError"),
            "com/samlscope/runner/cases/IdpVersionScenarioTestCase.class":
                (b"IIP-SSO01-em-idp-01",),
            "com/samlscope/runner/cases/IdpVersionScenarioTestCase$VersionFixture.class":
                (b"recorder-terminal-http-v1", b"observeBrowser"),
            "com/samlscope/runner/cases/IdpSignedRequestScenarioTestCase.class":
                (b"IIP-SSO01-ak-idp-01",),
            "com/samlscope/runner/cases/IdpSignedRequestScenarioTestCase$SignedFixture.class":
                (b"signed-request-recorder-terminal-http-v2", b"observeBrowser"),
            "com/samlscope/runner/cases/IdpErrorAssertionScenarioTestCase.class":
                (b"IIP-SSO01-d-idp-01",),
            "com/samlscope/runner/cases/IdpErrorAssertionScenarioTestCase$ErrorAssertionFixture.class":
                (b"recorder-terminal-http-v1", b"observeBrowser", b"UNRECOGNIZED_SUBJECT"),
        }
        for name, needles in required.items():
            value = archive.read(name)
            require(all(needle in value for needle in needles), "running Runner lacks terminal oracle")
    with zipfile.ZipFile(folder / runtime["jars"]["core"]["file"]) as archive:
        value = archive.read("com/samlscope/core/caseexec/CaseEvent$BrowserObservation.class")
        require(b"EvidenceRef" in value and b"httpStatus" in value, "running Core lacks evidence-bound browser event")


def _verify_configuration_restoration(folder, product):
    restoration = read(folder / "restoration.json")
    counts = read(folder / "operation-counts.json")
    require(restoration.get("restored") is True and counts.get("restored") is True,
            "target configuration was not restored")
    require(counts.get("human_operations") == 0 and counts.get("verdict_adopted") is False,
            "campaign operation record is incomplete")
    steps = read(folder / "steps.json")
    require(counts.get("probes") == len([step for step in steps if "result" in step]),
            "probe operation count mismatch")
    if product == "keycloak":
        original_raw = (folder / "main-client-original.json").read_bytes()
        configured_raw = (folder / "main-client-configured-readback.json").read_bytes()
        restored_raw = (folder / "main-client-restored-readback.json").read_bytes()
        original = json.loads(original_raw)
        configured = json.loads(configured_raw)
        restored = json.loads(restored_raw)
        require(json.dumps(restored, sort_keys=True, separators=(",", ":"))
                == json.dumps(original, sort_keys=True, separators=(",", ":")),
                "Keycloak client was not restored before deletion")
        require(configured.get("id") == original.get("id") and configured.get("clientId") == original.get("clientId"),
                "Keycloak configured client identity mismatch")
        cleanup = restoration.get("cleanup", {})
        require(restoration.get("import_ok") is True
                and read(folder / "import.json").get("status") == "success",
                "Keycloak native console import was not verified")
        require(all(cleanup.get(name) is True for name in (
            "requester_restore_attempted", "requester_restore_read_back",
            "requester_delete_attempted", "other_delete_attempted",
            "requester_read_back_absent", "other_read_back_absent", "read_back_absent",
            "initially_absent")), "Keycloak cleanup/read-back incomplete")
        require(read(folder / "final-client-absence-readback.json") == {
            "requester_query": [], "other_entity_query": []}, "temporary Keycloak clients remain")
        native = read(folder / "native-configuration.json")
        other_raw = (folder / "other-client-configured-readback.json").read_bytes()
        other = json.loads(other_raw)
        require(native.get("requester_entity") == original.get("clientId")
                and native.get("requester_client_id") == original.get("id")
                and native.get("requester_original_sha256") == sha(original_raw)
                and native.get("requester_configured_sha256") == sha(configured_raw)
                and native.get("other_entity") == other.get("clientId")
                and native.get("other_client_id") == other.get("id")
                and native.get("other_entity_readback_sha256") == sha(other_raw),
                "Keycloak native configuration hashes/identity mismatch")
        registered = set(native.get("registered_acs") or [])
        configured_redirects = set(configured.get("redirectUris") or [])
        original_redirects = set(original.get("redirectUris") or [])
        require(len(registered) == 2 and registered.issubset(configured_redirects)
                and configured_redirects == original_redirects | (registered - original_redirects)
                and configured.get("attributes", {}).get("saml.client.signature") == "false"
                and other.get("redirectUris") == [native.get("hostile_acs")],
                "Keycloak native configuration semantics mismatch")
        require(counts.get("temporary_configuration_apply_writes") == 3
                and counts.get("restoration_writes") == 3
                and counts.get("product_restarts") == 0, "Keycloak operation counts mismatch")
    elif product == "shibboleth":
        original = (folder / "original-providers.xml").read_bytes()
        final = (folder / "final-providers.xml").read_bytes()
        require(original == final and restoration.get("original_sha256") == sha(original)
                and restoration.get("final_sha256") == sha(final), "Shibboleth provider file not restored")
        operations = read(folder / "operations.json")
        fixture = (folder / "fixture.xml").read_bytes()
        configured = (folder / "configured-providers.xml").read_bytes()
        require((folder / "fixture-readback.xml").read_bytes() == fixture
                and (folder / "configured-providers-readback.xml").read_bytes() == configured,
                "Shibboleth native configuration read-back mismatch")
        require(restoration.get("temporary_file_removed") is True
                and all(item.get("read_back") is True for item in operations
                        if item.get("operation") == "write"),
                "Shibboleth configuration write/removal evidence incomplete")
        writes = len([item for item in operations if item.get("operation") == "write"])
        reloads = len([item for item in operations if item.get("operation") == "reload"])
        require(counts.get("configuration_write_attempts") == writes
                and counts.get("restoration_write_attempts") == 1
                and counts.get("reloads") == reloads == 2
                and counts.get("product_restarts") == 0, "Shibboleth operation counts mismatch")
    else:
        original = (folder / "original-sp-config.php").read_bytes()
        configured = (folder / "configured-sp-config.php").read_bytes()
        final = (folder / "final-sp-config.php").read_bytes()
        require(original == final and configured != original, "SimpleSAMLphp configuration restoration mismatch")
        require(restoration.get("original_sha256") == sha(original)
                and restoration.get("configured_sha256") == sha(configured)
                and restoration.get("final_sha256") == sha(final), "SimpleSAMLphp restoration hashes mismatch")
        native = read(folder / "native-configuration.json")
        parser_raw = (folder / "parser.stdout").read_bytes()
        metadata_raw = (folder / "suite-sp-metadata.xml").read_bytes()
        require(native.get("fixture_sha256") == sha(metadata_raw)
                and native.get("parser_output_sha256") == sha(parser_raw)
                and native.get("configured_sha256") == sha(configured)
                and native.get("validate_authnrequest") is True,
                "SimpleSAMLphp native parser/configuration binding mismatch")
        resolve = read(folder / "restoration-resolution-readback.json")
        require(resolve.get("entity_absent") is True and resolve.get("result", "").startswith("UNRESOLVED"),
                "SimpleSAMLphp restored runtime still resolves the temporary SP")
        operations = read(folder / "operations.json")
        reloads = len([item for item in operations if item.get("step") == "apache-graceful-reload"])
        require(counts.get("configuration_write_attempts") == 2
                and counts.get("restoration_write_attempts") == 1
                and counts.get("reloads") == reloads == 2
                and counts.get("product_restarts") == 0, "SimpleSAMLphp operation counts mismatch")
    return counts


def _load_originals(folder, entries):
    by_id = {entry.get("id"): entry for entry in entries}
    require(len(by_id) == len(entries) and None not in by_id, "duplicate/missing transcript identity")
    decoded_rows = read(folder / "decoded-manifest.json")
    decoded = {}
    for row in decoded_rows:
        entry_id = row.get("id")
        require(entry_id in by_id and entry_id not in decoded and TX_RE.fullmatch(entry_id),
                "invalid decoded-original identity")
        expected_file = f"decoded/{entry_id}.xml"
        require(row.get("file") == expected_file, "unexpected decoded-original path")
        raw = (folder / expected_file).read_bytes()
        require(row.get("sha256") == sha(raw)
                and by_id[entry_id].get("decodedSamlBytes") == len(raw), "decoded-original mismatch")
        decoded[entry_id] = raw
    browser_rows = read(folder / "browser-originals-manifest.json")
    browser = {}
    for row in browser_rows:
        entry_id = row.get("id")
        require(entry_id in by_id and entry_id not in browser and TX_RE.fullmatch(entry_id),
                "invalid browser-original identity")
        expected_file = f"browser-originals/{entry_id}.body"
        require(row.get("file") == expected_file, "unexpected browser-original path")
        raw = (folder / expected_file).read_bytes()
        require(row.get("sha256") == sha(raw) and row.get("bytes") == len(raw)
                == by_id[entry_id].get("bodyBytes") and len(raw) <= 64 * 1024,
                "browser-original mismatch")
        browser[entry_id] = raw
    return by_id, decoded, browser


def _verify_request(case_id, fixture, entry, raw, entity, sso):
    summary = entry.get("samlSummary") or {}
    action = summary.get("action_id")
    require(entry.get("direction") == "OUTBOUND" and entry.get("method") == "POST"
            and entry.get("url") == sso and entry.get("status") is None,
            "fixture request was not sent to the target SSO endpoint")
    require(summary.get("scenario_case_id") == case_id and summary.get("fixture_id") == fixture
            and summary.get("type") == "AuthnRequest" and summary.get("active_probe") is True
            and ACTION_RE.fullmatch(action or "") and entry.get("correlationId") == action,
            "fixture/action transcript binding mismatch")
    request = safe_xml(raw)
    require(request.tag == P + "AuthnRequest" and request.get("ID") == "_" + action
            and request.get("Destination") == sso, "request original identity/destination mismatch")
    issuer = one(request.findall(A + "Issuer"), "request requires one Issuer")
    require((issuer.text or "").strip() == entity, "request issuer mismatch")
    if case_id != "IIP-SSO01-ak-idp-01":
        require(request.get("AssertionConsumerServiceURL") == entity + "/sp/acs/0",
                "request ACS does not bind the Run plan")
    version = "2.0"
    if case_id == "IIP-SSO01-em-idp-01":
        version = {"baseline-success": "2.0", "version-1-1": "1.1", "version-3-0": "3.0"}[fixture]
    require(request.get("Version") == version, "request major-version fixture mismatch")
    if case_id == "IIP-SSO01-d-idp-01":
        names = request.findall(A + "Subject/" + A + "NameID")
        if fixture == "baseline-success":
            require(not names, "existing-principal control unexpectedly has Subject/NameID")
        else:
            name = one(names, "unknown-subject fixture requires one NameID")
            require(name.get("Format") == "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                    and (name.text or "") == "urn:samlscope:probe:unknown-subject:" + action,
                    "unknown-subject fixture mismatch")
    if case_id == "IIP-SSO01-ak-idp-01":
        references = request.findall(".//" + DS + "Reference")
        require(len(references) == 1, "signed request requires one Reference")
        if fixture == "bad-reference":
            require(references[0].get("URI") == "#_samlscope-unrelated-element",
                    "bad-reference fixture mismatch")
        else:
            require(references[0].get("URI") == "#_" + action, "signed request Reference mismatch")
        expected_acs = entity + ("/sp/acs/1" if fixture == "tampered-acs" else "/sp/acs/0")
        require(request.get("AssertionConsumerServiceURL") == expected_acs,
                "signed request ACS fixture mismatch")
    return request, action


def _verify_response(entry, raw, request_id, entity, target_entity):
    require(entry.get("direction") == "INBOUND" and entry.get("method") == "POST"
            and entry.get("status") == 200, "fixture response is not an inbound POST")
    response = safe_xml(raw)
    require(response.tag == P + "Response" and response.get("InResponseTo") == request_id,
            "response original does not correlate to request")
    destination = response.get("Destination")
    require(destination in {entity + "/sp/acs/0", entity + "/sp/acs/1"}
            and entry.get("url") == destination, "response destination mismatch")
    status = one(response.findall(P + "Status/" + P + "StatusCode"),
                 "response requires one top-level StatusCode").get("Value")
    assertions = len(response.findall(".//" + A + "Assertion")) + len(response.findall(".//" + A + "EncryptedAssertion"))
    summary = entry.get("samlSummary") or {}
    require(summary.get("type") == "Response" and summary.get("inResponseTo") == request_id
            and summary.get("destination") == destination and summary.get("statusCode") == status
            and summary.get("activeProbeAccepted") is True, "response summary/original mismatch")
    issuers = response.findall(A + "Issuer")
    require(issuers and (issuers[0].text or "").strip() == target_entity, "response issuer mismatch")
    return status == SUCCESS, assertions


def _verify_browser(entry, raw, action, sso):
    status = entry.get("status")
    require(entry.get("direction") == "INBOUND" and entry.get("method") == "BROWSER"
            and isinstance(status, int) and 400 <= status <= 599,
            "browser terminal observation is not HTTP 4xx/5xx")
    require(entry.get("correlationId") == action and origin(entry.get("url", "")) == origin(sso),
            "browser terminal observation is cross-origin or uncorrelated")
    require(entry.get("decodedSamlRef") is None and entry.get("decodedSamlBytes") == 0,
            "browser terminal observation unexpectedly contains SAML")
    require(entry.get("samlSummary") == {
        "failure_indicated": True,
        "type": "BrowserResponseObservation",
        "http_status": status,
        "url": entry["url"],
    }, "browser terminal summary mismatch")
    require(len(raw) == entry.get("bodyBytes"), "browser body/original mismatch")
    return "browser"


def _observation(case_id, fixture, observed_kind, response_value=None):
    control = fixture in {"baseline-success", "valid"}
    if control:
        if observed_kind != "response" or response_value != (True, True):
            return "control_failed"
        return "satisfied"
    if observed_kind == "browser":
        return "satisfied" if case_id == "IIP-SSO01-em-idp-01" else "violated"
    success, has_assertion = response_value
    if case_id == "IIP-SSO01-em-idp-01":
        return "violated" if success else "satisfied"
    if case_id == "IIP-SSO01-ak-idp-01":
        return "violated" if success and has_assertion else "satisfied"
    if success:
        return "violated"
    return "violated" if has_assertion else "satisfied"


def _verify_case(folder, case_id, result_case, entries, by_id, decoded, browser, entity, sso, target_entity):
    definition = CASES[case_id]
    requests = {}
    request_files = []
    for entry in entries:
        summary = entry.get("samlSummary") or {}
        if summary.get("scenario_case_id") != case_id:
            continue
        fixture = summary.get("fixture_id")
        require(fixture in definition["fixtures"] and fixture not in requests,
                "duplicate/unknown fixture request for " + case_id)
        require(entry["id"] in decoded, "fixture request decoded original missing")
        request, action = _verify_request(case_id, fixture, entry, decoded[entry["id"]], entity, sso)
        requests[fixture] = (entry, request, action)
        if case_id == "IIP-SSO01-ak-idp-01":
            request_files.append((fixture, folder / f"decoded/{entry['id']}.xml"))
    require(tuple(requests) == definition["fixtures"], "fixture request order/set mismatch for " + case_id)
    if request_files:
        _verify_ak_signatures(folder, request_files)

    evidence = result_case.get("evidence", [])
    require(all(item.get("kind") == "transcript" and TX_RE.fullmatch(item.get("reference", ""))
                for item in evidence), "case evidence is not Recorder transcript evidence")
    evidence_ids = [item["reference"] for item in evidence]
    require(len(evidence_ids) == len(set(evidence_ids)) == len(definition["fixtures"]),
            "case evidence count/uniqueness mismatch")
    used = set()
    outcomes = []
    for fixture, (request_entry, request, action) in requests.items():
        request_id = request.get("ID")
        candidates = [by_id[item] for item in evidence_ids
                      if by_id[item].get("correlationId") in {action, request_id}]
        observed = one(candidates, "fixture requires exactly one correlated evidence entry")
        require(observed["id"] not in used and observed.get("timestamp") > request_entry.get("timestamp"),
                "fixture evidence reused or out of order")
        used.add(observed["id"])
        if observed.get("method") == "BROWSER":
            require(observed["id"] in browser, "browser evidence original missing")
            kind = _verify_browser(observed, browser[observed["id"]], action, sso)
            value = None
        else:
            require(observed["id"] in decoded, "response evidence original missing")
            success, assertions = _verify_response(
                observed, decoded[observed["id"]], request_id, entity, target_entity)
            kind = "response"
            value = (success, assertions > 0)
        # Reject ambiguous duplicate callbacks for the same fixture even when only one is cited.
        correlated = [entry for entry in entries
                      if entry.get("direction") == "INBOUND"
                      and entry.get("correlationId") in {action, request_id}
                      and entry.get("method") in {"POST", "BROWSER"}]
        require(len(correlated) == 1 and correlated[0]["id"] == observed["id"],
                "fixture has duplicate/uncited inbound observations")
        outcomes.append((fixture, _observation(case_id, fixture, kind, value)))
    require(used == set(evidence_ids), "case evidence escapes replayed fixture set")
    require(all(value != "control_failed" for _, value in outcomes),
            "positive control did not produce correlated SAML Success")
    if any(value == "violated" for _, value in outcomes):
        expected_outcome = "VIOLATED"
        expected_verdict = definition["violated_verdict"]
        expected_reason = definition["violated_reason"]
    elif any(value == "not_verified" for _, value in outcomes):
        expected_outcome = expected_verdict = "NOT_VERIFIED"
        expected_reason = definition["inconclusive_reason"]
    else:
        expected_outcome, expected_verdict = "SATISFIED", "PASS"
        expected_reason = definition["satisfied_reason"]
    require((result_case.get("outcome"), result_case.get("verdict"), result_case.get("reason_code"),
             result_case.get("attested"), result_case.get("evidence_class"))
            == (expected_outcome, expected_verdict, expected_reason, False, "PROTOCOL_OBSERVED"),
            "formal case result differs from independent fixture replay")
    return {"case": case_id, "outcome": expected_outcome, "verdict": expected_verdict,
            "adoptable": expected_outcome != "NOT_VERIFIED",
            "observations": dict(outcomes), "evidence": evidence_ids}


def _verify_ak_signatures(folder, request_files):
    source = Path(__file__).with_name("VerifyTerminalHttpSignatures.java")
    with tempfile.TemporaryDirectory(prefix="terminal-http-signatures-") as temporary:
        subprocess.run(["javac", "-d", temporary, str(source)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        command = ["java", "-cp", temporary, "VerifyTerminalHttpSignatures",
                   str(folder / "suite-sp-metadata.xml")]
        for fixture, path in request_files:
            command.extend([fixture, str(path)])
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    observed = json.loads(result.stdout)
    require(observed == {fixture: fixture == "valid" for fixture, _ in request_files},
            "signed fixture validation result mismatch")


def verify_folder(folder, product, pins=None):
    folder = Path(folder)
    require(product in PRODUCT_CASES, "unsupported product")
    pins = ACCEPTED_SUITE if pins is None else pins
    created = read(folder / "created.json")["run"]
    run = created["id"]
    require(RUN_RE.fullmatch(run) is not None, "invalid Run identity")
    plan = read(folder / "plan.json")["plan"]["plan"]
    require(created.get("planId") == plan.get("id"), "Run/plan mismatch")
    expected = PRODUCT[product]
    require(plan.get("target", {}).get("entityId") == expected["target_entity"], "wrong target entity")
    require(plan.get("profile") == "browser_sso_idp", "wrong plan profile")
    require(plan.get("requestSigningMode") == "REQUIRED", "terminal campaign did not require signed requests")
    _verify_target_runtime(folder, product, float(created["createdAt"]))
    _verify_suite_runtime(folder, run, float(created["createdAt"]), pins)
    counts = _verify_configuration_restoration(folder, product)

    entries = read(folder / "transcript.json")
    require(all(entry.get("runId") == run for entry in entries), "cross-Run transcript entry")
    by_id, decoded, browser = _load_originals(folder, entries)
    metadata = (folder / "suite-sp-metadata.xml").read_bytes()
    metadata_root = safe_xml(metadata)
    require(metadata_root.get("entityID") == "http://localhost:18080/p/" + plan["id"],
            "Suite metadata entity does not bind the plan")
    entity = metadata_root.get("entityID")

    evaluation = folder / EVALUATION
    before = read(evaluation / "transcript-before.json")
    after = read(evaluation / "transcript.json")
    require(before == after == entries, "formal re-evaluation changed/used another transcript")
    evaluation_record = read(evaluation / "evaluation.json")
    require(isinstance(evaluation_record.get("completed"), list)
            and isinstance(evaluation_record.get("remaining"), dict),
            "formal re-evaluation receipt is malformed")
    original_result = read(folder / "result.json")
    final_result = read(evaluation / "result.json")
    require(final_result.get("run", {}).get("id") == run
            and final_result.get("profile", {}).get("id") == "browser-sso-idp"
            and final_result.get("target", {}).get("role") == "IDP",
            "formal result Run/profile/role mismatch")
    require(final_result.get("suite", {}).get("image_digest") == pins["image_id"],
            "formal result Suite image mismatch")
    target_metadata = (folder / "target-metadata.xml").read_bytes()
    require(final_result.get("target", {}).get("metadata_digest") == "sha256:" + sha(target_metadata),
            "formal result target metadata mismatch")

    adopted = {}
    report = []
    for case_id in PRODUCT_CASES[product]:
        original = find_case(original_result, case_id)
        final = find_case(final_result, case_id)
        require(original == final, "formal re-evaluation changed case result: " + case_id)
        case_report = _verify_case(folder, case_id, final, entries, by_id, decoded, browser,
                                   entity, expected["sso"], expected["target_entity"])
        report.append(case_report)
        if case_report["adoptable"]:
            adopted[case_id] = final
    return evaluation / "result.json", adopted, {
        "product": product, "run": run, "cases": report, "operations": counts,
    }


def tamper_self_test(folder, product, pins=None):
    folder = Path(folder)
    pins = ACCEPTED_SUITE if pins is None else pins

    def rejected(label, mutate):
        with tempfile.TemporaryDirectory(prefix="terminal-http-tamper-") as temporary:
            trial = Path(temporary) / "evidence"
            shutil.copytree(folder, trial)
            mutate(trial)
            try:
                verify_folder(trial, product, pins)
            except (ValueError, KeyError, OSError, ET.ParseError, subprocess.CalledProcessError,
                    zipfile.BadZipFile):
                return label
            raise RuntimeError("tamper accepted: " + label)

    final = read(folder / EVALUATION / "result.json")
    transcript = read(folder / "transcript.json")
    entries = {entry["id"]: entry for entry in transcript}
    target_cases = PRODUCT_CASES[product]
    browser_ref = next((item["reference"] for case_id in target_cases
                        for item in find_case(final, case_id).get("evidence", [])
                        if entries[item["reference"]].get("method") == "BROWSER"), None)
    response_ref = next(item["reference"] for case_id in target_cases
                        for item in find_case(final, case_id).get("evidence", [])
                        if item["reference"] != browser_ref)

    def alter_json(path, mutate):
        value = read(path)
        mutate(value)
        Path(path).write_text(json.dumps(value))

    def alter_transcripts(trial, mutate):
        for path in (trial / "transcript.json",
                     trial / EVALUATION / "transcript-before.json",
                     trial / EVALUATION / "transcript.json"):
            alter_json(path, mutate)

    request_id = next(entry["id"] for entry in transcript
                      if (entry.get("samlSummary") or {}).get("scenario_case_id") in target_cases)

    def change_run(value):
        value[0]["runId"] = "run_00000000000000000000000000"

    def change_action(value):
        entry = next(item for item in value if item["id"] == request_id)
        entry["correlationId"] = "action_00000000000000000000000000000000"
        entry["samlSummary"]["action_id"] = entry["correlationId"]

    mutations = [
        ("response-original", lambda trial: (trial / f"decoded/{response_ref}.xml").write_bytes(
            (trial / f"decoded/{response_ref}.xml").read_bytes() + b" ")),
        ("cross-run", lambda trial: alter_transcripts(trial, change_run)),
        ("action-correlation", lambda trial: alter_transcripts(trial, change_action)),
        ("target-runtime", lambda trial: (trial / "target-version-runtime-end.txt").write_text("0.0.0\n")),
        ("suite-jar", lambda trial: (trial / "suite-runner-0.1.0.jar").write_bytes(
            (trial / "suite-runner-0.1.0.jar").read_bytes() + b"tamper")),
        ("restoration", lambda trial: alter_json(trial / "restoration.json",
            lambda value: value.__setitem__("restored", False))),
    ]
    if browser_ref is not None:
        def change_browser(value, status=None, url=None):
            entry = next(item for item in value if item["id"] == browser_ref)
            if status is not None:
                entry["status"] = status
                entry["samlSummary"]["http_status"] = status
            if url is not None:
                entry["url"] = url
                entry["samlSummary"]["url"] = url

        mutations.extend([
            ("browser-original", lambda trial: (trial / f"browser-originals/{browser_ref}.body").write_bytes(
                (trial / f"browser-originals/{browser_ref}.body").read_bytes() + b"tamper")),
            ("browser-status-600", lambda trial: alter_transcripts(
                trial, lambda value: change_browser(value, status=600))),
            ("browser-cross-origin", lambda trial: alter_transcripts(
                trial, lambda value: change_browser(value, url="http://invalid.example/error"))),
        ])
    return [rejected(label, mutate) for label, mutate in mutations]


_VERIFIED = {}


def verify(root, product):
    """Return only formally replayed cases after running the complete tamper gate once."""
    require(product in EVIDENCE_FOLDERS, "unsupported terminal HTTP product")
    folder = Path(root) / EVIDENCE_FOLDERS[product]
    cache_key = (str(folder.resolve()), product)
    if cache_key not in _VERIFIED:
        result, cases, _ = verify_folder(folder, product)
        rejected = set(tamper_self_test(folder, product))
        expected = {
            "response-original", "cross-run", "action-correlation", "target-runtime",
            "suite-jar", "restoration", "browser-original", "browser-status-600",
            "browser-cross-origin",
        }
        require(rejected == expected, "terminal HTTP tamper self-test coverage mismatch")
        _VERIFIED[cache_key] = (result, cases)
    return _VERIFIED[cache_key]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--product", choices=tuple(PRODUCT_CASES), required=True)
    parser.add_argument("--tamper-self-test", action="store_true")
    args = parser.parse_args()
    result, cases, report = verify_folder(args.folder.resolve(), args.product)
    print(result, {name: value["verdict"] for name, value in cases.items()})
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    if args.tamper_self_test:
        print("tamper rejected:", ", ".join(tamper_self_test(args.folder.resolve(), args.product)))


if __name__ == "__main__":
    main()
