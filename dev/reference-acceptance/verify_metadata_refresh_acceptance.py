#!/usr/bin/env python3
"""Fail-closed formal adoption gate for SimpleSAMLphp IIP-MD02.a."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/simplesamlphp"))
from signed_request_observation import signature_rejection

from verify_terminal_http_acceptance import (
    _verify_target_runtime, _verify_suite_runtime, find_case, parsed_time,
)

CASE = "IIP-MD02-a-idp-01"
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
P = "{urn:oasis:names:tc:SAML:2.0:protocol}"
MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
EVALUATION = "evaluation-terminal-http-v1"
RECEIPT_FILES = (
    "original-config.php", "configured-config.php", "final-config.php", "effective-source.json",
    "operation-counts.json", "proxy-requests.jsonl", "metadata-a.xml", "metadata-b.xml",
    "signature-control.json", "signature-control-response.html",
    "target-runtime-start.json", "target-runtime-end.json",
    "target-container-inspect-start.json", "target-container-inspect-end.json",
    "target-image-inspect-start.json", "target-image-inspect-end.json",
    "target-version-runtime-start.txt", "target-version-runtime-end.txt",
    "target-version-source-start.txt", "target-version-source-end.txt",
)

ACCEPTED_SUITE = {
    "image_id": "sha256:1a52a1edc3a574a7afabfcedc8448089c0e9b942f005727513ce441ffa184d6a",
    "jars": {
        "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe",
        "runner": "d36a8259a952e5cbf00d51c7642db4a8c6dca2666234d2955d46f136dbe73f9d",
        "saml": "2a60fa9d24b9857410e14f61890621261538b141aa313927b3410b2892221b41",
    },
}


def require(value, detail):
    if not value:
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


def decoded_originals(folder, transcript):
    rows = read(folder / "decoded-manifest.json")
    require(len({row.get("id") for row in rows}) == len(rows), "duplicate decoded manifest ID")
    by_id = {entry["id"]: entry for entry in transcript}
    values = {}
    for row in rows:
        entry = by_id.get(row.get("id"))
        path = folder / row.get("file", "missing")
        raw = path.read_bytes()
        require(path.resolve().parent == (folder / "decoded").resolve(), "decoded original escapes folder")
        require(entry is not None and entry.get("decodedSamlRef")
                == f"transcripts/{entry['runId']}/{entry['id']}.saml.xml", "decoded source mismatch")
        require(row.get("sha256") == sha(raw) and row.get("bytes") == len(raw)
                == entry.get("decodedSamlBytes"), "decoded original hash/size mismatch")
        values[entry["id"]] = raw
    require(set(values) == {entry["id"] for entry in transcript if entry.get("decodedSamlRef")},
            "decoded manifest is incomplete")
    return values


def verify_runtime_receipt(folder, manifest):
    summaries = []
    for phase, field in (("start", "targetRuntimeStartSha256"), ("end", "targetRuntimeEndSha256")):
        path = folder / f"target-runtime-{phase}.json"
        raw = path.read_bytes()
        require(manifest.get(field) == sha(raw), "target runtime receipt hash mismatch")
        value = json.loads(raw)
        require(value.get("schema") == "samlscope-terminal-http-target-runtime-v1"
                and value.get("product") == "simplesamlphp" and value.get("phase") == phase,
                "wrong target runtime receipt")
        for name, key in ((f"target-container-inspect-{phase}.json", "docker_inspect_sha256"),
                          (f"target-image-inspect-{phase}.json", "image_inspect_sha256")):
            require(value.get(key) == sha((folder / name).read_bytes()), "runtime backing original mismatch")
        for key in ("runtime_version", "version_source"):
            record = value.get(key, {})
            require(record.get("sha256") == sha((folder / record.get("file", "missing")).read_bytes()),
                    "runtime version backing original mismatch")
        summaries.append(value)
    require(summaries[0].get("binding") == summaries[1].get("binding")
            and summaries[0].get("runtime_version", {}).get("value")
                == summaries[1].get("runtime_version", {}).get("value") == "2.5.0"
            and summaries[0].get("version_source", {}).get("sha256")
                == summaries[1].get("version_source", {}).get("sha256"),
            "target identity/version changed during refresh")


def verify_phase(folder, manifest, transcript, originals, name, variant, metadata):
    entries = {entry["id"]: entry for entry in transcript}
    phase = manifest.get(name, {})
    require(phase.get("variant") == variant, "wrong phase variant")
    fetch = entries.get(phase.get("fetchReference"))
    prepared = entries.get(phase.get("preparedReference"))
    request = entries.get(phase.get("requestReference"))
    response = entries.get(phase.get("responseReference"))
    require(all(value is not None for value in (fetch, prepared, request, response)), "phase reference missing")
    control = None
    if "controlRequestReference" in phase:
        control = entries.get(phase.get("controlRequestReference"))
        require(control is not None, "control request reference missing")
        control_summary = control.get("samlSummary", {})
        require(control["direction"] == "OUTBOUND" and control.get("method") == "POST"
                and control_summary.get("type") == "AuthnRequest"
                and control_summary.get("campaign") == "metadata-polling"
                and control_summary.get("variant") == variant
                and control_summary.get("metadataSignatureControl") == "invalid"
                and control_summary.get("id") == control.get("correlationId"),
                "signature control transcript mismatch")
        control_xml = safe_xml(originals[control["id"]])
        require(control_xml.tag == P + "AuthnRequest"
                and control_xml.get("ID") == control_summary.get("id"),
                "signature control original/correlation mismatch")
    require(fetch["direction"] == "INBOUND" and fetch.get("method") == "GET"
            and fetch.get("samlSummary", {}) == {"type": "MetadataFetch", "variant": variant, "feed": "live"}
            and urllib.parse.urlsplit(fetch.get("url", "")).hostname == "samlscope-reference-suite",
            "native metadata fetch is not the target relay request")
    summary = prepared.get("samlSummary", {})
    require(prepared["direction"] == "OUTBOUND" and prepared.get("method") == "GET"
            and summary.get("type") == "MetadataPrepared" and summary.get("sourceType") == "MetadataFetch"
            and summary.get("fetchTranscriptId") == fetch["id"] and summary.get("variant") == variant
            and summary.get("feed") == "live" and summary.get("metadataSha256") == sha(metadata)
            and originals.get(prepared["id"]) == metadata, "served metadata original mismatch")
    request_summary = request.get("samlSummary", {})
    require(request["direction"] == "OUTBOUND" and request.get("method") == "POST"
            and request_summary.get("type") == "AuthnRequest"
            and request_summary.get("campaign") == "metadata-polling"
            and request_summary.get("variant") == variant
            and request_summary.get("metadataSignatureControl") == "valid"
            and request_summary.get("id") == request.get("correlationId"), "polling request mismatch")
    request_xml = safe_xml(originals[request["id"]])
    request_id = request_xml.get("ID")
    require(request_xml.tag == P + "AuthnRequest" and request_id == request_summary.get("id"),
            "request original/correlation mismatch")
    response_summary = response.get("samlSummary", {})
    response_xml = safe_xml(originals[response["id"]])
    require(response["direction"] == "INBOUND" and response.get("method") == "POST"
            and response_summary.get("type") == "Response"
            and response_summary.get("metadataProbeAccepted") is True
            and response_summary.get("statusCode") == SUCCESS
            and response_summary.get("inResponseTo") == request_id
            and response_xml.tag == P + "Response" and response_xml.get("InResponseTo") == request_id
            and response_xml.get("Destination") == response.get("url"), "correlated Success original mismatch")
    statuses = response_xml.findall("./" + P + "Status/" + P + "StatusCode")
    require(len(statuses) == 1 and statuses[0].get("Value") == SUCCESS, "response Status is not Success")
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(response["url"]).query, strict_parsing=True)
    require(query == {"mdv": [variant], "run": [manifest["runId"]]}, "callback URL correlation mismatch")
    lower = control if control is not None else request
    require(float(lower["timestamp"]) <= float(fetch["timestamp"])
            <= float(prepared["timestamp"]) < float(response["timestamp"]), "phase events out of order")
    if control is not None:
        require(float(prepared["timestamp"]) <= float(request["timestamp"])
                < float(response["timestamp"]), "control/valid-request events out of order")
    require(sum(1 for entry in transcript if entry["direction"] == "OUTBOUND"
                and entry.get("correlationId") == request_id) == 1, "duplicate request correlation")
    require(sum(1 for entry in transcript if entry["direction"] == "INBOUND"
                and entry.get("samlSummary", {}).get("inResponseTo") == request_id) == 1,
            "duplicate response correlation")
    return request, response, fetch, control


def verify_signature_rejection(folder, manifest, originals, phase_b):
    control = phase_b[3]
    require(control is not None, "B phase lacks invalid-signature control")
    evidence = read(folder / "signature-control.json")
    response = (folder / "signature-control-response.html").read_bytes()
    request = originals[control["id"]]
    summary = control.get("samlSummary", {})
    request_url = control.get("url")
    response_url = evidence.get("response_url")
    request_origin = urllib.parse.urlsplit(request_url or "")
    response_origin = urllib.parse.urlsplit(response_url or "")
    def effective_port(value):
        if value.port is not None:
            return value.port
        return 443 if value.scheme.lower() == "https" else 80 if value.scheme.lower() == "http" else -1
    require(evidence.get("request_id") == summary.get("id")
            and evidence.get("request_sha256") == sha(request)
            and evidence.get("request_url") == request_url
            and evidence.get("response_url_exact_match") is True
            and request_origin.scheme.lower() == response_origin.scheme.lower()
            and request_origin.hostname == response_origin.hostname
            and effective_port(request_origin) == effective_port(response_origin)
            and isinstance(evidence.get("response_status"), int)
            and 400 <= evidence["response_status"] <= 599
            and evidence.get("response_body_sha256") == sha(response)
            and signature_rejection(response.decode("utf-8"), evidence["response_status"])
                == "signature-value-invalid"
            and evidence.get("native_signature_rejection") == "signature-value-invalid"
            and evidence.get("saml_response_form_present") is False,
            "product-native invalid-signature rejection mismatch")
    observed = parsed_time(evidence.get("observed_at", ""))
    require(float(control["timestamp"]) <= observed <= float(phase_b[0]["timestamp"]),
            "signature control response time is not bound to the B exchange")


def verify_signatures(folder, manifest):
    source = Path(__file__).with_name("VerifyMetadataRefreshSignatures.java")
    decoded = {row["id"]: folder / row["file"] for row in read(folder / "decoded-manifest.json")}
    request_a = decoded[manifest["phaseA"]["requestReference"]]
    request_b = decoded[manifest["phaseB"]["requestReference"]]
    control_b = decoded[manifest["phaseB"]["controlRequestReference"]]
    with tempfile.TemporaryDirectory(prefix="metadata-refresh-signatures-") as temporary:
        subprocess.run(["javac", "-d", temporary, str(source)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = subprocess.run(["java", "-cp", temporary, "VerifyMetadataRefreshSignatures",
            str(folder / "metadata-a.xml"), str(request_a), str(folder / "metadata-b.xml"), str(request_b),
            str(control_b)],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    require(json.loads(result.stdout) == {"a_valid": True, "b_valid": True,
            "b_valid_with_a": False, "invalid_b_valid_with_b": False,
            "invalid_b_valid_with_a": False, "a_keys": 1, "b_keys": 1},
            "changed-key control mismatch")


def verify_receipt(folder):
    folder = Path(folder)
    manifest = read(folder / "metadata-refresh-manifest.json")
    run = manifest.get("runId")
    require(manifest.get("schema") == "samlscope-native-metadata-refresh-v1"
            and manifest.get("adapter") == "simplesamlphp-native-mdq-refresh-v1"
            and RUN_RE.fullmatch(run or "") is not None, "wrong refresh receipt identity")
    campaign = read(folder / "campaign.json")
    wait = manifest.get("refreshWaitSeconds")
    require(campaign.get("campaignVariants") == ["control", "no-valid-until"]
            and campaign.get("pollingDelaySeconds") == wait and isinstance(wait, int) and wait >= 2,
            "refresh wait/variants do not match the Run campaign")
    hashes = {
        "originalConfigSha256": "original-config.php", "configuredConfigSha256": "configured-config.php",
        "finalConfigSha256": "final-config.php", "effectiveSourceSha256": "effective-source.json",
        "operationCountsSha256": "operation-counts.json", "metadataASha256": "metadata-a.xml",
        "metadataBSha256": "metadata-b.xml", "proxyRequestsSha256": "proxy-requests.jsonl",
        "signatureControlSha256": "signature-control.json",
        "signatureControlResponseSha256": "signature-control-response.html",
    }
    for field, name in hashes.items():
        require(manifest.get(field) == sha((folder / name).read_bytes()), name + " hash mismatch")
    original = (folder / "original-config.php").read_bytes()
    configured = (folder / "configured-config.php").read_bytes()
    final = (folder / "final-config.php").read_bytes()
    overlay = ("\n$config['metadata.sources'] = [['type'=>'flatfile'], "
               "['type'=>'mdq','server'=>'http://127.0.0.1:8081','cachelength'=>%d]];\n" % wait).encode()
    require(final == original and configured == original + overlay, "configuration/read-back/restore mismatch")
    effective = read(folder / "effective-source.json")
    require(effective == [{"type": "flatfile"},
                          {"type": "mdq", "server": "http://127.0.0.1:8081", "cachelength": wait}],
            "effective native source differs")
    counts = read(folder / "operation-counts.json")
    require(counts.get("restored") is True and counts.get("product_configuration_writes") == 2
            and counts.get("restoration_writes") == 1 and counts.get("product_restarts") == 0
            and counts.get("human_operations") == 0, "operation counts differ")
    verify_runtime_receipt(folder, manifest)
    transcript = read(folder / "transcript.json")
    require(transcript and all(entry.get("runId") == run for entry in transcript)
            and len({entry.get("id") for entry in transcript}) == len(transcript), "mixed/duplicate transcript")
    originals = decoded_originals(folder, transcript)
    metadata_a = (folder / "metadata-a.xml").read_bytes()
    metadata_b = (folder / "metadata-b.xml").read_bytes()
    root_a, root_b = safe_xml(metadata_a), safe_xml(metadata_b)
    require(root_a.tag == root_b.tag == MD + "EntityDescriptor"
            and root_a.get("entityID") == root_b.get("entityID") == manifest.get("entityId")
            and metadata_a != metadata_b, "A/B metadata identity/change mismatch")
    a = verify_phase(folder, manifest, transcript, originals, "phaseA", "control", metadata_a)
    b = verify_phase(folder, manifest, transcript, originals, "phaseB", manifest.get("variantB"), metadata_b)
    require(b[3] is not None and float(b[3]["timestamp"]) >= float(a[1]["timestamp"]) + wait,
            "B control started before approved refresh wait")
    verify_signature_rejection(folder, manifest, originals, b)
    relay = [json.loads(line) for line in (folder / "proxy-requests.jsonl").read_text().splitlines() if line]
    for raw, (_, response, fetch, _) in ((metadata_a, a), (metadata_b, b)):
        matches = [item for item in relay if item.get("entityId") == manifest.get("entityId")
                   and item.get("responseSha256") == sha(raw) and item.get("httpStatus") == 200
                   and float(fetch["timestamp"]) <= parsed_time(item.get("observedAt", ""))
                   <= float(response["timestamp"])]
        require(matches, "native relay original does not bind the served metadata")
    verify_signatures(folder, manifest)
    return manifest


def verify_suite_oracle(folder, run, created_at):
    _verify_suite_runtime(folder, run, created_at, ACCEPTED_SUITE)
    runtime = read(folder / "suite-runtime-terminal-http.json")
    with zipfile.ZipFile(folder / runtime["jars"]["runner"]["file"]) as archive:
        required = {
            "com/samlscope/runner/cases/MetadataRefreshEvidenceFile.class":
                (b"samlscope-native-metadata-refresh-v1", b"metadata.native-refresh-observed"),
            "com/samlscope/runner/cases/MetadataRefreshConfigurationTestCase.class":
                (b"IIP-MD02-a-idp-01", b"native-metadata-refresh"),
            "com/samlscope/runner/cases/ApprovedConfigCaseRegistry.class":
                (b"MetadataRefreshConfigurationTestCase",),
        }
        for name, needles in required.items():
            value = archive.read(name)
            require(all(needle in value for needle in needles), "running Runner lacks MD02.a oracle")


def tamper_self_test(folder):
    manifest_name = "metadata-refresh-manifest.json"
    tests = []
    with tempfile.TemporaryDirectory(prefix="metadata-refresh-tamper-") as temporary:
        base = Path(temporary) / "base"
        base.mkdir()
        for name in (*RECEIPT_FILES, manifest_name, "campaign.json", "transcript.json", "decoded-manifest.json"):
            shutil.copy2(folder / name, base / name)
        shutil.copytree(folder / "decoded", base / "decoded")

        def rejected(name, mutate):
            candidate = Path(temporary) / name
            shutil.copytree(base, candidate)
            mutate(candidate)
            try:
                verify_receipt(candidate)
            except Exception:
                tests.append(name)
                return
            raise ValueError("tamper was accepted: " + name)

        def update_manifest(path, mutate):
            value = read(path / manifest_name)
            mutate(value)
            (path / manifest_name).write_text(json.dumps(value, indent=2) + "\n")

        rejected("wait", lambda path: update_manifest(path,
                 lambda value: value.__setitem__("refreshWaitSeconds", value["refreshWaitSeconds"] + 1)))
        def same_metadata(path):
            raw = (path / "metadata-a.xml").read_bytes()
            (path / "metadata-b.xml").write_bytes(raw)
            update_manifest(path, lambda value: value.__setitem__("metadataBSha256", sha(raw)))
        rejected("metadata-b", same_metadata)
        rejected("request-reference", lambda path: update_manifest(path,
                 lambda value: value["phaseB"].__setitem__("requestReference",
                                                           value["phaseA"]["requestReference"])))
        def restore(path):
            raw = b"changed"
            (path / "final-config.php").write_bytes(raw)
            update_manifest(path, lambda value: value.__setitem__("finalConfigSha256", sha(raw)))
        rejected("restore", restore)
        def relay(path):
            rows = [json.loads(line) for line in (path / "proxy-requests.jsonl").read_text().splitlines() if line]
            b_hash = read(path / manifest_name)["metadataBSha256"]
            rows = [row for row in rows if row.get("responseSha256") != b_hash]
            raw = ("\n".join(json.dumps(row) for row in rows) + "\n").encode()
            (path / "proxy-requests.jsonl").write_bytes(raw)
            update_manifest(path, lambda value: value.__setitem__("proxyRequestsSha256", sha(raw)))
        rejected("relay", relay)
        def runtime(path):
            value = read(path / "target-runtime-end.json")
            value["binding"]["container_id"] = "0" * 64
            raw = (json.dumps(value) + "\n").encode()
            (path / "target-runtime-end.json").write_bytes(raw)
            update_manifest(path, lambda item: item.__setitem__("targetRuntimeEndSha256", sha(raw)))
        rejected("runtime", runtime)
        def signature_response(path):
            raw = b"<html><body>generic internal error</body></html>"
            (path / "signature-control-response.html").write_bytes(raw)
            evidence = read(path / "signature-control.json")
            evidence["response_body_sha256"] = sha(raw)
            evidence_raw = (json.dumps(evidence, indent=2) + "\n").encode()
            (path / "signature-control.json").write_bytes(evidence_raw)
            update_manifest(path, lambda value: (
                value.__setitem__("signatureControlResponseSha256", sha(raw)),
                value.__setitem__("signatureControlSha256", sha(evidence_raw))))
        rejected("signature-response", signature_response)
    bad_pins = json.loads(json.dumps(ACCEPTED_SUITE))
    bad_pins["jars"]["runner"] = "0" * 64
    run = read(folder / "created.json")["run"]
    try:
        _verify_suite_runtime(folder, run["id"], float(run["createdAt"]), bad_pins)
    except Exception:
        tests.append("suite-jar-pin")
    else:
        raise ValueError("Suite JAR pin tamper was accepted")
    require(set(tests) == {"wait", "metadata-b", "request-reference", "restore", "relay", "runtime",
                           "signature-response",
                           "suite-jar-pin"}, "tamper self-test coverage mismatch")
    return tests


def verify(folder, run_tamper=True):
    supplied = Path(folder)
    folder = supplied.resolve()
    manifest = verify_receipt(folder)
    run_record = read(folder / "created.json")["run"]
    run = run_record["id"]
    require(run == manifest["runId"] and RUN_RE.fullmatch(run) is not None, "Run mismatch")
    plan = read(folder / "plan.json")["plan"]["plan"]
    require(run_record.get("planId") == plan.get("id") and plan.get("profile") == "metadata_idp"
            and plan.get("target", {}).get("entityId") == "http://localhost:18380/idp"
            and plan.get("requestSigningMode") == "REQUIRED", "wrong Run/plan/profile")
    _verify_target_runtime(folder, "simplesamlphp", float(run_record["createdAt"]))
    verify_suite_oracle(folder, run, float(run_record["createdAt"]))
    before = find_case(read(folder / "result-before.json"), CASE)
    after_result = read(folder / "result-after.json")
    require(after_result == read(folder / "result.json"), "canonical formal result differs")
    after = find_case(after_result, CASE)
    require(before.get("verdict") == "NOT_VERIFIED", "campaign did not begin unverified")
    require((after.get("outcome"), after.get("verdict"), after.get("reason_code"),
             after.get("attested"), after.get("evidence_class"))
            == ("SATISFIED", "PASS", "metadata.native-refresh-observed", False, "OPERATOR_ASSISTED"),
            "formal MD02.a result mismatch")
    expected = {"transcript:" + manifest[name][field]
                for name in ("phaseA", "phaseB")
                for field in ("fetchReference", "preparedReference", "requestReference", "responseReference")}
    expected.add("transcript:" + manifest["phaseB"]["controlRequestReference"])
    expected.add(run + ".refresh/manifest.json")
    require({item.get("reference") for item in after.get("evidence", [])} == expected,
            "formal evidence references differ")
    require(read(folder / "transcript.json") == read(folder / "adopted-transcript.json")
            == read(folder / EVALUATION / "transcript-before.json")
            == read(folder / EVALUATION / "transcript.json"), "formal re-evaluation changed transcript")
    require(after_result == read(folder / EVALUATION / "result.json"), "captured formal result differs")
    installed = read(folder / "metadata-refresh-receipt-install.json")
    require(installed.get("runId") == run and len(installed.get("readBackSha256", [])) == len(RECEIPT_FILES) + 1
            and installed.get("productConfigurationWrites") == 2
            and installed.get("restorationWrites") == 1
            and installed.get("productRestarts") == installed.get("humanOperations") == 0,
            "receipt install/read-back mismatch")
    tests = tamper_self_test(folder) if run_tamper else []
    return supplied / "result.json", {CASE: after}, tests


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--tamper-self-test", action="store_true")
    args = parser.parse_args()
    path, cases, tests = verify(args.folder, args.tamper_self_test)
    print(path, {name: row["verdict"] for name, row in cases.items()}, tests)
