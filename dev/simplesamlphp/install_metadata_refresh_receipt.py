#!/usr/bin/env python3
"""Validate and install one restored SSP MD02.a refresh campaign receipt."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
SUITE = "samlscope-reference-suite"
VARIANTS = ("control", "no-valid-until")
FILES = (
    "original-config.php", "configured-config.php", "final-config.php", "effective-source.json",
    "operation-counts.json", "proxy-requests.jsonl", "metadata-a.xml", "metadata-b.xml",
    "signature-control.json", "signature-control-response.html",
    "target-runtime-start.json", "target-runtime-end.json",
    "target-container-inspect-start.json", "target-container-inspect-end.json",
    "target-image-inspect-start.json", "target-image-inspect-end.json",
    "target-version-runtime-start.txt", "target-version-runtime-end.txt",
    "target-version-source-start.txt", "target-version-source-end.txt",
)


def read(path):
    return json.loads(Path(path).read_text())


def one(values, label):
    if len(values) != 1:
        raise ValueError(label + " must have exactly one record")
    return values[0]


def copy_decoded(folder, transcript):
    target = folder / "decoded"
    target.mkdir(exist_ok=False)
    rows = []
    for entry in transcript:
        source = entry.get("decodedSamlRef")
        if not source:
            if entry.get("decodedSamlBytes") != 0:
                raise ValueError("Decoded original size without reference")
            continue
        expected = "transcripts/%s/%s.saml.xml" % (entry["runId"], entry["id"])
        if source != expected or entry.get("decodedSamlBytes", 0) <= 0:
            raise ValueError("Unexpected decoded original reference")
        destination = target / (entry["id"] + ".xml")
        subprocess.run(["docker", "cp", SUITE + ":/data/" + source, str(destination)],
                       check=True, timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        raw = destination.read_bytes()
        if len(raw) != entry["decodedSamlBytes"]:
            raise ValueError("Decoded original size mismatch")
        rows.append(dict(id=entry["id"], file="decoded/" + destination.name,
                         sha256=SHA(raw), bytes=len(raw)))
    (folder / "decoded-manifest.json").write_text(json.dumps(rows, indent=2) + "\n")
    return {row["id"]: folder / row["file"] for row in rows}


def phase(transcript, phase_record, variant, run, decoded):
    entries = {entry["id"]: entry for entry in transcript}
    request = entries[phase_record["requestReference"]]
    response = entries[phase_record["responseReference"]]
    request_id = request.get("samlSummary", {}).get("id")
    if not (request["runId"] == response["runId"] == run
            and request["direction"] == "OUTBOUND" and request.get("method") == "POST"
            and request.get("samlSummary", {}).get("type") == "AuthnRequest"
            and request.get("samlSummary", {}).get("campaign") == "metadata-polling"
            and request.get("samlSummary", {}).get("variant") == variant
            and request.get("samlSummary", {}).get("metadataSignatureControl") == "valid"
            and response["direction"] == "INBOUND"
            and response.get("samlSummary", {}).get("type") == "Response"
            and response.get("samlSummary", {}).get("metadataProbeAccepted") is True
            and response.get("samlSummary", {}).get("inResponseTo") == request_id
            and response.get("samlSummary", {}).get("statusCode")
                == "urn:oasis:names:tc:SAML:2.0:status:Success"
            and request["id"] in decoded and response["id"] in decoded):
        raise ValueError("Incomplete correlated polling exchange for " + variant)
    control = None
    lower = request
    if "controlRequestReference" in phase_record:
        control = entries[phase_record["controlRequestReference"]]
        control_summary = control.get("samlSummary", {})
        if not (control["direction"] == "OUTBOUND" and control.get("method") == "POST"
                and control_summary.get("type") == "AuthnRequest"
                and control_summary.get("campaign") == "metadata-polling"
                and control_summary.get("variant") == variant
                and control_summary.get("metadataSignatureControl") == "invalid"
                and control["id"] in decoded):
            raise ValueError("Invalid-signature control transcript is incomplete")
        lower = control
    # A valid request triggers its own native lookup.  For the B phase, the corrupt control also
    # triggers an earlier lookup; bind the receipt to that first post-wait refresh because it is
    # the lookup whose product-native rejection proves that the changed key was consumed.  The
    # later valid request remains cryptographically bound to B and supplies the Success control.
    upper = request if control is not None else response
    fetches = [entry for entry in transcript
        if entry["direction"] == "INBOUND" and entry.get("method") == "GET"
        and entry.get("samlSummary", {}).get("type") == "MetadataFetch"
        and entry.get("samlSummary", {}).get("variant") == variant
        and entry.get("samlSummary", {}).get("feed") == "live"
        and urlsplit(entry.get("url") or "").hostname == "samlscope-reference-suite"
        and float(lower["timestamp"]) <= float(entry["timestamp"]) < float(upper["timestamp"])]
    fetch = one(fetches, variant + " native metadata fetch")
    prepared = one([entry for entry in transcript
        if entry["direction"] == "OUTBOUND" and entry.get("method") == "GET"
        and entry.get("samlSummary", {}).get("type") == "MetadataPrepared"
        and entry.get("samlSummary", {}).get("sourceType") == "MetadataFetch"
        and entry.get("samlSummary", {}).get("fetchTranscriptId") == fetch["id"]
        and entry.get("samlSummary", {}).get("variant") == variant
        and entry.get("samlSummary", {}).get("feed") == "live"], variant + " served metadata")
    if prepared["id"] not in decoded or not (float(fetch["timestamp"]) <= float(prepared["timestamp"])
                                               < float(response["timestamp"])):
        raise ValueError("Served metadata original is missing or out of order")
    raw = decoded[prepared["id"]].read_bytes()
    if SHA(raw) != prepared.get("samlSummary", {}).get("metadataSha256"):
        raise ValueError("Served metadata hash mismatch")
    result = dict(variant=variant, fetchReference=fetch["id"], preparedReference=prepared["id"],
                  requestReference=request["id"], responseReference=response["id"])
    if control is not None:
        result["controlRequestReference"] = control["id"]
    return result, raw, request, response, fetch, control


def install(folder):
    folder = Path(folder).resolve()
    created = read(folder / "created.json")
    run = created["run"]["id"]
    if RUN_RE.fullmatch(run) is None:
        raise ValueError("Invalid Run identifier")
    plan_response = read(folder / "plan.json")["plan"]
    plan = plan_response["plan"]
    campaign = read(folder / "campaign.json")
    wait = campaign["pollingDelaySeconds"]
    if campaign.get("campaignVariants") != list(VARIANTS):
        raise ValueError("Campaign variants differ from the refresh proof")
    if wait < 2:
        raise ValueError("Refresh wait is too short")
    restoration = read(folder / "restoration.json")
    original = (folder / "original-config.php").read_bytes()
    final = (folder / "final-config.php").read_bytes()
    if not restoration["restored"] or original != final or SHA(original) != restoration["original_sha256"]:
        raise ValueError("Product configuration was not restored")
    operations = read(folder / "operation-counts.json")
    if not (operations["restored"] and operations["product_configuration_writes"] == 2
            and operations["restoration_writes"] == 1 and operations["product_restarts"] == 0
            and operations["human_operations"] == 0):
        raise ValueError("Operation counts differ from the automatic restored campaign")
    transcript = read(folder / "transcript.json")
    if not transcript or any(entry["runId"] != run for entry in transcript):
        raise ValueError("Transcript is empty or contains another Run")
    if len({entry["id"] for entry in transcript}) != len(transcript):
        raise ValueError("Transcript IDs are not unique")
    decoded = copy_decoded(folder, transcript)
    phase_records = read(folder / "phase-records.json")
    if [item["variant"] for item in phase_records] != list(VARIANTS):
        raise ValueError("Campaign phase order differs")
    phases = []
    metadata = []
    observations = []
    for record, variant in zip(phase_records, VARIANTS):
        bound, raw, request, response, fetch, control_entry = phase(
            transcript, record, variant, run, decoded)
        phases.append(bound)
        metadata.append(raw)
        observations.append((request, response, fetch, control_entry))
    control = observations[1][3]
    if control is None:
        raise ValueError("B phase lacks the invalid-signature control")
    if float(control["timestamp"]) < float(observations[0][1]["timestamp"]) + wait:
        raise ValueError("Second request started before the approved refresh wait")
    if metadata[0] == metadata[1]:
        raise ValueError("Metadata did not change")
    (folder / "metadata-a.xml").write_bytes(metadata[0])
    (folder / "metadata-b.xml").write_bytes(metadata[1])
    requests = [json.loads(line) for line in (folder / "proxy-requests.jsonl").read_text().splitlines() if line]
    if len(requests) < 2:
        raise ValueError("Native relay did not record both versions")
    entity = plan_response["entityId"]
    native = read(folder / "signature-control.json")
    control_original = decoded[control["id"]].read_bytes()
    control_response = (folder / "signature-control-response.html").read_bytes()
    if not (native.get("request_id") == control.get("samlSummary", {}).get("id")
            and native.get("request_sha256") == SHA(control_original)
            and native.get("request_url") == control.get("url")
            and native.get("response_url_exact_match") is True
            and native.get("response_status") == 500
            and native.get("response_body_sha256") == SHA(control_response)
            and native.get("native_signature_rejection") == "signature-value-invalid"
            and native.get("saml_response_form_present") is False):
        raise ValueError("Product-native signature rejection does not bind the control request")
    for raw, (_, response, fetch, _) in zip(metadata, observations):
        matching = [item for item in requests if item.get("entityId") == entity
                    and item.get("responseSha256") == SHA(raw) and item.get("httpStatus") == 200]
        if not matching:
            raise ValueError("Native relay is not bound to served metadata")

    manifest = dict(schema="samlscope-native-metadata-refresh-v1", runId=run,
        adapter="simplesamlphp-native-mdq-refresh-v1", entityId=entity,
        variantB=VARIANTS[1], refreshWaitSeconds=wait,
        originalConfigSha256=SHA(original), configuredConfigSha256=SHA((folder / "configured-config.php").read_bytes()),
        finalConfigSha256=SHA(final), effectiveSourceSha256=SHA((folder / "effective-source.json").read_bytes()),
        operationCountsSha256=SHA((folder / "operation-counts.json").read_bytes()),
        targetRuntimeStartSha256=SHA((folder / "target-runtime-start.json").read_bytes()),
        targetRuntimeEndSha256=SHA((folder / "target-runtime-end.json").read_bytes()),
        metadataASha256=SHA(metadata[0]), metadataBSha256=SHA(metadata[1]),
        signatureControlSha256=SHA((folder / "signature-control.json").read_bytes()),
        signatureControlResponseSha256=SHA((folder / "signature-control-response.html").read_bytes()),
        proxyRequestsSha256=SHA((folder / "proxy-requests.jsonl").read_bytes()),
        phaseA=phases[0], phaseB=phases[1])
    manifest_path = folder / "metadata-refresh-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    receipt = "/data/metadata-rejection-evidence/" + run + ".refresh"
    subprocess.run(["docker", "exec", SUITE, "mkdir", "-p", receipt], check=True, timeout=30)
    for name in FILES:
        subprocess.run(["docker", "cp", str(folder / name), SUITE + ":" + receipt + "/" + name],
                       check=True, timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(["docker", "cp", str(manifest_path), SUITE + ":" + receipt + "/manifest.json"],
                   check=True, timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    names = [*FILES, "manifest.json"]
    output = subprocess.check_output(["docker", "exec", SUITE, "sha256sum",
                                      *[receipt + "/" + name for name in names]], text=True, timeout=30)
    actual = [line.split()[0] for line in output.splitlines()]
    expected = [*[SHA((folder / name).read_bytes()) for name in FILES], SHA(manifest_path.read_bytes())]
    if actual != expected:
        raise ValueError("Suite receipt read-back mismatch")
    result = dict(runId=run, target=receipt, readBackSha256=actual,
                  productConfigurationWrites=2, restorationWrites=1,
                  productRestarts=0, humanOperations=0)
    (folder / "metadata-refresh-receipt-install.json").write_text(json.dumps(result, indent=2) + "\n")
    return run


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder")
    print(install(parser.parse_args().folder))
