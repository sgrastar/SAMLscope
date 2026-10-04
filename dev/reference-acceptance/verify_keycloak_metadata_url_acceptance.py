#!/usr/bin/env python3
"""Fail-closed verifier for Keycloak native MD01.a/MD02.a campaign evidence."""

import argparse
import copy
import datetime
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.parse
import zipfile
import xml.etree.ElementTree as ET

if not __debug__:
    raise RuntimeError("Acceptance verification must not run with Python optimization")

REPO = Path(__file__).resolve().parents[2]
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
PLAN_RE = re.compile(r"plan_[0-9A-HJKMNP-TV-Z]{26}")
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
JAR_MANIFEST_SHA = "89a154de4e237a5c0280a262a38ed2f71d9648f09a88a47bead9c695fae0207e"
RELAY_SOURCE_SHA = "7067092aafdaaffcddabbf9fcf60b53e6e1d20f6061f52f3c652197f626e865b"
RELAY_CLASS_SHA = "d3420b3bb70baa40763ae9b8eab295ca767fa929f4d0f46b52a2c23e8ed96ded"
SUITE_CAPTURE_IMAGE = "sha256:846083123e759f24e88a89f9badba50c4e4cd110b3b13563e8295c9829886cdb"
SUITE_CAPTURE_JARS = {
    "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe",
    "runner": "94dca2c3c134cf2ad3c30fb4a271448b729c7327b464bff0070a83b45b157dae",
    "saml": "cbfdb79f54ed967f58c8153eb8d0dda350016030c552d0aaee3fc30988d3bf73",
}
EVALUATION_PINS = {
    "mdq": {
        "image": "sha256:5658cdff7bdd9964b2bf6bfcdcb941cbce3df3c006dd6d21fdd0228d558297eb",
        "jars": {
            "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe",
            "runner": "7ff2daafcdd15002626f78c385720b2fc527a7a706692834eef22547e24ec1c4",
            "saml": "cbfdb79f54ed967f58c8153eb8d0dda350016030c552d0aaee3fc30988d3bf73",
        },
        "classes": {
            "com/samlscope/runner/cases/KeycloakMetadataUrlEvidenceFile.class":
                "fcf50ea6b873d320c9bbb19d9ed54fc523b14103d9cf3bb30cccf3c26d9e87fa",
            "com/samlscope/runner/cases/MdqAcquisitionConfigurationTestCase.class":
                "fd6ee76f814024183196a00dac0caf146a127117afea74c2f1cce14ea6328fdc",
            "com/samlscope/runner/cases/MetadataRefreshEvidenceFile.class":
                "ff168650a25c858c8bf743eec14333433789e3ce6a7daf4eaaec2ed585532be3",
        },
    },
    "refresh": {
        "image": "sha256:6d22ec7bd5b16e9c9191b42d3d915f92d621a3f670c81b24746dd8b0cd5f9b90",
        "jars": {
            "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe",
            "runner": "55416901184a95b8841339ba4b37f996a6eee6c9cc20300d0e1f5402b6e7475b",
            "saml": "cbfdb79f54ed967f58c8153eb8d0dda350016030c552d0aaee3fc30988d3bf73",
        },
        "classes": {
            "com/samlscope/runner/cases/KeycloakMetadataUrlEvidenceFile.class":
                "a9fe68a6ab242391d9c147e508c4f336453745031e05575f9da66bec5a42bfa6",
            "com/samlscope/runner/cases/MdqAcquisitionConfigurationTestCase.class":
                "fd6ee76f814024183196a00dac0caf146a127117afea74c2f1cce14ea6328fdc",
            "com/samlscope/runner/cases/MetadataRefreshEvidenceFile.class":
                "ff168650a25c858c8bf743eec14333433789e3ce6a7daf4eaaec2ed585532be3",
        },
    },
}
CRITICAL_JARS = {
    "org.keycloak.keycloak-services-26.7.2.jar":
        "213c45bb357e0881ead8284f12308e3c9fd8e09e7f0b6ec816f95f8b0921bea9",
    "org.keycloak.keycloak-model-infinispan-26.7.2.jar":
        "63ba0e2133e3a5a65f5a4b7944018d3ae7b524aecbcaeacadcdfc7a004fb76d6",
    "org.keycloak.keycloak-saml-core-public-26.7.2.jar":
        "e1262687b87e92edb759b02d568fed8518d5e00b32a70749bee61a787178bbb2",
    "org.keycloak.keycloak-server-spi-private-26.7.2.jar":
        "a9541ffb99d572a487afdbd0ce112f3038f8d58119857219306e14d3af400afa",
}
MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
P = "{urn:oasis:names:tc:SAML:2.0:protocol}"


def require(value, detail):
    if not value:
        raise ValueError(detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def instant(value):
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


class Evidence:
    def __init__(self, folder, overrides=None):
        self.folder = Path(folder).resolve()
        self.overrides = overrides or {}

    def raw(self, name):
        if name in self.overrides:
            return self.overrides[name]
        path = (self.folder / name).resolve()
        require(path.parent in {self.folder, (self.folder / "decoded").resolve(),
                                (self.folder / "evaluation").resolve()},
                "evidence path escapes folder")
        require(path.is_file() and not path.is_symlink(), "evidence original missing: " + name)
        return path.read_bytes()

    def json(self, name):
        return json.loads(self.raw(name))


def decoded(evidence, transcript):
    by_id = {entry["id"]: entry for entry in transcript}
    require(len(by_id) == len(transcript), "duplicate transcript identifier")
    values = {}
    rows = evidence.json("decoded-manifest.json")
    for row in rows:
        require(set(row) == {"id", "file", "sha256"} and row["id"] in by_id,
                "decoded manifest row differs")
        require(row["file"] == "decoded/" + row["id"] + ".xml", "decoded path differs")
        raw = evidence.raw(row["file"])
        entry = by_id[row["id"]]
        require(entry.get("decodedSamlRef") == "transcripts/%s/%s.saml.xml" %
                (entry["runId"], entry["id"]), "decoded reference differs")
        require(entry.get("decodedSamlBytes") == len(raw) and row["sha256"] == sha(raw),
                "decoded original differs")
        values[row["id"]] = raw
    require(set(values) == {entry["id"] for entry in transcript if entry.get("decodedSamlRef")},
            "decoded originals are incomplete")
    return by_id, values


def safe_xml(raw):
    require(b"<!DOCTYPE" not in raw.upper() and b"<!ENTITY" not in raw.upper(), "unsafe XML")
    return ET.fromstring(raw)


def check_hash(evidence, manifest, name, field):
    raw = evidence.raw(name)
    require(manifest.get(field) == sha(raw), "hash binding differs: " + name)
    return raw


def runtime(evidence, manifest, phase):
    value = json.loads(check_hash(evidence, manifest, "target-runtime-" + phase + ".json",
                                  "targetRuntime" + phase.title() + "Sha256"))
    require(value.get("schema") == "samlscope-keycloak-metadata-url-runtime-v1"
            and value.get("phase") == phase and value.get("product") == "keycloak"
            and value.get("productVersion") == "26.7.2" and value.get("imageId") == IMAGE
            and re.fullmatch(r"[0-9a-f]{64}", value.get("containerId", ""))
            and value.get("runningAtCapture") is True
            and IMAGE.removeprefix("sha256:") in value.get("configuredImage", ""),
            "target runtime identity differs")
    keys = value.get("environmentKeys")
    require(isinstance(keys, list) and keys == sorted(set(keys)) and keys
            and all(isinstance(key, str) and "=" not in key for key in keys),
            "environment key-only capture differs")
    require(not any(key.startswith("KC_SPI_PUBLIC_KEY_STORAGE_INFINISPAN_") for key in keys),
            "public-key storage override was active")
    jars_raw = evidence.raw("keycloak-jars-" + phase + ".json")
    providers_raw = evidence.raw("provider-inventory-" + phase + ".json")
    config = evidence.raw("keycloak-config-" + phase + ".txt")
    require(value.get("jarManifestSha256") == sha(jars_raw) == JAR_MANIFEST_SHA
            and value.get("providerInventorySha256") == sha(providers_raw)
            and value.get("keycloakConfigSha256") == sha(config), "runtime backing hash differs")
    jars = json.loads(jars_raw)
    require(len(jars) == 348 and [row["path"] for row in jars] ==
            sorted(row["path"] for row in jars), "full JAR inventory differs")
    found = {Path(row["path"]).name: row["sha256"] for row in jars}
    require(all(found.get(name) == digest for name, digest in CRITICAL_JARS.items()),
            "critical Keycloak JAR differs")
    providers = json.loads(providers_raw)
    require(providers == {
        "configurationBasis": "factory-defaults-no-runtime-override",
        "httpClientProvider": "default", "maxCacheTimeSeconds": 86400,
        "minTimeBetweenRequestsSeconds": 10, "productVersion": "26.7.2",
        "publicKeyStorageProvider": "infinispan",
        "schema": "samlscope-keycloak-metadata-provider-inventory-v1",
        "servicesJarSha256": CRITICAL_JARS["org.keycloak.keycloak-services-26.7.2.jar"],
        "storageJarSha256": CRITICAL_JARS["org.keycloak.keycloak-model-infinispan-26.7.2.jar"],
    }, "native provider inventory differs")
    require(b"public-key-storage" not in config.lower()
            and b"public_key_storage" not in config.lower(), "runtime config overrides storage")
    return value


def common(evidence, manifest, run, entity, expected_writes, expected_roundtrips, expected_fetches):
    before = check_hash(evidence, manifest, "admin-before.json", "adminBeforeSha256")
    configured_raw = check_hash(evidence, manifest, "admin-configured.json", "adminConfiguredSha256")
    final = check_hash(evidence, manifest, "admin-final.json", "adminFinalSha256")
    require(before == final and json.loads(before) == [], "native client was not exactly restored")
    configured_projection = json.loads(configured_raw)
    require(configured_projection.get("schema") == "samlscope-keycloak-client-readback-projection-v1"
            and configured_projection.get("redactedCredentialFields") == [
                "attributes.saml.signing.certificate",
                "attributes.saml.signing.private.key", "secret"]
            and "secret" in configured_projection.get("observedTopLevelFields", [])
            and "saml.signing.private.key" in configured_projection.get("observedAttributeFields", []),
            "credential-safe readback projection differs")
    configured = configured_projection.get("client", {})
    attributes = configured.get("attributes", {})
    require(configured.get("clientId") == entity and configured.get("protocol") == "saml"
            and configured.get("enabled") is True
            and any(value.startswith(entity + "/sp/acs/0") for value in configured.get("redirectUris", []))
            and attributes.get("saml.client.signature") == "true"
            and attributes.get("saml.useMetadataDescriptorUrl") == "true"
            and attributes.get("saml.metadataDescriptorUrl") == manifest["relayUrl"]
            and attributes.get("saml.force.post.binding") == "true"
            and "secret" not in configured and "saml.signing.certificate" not in attributes
            and "saml.signing.private.key" not in attributes,
            "native metadata URL configuration differs")
    counts = json.loads(check_hash(evidence, manifest, "operation-counts.json", "operationCountsSha256"))
    require(counts == {"restored": True, "productConfigurationWrites": expected_writes,
            "restorationWrites": 1,
            "protocolRoundTrips": expected_roundtrips, "metadataFetches": expected_fetches,
            "productRestarts": 0, "humanOperations": 0, "temporaryRelayStopped": True},
            "operation counts differ")
    require(sha(evidence.raw("KeycloakMetadataUrlRelay.java")) ==
            manifest.get("relaySourceSha256") == RELAY_SOURCE_SHA, "relay source differs")
    require(sha(evidence.raw("KeycloakMetadataUrlRelay.class")) == RELAY_CLASS_SHA,
            "executed relay class differs")
    relay_raw = check_hash(evidence, manifest, "relay-requests.jsonl", "relayRequestsSha256")
    records = [json.loads(line) for line in relay_raw.splitlines() if line]
    require(len(records) == expected_fetches
            and [row["sequence"] for row in records] == list(range(1, expected_fetches + 1)),
            "relay sequence/count differs")
    for row in records:
        require(row["method"] == "GET" and row["httpStatus"] == 200 and row["failure"] == ""
                and row["entityId"] == entity
                and row["requestPath"] == "/entities/" + urllib.parse.quote(entity, safe="")
                and row["servedFile"] == "relay-body-%d.xml" % row["sequence"]
                and sha(evidence.raw(row["servedFile"])) == row["servedSha256"],
                "relay original differs")
    start, end = runtime(evidence, manifest, "start"), runtime(evidence, manifest, "end")
    require((start["containerId"], start["imageId"], start["startedAt"])
            == (end["containerId"], end["imageId"], end["startedAt"])
            and evidence.raw("keycloak-jars-start.json") == evidence.raw("keycloak-jars-end.json")
            and evidence.raw("provider-inventory-start.json") == evidence.raw("provider-inventory-end.json")
            and evidence.raw("keycloak-config-start.txt") == evidence.raw("keycloak-config-end.txt"),
            "target runtime changed during campaign")
    suite = evidence.json("suite-runtime.json")
    require(suite.get("imageId") == SUITE_CAPTURE_IMAGE and suite.get("runningAtCapture") is True,
            "capture Suite runtime differs")
    for name, digest in SUITE_CAPTURE_JARS.items():
        row = suite["jars"][name]
        require(row["sha256"] == digest == sha(evidence.raw(row["file"])),
                "capture Suite JAR differs: " + name)
    transcript = evidence.json("transcript.json")
    require(transcript and all(row.get("runId") == run for row in transcript), "transcript Run differs")
    entries, originals = decoded(evidence, transcript)
    return entries, originals, records


def success(entries, originals, receipt, metadata_probe, active_probe=False):
    request = entries.get(receipt.get("requestReference"))
    response = entries.get(receipt.get("responseReference"))
    require(request and response and request["id"] in originals and response["id"] in originals,
            "exchange originals are unavailable")
    request_xml, response_xml = safe_xml(originals[request["id"]]), safe_xml(originals[response["id"]])
    request_id = request_xml.attrib.get("ID")
    require(request and response and request["direction"] == "OUTBOUND"
            and request["samlSummary"].get("type") == "AuthnRequest"
            and response["direction"] == "INBOUND"
            and response["samlSummary"].get("type") == "Response"
            and response["samlSummary"].get("inResponseTo") == request_id
            and response["samlSummary"].get("statusCode") == SUCCESS
            and response["samlSummary"].get(
                "metadataProbeAccepted" if metadata_probe else
                "activeProbeAccepted" if active_probe else "normalFlowAccepted") is True
            and (not active_probe or (request["samlSummary"].get("active_probe") is True
                and request["samlSummary"].get("fixture_id") == "valid"
                and request["samlSummary"].get("scenario_case_id") == "IIP-ALG01-a-idp-01"
                and request["samlSummary"].get("action_id") == request.get("correlationId"))),
            "correlated Success exchange differs")
    require(request_xml.tag == P + "AuthnRequest" and response_xml.tag == P + "Response"
            and response_xml.attrib.get("InResponseTo") == request_xml.attrib["ID"]
            and response_xml.attrib.get("Destination") == response["url"], "SAML originals differ")
    return request, response


def terminal(evidence, entries, originals, request, name):
    record = evidence.json(name + ".json")
    body = evidence.raw(name + "-response.html")
    request_id = request["samlSummary"]["id"]
    first = urllib.parse.urlsplit(request["url"])
    second = urllib.parse.urlsplit(record["responseUrl"])
    require(record["requestId"] == request_id
            and record["requestSha256"] == sha(originals[request["id"]])
            and record["requestUrl"] == request["url"]
            and (first.scheme, first.hostname, first.port or 80) ==
                (second.scheme, second.hostname, second.port or 80)
            and 400 <= record["responseStatus"] <= 599
            and record["responseBodySha256"] == sha(body)
            and record["samlResponseFormPresent"] is False
            and record["deliveryState"] == "HTTP_RESPONSE"
            and record["productVerdictAssigned"] is False
            and not any(row["direction"] == "INBOUND"
                        and row.get("samlSummary", {}).get("inResponseTo") == request_id
                        for row in entries.values()), "target terminal rejection differs")
    return instant(record["observedAt"])


def formal_evaluation(evidence, run, mode):
    require(mode in EVALUATION_PINS, "formal evaluation runtime is not pinned")
    pin = EVALUATION_PINS[mode]
    runtime = evidence.json("evaluation/suite-runtime.json")
    require(runtime.get("schema") == "samlscope-keycloak-metadata-url-suite-runtime-v1"
            and runtime.get("runId") == run and runtime.get("phase") == "formal-evaluation"
            and runtime.get("imageId") == pin["image"] and runtime.get("runningAtCapture") is True
            and re.fullmatch(r"[0-9a-f]{64}", runtime.get("containerId", "")) is not None
            and runtime.get("startedAt"), "formal Suite runtime differs")
    for name, digest in pin["jars"].items():
        row = runtime["jars"][name]
        require(row["path"] == "/opt/samlscope/lib/%s-0.1.0.jar" % name
                and row["file"] == "suite-%s-0.1.0.jar" % name
                and row["sha256"] == digest == sha(evidence.raw("evaluation/" + row["file"])),
                "formal Suite JAR differs: " + name)
    runner = evidence.raw("evaluation/" + runtime["jars"]["runner"]["file"])
    with zipfile.ZipFile(io.BytesIO(runner)) as archive:
        for name, digest in pin["classes"].items():
            raw = archive.read(name)
            require(runtime["classes"][name] == {"sha256": digest, "size": len(raw)}
                    and sha(raw) == digest, "formal Runner class differs: " + name)
    require(evidence.raw("receipt-install.json") == evidence.raw("evaluation/receipt-installation.json"),
            "receipt installation read-back differs")
    installed = evidence.json("receipt-install.json")
    require(installed.get("runId") == run
            and installed.get("target") == "/data/metadata-rejection-evidence/" + run
                + (".mdq" if mode == "mdq" else ".refresh")
            and installed.get("configurationWrites") == 2
            and installed.get("restorationWrites") == 1
            and installed.get("productRestarts") == installed.get("humanOperations") == 0
            and isinstance(installed.get("readBackSha256"), list)
            and all(re.fullmatch(r"[0-9a-f]{64}", item) for item in installed["readBackSha256"]),
            "receipt installation record differs")
    before = evidence.json("evaluation/transcript-before.json")
    after = evidence.json("evaluation/transcript.json")
    require(before == after == evidence.json("transcript.json"),
            "formal re-evaluation changed the Run transcript")


def verify_folder(folder, require_adoption=False, overrides=None, run_signatures=True):
    evidence = Evidence(folder, overrides)
    manifest = evidence.json("manifest.json")
    run = manifest.get("runId")
    require(RUN_RE.fullmatch(run or "") is not None, "manifest Run differs")
    created = evidence.json("created.json")["run"]
    plan_document = evidence.json("plan.json")["plan"]
    plan = created["planId"]
    entity = manifest.get("entityId")
    require(created["id"] == run and PLAN_RE.fullmatch(plan) is not None
            and plan_document["plan"]["id"] == plan
            and entity == "http://localhost:18080/p/" + plan, "Plan/Run/entity binding differs")
    expected_relay = "http://samlscope-keycloak-metadata-relay:8081/entities/" + \
        urllib.parse.quote(entity, safe="")
    require(manifest.get("relayUrl") == expected_relay, "stable relay URL differs")
    mode = "mdq" if manifest.get("schema") == "samlscope-keycloak-native-mdq-v1" else "refresh"
    if mode == "mdq":
        require(manifest.get("adapter") == "keycloak-native-mdq-v1"
                and manifest.get("sourceUrl") == "http://samlscope-reference-suite:8080/mdq/" +
                    urllib.parse.quote(entity, safe=""), "MDQ receipt identity differs")
        entries, originals, records = common(evidence, manifest, run, entity, 2, 2, 1)
        metadata = check_hash(evidence, manifest, "metadata-mdq.xml", "metadataSha256")
        root = safe_xml(metadata)
        require(root.tag == MD + "EntityDescriptor" and root.attrib.get("entityID") == entity,
                "MDQ metadata identity differs")
        bootstrap_request, bootstrap_response = success(
            entries, originals, manifest["bootstrap"], False, False)
        bootstrap_xml = safe_xml(originals[bootstrap_request["id"]])
        bootstrap_id = bootstrap_xml.attrib.get("ID")
        require(bootstrap_request.get("samlSummary", {}).get("active_probe") is not True
                and bootstrap_request.get("method") == "GET"
                and bootstrap_id == bootstrap_request.get("correlationId")
                and bootstrap_id == bootstrap_request.get("samlSummary", {}).get("id"),
                "bootstrap request identity differs")
        request, response = success(entries, originals, manifest["exchange"], False, True)
        require(request.get("method") == "POST", "active-probe binding differs")
        request_id = safe_xml(originals[request["id"]]).attrib["ID"]
        action_id = request.get("correlationId")
        require(sum(row["direction"] == "OUTBOUND" and row.get("correlationId") == action_id
                    for row in entries.values()) == 1
                and sum(row["direction"] == "INBOUND"
                        and row.get("samlSummary", {}).get("inResponseTo") == request_id
                        for row in entries.values()) == 1,
                "active-probe action/request correlation is ambiguous")
        relay = records[0]
        require(relay["sequence"] == manifest["bootstrap"]["relaySequence"]
                and relay["mode"] == "fetch" and relay["sourceUrl"] == manifest["sourceUrl"]
                and relay["upstreamSha256"] == relay["servedSha256"] == sha(metadata)
                and float(bootstrap_request["timestamp"]) <= instant(relay["startedAt"])
                <= instant(relay["completedAt"]) <= float(bootstrap_response["timestamp"])
                < float(request["timestamp"]) < float(response["timestamp"]),
                "MDQ native fetch/use correlation differs")
        signature_args = [evidence.folder / "metadata-mdq.xml",
                          evidence.folder / "decoded" / (request["id"] + ".xml")]
        case_id, reason = "IIP-MD01-a-idp-01", "mdq.native-acquisition-observed"
    else:
        require(manifest.get("adapter") == "keycloak-native-metadata-url-refresh-v1"
                and manifest.get("refreshWaitSeconds") == 12
                and manifest.get("minimumRefreshSeconds") == 10
                and (manifest.get("variantA"), manifest.get("variantB"), manifest.get("oldKeyVariant"))
                    == ("entity-root", "no-valid-until", "keyvalue-only")
                and manifest.get("sourceUrl") == "http://samlscope-reference-suite:8080/p/%s/metadata/live?run=%s"
                    % (plan, run), "refresh receipt identity differs")
        entries, originals, records = common(evidence, manifest, run, entity, 2, 4, 3)
        metadata_a = check_hash(evidence, manifest, "metadata-a.xml", "metadataASha256")
        metadata_b = check_hash(evidence, manifest, "metadata-b.xml", "metadataBSha256")
        require(metadata_a != metadata_b and safe_xml(metadata_a).attrib.get("entityID") == entity
                and safe_xml(metadata_b).attrib.get("entityID") == entity, "A/B metadata differs")
        phase_a, phase_b = manifest["phaseA"], manifest["phaseB"]
        request_a, response_a = success(entries, originals, phase_a, True)
        request_b, response_b = success(entries, originals, phase_b, True)
        control_b = entries.get(phase_b.get("controlRequestReference"))
        old = entries.get(manifest["oldKeyControl"].get("requestReference"))
        require(control_b and old and control_b["samlSummary"].get("metadataSignatureControl") == "invalid"
                and old["samlSummary"].get("metadataSignatureControl") == "valid"
                and old["samlSummary"].get("variant") == "keyvalue-only"
                and control_b["id"] in originals and old["id"] in originals,
                "negative-control transcript differs")
        control_observed = terminal(evidence, entries, originals, control_b, "signature-control")
        old_observed = terminal(evidence, entries, originals, old, "old-key-control")
        require(float(control_b["timestamp"]) >= float(response_a["timestamp"]) + 12
                and float(old["timestamp"]) >= float(response_b["timestamp"]) + 12,
                "approved refresh wait was not observed")
        for phase, request, response, expected, record, lower in (
                (phase_a, request_a, response_a, metadata_a, records[0], float(request_a["timestamp"])),
                (phase_b, request_b, response_b, metadata_b, records[1], float(control_b["timestamp"]))):
            fetch, prepared = entries.get(phase.get("fetchReference")), entries.get(phase.get("preparedReference"))
            require(fetch and prepared and fetch["samlSummary"].get("type") == "MetadataFetch"
                    and prepared["samlSummary"].get("type") == "MetadataPrepared"
                    and prepared["samlSummary"].get("fetchTranscriptId") == fetch["id"]
                    and originals[prepared["id"]] == expected
                    and record["sequence"] == phase["relaySequence"]
                    and record["mode"] == "fetch" and record["sourceUrl"] == manifest["sourceUrl"]
                    and record["upstreamSha256"] == record["servedSha256"] == sha(expected)
                    and lower <= instant(record["startedAt"]) <= instant(record["completedAt"])
                    <= float(response["timestamp"]), "A/B native fetch correlation differs")
        require(records[2]["sequence"] == manifest["oldKeyControl"]["relaySequence"]
                and records[2]["mode"] == "frozen"
                and records[2]["servedSha256"] == records[2]["upstreamSha256"] == sha(metadata_b)
                and float(old["timestamp"]) <= instant(records[2]["startedAt"])
                <= instant(records[2]["completedAt"]) <= old_observed
                and control_observed < float(request_b["timestamp"]), "old-key refetch correlation differs")
        signature_args = [evidence.folder / "metadata-a.xml",
                          evidence.folder / "decoded" / (request_a["id"] + ".xml"),
                          evidence.folder / "metadata-b.xml",
                          evidence.folder / "decoded" / (request_b["id"] + ".xml"),
                          evidence.folder / "decoded" / (control_b["id"] + ".xml"),
                          evidence.folder / "decoded" / (old["id"] + ".xml")]
        case_id, reason = "IIP-MD02-a-idp-01", "metadata.native-refresh-observed"
    if run_signatures and not overrides:
        with tempfile.TemporaryDirectory(prefix="verify-keycloak-metadata-url-") as temporary:
            source = REPO / "dev/reference-acceptance/VerifyKeycloakMetadataUrlSignatures.java"
            subprocess.run(["javac", "-d", temporary, str(source)], check=True, timeout=60)
            output = subprocess.check_output(
                ["java", "-cp", temporary, "VerifyKeycloakMetadataUrlSignatures",
                 *map(str, signature_args)], text=True, timeout=60)
            require(json.loads(output), "signature verifier returned no result")
    cases = {}
    if require_adoption:
        formal_evaluation(evidence, run, mode)
        result = evidence.json("evaluation/result.json")
        values = [case for requirement in result.get("requirements", [])
                  for case in requirement.get("cases", []) if case.get("id") == case_id]
        require(len(values) == 1 and values[0].get("outcome") == "SATISFIED"
                and values[0].get("reason_code") == reason
                and any(ref.get("reference") == run + (".mdq" if mode == "mdq" else ".refresh") + "/manifest.json"
                        for ref in values[0].get("evidence", [])), "formal adoption differs")
        cases[case_id] = {key: values[0].get(key) for key in ("outcome", "verdict", "reason_code")}
    return {"runId": run, "mode": mode, "caseId": case_id, "cases": cases,
            "restored": True, "manifestSha256": sha(evidence.raw("manifest.json"))}


def tamper_tests(folder):
    folder = Path(folder)
    baseline = json.loads((folder / "manifest.json").read_text())
    attempts = []

    def reject(label, mutate):
        manifest = copy.deepcopy(baseline)
        overrides = {}
        mutate(manifest, overrides)
        overrides["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
        try:
            verify_folder(folder, False, overrides, False)
        except Exception:
            attempts.append(label)
            return
        raise AssertionError("Tamper accepted: " + label)

    reject("cross-run", lambda value, files: value.__setitem__("runId", "run_0" * 6))
    reject("admin-final", lambda value, files: (
        files.__setitem__("admin-final.json", b"[{}]\n"),
        value.__setitem__("adminFinalSha256", sha(files["admin-final.json"]))))
    reject("operation-count", lambda value, files: (
        files.__setitem__("operation-counts.json", json.dumps({"restored": True}).encode()),
        value.__setitem__("operationCountsSha256", sha(files["operation-counts.json"]))))
    reject("relay-source", lambda value, files: value.__setitem__("relaySourceSha256", "0" * 64))
    reject("runtime", lambda value, files: value.__setitem__("targetRuntimeEndSha256", "0" * 64))
    if baseline["schema"].endswith("mdq-v1"):
        reject("metadata", lambda value, files: value.__setitem__("metadataSha256", "0" * 64))
        reject("response-ref", lambda value, files: value["exchange"].__setitem__("responseReference", "tx_0"))
        reject("bootstrap-cross-ref", lambda value, files: value["bootstrap"].__setitem__(
            "responseReference", value["exchange"]["responseReference"]))

        def wrong_action(value, files):
            transcript = json.loads((folder / "transcript.json").read_text())
            request = value["exchange"]["requestReference"]
            for row in transcript:
                if row["id"] == request:
                    row["samlSummary"]["action_id"] = "action_other"
            files["transcript.json"] = canonical_json(transcript)

        reject("active-action", wrong_action)
    else:
        reject("metadata-b", lambda value, files: value.__setitem__("metadataBSha256", "0" * 64))
        reject("status-600", lambda value, files: (
            files.__setitem__("signature-control.json", canonical_json({
                **json.loads((folder / "signature-control.json").read_text()), "responseStatus": 600})),
            value.__setitem__("signatureControlSha256", sha(files["signature-control.json"]))))
        reject("missing-old-refetch", lambda value, files: value["oldKeyControl"].__setitem__("relaySequence", 2))
        reject("short-wait", lambda value, files: value.__setitem__("refreshWaitSeconds", 9))
        reject("wrong-old-variant", lambda value, files: value.__setitem__("oldKeyVariant", "no-valid-until"))
        reject("control-cross-ref", lambda value, files: value["phaseB"].__setitem__(
            "controlRequestReference", value["phaseA"]["requestReference"]))
    return attempts


def verify(root, case_id):
    folders = {
        "IIP-MD01-a-idp-01": "keycloak-md01-native-url-v158-r7",
        "IIP-MD02-a-idp-01": "keycloak-md02-native-refresh-v158-r3",
    }
    require(case_id in folders, "unsupported Keycloak metadata URL case")
    folder = Path(root) / folders[case_id]
    summary = verify_folder(folder, True)
    require(summary["caseId"] == case_id, "formal case differs")
    rejected = tamper_tests(folder)
    expected = ({"cross-run", "admin-final", "operation-count", "relay-source", "runtime",
                 "metadata", "response-ref", "bootstrap-cross-ref", "active-action"}
                if case_id == "IIP-MD01-a-idp-01" else
                {"cross-run", "admin-final", "operation-count", "relay-source", "runtime",
                 "metadata-b", "status-600", "missing-old-refetch", "short-wait",
                 "wrong-old-variant", "control-cross-ref"})
    require(set(rejected) == expected, "tamper rejection inventory differs")
    result_path = folder / "evaluation" / "result.json"
    result = json.loads(result_path.read_text())
    cases = {case["id"]: case for requirement in result["requirements"]
             for case in requirement["cases"]}
    return result_path, cases


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folders", nargs="+", type=Path)
    parser.add_argument("--require-adoption", action="store_true")
    args = parser.parse_args()
    results = []
    for folder in args.folders:
        result = verify_folder(folder, args.require_adoption)
        result["tamperRejected"] = tamper_tests(folder)
        results.append(result)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
