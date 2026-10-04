#!/usr/bin/env python3
"""Capture Keycloak's native metadata-URL acquisition and A-to-B refresh behavior.

This reference-only driver creates one temporary native SAML client, points its stable metadata
URL at an evidence-recording relay, runs the Suite's signed controls, and deletes the client in a
``finally`` block.  It never assigns a product verdict.  Admin credentials, login credentials, and
cookies remain in memory and are not included in any evidence file.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
from import_metadata_batch import api, save, BASE  # noqa: E402
from reference_flow import Client  # noqa: E402
from capture_run_originals import capture as capture_originals  # noqa: E402

ADMIN = "http://localhost:18180/admin/realms/samlscope"
TOKEN = "http://localhost:18180/realms/master/protocol/openid-connect/token"
TARGET = "http://localhost:18180/realms/samlscope/protocol/saml"
TARGET_ENTITY = "http://localhost:18180/realms/samlscope"
TARGET_METADATA = "http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor"
CONTAINER = "samlscope-reference-keycloak"
SUITE = "samlscope-reference-suite"
RELAY = "samlscope-keycloak-metadata-relay"
NETWORK = "samlscope-reference"
IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
PLAN_RE = re.compile(r"plan_[0-9A-HJKMNP-TV-Z]{26}")
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
MDQ_SCHEMA = "samlscope-keycloak-native-mdq-v1"
REFRESH_SCHEMA = "samlscope-keycloak-native-metadata-refresh-v1"
MDQ_ADAPTER = "keycloak-native-mdq-v1"
REFRESH_ADAPTER = "keycloak-native-metadata-url-refresh-v1"
VARIANTS = ("entity-root", "no-valid-until", "keyvalue-only")
USER = os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user")
PASSWORD = os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password")
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def admin_token():
    raw = urllib.parse.urlencode({
        "client_id": "admin-cli",
        "username": os.environ.get("KEYCLOAK_ADMIN_USERNAME", "admin"),
        "password": os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"),
        "grant_type": "password",
    }).encode()
    with urllib.request.urlopen(urllib.request.Request(TOKEN, data=raw), timeout=30) as response:
        return json.load(response)["access_token"]


def admin(access_token, path, body=None, method="GET"):
    request = urllib.request.Request(
        ADMIN + path,
        data=None if body is None else canonical(body),
        method=method,
        headers={"Authorization": "Bearer " + access_token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return None if not raw else json.loads(raw)
    except urllib.error.HTTPError as error:
        raise RuntimeError("Keycloak Admin API failed: %s %s" % (error.code, path.split("?", 1)[0])) from None


def lookup(access_token, entity):
    return admin(access_token, "/clients?clientId=" + urllib.parse.quote(entity, safe=""))


def detail(access_token, entity):
    rows = lookup(access_token, entity)
    if len(rows) != 1:
        raise RuntimeError("Expected exactly one temporary client")
    value = admin(access_token, "/clients/" + rows[0]["id"])
    if value.get("id") != rows[0].get("id") or value.get("clientId") != entity:
        raise RuntimeError("Temporary client identity changed")
    return value


def client_recipe(entity, relay, run=None):
    redirects = [entity + "/sp/acs/0"]
    if run is not None:
        redirects.extend(entity + "/sp/acs/0?mdv=" + variant + "&run=" + run for variant in VARIANTS)
    return {
        "clientId": entity,
        "name": "SAMLscope native metadata URL evidence",
        "protocol": "saml",
        "enabled": True,
        "redirectUris": redirects,
        "fullScopeAllowed": False,
        "defaultClientScopes": [],
        "optionalClientScopes": [],
        "attributes": {
            "saml.client.signature": "true",
            "saml.server.signature": "true",
            "saml.assertion.signature": "true",
            "saml.force.post.binding": "true",
            "saml.useMetadataDescriptorUrl": "true",
            "saml.metadataDescriptorUrl": relay,
            "saml_assertion_consumer_url_post": entity + "/sp/acs/0",
        },
    }


def configured_projection(value):
    """Persist only the read-back fields needed by the oracle, never generated credentials."""
    attributes = value.get("attributes") or {}
    safe_attribute_names = (
        "saml.client.signature", "saml.server.signature", "saml.assertion.signature",
        "saml.force.post.binding", "saml.useMetadataDescriptorUrl",
        "saml.metadataDescriptorUrl", "saml_assertion_consumer_url_post",
    )
    redacted = []
    if "secret" in value:
        redacted.append("secret")
    for name in ("saml.signing.certificate", "saml.signing.private.key"):
        if name in attributes:
            redacted.append("attributes." + name)
    return {
        "schema": "samlscope-keycloak-client-readback-projection-v1",
        "client": {
            "id": value.get("id"), "clientId": value.get("clientId"),
            "protocol": value.get("protocol"), "enabled": value.get("enabled"),
            "redirectUris": value.get("redirectUris"),
            "attributes": {name: attributes.get(name) for name in safe_attribute_names},
        },
        "observedTopLevelFields": sorted(value),
        "observedAttributeFields": sorted(attributes),
        "redactedCredentialFields": sorted(redacted),
    }


def create_run(output, mode, wait):
    created_plan = api("/api/plans", {
        "name": "Keycloak native metadata URL " + mode,
        "profile": "metadata_idp",
        "targetKind": "IDP",
        "targetEntityId": TARGET_ENTITY,
        "metadataSourceKind": "URL",
        "metadataSourceLocation": TARGET_METADATA,
        "suiteMetadataDelivery": "HTTP_URL",
        "declaredFeatures": {},
        "parameters": {
            "clockSkewToleranceSeconds": 180,
            "metadataRefreshWaitSeconds": wait,
            "testUserHint": USER,
            "requestSigningMode": "REQUIRED",
        },
        "interaction": {"allowBrowserSteps": True, "allowAttestation": False, "preset": "quick"},
        "authorizedTarget": True,
    })
    save(output / "plan.json", created_plan)
    plan = created_plan["plan"]["plan"]["id"]
    if not PLAN_RE.fullmatch(plan):
        raise RuntimeError("Invalid Plan identifier")
    created = api("/api/plans/" + plan + "/runs", {})
    save(output / "created.json", created)
    run = created["run"]["id"]
    if not RUN_RE.fullmatch(run):
        raise RuntimeError("Invalid Run identifier")
    preflight = api("/api/runs/" + run + "/preflight", {})
    save(output / "preflight.json", preflight)
    if any(check.get("status") == "FAIL" for check in preflight.get("checks", [])):
        raise RuntimeError("Suite preflight failed before product configuration")
    return plan, run, BASE + "/p/" + plan


def jar_manifest():
    command = (
        "for f in /opt/keycloak/lib/lib/main/*.jar; do "
        "h=$(sha256sum \"$f\" | cut -d' ' -f1); s=$(stat -c %s \"$f\"); "
        "printf '%s\\t%s\\t%s\\n' \"$f\" \"$h\" \"$s\"; done"
    )
    raw = subprocess.check_output(["docker", "exec", CONTAINER, "sh", "-c", command], text=True, timeout=180)
    rows = []
    for line in raw.splitlines():
        path, digest, size = line.split("\t")
        if not re.fullmatch(r"/opt/keycloak/lib/lib/main/[^/]+\.jar", path):
            raise RuntimeError("Unexpected Keycloak JAR path")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError("Invalid JAR digest")
        rows.append({"path": path, "sha256": digest, "size": int(size)})
    rows.sort(key=lambda value: value["path"])
    if len(rows) != 348 or len({row["path"] for row in rows}) != 348:
        raise RuntimeError("Keycloak JAR inventory is incomplete")
    return rows


def runtime_capture(output, phase):
    inspected = json.loads(subprocess.check_output(
        ["docker", "inspect", CONTAINER], timeout=30))[0]
    if inspected["Image"] != IMAGE or not inspected["State"]["Running"]:
        raise RuntimeError("Unexpected Keycloak runtime")
    version_output = subprocess.check_output(
        ["docker", "exec", CONTAINER, "/opt/keycloak/bin/kc.sh", "--version"],
        text=True, timeout=60).strip()
    version = version_output.splitlines()[0]
    if version != "Keycloak 26.7.2":
        raise RuntimeError("Unexpected Keycloak version")
    jars = canonical(jar_manifest()) + b"\n"
    jars_path = output / ("keycloak-jars-" + phase + ".json")
    jars_path.write_bytes(jars)
    config = subprocess.check_output(
        ["docker", "exec", CONTAINER, "cat", "/opt/keycloak/conf/keycloak.conf"], timeout=30)
    (output / ("keycloak-config-" + phase + ".txt")).write_bytes(config)
    by_name = {Path(row["path"]).name: row["sha256"] for row in json.loads(jars)}
    providers = {
        "schema": "samlscope-keycloak-metadata-provider-inventory-v1",
        "productVersion": "26.7.2",
        "publicKeyStorageProvider": "infinispan",
        "httpClientProvider": "default",
        "minTimeBetweenRequestsSeconds": 10,
        "maxCacheTimeSeconds": 86400,
        "configurationBasis": "factory-defaults-no-runtime-override",
        "servicesJarSha256": by_name["org.keycloak.keycloak-services-26.7.2.jar"],
        "storageJarSha256": by_name["org.keycloak.keycloak-model-infinispan-26.7.2.jar"],
    }
    providers_raw = canonical(providers) + b"\n"
    (output / ("provider-inventory-" + phase + ".json")).write_bytes(providers_raw)
    summary = {
        "schema": "samlscope-keycloak-metadata-url-runtime-v1",
        "phase": phase,
        "product": "keycloak",
        "productVersion": "26.7.2",
        "containerId": inspected["Id"],
        "imageId": inspected["Image"],
        "configuredImage": inspected["Config"]["Image"],
        "startedAt": inspected["State"]["StartedAt"],
        "runningAtCapture": inspected["State"]["Running"],
        "environmentKeys": sorted(value.split("=", 1)[0] for value in inspected["Config"].get("Env", [])),
        "jarManifestSha256": SHA(jars),
        "providerInventorySha256": SHA(providers_raw),
        "keycloakConfigSha256": SHA(config),
    }
    write_json(output / ("target-runtime-" + phase + ".json"), summary)


def suite_capture(output):
    inspected = json.loads(subprocess.check_output(["docker", "inspect", SUITE], timeout=30))[0]
    jars = {}
    for name in ("core", "runner", "saml"):
        source = "/opt/samlscope/lib/%s-0.1.0.jar" % name
        destination = output / ("suite-%s-0.1.0.jar" % name)
        subprocess.run(["docker", "cp", SUITE + ":" + source, str(destination)],
                       check=True, capture_output=True, timeout=60)
        jars[name] = {"path": source, "file": destination.name, "sha256": SHA(destination.read_bytes())}
    write_json(output / "suite-runtime.json", {
        "schema": "samlscope-keycloak-metadata-url-suite-runtime-v1",
        "containerId": inspected["Id"],
        "imageId": inspected["Image"],
        "configuredImage": inspected["Config"]["Image"],
        "startedAt": inspected["State"]["StartedAt"],
        "runningAtCapture": inspected["State"]["Running"],
        "jars": jars,
    })


def write_properties(output, entity, source, mode, frozen=None):
    lines = ["entityId=" + entity, "sourceUrl=" + source, "mode=" + mode]
    if frozen is not None:
        lines.append("frozenFile=" + frozen)
    raw = ("\n".join(lines) + "\n").encode()
    temporary = output / "relay.properties.next"
    temporary.write_bytes(raw)
    temporary.replace(output / "relay.properties")
    return raw


def start_relay(output):
    source = REPO / "dev/keycloak/KeycloakMetadataUrlRelay.java"
    shutil.copy2(source, output / source.name)
    classes = output / "relay-classes"
    classes.mkdir()
    subprocess.run(["javac", "--add-modules", "jdk.httpserver", "-d", str(classes), str(source)],
                   check=True, timeout=60)
    shutil.copy2(classes / "KeycloakMetadataUrlRelay.class", output / "KeycloakMetadataUrlRelay.class")
    existing = subprocess.run(["docker", "container", "inspect", RELAY], capture_output=True)
    if existing.returncode == 0:
        raise RuntimeError("Another metadata relay container exists")
    subprocess.run([
        "docker", "run", "-d", "--name", RELAY, "--network", NETWORK,
        "-v", str(classes) + ":/relay:ro", "-v", str(output) + ":/evidence:rw",
        "--entrypoint", "/usr/bin/java", IMAGE, "--add-modules", "jdk.httpserver",
        "-cp", "/relay", "KeycloakMetadataUrlRelay", "/evidence", "8081",
    ], check=True, capture_output=True, timeout=60)
    time.sleep(1)
    running = subprocess.check_output(
        ["docker", "inspect", "--format", "{{.State.Running}}", RELAY], text=True, timeout=30).strip()
    if running != "true":
        raise RuntimeError("Metadata relay did not remain running")


def stop_relay():
    if subprocess.run(["docker", "container", "inspect", RELAY], capture_output=True).returncode != 0:
        return False
    subprocess.run(["docker", "stop", "-t", "10", RELAY], check=True, capture_output=True, timeout=30)
    subprocess.run(["docker", "rm", RELAY], check=True, capture_output=True, timeout=30)
    return True


class ObservedClient(Client):
    def __init__(self, output, label):
        super().__init__()
        self.output = output
        self.label = label
        self.records = []

    def request(self, url, fields=None):
        pending = None
        if url == TARGET and fields and "SAMLRequest" in fields:
            raw = base64.b64decode(fields["SAMLRequest"], validate=True)
            root = ET.fromstring(raw)
            pending = {"requestId": root.get("ID"), "requestSha256": SHA(raw), "requestUrl": url}
        final, page, status = super().request(url, fields)
        if pending is not None:
            safe = urllib.parse.urlsplit(final)
            pending.update({
                "responseUrl": urllib.parse.urlunsplit((safe.scheme, safe.netloc, safe.path, "", "")),
                "responseStatus": status,
                "responseBodySha256": SHA(page.encode()),
                "observedAt": utcnow(),
                "samlResponseFormPresent": bool(re.search(r'name=["\']SAMLResponse["\']', page, re.I)),
                "deliveryState": "HTTP_RESPONSE",
                "productVerdictAssigned": False,
            })
            self.records.append(pending)
            if status >= 400 and not pending["samlResponseFormPresent"]:
                (self.output / (self.label + "-response.html")).write_bytes(page.encode())
                write_json(self.output / (self.label + ".json"), pending)
        return final, page, status


def relay_records(output):
    path = output / "relay-requests.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def arm(run, output, variant, suffix):
    state = api("/api/runs/" + run + "/metadata-lab")
    if state["selectedVariant"] != variant:
        raise RuntimeError("Unexpected polling variant")
    with urllib.request.urlopen(state["automaticStartUrl"], timeout=30) as response:
        if response.status != 202:
            raise RuntimeError("Fixture dispatch did not wait for retrieval")
        response.read()
    with urllib.request.urlopen(state["metadataUrl"], timeout=30) as response:
        (output / ("operator-fixture-" + suffix + ".xml")).write_bytes(response.read())
    return state


def transcript(run):
    values = api("/api/runs/" + run + "/transcript")
    if any(value.get("runId") != run for value in values):
        raise RuntimeError("Mixed Run transcript")
    if len({value["id"] for value in values}) != len(values):
        raise RuntimeError("Duplicate transcript ID")
    return values


def new_request(entries, previous, variant=None, control=None):
    values = [entry for entry in entries if entry["id"] not in previous
              and entry["direction"] == "OUTBOUND"
              and entry.get("samlSummary", {}).get("type") == "AuthnRequest"]
    if variant is not None:
        values = [entry for entry in values if entry["samlSummary"].get("variant") == variant]
    if control is not None:
        values = [entry for entry in values
                  if entry["samlSummary"].get("metadataSignatureControl") == control]
    if len(values) != 1:
        raise RuntimeError("Issued AuthnRequest is ambiguous")
    return values[0]


def response_for(entries, request, metadata_probe):
    request_id = request["samlSummary"]["id"]
    values = [entry for entry in entries if entry["direction"] == "INBOUND"
              and entry.get("samlSummary", {}).get("type") == "Response"
              and entry["samlSummary"].get("inResponseTo") == request_id
              and entry["samlSummary"].get("statusCode") == SUCCESS
              and entry["samlSummary"].get(
                  "metadataProbeAccepted" if metadata_probe else "normalFlowAccepted") is True]
    if len(values) != 1:
        raise RuntimeError("Correlated Success is unavailable")
    return values[0]


def target_fetch(entries, request, response, variant):
    fetches = [entry for entry in entries if entry["direction"] == "INBOUND"
               and entry.get("samlSummary", {}).get("type") == "MetadataFetch"
               and entry["samlSummary"].get("variant") == variant
               and entry["samlSummary"].get("feed") == "live"
               and float(request["timestamp"]) <= float(entry["timestamp"]) < float(response["timestamp"])]
    if len(fetches) != 1:
        raise RuntimeError("Target-triggered Suite metadata fetch is ambiguous")
    fetch = fetches[0]
    prepared = [entry for entry in entries if entry["direction"] == "OUTBOUND"
                and entry.get("samlSummary", {}).get("type") == "MetadataPrepared"
                and entry["samlSummary"].get("fetchTranscriptId") == fetch["id"]]
    if len(prepared) != 1:
        raise RuntimeError("Target-triggered prepared metadata is ambiguous")
    return fetch, prepared[0]


def polling_flow(run, output, variant, suffix, invalid_control=False):
    state = api("/api/runs/" + run + "/metadata-lab")
    start = state["automaticStartUrl"]
    control = None
    if invalid_control:
        before = {entry["id"] for entry in transcript(run)}
        client = ObservedClient(output, "signature-control")
        result = client.flow(start + "&signatureControl=invalid", None, USER, PASSWORD)
        entries = transcript(run)
        control = new_request(entries, before, variant, "invalid")
        if result.startswith("recorded") or any(
                entry.get("samlSummary", {}).get("inResponseTo") == control["samlSummary"]["id"]
                for entry in entries if entry["direction"] == "INBOUND"):
            raise RuntimeError("Invalid signature produced a correlated SAML response")
        if not (output / "signature-control.json").is_file():
            raise RuntimeError("Invalid signature lacks target-owned terminal HTTP evidence")
        if api("/api/runs/" + run + "/metadata-lab")["campaignIndex"] != state["campaignIndex"]:
            raise RuntimeError("Invalid signature advanced the campaign")
    before = {entry["id"] for entry in transcript(run)}
    result = Client().flow(start, None, USER, PASSWORD)
    entries = transcript(run)
    request = new_request(entries, before, variant, "valid")
    response = response_for(entries, request, True)
    if api("/api/runs/" + run + "/metadata-lab")["campaignIndex"] != state["campaignIndex"] + 1:
        raise RuntimeError("Valid polling request did not complete")
    fetch, prepared = target_fetch(entries, control or request, response, variant)
    return {
        "variant": variant,
        "fetchReference": fetch["id"],
        "preparedReference": prepared["id"],
        "requestReference": request["id"],
        "responseReference": response["id"],
        **({} if control is None else {"controlRequestReference": control["id"]}),
    }, prepared, request, response, control


def normal_flow(run, entity):
    before = {entry["id"] for entry in transcript(run)}
    result = Client().flow(entity + "/start/m0-roundtrip?run=" + run, None, USER, PASSWORD)
    entries = transcript(run)
    request = new_request(entries, before)
    response = response_for(entries, request, False)
    if result != "recorded":
        raise RuntimeError("Normal SSO control did not complete")
    return request, response


def signed_active_control(run):
    state = api("/api/runs/" + run + "/active-probe")
    if state.get("state") != "READY" or state.get("caseId") != "IIP-ALG01-a-idp-01":
        raise RuntimeError("Expected ALG01 valid signed-request control")
    before = {entry["id"] for entry in transcript(run)}
    Client().flow(state["startUrl"], None, USER, PASSWORD)
    entries = transcript(run)
    request = new_request(entries, before)
    summary = request.get("samlSummary", {})
    if not (summary.get("active_probe") is True and summary.get("fixture_id") == "valid"
            and summary.get("scenario_case_id") == "IIP-ALG01-a-idp-01"
            and summary.get("action_id") == request.get("correlationId")):
        raise RuntimeError("Signed active-probe request identity differs")
    # Active-probe summaries intentionally bind the deterministic action ID, not the raw SAML
    # request ID.  The persisted originals are correlated by the reader/verifier after capture;
    # here require one and only one new normal Success from this browser action.
    responses = [entry for entry in entries if entry["id"] not in before
                 and entry["direction"] == "INBOUND"
                 and entry.get("samlSummary", {}).get("type") == "Response"
                 and entry["samlSummary"].get("statusCode") == SUCCESS
                 and entry["samlSummary"].get("activeProbeAccepted") is True
                 and float(entry["timestamp"]) > float(request["timestamp"])]
    if len(responses) != 1:
        raise RuntimeError("Signed active-probe Success is ambiguous")
    return request, responses[0]


def old_key_flow(run, output, state):
    before = {entry["id"] for entry in transcript(run)}
    client = ObservedClient(output, "old-key-control")
    result = client.flow(state["automaticStartUrl"], None, USER, PASSWORD)
    entries = transcript(run)
    request = new_request(entries, before, "keyvalue-only", "valid")
    if result == "recorded" or any(
            entry.get("samlSummary", {}).get("inResponseTo") == request["samlSummary"]["id"]
            for entry in entries if entry["direction"] == "INBOUND"):
        raise RuntimeError("Old signing key was accepted after refresh")
    if not (output / "old-key-control.json").is_file():
        raise RuntimeError("Old signing key lacks target-owned terminal HTTP evidence")
    return request


def decoded_body(output, entry):
    path = output / "decoded" / (entry["id"] + ".xml")
    if not path.is_file():
        raise RuntimeError("Decoded transcript original is unavailable")
    raw = path.read_bytes()
    if SHA(raw) != entry.get("samlSummary", {}).get("metadataSha256"):
        raise RuntimeError("Prepared metadata hash differs")
    return raw


def hash_fields(output, manifest, names):
    for field, name in names.items():
        manifest[field] = SHA((output / name).read_bytes())


def finish_evidence(output, run):
    entries = transcript(run)
    write_json(output / "transcript.json", entries)
    capture_originals(output, run, entries)
    for endpoint, filename in (("result.json", "result-before.json"),
                               ("protocol-evidence", "protocol-evidence.json")):
        try:
            write_json(output / filename, api("/api/runs/" + run + "/" + endpoint))
        except Exception as error:
            write_json(output / (filename + ".unavailable"), {"reason": type(error).__name__})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("mdq", "refresh"), required=True)
    parser.add_argument("--refresh-wait-seconds", type=int, default=12)
    args = parser.parse_args()
    if args.refresh_wait_seconds < 10 or args.refresh_wait_seconds > 60:
        parser.error("refresh wait must be 10..60 seconds")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    runtime_capture(output, "start")
    suite_capture(output)
    plan, run, entity = create_run(output, args.mode, args.refresh_wait_seconds)
    relay_url = "http://" + RELAY + ":8081/entities/" + urllib.parse.quote(entity, safe="")
    source = ("http://samlscope-reference-suite:8080/mdq/" + urllib.parse.quote(entity, safe="")
              if args.mode == "mdq" else
              "http://samlscope-reference-suite:8080/p/%s/metadata/live?run=%s" % (plan, run))
    original = canonical(lookup(admin_token(), entity)) + b"\n"
    if json.loads(original) != []:
        raise RuntimeError("Refusing to replace an existing Keycloak client")
    (output / "admin-before.json").write_bytes(original)
    configuration_created = False
    configured_full = None
    owned = None
    relay_started = False
    restored = False
    counts = {
        "restored": False, "productConfigurationWrites": 0, "restorationWrites": 0,
        "protocolRoundTrips": 0, "metadataFetches": 0,
        "productRestarts": 0, "humanOperations": 0,
    }
    manifest = None
    try:
        write_properties(output, entity, source, "fetch")
        start_relay(output)
        relay_started = True
        access = admin_token()
        admin(access, "/clients", client_recipe(
            entity, relay_url, run if args.mode == "refresh" else None), "POST")
        configuration_created = True
        counts["productConfigurationWrites"] += 1
        configured_full = detail(access, entity)
        owned = configured_full["id"]
        (output / "admin-configured.json").write_bytes(
            canonical(configured_projection(configured_full)) + b"\n")

        tests_started = False
        if args.mode == "mdq":
            # The Suite requires one completed login before profile tests can start.  The
            # bootstrap is also the target-triggered native MDQ fetch.  The subsequent signed
            # active probe must then succeed with the signing key from that exact MDQ original.
            bootstrap_request, bootstrap_response = normal_flow(run, entity)
            counts["protocolRoundTrips"] += 1
            records = relay_records(output)
            if len(records) != 1:
                raise RuntimeError("Native MDQ bootstrap fetch count differs")
            save(output / "tests-start.json", api("/api/runs/" + run + "/tests/start", {}))
            tests_started = True
            request, response = signed_active_control(run)
            counts["protocolRoundTrips"] += 1
            records = relay_records(output)
            if len(records) != 1:
                raise RuntimeError("Native MDQ fetch count differs")
            manifest = {
                "schema": MDQ_SCHEMA, "adapter": MDQ_ADAPTER, "runId": run,
                "entityId": entity, "relayUrl": relay_url, "sourceUrl": source,
                "metadataSha256": records[0]["servedSha256"],
                "bootstrap": {"requestReference": bootstrap_request["id"],
                              "responseReference": bootstrap_response["id"],
                              "relaySequence": records[0]["sequence"]},
                "exchange": {"requestReference": request["id"], "responseReference": response["id"]},
            }
            shutil.copy2(output / records[0]["servedFile"], output / "metadata-mdq.xml")
            counts["metadataFetches"] = 1
        else:
            campaign = api("/api/runs/" + run + "/metadata-lab/automatic-polling", {
                "variants": list(VARIANTS), "pollingDelaySeconds": args.refresh_wait_seconds})
            save(output / "campaign.json", campaign)
            state_a = arm(run, output, "entity-root", "a")
            before_records = len(relay_records(output))
            phase_a, prepared_a, request_a, response_a, _ = polling_flow(
                run, output, "entity-root", "a")
            records = relay_records(output)
            if len(records) != before_records + 1:
                raise RuntimeError("A phase did not perform exactly one native fetch")
            phase_a["relaySequence"] = records[-1]["sequence"]
            counts["protocolRoundTrips"] += 1
            time.sleep(max(0, float(response_a["timestamp"]) + args.refresh_wait_seconds + 0.75 - time.time()))

            arm(run, output, "no-valid-until", "b")
            before_records = len(relay_records(output))
            phase_b, prepared_b, request_b, response_b, control_b = polling_flow(
                run, output, "no-valid-until", "b", invalid_control=True)
            records = relay_records(output)
            if len(records) != before_records + 1:
                raise RuntimeError("B phase did not perform exactly one native fetch")
            phase_b["relaySequence"] = records[-1]["sequence"]
            counts["protocolRoundTrips"] += 2
            time.sleep(max(0, float(response_b["timestamp"]) + args.refresh_wait_seconds + 0.75 - time.time()))

            state_old = arm(run, output, "keyvalue-only", "old")
            # Freeze the stable native URL at B.  An old-A request can only be rejected after a
            # fresh target GET; a cache-only failure or a Suite operator fetch is insufficient.
            records = relay_records(output)
            b_file = records[-1]["servedFile"]
            write_properties(output, entity, source, "frozen", b_file)
            before_records = len(records)
            old_request = old_key_flow(run, output, state_old)
            records = relay_records(output)
            if len(records) != before_records + 1:
                raise RuntimeError("Old-key control did not perform exactly one native refetch")
            counts["protocolRoundTrips"] += 1
            counts["metadataFetches"] = len(records)

            # Capture originals before constructing the manifest so its metadata bytes are bound
            # to both the target relay and the Suite's MetadataPrepared transcript entries.
            finish_evidence(output, run)
            metadata_a = decoded_body(output, prepared_a)
            metadata_b = decoded_body(output, prepared_b)
            (output / "metadata-a.xml").write_bytes(metadata_a)
            (output / "metadata-b.xml").write_bytes(metadata_b)
            if SHA(metadata_a) != records[0]["servedSha256"] or SHA(metadata_b) != records[1]["servedSha256"]:
                raise RuntimeError("Relay and Suite metadata originals differ")
            manifest = {
                "schema": REFRESH_SCHEMA, "adapter": REFRESH_ADAPTER, "runId": run,
                "entityId": entity, "relayUrl": relay_url, "sourceUrl": source,
                "refreshWaitSeconds": args.refresh_wait_seconds, "minimumRefreshSeconds": 10,
                "variantA": "entity-root", "variantB": "no-valid-until",
                "oldKeyVariant": "keyvalue-only",
                "metadataASha256": SHA(metadata_a), "metadataBSha256": SHA(metadata_b),
                "phaseA": phase_a, "phaseB": phase_b,
                "oldKeyControl": {"variant": "keyvalue-only",
                                  "requestReference": old_request["id"],
                                  "relaySequence": records[-1]["sequence"]},
            }
            if phase_b.pop("controlRequestReference") is None:
                raise RuntimeError("B phase control reference missing")
            phase_b["controlRequestReference"] = control_b["id"]
            try:
                with urllib.request.urlopen(urllib.request.Request(
                        api("/api/runs/" + run + "/metadata-lab")["automaticContinueUrl"], data=b""),
                        timeout=30) as response:
                    response.read()
            except Exception:
                pass
        if not tests_started:
            save(output / "tests-start.json", api("/api/runs/" + run + "/tests/start", {}))
    finally:
        try:
            access = admin_token()
            current = lookup(access, entity)
            if configuration_created:
                if len(current) != 1 or current[0].get("id") != owned:
                    raise RuntimeError("Concurrent temporary client replacement detected")
                current_detail = admin(access, "/clients/" + owned)
                if canonical(current_detail) != canonical(configured_full):
                    raise RuntimeError("Concurrent temporary client edit detected")
                admin(access, "/clients/" + owned, method="DELETE")
                counts["productConfigurationWrites"] += 1
                counts["restorationWrites"] += 1
            final = canonical(lookup(access, entity)) + b"\n"
            (output / "admin-final.json").write_bytes(final)
            restored = final == original
            counts["restored"] = restored
        finally:
            if relay_started:
                counts["temporaryRelayStopped"] = stop_relay()
            runtime_capture(output, "end")
            write_json(output / "operation-counts.json", counts)
        if not restored:
            raise RuntimeError("Keycloak temporary client restoration failed")

    if args.mode == "mdq":
        finish_evidence(output, run)
    if manifest is None:
        raise RuntimeError("Campaign did not produce a receipt manifest")
    common = {
        "adminBeforeSha256": "admin-before.json",
        "adminConfiguredSha256": "admin-configured.json",
        "adminFinalSha256": "admin-final.json",
        "operationCountsSha256": "operation-counts.json",
        "relaySourceSha256": "KeycloakMetadataUrlRelay.java",
        "relayRequestsSha256": "relay-requests.jsonl",
        "targetRuntimeStartSha256": "target-runtime-start.json",
        "targetRuntimeEndSha256": "target-runtime-end.json",
    }
    hash_fields(output, manifest, common)
    if args.mode == "refresh":
        hash_fields(output, manifest, {
            "signatureControlSha256": "signature-control.json",
            "signatureControlResponseSha256": "signature-control-response.html",
            "oldKeyControlSha256": "old-key-control.json",
            "oldKeyControlResponseSha256": "old-key-control-response.html",
        })
    write_json(output / "manifest.json", manifest)
    write_json(output / "campaign-summary.json", {
        "runId": run, "mode": args.mode, "restored": restored,
        "manifestSha256": SHA((output / "manifest.json").read_bytes()),
        "operationCounts": counts, "productVerdictAssigned": False,
    })
    print(run, args.mode, "captured and restored")


if __name__ == "__main__":
    main()
