#!/usr/bin/env python3
"""Prove Keycloak lacks MD06.b multi-peer and MD03.d source-scoped trust capabilities.

The recorder uses both installed native metadata-import entry points, pins their runtime
classes and provider inventory, and performs SSO for two independent Suite peers.  Each
peer requires a separate Keycloak client, and metadata documents from two nominal sources
signed by the same root key are both consumed because no source-scoped metadata-signature
trust setting exists.  Both clients are deleted and read back absent before the approved
``capability_absent`` conclusions are submitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from import_metadata_batch import api, save, BASE
from reference_flow import Client
from attribute_policy_capability_absence import (
    canonical, capture_runtime, product_token, redact_client_credentials,
)
from metadata_url_campaign import runtime_capture
from md06b_multi_peer_campaign import capture_suite, create_peer
from md03d_source_scoped_trust_campaign import generate_material

CONTAINER = "samlscope-reference-keycloak"
IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
ADMIN = "http://localhost:18180/admin/realms/samlscope"
TARGET = {
    "container": CONTAINER,
    "targetEntityId": "http://localhost:18180/realms/samlscope",
    "targetMetadata": "http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor",
    "health": "http://localhost:18180/realms/samlscope/protocol/saml/descriptor",
}
CASES = ("IIP-MD06-b-idp-01", "IIP-MD03-d-idp-01")
RELAY = "samlscope-keycloak-source-relay"
RELAY_SOURCE = REPO / "dev/keycloak/KeycloakMultiSourceRelay.java"
ALL_JARS_SCANNER = REPO / "dev/keycloak/KeycloakAllJarNativeScan.java"
JAVA_IN_TARGET = "/usr/lib/jvm/java-21-openjdk-21.0.12.1.1-1.2.el9.aarch64/bin/java"
USER = os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user")
PASSWORD = os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password")
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
SENSITIVE = {"secret", "registrationaccesstoken", "accesstoken", "password"}
SEARCH_TERMS = ("saml.metadataDescriptorUrl", "saml.useMetadataDescriptorUrl", "metadataDescriptorUrl",
                "validateCertificate", "trustAnchor", "SignatureValidation", "DynamicHTTPMetadataProvider", "MDQ")


def admin(token: str, path: str, body=None, method="GET", content_type="application/json"):
    raw = None if body is None else (body if isinstance(body, bytes) else canonical(body))
    request = urllib.request.Request(ADMIN + path, data=raw, method=method,
        headers={"Authorization": "Bearer " + token, "Content-Type": content_type})
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            value = response.read()
            return response.status, None if not value else json.loads(value)
    except urllib.error.HTTPError as error:
        raise RuntimeError("Keycloak Admin API failed %s %s" % (error.code, path.split("?", 1)[0])) from None


def lookup(token: str, entity: str):
    return admin(token, "/clients?clientId=" + urllib.parse.quote(entity, safe=""))[1]


def converter(token: str, metadata: bytes):
    return admin(token, "/client-description-converter", metadata, "POST", "application/xml")[1]


def safe_client(value: dict):
    """Remove generated client credentials before any representation is persisted."""
    cleaned, removed = redact_client_credentials(value)
    attributes = cleaned.get("attributes") or {}
    if "saml.signing.private.key" in attributes:
        attributes.pop("saml.signing.private.key")
        removed.append("/attributes/saml.signing.private.key")
    return cleaned, sorted(removed)


def client_recipe(entity: str, source_url: str) -> dict:
    return {
        "clientId": entity, "name": "SAMLscope metadata-source capability evidence",
        "protocol": "saml", "enabled": True, "redirectUris": [entity + "/sp/acs/0"],
        "fullScopeAllowed": False, "defaultClientScopes": [], "optionalClientScopes": [],
        "attributes": {
            "saml.client.signature": "true", "saml.server.signature": "true",
            "saml.assertion.signature": "true", "saml.force.post.binding": "true",
            "saml.useMetadataDescriptorUrl": "true", "saml.metadataDescriptorUrl": source_url,
            "saml_assertion_consumer_url_post": entity + "/sp/acs/0",
        },
    }


def scan_runtime_classes(folder: Path) -> dict:
    records = {}
    for jar_name in ("keycloak-services-runtime.jar", "keycloak-saml-core-public-runtime.jar"):
        jar = folder / jar_name
        values = {}
        with zipfile.ZipFile(jar) as archive:
            for entry in archive.namelist():
                if not entry.endswith(".class"):
                    continue
                raw = archive.read(entry)
                hits = [term for term in SEARCH_TERMS if term.encode() in raw]
                if hits:
                    values[entry] = hits
        records[jar_name] = values
    (folder / "metadata-source-term-inventory.json").write_bytes(canonical(records))
    return records


def scan_all_runtime_jars(folder: Path) -> dict:
    """Scan every JAR from an immutable disposable copy of the target image."""
    with tempfile.TemporaryDirectory(prefix="samlscope-keycloak-all-jars-") as temporary:
        classes = Path(temporary) / "classes"
        classes.mkdir()
        subprocess.run(["javac", "--release", "21", "-d", str(classes), str(ALL_JARS_SCANNER)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        shutil.copy2(ALL_JARS_SCANNER, folder / ALL_JARS_SCANNER.name)
        subprocess.run(["docker", "run", "--rm", "--read-only",
                        "-v", str(classes) + ":/scanner:ro",
                        "-v", str(folder) + ":/evidence:rw",
                        "--entrypoint", JAVA_IN_TARGET, IMAGE, "-cp", "/scanner",
                        "KeycloakAllJarNativeScan", "/opt/keycloak/lib/lib/main",
                        "/evidence/all-jars-native-scan.json"],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    scan = json.loads((folder / "all-jars-native-scan.json").read_text())
    jar_manifest = json.loads((folder / "keycloak-jars-start.json").read_text())
    if scan.get("jarCount") != 348 or scan.get("jars") != jar_manifest:
        raise RuntimeError("all-JAR native scan does not match captured runtime manifest")
    manifest = {
        "schema": "samlscope-keycloak-all-jars-native-scan-manifest-v1",
        "targetImageId": IMAGE,
        "scannerSourceFile": ALL_JARS_SCANNER.name,
        "scannerSourceSha256": SHA((folder / ALL_JARS_SCANNER.name).read_bytes()),
        "scanFile": "all-jars-native-scan.json",
        "scanSha256": SHA((folder / "all-jars-native-scan.json").read_bytes()),
        "jarManifestFile": "keycloak-jars-start.json",
        "jarManifestSha256": SHA((folder / "keycloak-jars-start.json").read_bytes()),
        "jarCount": 348,
        "execution": "disposable-read-only-container-from-target-image",
        "targetProductWrites": 0,
        "productRestarts": 0,
        "humanOperations": 0,
    }
    (folder / "all-jars-native-scan-manifest.json").write_bytes(canonical(manifest))
    return manifest


def start_relay(out: Path, peers: list[dict]) -> None:
    if subprocess.run(["docker", "container", "inspect", RELAY], capture_output=True).returncode == 0:
        raise RuntimeError("another Keycloak metadata source relay exists")
    classes = out / "relay-classes"
    classes.mkdir()
    subprocess.run(["javac", "--add-modules", "jdk.httpserver", "-d", str(classes), str(RELAY_SOURCE)],
                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    shutil.copy2(RELAY_SOURCE, out / RELAY_SOURCE.name)
    shutil.copy2(classes / "KeycloakMultiSourceRelay.class", out / "KeycloakMultiSourceRelay.class")
    mapping = "".join(peer["entity"] + "\t" + peer["signedMetadataFile"] + "\n" for peer in peers)
    (out / "relay-mapping.tsv").write_text(mapping)
    subprocess.run(["docker", "run", "-d", "--name", RELAY, "--network", "samlscope-reference",
                    "-v", str(classes) + ":/relay:ro", "-v", str(out) + ":/evidence:rw",
                    "--entrypoint", "/usr/bin/java", IMAGE, "--add-modules", "jdk.httpserver",
                    "-cp", "/relay", "KeycloakMultiSourceRelay", "/evidence", "relay-mapping.tsv", "8081"],
                   check=True, stdout=subprocess.PIPE, timeout=60)
    running = subprocess.check_output(["docker", "inspect", "--format", "{{.State.Running}}", RELAY],
                                      text=True, timeout=30).strip()
    if running != "true":
        raise RuntimeError("metadata source relay failed to start")


def stop_relay() -> bool:
    if subprocess.run(["docker", "container", "inspect", RELAY], capture_output=True).returncode != 0:
        return False
    subprocess.run(["docker", "stop", "-t", "10", RELAY], check=True,
                   stdout=subprocess.PIPE, timeout=30)
    subprocess.run(["docker", "rm", RELAY], check=True, stdout=subprocess.PIPE, timeout=30)
    return True


def correlate(peer: dict, out: Path) -> dict:
    before = {row["id"] for row in api("/api/runs/" + peer["run"] + "/transcript")}
    status = Client().flow(peer["entity"] + "/start/m0-roundtrip?run=" + peer["run"],
                           None, USER, PASSWORD)
    transcript = api("/api/runs/" + peer["run"] + "/transcript")
    new = [row for row in transcript if row["id"] not in before]
    requests = [row for row in new if row["direction"] == "OUTBOUND"
                and row["samlSummary"].get("type") == "AuthnRequest"]
    if len(requests) != 1:
        raise RuntimeError("ambiguous Keycloak control request")
    request = requests[0]
    responses = [row for row in new if row["direction"] == "INBOUND"
                 and row["samlSummary"].get("type") == "Response"
                 and row["samlSummary"].get("inResponseTo") == request["samlSummary"].get("id")
                 and row["samlSummary"].get("statusCode") ==
                 "urn:oasis:names:tc:SAML:2.0:status:Success"]
    if status != "recorded" or len(responses) != 1:
        raise RuntimeError("correlated Keycloak Success missing")
    response = responses[0]
    originals = []
    for row in (request, response):
        reference = row.get("decodedSamlRef")
        if not reference or Path(reference).is_absolute() or ".." in Path(reference).parts:
            raise RuntimeError("invalid transcript original")
        path = out / "decoded" / (row["id"] + ".xml")
        path.parent.mkdir(exist_ok=True)
        subprocess.run(["docker", "cp", "samlscope-reference-suite:/data/" + reference, str(path)],
                       check=True, stdout=subprocess.DEVNULL, timeout=60)
        originals.append({"id": row["id"], "file": str(path.relative_to(out)),
                          "sha256": SHA(path.read_bytes())})
    save(out / (peer["label"] + "-transcript.json"), transcript)
    record = {"run": peer["run"], "entityId": peer["entity"], "flowStatus": status,
              "requestId": request["samlSummary"]["id"], "requestTranscriptId": request["id"],
              "responseTranscriptId": response["id"], "statusCode": response["samlSummary"]["statusCode"],
              "originals": originals}
    save(out / (peer["label"] + "-correlation.json"), record)
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    token = product_token()
    before_runtime = runtime_capture(out, "start")
    full_runtime = capture_runtime(out, token)
    term_inventory = scan_runtime_classes(out)
    scan_all_runtime_jars(out)
    suite_start = capture_suite(out, "start")
    source_a = create_peer("source-a", TARGET, out)
    source_b = create_peer("source-b", TARGET, out)
    peers = [source_a, source_b]
    with tempfile.TemporaryDirectory(prefix="samlscope-keycloak-md-source-") as temporary:
        material = generate_material(out, peers, Path(temporary))
    material["temporaryPrivateKeysRemoved"] = True
    save(out / "key-material-manifest.json", material)
    converter_records = []
    for peer in peers:
        raw = (out / peer["signedMetadataFile"]).read_bytes()
        converted = converter(token, raw)
        safe, removed = safe_client(converted)
        if removed:
            raise RuntimeError("native converter unexpectedly returned credentials")
        encoded = canonical(safe)
        (out / (peer["label"] + "-converter-output.json")).write_bytes(encoded)
        converter_records.append({"source": peer["label"], "entityId": peer["entity"],
            "fixtureSha256": SHA(raw), "outputFile": peer["label"] + "-converter-output.json",
            "outputSha256": SHA(encoded), "clientId": safe.get("clientId"),
            "protocol": safe.get("protocol")})
    save(out / "converter-observations.json", converter_records)
    before = {peer["label"]: canonical(lookup(token, peer["entity"])) for peer in peers}
    for label, raw in before.items():
        (out / (label + "-client-before.json")).write_bytes(raw)
        if raw != b"[]\n":
            raise RuntimeError("refusing to overwrite an existing Keycloak client")
    operations = []
    relay_started = False
    created = []
    correlations = []
    restored = False
    try:
        start_relay(out, peers)
        relay_started = True
        operations.append({"operation": "temporary-relay-start", "completed": True})
        for peer in peers:
            source_url = ("http://" + RELAY + ":8081/entities/"
                          + urllib.parse.quote(peer["entity"], safe=""))
            recipe = client_recipe(peer["entity"], source_url)
            save(out / (peer["label"] + "-client-recipe.json"), recipe)
            status, _ = admin(token, "/clients", recipe, "POST")
            if status != 201:
                raise RuntimeError("native Keycloak client creation failed")
            operations.append({"operation": "product-client-create", "source": peer["label"],
                               "entityId": peer["entity"], "httpStatus": status})
            rows = lookup(token, peer["entity"])
            if len(rows) != 1 or not re.fullmatch(r"[0-9a-f-]{36}", rows[0]["id"]):
                raise RuntimeError("temporary client read-back ambiguous")
            created.append((peer, rows[0]["id"]))
            detail = admin(token, "/clients/" + rows[0]["id"])[1]
            safe, removed = safe_client(detail)
            if removed != ["/attributes/saml.signing.private.key", "/secret"]:
                raise RuntimeError("unexpected credential inventory")
            (out / (peer["label"] + "-client-readback.json")).write_bytes(canonical(safe))
            correlations.append(correlate(peer, out))
            operations.append({"operation": "protocol-roundtrip", "source": peer["label"],
                               "run": peer["run"], "success": True})
            after_detail = admin(token, "/clients/" + rows[0]["id"])[1]
            after_safe, after_removed = safe_client(after_detail)
            if canonical(after_safe) != canonical(safe) or after_removed != removed:
                raise RuntimeError("temporary client changed during SSO")
            (out / (peer["label"] + "-client-after-sso.json")).write_bytes(canonical(after_safe))
    finally:
        cleanup_failures = []
        for peer, internal_id in reversed(created):
            try:
                status, _ = admin(token, "/clients/" + internal_id, None, "DELETE")
                operations.append({"operation": "product-client-delete", "source": peer["label"],
                                   "entityId": peer["entity"], "httpStatus": status})
                if status != 204 or lookup(token, peer["entity"]):
                    raise RuntimeError("client deletion read-back failed")
            except Exception as error:
                cleanup_failures.append(peer["label"] + ":" + type(error).__name__ + ":" + str(error))
        relay_stopped = False
        if relay_started:
            try:
                relay_stopped = stop_relay()
                operations.append({"operation": "temporary-relay-stop", "completed": relay_stopped})
            except Exception as error:
                cleanup_failures.append("relay:" + type(error).__name__ + ":" + str(error))
        after = {peer["label"]: canonical(lookup(token, peer["entity"])) for peer in peers}
        for label, raw in after.items():
            (out / (label + "-client-final.json")).write_bytes(raw)
        restored = not cleanup_failures and relay_stopped and before == after \
            and all(raw == b"[]\n" for raw in after.values())
        save(out / "restoration.json", {"restored": restored, "failures": cleanup_failures,
             "beforeSha256": {key: SHA(value) for key, value in before.items()},
             "finalSha256": {key: SHA(value) for key, value in after.items()},
             "finalClients": {key: json.loads(value) for key, value in after.items()},
             "temporaryRelayStopped": relay_stopped})
        relay_rows = []
        if (out / "relay-requests.jsonl").is_file():
            relay_rows = [json.loads(line) for line in (out / "relay-requests.jsonl").read_text().splitlines()]
        save(out / "operation-counts.json", {"operations": operations,
             "nativeConverterCalls": len(converter_records),
             "productConfigurationWrites": sum(row["operation"] == "product-client-create" for row in operations),
             "restorationWrites": sum(row["operation"] == "product-client-delete" for row in operations),
             "protocolRoundTrips": sum(row["operation"] == "protocol-roundtrip" for row in operations),
             "metadataFetches": len(relay_rows), "productRestarts": 0, "humanOperations": 0,
             "restored": restored})
        if not restored:
            raise RuntimeError("Keycloak client restoration failed")
    runtime_capture(out, "end")
    suite_final = capture_suite(out, "final")
    receipt = {
        "schema": "samlscope-keycloak-metadata-source-capability-absence-v1",
        "product": "keycloak", "productVersion": "26.7.2", "targetEntityId": TARGET["targetEntityId"],
        "cases": list(CASES), "primaryRun": source_a["run"], "secondaryRun": source_b["run"],
        "sources": peers, "correlations": correlations,
        "keyMaterialFile": "key-material-manifest.json",
        "converterObservationsFile": "converter-observations.json",
        "runtimeCapabilityFile": "runtime-capability.json",
        "runtimeTermInventoryFile": "metadata-source-term-inventory.json",
        "runtimeTermInventorySha256": SHA((out / "metadata-source-term-inventory.json").read_bytes()),
        "suiteRuntime": suite_start,
        "restorationFile": "restoration.json", "operationCountsFile": "operation-counts.json",
        "controls": {
            "normal": "two-distinct-peer-correlated-successes-through-native-metadata-url",
            "md06bNegative": "second-peer-requires-second-client-create",
            "md03dNegative": "source-b-signed-by-source-a-key-is-accepted-with-no-source-trust-setting",
        },
    }
    (out / "receipt.json").write_bytes(canonical(receipt))
    receipt_sha = SHA((out / "receipt.json").read_bytes())
    note = ("Machine-verified Keycloak 26.7.2 metadata-source capability absence; receipt sha256="
            + receipt_sha + "; native imports require a client per entity and expose no source-scoped trust anchor")
    save(out / "tests-start.json", api("/api/runs/" + source_a["run"] + "/tests/start", {}))
    for case in CASES:
        save(out / (case + "-configure.json"), api("/api/runs/" + source_a["run"] + "/cases/"
            + case + "/configure", {"value": "capability_absent", "note": note}))
    save(out / "result.json", api("/api/runs/" + source_a["run"] + "/result.json"))
    print(source_a["run"], source_b["run"], "restored", restored, "receipt", receipt_sha,
          "term classes", sum(len(value) for value in term_inventory.values()))


if __name__ == "__main__":
    main()
