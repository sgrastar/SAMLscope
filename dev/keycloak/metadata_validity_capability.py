#!/usr/bin/env python3
"""Prove Keycloak's installed SAML metadata paths lack MD04.a/b/c rejection capability.

The campaign uses one temporary SAML client with Keycloak's native metadata descriptor URL.
For every approved validity fixture it requires a product-native metadata GET, an invalid signed
request rejection, and a Run-correlated Success response for the valid signed request.  The exact
same metadata original is also submitted to Keycloak's native client-description converter.

The resulting capability-absence conclusion is only submitted after the running product JARs,
installed providers, configuration, all originals, and exact restoration have been retained and
locally verified.  Credentials and cookies remain in memory and are never persisted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))

from import_metadata_batch import api, save  # noqa: E402
from metadata_url_campaign import (  # noqa: E402
    ADMIN, CONTAINER, IMAGE, RELAY,
    TARGET_ENTITY, TARGET_METADATA, admin, admin_token, arm, canonical,
    client_recipe, create_run, detail, finish_evidence, hash_fields, lookup,
    polling_flow, relay_records, runtime_capture, start_relay, stop_relay,
    suite_capture, transcript, utcnow, write_json, write_properties,
)

SCHEMA = "samlscope-keycloak-metadata-validity-capability-v1"
ADAPTER = "keycloak-native-metadata-validity-capability-v1"
CASES = ("IIP-MD04-a-idp-01", "IIP-MD04-b-idp-01", "IIP-MD04-c-idp-01")
VARIANTS = ("control", "no-valid-until", "expired", "valid-until-near", "valid-until-far")
WAIT_SECONDS = 12
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
SENSITIVE = {"secret", "registrationaccesstoken", "accesstoken", "password"}

JARS = {
    "services": "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar",
    "storage": "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-model-infinispan-26.7.2.jar",
    "saml": "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-saml-core-26.7.2.jar",
    "saml-public": "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-saml-core-public-26.7.2.jar",
    "server-spi-private": "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-server-spi-private-26.7.2.jar",
}
CLASSES = {
    "abstract-metadata-loader": ("services", "org.keycloak.protocol.saml.SamlAbstractMetadataPublicKeyLoader"),
    "metadata-loader": ("services", "org.keycloak.protocol.saml.SamlMetadataPublicKeyLoader"),
    "protocol-utils": ("services", "org.keycloak.protocol.saml.SamlProtocolUtils"),
    "saml-client": ("services", "org.keycloak.protocol.saml.SamlClient"),
    "saml-config": ("services", "org.keycloak.protocol.saml.SamlConfigAttributes"),
    "metadata-converter": ("services", "org.keycloak.protocol.saml.EntityDescriptorDescriptionConverter"),
    "registration-provider": (
        "services", "org.keycloak.protocol.saml.clientregistration.EntityDescriptorClientRegistrationProvider"),
    "key-storage": ("storage", "org.keycloak.keys.infinispan.InfinispanPublicKeyStorageProvider"),
    "key-storage-factory": (
        "storage", "org.keycloak.keys.infinispan.InfinispanPublicKeyStorageProviderFactory"),
    "entity-descriptor": ("saml-public", "org.keycloak.dom.saml.v2.metadata.EntityDescriptorType"),
    "entities-descriptor": ("saml-public", "org.keycloak.dom.saml.v2.metadata.EntitiesDescriptorType"),
    "metadata-parser": (
        "saml", "org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLEntityDescriptorParser"),
}


def require(value: object, detail: str) -> None:
    if not value:
        raise RuntimeError(detail)


def redact(value, path=""):
    if isinstance(value, dict):
        cleaned, removed = {}, []
        for key, child in value.items():
            child_path = path + "/" + key.replace("~", "~0").replace("/", "~1")
            lowered = key.lower()
            if (lowered in SENSITIVE or "private.key" in lowered
                    or "privatekey" in lowered):
                removed.append(child_path)
            else:
                cleaned[key], nested = redact(child, child_path)
                removed.extend(nested)
        return cleaned, removed
    if isinstance(value, list):
        cleaned, removed = [], []
        for index, child in enumerate(value):
            safe, nested = redact(child, path + "/" + str(index))
            cleaned.append(safe)
            removed.extend(nested)
        return cleaned, removed
    return value, []


def product_admin(access: str, path: str, body: bytes | None = None,
                  method: str = "GET", content_type: str = "application/json"):
    request = urllib.request.Request(
        ADMIN + path, data=body, method=method,
        headers={"Authorization": "Bearer " + access, "Content-Type": content_type},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
            return response.status, None if not raw else json.loads(raw)
    except urllib.error.HTTPError as error:
        return error.code, {"error": error.read().decode("utf-8", "replace")[:1000]}


def capture_capability_runtime(output: Path, access: str) -> dict:
    inspect = json.loads(subprocess.check_output(["docker", "inspect", CONTAINER], timeout=30))[0]
    require(inspect.get("State", {}).get("Running") is True and inspect.get("Image") == IMAGE,
            "Unexpected Keycloak runtime")
    for mount in inspect.get("Mounts", []):
        destination = (mount.get("Destination") or "").rstrip("/")
        require(not any(path == destination or path.startswith(destination + "/") for path in JARS.values()),
                "A retained product JAR is covered by a mount")

    providers = subprocess.check_output(
        ["docker", "exec", CONTAINER, "sh", "-c",
         "cd /opt/keycloak/providers && find . -type f -print | LC_ALL=C sort"], timeout=30)
    require(providers == b"./README.md\n", "Custom provider inventory is not empty")
    (output / "providers-inventory.txt").write_bytes(providers)
    subprocess.run(["docker", "cp", CONTAINER + ":/opt/keycloak/providers/README.md",
                    str(output / "providers-README.md")], check=True,
                   stdout=subprocess.DEVNULL, timeout=30)

    request = urllib.request.Request(
        "http://localhost:18180/admin/serverinfo",
        headers={"Authorization": "Bearer " + access})
    with urllib.request.urlopen(request, timeout=30) as response:
        server = json.load(response)
    subset = {
        "providers": {name: server["providers"][name] for name in (
            "client-description-converter", "client-registration", "login-protocol",
            "publicKeyCache", "publicKeyStorage")},
    }
    (output / "serverinfo-validity-providers.json").write_bytes(canonical(subset) + b"\n")

    jars = output / "product-jars"
    jars.mkdir()
    jar_paths = {}
    for label, source in JARS.items():
        destination = jars / (label + ".jar")
        subprocess.run(["docker", "cp", CONTAINER + ":" + source, str(destination)],
                       check=True, stdout=subprocess.DEVNULL, timeout=90)
        jar_paths[label] = destination

    originals = output / "product-originals"
    originals.mkdir()
    records = {}
    for label, (jar_label, class_name) in sorted(CLASSES.items()):
        entry = class_name.replace(".", "/") + ".class"
        with zipfile.ZipFile(jar_paths[jar_label]) as archive:
            raw = archive.read(entry)
        class_file = originals / (label + ".class")
        javap_file = originals / (label + ".javap.txt")
        class_file.write_bytes(raw)
        disassembly = subprocess.check_output(
            ["javap", "-classpath", os.pathsep.join(str(path) for path in jar_paths.values()),
             "-c", "-p", class_name], timeout=90)
        javap_file.write_bytes(disassembly)
        records[label] = {
            "className": class_name, "jar": jar_label, "jarEntry": entry,
            "classFile": str(class_file.relative_to(output)), "classSha256": SHA(raw),
            "javapFile": str(javap_file.relative_to(output)), "javapSha256": SHA(disassembly),
        }

    # Bind the prior exhaustive 348-JAR scan to the exact current JAR manifest.  Its backing JARs
    # with every validity/configuration hit are retained above and replayed by the adoption verifier.
    feasibility = REPO / "build/acceptance/reference-20260930/keycloak-md04-validity-feasibility"
    for name in ("all-jars-scan.json", "scan_keycloak_jars.py"):
        shutil.copy2(feasibility / name, output / name)

    runtime = {
        "schema": "samlscope-keycloak-validity-runtime-v1",
        "product": "keycloak", "productVersion": "26.7.2",
        "containerId": inspect["Id"], "imageId": inspect["Image"],
        "configuredImage": inspect["Config"]["Image"],
        "containerStartedAt": inspect["State"]["StartedAt"],
        "providersInventorySha256": SHA(providers),
        "providersReadmeSha256": SHA((output / "providers-README.md").read_bytes()),
        "serverInfoSha256": SHA((output / "serverinfo-validity-providers.json").read_bytes()),
        "jars": {label: {"path": JARS[label], "file": str(path.relative_to(output)),
                         "sha256": SHA(path.read_bytes())}
                 for label, path in jar_paths.items()},
        "classes": records,
        "allJarsScanSha256": SHA((output / "all-jars-scan.json").read_bytes()),
        "scanSourceSha256": SHA((output / "scan_keycloak_jars.py").read_bytes()),
        "productConfigurationWrites": 0, "productRestarts": 0, "humanOperations": 0,
    }
    write_json(output / "validity-runtime.json", runtime)
    return runtime


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)

    runtime_capture(output, "start")
    suite_capture(output)
    plan, run, entity = create_run(output, "validity-capability", WAIT_SECONDS)
    source = "http://samlscope-reference-suite:8080/p/%s/metadata/live?run=%s" % (plan, run)
    relay_url = "http://" + RELAY + ":8081/entities/" + urllib.parse.quote(entity, safe="")
    access = admin_token()
    before_full = lookup(access, entity)
    require(before_full == [], "Refusing to replace an existing Keycloak client")
    (output / "admin-before.json").write_bytes(canonical(before_full) + b"\n")

    configured_full = None
    owned = None
    relay_started = False
    restored = False
    phases = []
    conversions = []
    counts = {
        "restored": False, "productConfigurationWrites": 0, "restorationWrites": 0,
        "protocolRoundTrips": 0, "metadataFetches": 0, "metadataConverterCalls": 0,
        "productRestarts": 0, "humanOperations": 0,
    }
    try:
        write_properties(output, entity, source, "fetch")
        start_relay(output)
        relay_started = True
        recipe = client_recipe(entity, relay_url)
        recipe["redirectUris"] = [entity + "/sp/acs/0"] + [
            entity + "/sp/acs/0?mdv=" + variant + "&run=" + run
            for variant in VARIANTS
        ]
        admin(access, "/clients", recipe, "POST")
        counts["productConfigurationWrites"] += 1
        configured_full = detail(access, entity)
        owned = configured_full["id"]
        safe_configured, removed = redact(configured_full)
        require("/attributes/saml.signing.private.key" in removed,
                "Expected generated SAML private key was not redacted")
        require(set(removed) <= {"/secret", "/attributes/saml.signing.private.key"},
                "Unexpected credential fields in client state")
        (output / "admin-configured.json").write_bytes(canonical(safe_configured) + b"\n")
        write_json(output / "admin-redaction.json", {
            "removedFields": removed, "credentialValuesPersisted": False,
            "fullRepresentationHeldInMemoryOnly": True,
        })

        campaign = api("/api/runs/" + run + "/metadata-lab/automatic-polling", {
            "variants": list(VARIANTS), "pollingDelaySeconds": WAIT_SECONDS})
        save(output / "campaign.json", campaign)

        for index, variant in enumerate(VARIANTS):
            state = arm(run, output, variant, variant)
            before_relay = len(relay_records(output))
            phase, prepared, request, response, control = polling_flow(
                run, output, variant, variant, invalid_control=True)
            control_record = output / "signature-control.json"
            control_body = output / "signature-control-response.html"
            require(control_record.is_file() and control_body.is_file(),
                    "Product-owned invalid-signature rejection evidence is missing")
            variant_record = output / ("signature-control-" + variant + ".json")
            variant_body = output / ("signature-control-" + variant + "-response.html")
            control_record.replace(variant_record)
            control_body.replace(variant_body)
            records = relay_records(output)
            require(len(records) == before_relay + 1,
                    variant + " did not perform exactly one native metadata fetch")
            served_path = output / records[-1]["servedFile"]
            fixture = served_path.read_bytes()
            require(SHA(fixture) == records[-1]["servedSha256"],
                    "Relay metadata original hash mismatch")
            metadata_path = output / ("metadata-" + variant + ".xml")
            metadata_path.write_bytes(fixture)
            status, converted = product_admin(access, "/client-description-converter",
                                               fixture, "POST", "application/xml")
            require(status == 200 and isinstance(converted, dict),
                    "Native metadata converter did not accept " + variant)
            converted_raw = canonical(converted) + b"\n"
            converted_path = output / ("converter-" + variant + ".json")
            converted_path.write_bytes(converted_raw)
            conversions.append({
                "variant": variant, "fixtureSha256": SHA(fixture),
                "converterOutputSha256": SHA(converted_raw), "httpStatus": status,
            })
            counts["metadataConverterCalls"] += 1
            phase["relaySequence"] = records[-1]["sequence"]
            phase["fixtureSha256"] = SHA(fixture)
            phase["converterOutputSha256"] = SHA(converted_raw)
            phase["invalidControlRecordFile"] = variant_record.name
            phase["invalidControlRecordSha256"] = SHA(variant_record.read_bytes())
            phase["invalidControlResponseFile"] = variant_body.name
            phase["invalidControlResponseSha256"] = SHA(variant_body.read_bytes())
            require(control is not None, "Invalid-signature control is missing")
            phases.append(phase)
            counts["protocolRoundTrips"] += 2
            counts["metadataFetches"] += 1
            if index + 1 < len(VARIANTS):
                time.sleep(max(0, float(response["timestamp"]) + WAIT_SECONDS + 0.75 - time.time()))

        save(output / "tests-start.json", api("/api/runs/" + run + "/tests/start", {}))
        finish_evidence(output, run)
        save(output / "converter-observations.json", conversions)
        capture_capability_runtime(output, access)

        # Verify configured state once more after every native flow before deleting it.
        require(detail(access, entity) == configured_full,
                "Temporary Keycloak client changed during the campaign")
    finally:
        try:
            access = admin_token()
            current = lookup(access, entity)
            if owned is not None:
                require(len(current) == 1 and current[0].get("id") == owned,
                        "Concurrent temporary client replacement detected")
                require(admin(access, "/clients/" + owned) == configured_full,
                        "Concurrent temporary client edit detected")
                admin(access, "/clients/" + owned, method="DELETE")
                counts["productConfigurationWrites"] += 1
                counts["restorationWrites"] += 1
            final = lookup(access, entity)
            (output / "admin-final.json").write_bytes(canonical(final) + b"\n")
            restored = final == before_full
            counts["restored"] = restored
        finally:
            if relay_started:
                counts["temporaryRelayStopped"] = stop_relay()
            runtime_capture(output, "end")
            write_json(output / "operation-counts.json", counts)
        require(restored, "Keycloak temporary client restoration failed")

    manifest = {
        "schema": SCHEMA, "adapter": ADAPTER, "runId": run, "planId": plan,
        "entityId": entity, "targetEntityId": TARGET_ENTITY,
        "targetMetadataLocation": TARGET_METADATA,
        "sourceUrl": source, "relayUrl": relay_url,
        "variants": list(VARIANTS), "refreshWaitSeconds": WAIT_SECONDS,
        "configuredThresholdSeconds": None,
        "configurationConclusion": "capability-absent",
        "phases": phases, "conversions": conversions,
        "createdAt": utcnow(),
    }
    hash_fields(output, manifest, {
        "adminBeforeSha256": "admin-before.json",
        "adminConfiguredSha256": "admin-configured.json",
        "adminFinalSha256": "admin-final.json",
        "adminRedactionSha256": "admin-redaction.json",
        "operationCountsSha256": "operation-counts.json",
        "relaySourceSha256": "KeycloakMetadataUrlRelay.java",
        "relayRequestsSha256": "relay-requests.jsonl",
        "targetRuntimeStartSha256": "target-runtime-start.json",
        "targetRuntimeEndSha256": "target-runtime-end.json",
        "validityRuntimeSha256": "validity-runtime.json",
        "converterObservationsSha256": "converter-observations.json",
        "transcriptSha256": "transcript.json",
        "decodedManifestSha256": "decoded-manifest.json",
        "targetMetadataSha256": "target-metadata.xml",
    })
    write_json(output / "manifest.json", manifest)

    note = (
        "Machine-verified Keycloak 26.7.2 evidence: native metadata URL and import paths accepted "
        "and used metadata with missing, past, near-boundary, and far-boundary validUntil values; "
        "the retained installed provider/JAR originals expose only cache expiry/reload controls and "
        "no metadata validity rejection setting. Evidence manifest sha256="
        + SHA((output / "manifest.json").read_bytes())
    )
    conclusions = {}
    for case in CASES:
        conclusions[case] = api("/api/runs/" + run + "/cases/" + case + "/configure", {
            "value": "capability_absent", "note": note})
    save(output / "capability-conclusions.json", conclusions)
    save(output / "protocol-evidence-after.json",
         api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
    save(output / "result-after.json", api("/api/runs/" + run + "/result.json"))
    after = transcript(run)
    require(after == json.loads((output / "transcript.json").read_text()),
            "Configuration conclusion changed protocol transcript")
    save(output / "transcript-after.json", after)
    print(run, "captured, capability absent concluded, restored", restored)


if __name__ == "__main__":
    main()
