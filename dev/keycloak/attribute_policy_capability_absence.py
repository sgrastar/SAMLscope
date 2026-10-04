#!/usr/bin/env python3
"""Prove Keycloak's installed IdP cannot consume metadata attribute-policy inputs.

The campaign is deliberately narrower than the positive attribute-policy campaign.  It
records every installed native SAML metadata-import entry point and every installed SAML
protocol mapper from the running product, converts all approved policy fixtures through
the product's administration endpoint, runs one normal SSO control, and restores the
temporary client exactly.  Only the two approved ``normative_capability`` cases are then
concluded as capability-absent; IDP04.b is never concluded by this recorder.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse as urls
import urllib.request as http
import zipfile

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
from import_metadata_batch import BASE, api, save  # noqa: E402
from reference_flow import Client  # noqa: E402
from verify_keycloak_attribute_policy_capability_absence import (  # noqa: E402
    fixture_semantics as verify_fixture_semantics,
    verify_converter_semantics,
    verify_normal_control_import,
    verify_normal_sso,
    verify_restoration,
    verify_runtime,
)

CONTAINER = "samlscope-reference-keycloak"
ADMIN = "http://localhost:18180/admin/realms/samlscope"
TOKEN_URL = "http://localhost:18180/realms/master/protocol/openid-connect/token"
TARGET_ENTITY = "http://localhost:18180/realms/samlscope"
IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
SERVICES_JAR = "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar"
SAML_JAR = "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-saml-core-public-26.7.2.jar"

CASES = ["IIP-IDP03-a-idp-01", "IIP-IDP04-a-idp-01"]
CONDITIONS = [
    ("entity-present", "attribute-policy-entity-present"),
    ("entity-absent", "attribute-policy-entity-absent"),
    ("requested-required", "attribute-policy-requested-required"),
    ("requested-optional", "attribute-policy-requested-optional"),
    ("requested-absent", "attribute-policy-requested-absent"),
    ("indexed", "attribute-policy-indexed"),
    # Keep the normal control active when its imported client performs the SSO round trip.
    ("baseline", "control"),
]

MAPPERS = {
    "saml-audience-mapper": "org.keycloak.protocol.saml.mappers.SAMLAudienceProtocolMapper",
    "saml-audience-resolve-mapper": "org.keycloak.protocol.saml.mappers.SAMLAudienceResolveProtocolMapper",
    "saml-authn-context-class-ref-mapper": "org.keycloak.protocol.saml.mappers.AuthnContextClassRefMapper",
    "saml-group-membership-mapper": "org.keycloak.protocol.saml.mappers.GroupMembershipMapper",
    "saml-hardcode-attribute-mapper": "org.keycloak.protocol.saml.mappers.HardcodedAttributeMapper",
    "saml-hardcode-role-mapper": "org.keycloak.protocol.saml.mappers.HardcodedRole",
    "saml-organization-group-membership-mapper":
        "org.keycloak.organization.protocol.mappers.saml.OrganizationGroupMembershipMapper",
    "saml-organization-membership-mapper":
        "org.keycloak.organization.protocol.mappers.saml.OrganizationMembershipMapper",
    "saml-role-list-mapper": "org.keycloak.protocol.saml.mappers.RoleListMapper",
    "saml-role-name-mapper": "org.keycloak.protocol.saml.mappers.RoleNameMapper",
    "saml-user-attribute-mapper": "org.keycloak.protocol.saml.mappers.UserAttributeStatementMapper",
    "saml-user-attribute-nameid-mapper": "org.keycloak.protocol.saml.mappers.UserAttributeNameIdMapper",
    "saml-user-property-mapper": "org.keycloak.protocol.saml.mappers.UserPropertyAttributeStatementMapper",
    "saml-user-session-note-mapper": "org.keycloak.protocol.saml.mappers.UserSessionNoteStatementMapper",
}
ATTRIBUTE_OUTPUT_MAPPERS = {
    "saml-group-membership-mapper", "saml-hardcode-attribute-mapper",
    "saml-organization-group-membership-mapper", "saml-organization-membership-mapper",
    "saml-role-list-mapper", "saml-user-attribute-mapper", "saml-user-property-mapper",
    "saml-user-session-note-mapper",
}
PATH_CLASSES = {
    "adminConverterResource": "org.keycloak.services.resources.admin.RealmAdminResource",
    "metadataConverter": "org.keycloak.protocol.saml.EntityDescriptorDescriptionConverter",
    "registrationProvider":
        "org.keycloak.protocol.saml.clientregistration.EntityDescriptorClientRegistrationProvider",
    "registrationProviderFactory":
        "org.keycloak.protocol.saml.clientregistration.EntityDescriptorClientRegistrationProviderFactory",
    "samlProtocol": "org.keycloak.protocol.saml.SamlProtocol",
}
REFERENCE_TERMS = ["EntityAttributes", "RequestedAttribute", "AttributeConsumingService", "isIsRequired"]
SENSITIVE_CLIENT_FIELDS = {"secret", "registrationaccesstoken", "accesstoken", "password"}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def redact_client_credentials(value, path=""):
    """Return a persisted-safe client representation and the removed JSON-pointer paths.

    Keycloak generates a client secret even for the temporary SAML client.  The complete
    representations are compared only in memory before and after the SSO control; credential
    values must never enter the evidence directory.
    """
    if isinstance(value, dict):
        cleaned, removed = {}, []
        for key, child in value.items():
            child_path = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if key.lower() in SENSITIVE_CLIENT_FIELDS:
                removed.append(child_path)
                continue
            cleaned[key], nested = redact_client_credentials(child, child_path)
            removed.extend(nested)
        return cleaned, removed
    if isinstance(value, list):
        cleaned, removed = [], []
        for index, child in enumerate(value):
            safe, nested = redact_client_credentials(child, path + "/" + str(index))
            cleaned.append(safe)
            removed.extend(nested)
        return cleaned, removed
    return value, []


def product_token() -> str:
    body = urls.urlencode({
        "client_id": "admin-cli",
        "username": os.environ.get("KEYCLOAK_ADMIN_USERNAME", "admin"),
        "password": os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"),
        "grant_type": "password",
    }).encode()
    with http.urlopen(http.Request(TOKEN_URL, data=body), timeout=30) as response:
        return json.load(response)["access_token"]


def capture_runtime(folder: Path, token: str) -> dict:
    inspect_raw = subprocess.check_output(["docker", "inspect", CONTAINER], timeout=30)
    inspect = json.loads(inspect_raw)[0]
    if inspect.get("State", {}).get("Running") is not True or inspect.get("Image") != IMAGE:
        raise RuntimeError("unexpected Keycloak runtime")
    for mount in inspect.get("Mounts", []):
        destination = mount.get("Destination", "").rstrip("/")
        if any(path == destination or path.startswith(destination + "/")
               for path in (SERVICES_JAR, SAML_JAR)):
            raise RuntimeError("retained runtime JAR is covered by a host mount")
    # Persist only fields used for runtime binding.  docker inspect also contains bootstrap
    # credentials in Config.Env, which must never become acceptance evidence.
    sanitized_inspect = [{"Id": inspect["Id"], "Image": inspect["Image"],
        "Config": {"Image": inspect["Config"]["Image"]},
        "State": {"Running": inspect["State"]["Running"],
                  "StartedAt": inspect["State"]["StartedAt"]},
        "Mounts": [{"Destination": mount.get("Destination", ""), "Type": mount.get("Type", "")}
                   for mount in inspect.get("Mounts", [])]}]
    (folder / "target-container-inspect.json").write_bytes(canonical(sanitized_inspect))
    image_raw = subprocess.check_output(["docker", "image", "inspect", IMAGE], timeout=30)
    image = json.loads(image_raw)[0]
    (folder / "target-image-inspect.json").write_bytes(canonical([{
        "Id": image["Id"], "RepoDigests": image.get("RepoDigests", [])}]))
    providers_inventory = subprocess.check_output(
        ["docker", "exec", CONTAINER, "sh", "-c",
         "cd /opt/keycloak/providers && find . -type f -print | LC_ALL=C sort"], timeout=30)
    if providers_inventory != b"./README.md\n":
        raise RuntimeError("unexpected custom Keycloak provider inventory")
    (folder / "providers-inventory.txt").write_bytes(providers_inventory)
    provider_readme = folder / "providers-README.md"
    subprocess.run(["docker", "cp", CONTAINER + ":/opt/keycloak/providers/README.md",
                    str(provider_readme)], check=True, stdout=subprocess.DEVNULL, timeout=30)

    request = http.Request("http://localhost:18180/admin/serverinfo",
                           headers={"Authorization": "Bearer " + token})
    with http.urlopen(request, timeout=30) as response:
        server = json.load(response)
    subset = {
        "protocolMapperTypes": {"saml": server["protocolMapperTypes"]["saml"]},
        "providers": {name: server["providers"][name] for name in
                      ("client-description-converter", "client-registration", "protocol-mapper")},
    }
    server_raw = canonical(subset)
    (folder / "serverinfo-native-inventory.json").write_bytes(server_raw)

    jar = folder / "keycloak-services-runtime.jar"
    saml_jar = folder / "keycloak-saml-core-public-runtime.jar"
    subprocess.run(["docker", "cp", CONTAINER + ":" + SERVICES_JAR, str(jar)],
                   check=True, stdout=subprocess.DEVNULL, timeout=60)
    subprocess.run(["docker", "cp", CONTAINER + ":" + SAML_JAR, str(saml_jar)],
                   check=True, stdout=subprocess.DEVNULL, timeout=60)

    class_records = {}
    originals = folder / "product-originals"
    originals.mkdir()
    classes = {**PATH_CLASSES, **{"mapper." + key: value for key, value in MAPPERS.items()}}
    with zipfile.ZipFile(jar) as archive:
        for label, class_name in sorted(classes.items()):
            entry = class_name.replace(".", "/") + ".class"
            raw = archive.read(entry)
            stem = label.replace(".", "__")
            class_file = originals / (stem + ".class")
            javap_file = originals / (stem + ".javap.txt")
            class_file.write_bytes(raw)
            disassembly = subprocess.check_output(
                ["javap", "-classpath", str(jar), "-c", "-p", class_name], timeout=60)
            javap_file.write_bytes(disassembly)
            class_records[label] = {
                "className": class_name, "jarEntry": entry,
                "classFile": str(class_file.relative_to(folder)), "classSha256": sha(raw),
                "javapFile": str(javap_file.relative_to(folder)), "javapSha256": sha(disassembly),
            }

        service_entries = {}
        for label, entry in {
            "descriptionConverterFactories":
                "META-INF/services/org.keycloak.exportimport.ClientDescriptionConverterFactory",
            "clientRegistrationFactories":
                "META-INF/services/org.keycloak.services.clientregistration.ClientRegistrationProviderFactory",
            "protocolMappers": "META-INF/services/org.keycloak.protocol.ProtocolMapper",
        }.items():
            raw = archive.read(entry)
            path = originals / (label + ".services.txt")
            path.write_bytes(raw)
            service_entries[label] = {"jarEntry": entry, "file": str(path.relative_to(folder)),
                                      "sha256": sha(raw)}

        reference_inventory = {}
        for entry in archive.namelist():
            if not entry.endswith(".class"):
                continue
            raw = archive.read(entry)
            hits = [term for term in REFERENCE_TERMS if term.encode() in raw]
            if hits:
                reference_inventory[entry] = hits
    (folder / "metadata-reference-inventory.json").write_bytes(canonical(reference_inventory))

    manifest = {
        "schema": "samlscope-keycloak-attribute-policy-capability-v1",
        "containerId": inspect["Id"], "imageId": inspect["Image"],
        "configuredImage": inspect["Config"]["Image"],
        "containerStartedAt": inspect["State"]["StartedAt"],
        "servicesJarPath": SERVICES_JAR, "servicesJarSha256": sha(jar.read_bytes()),
        "samlJarPath": SAML_JAR, "samlJarSha256": sha(saml_jar.read_bytes()),
        "serverInfoSha256": sha(server_raw), "classRecords": class_records,
        "providersInventorySha256": sha(providers_inventory),
        "providersReadmeSha256": sha(provider_readme.read_bytes()),
        "serviceEntries": service_entries,
        "referenceInventorySha256": sha((folder / "metadata-reference-inventory.json").read_bytes()),
        "installedSamlMappers": sorted(MAPPERS),
        "attributeOutputMappers": sorted(ATTRIBUTE_OUTPUT_MAPPERS),
        "productConfigurationWrites": 0, "productRestarts": 0, "humanOperations": 0,
    }
    save(folder / "runtime-capability.json", manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError("Evidence directory must be empty")
    out.mkdir(parents=True, exist_ok=True)

    token = product_token()
    admin_operations = []

    def admin(path: str, body=None, method: str = "GET", content_type: str = "application/json"):
        if body is None:
            raw = None
        elif isinstance(body, bytes):
            raw = body
        else:
            raw = json.dumps(body).encode()
        request = http.Request(ADMIN + path, data=raw, method=method,
            headers={"Authorization": "Bearer " + token, "Content-Type": content_type})
        record = {"method": method, "path": path.split("?")[0], "kind":
                  "metadata-conversion" if path == "/client-description-converter" else "client-state",
                  "status": "attempted"}
        admin_operations.append(record)
        try:
            with http.urlopen(request, timeout=60) as response:
                payload = response.read()
                record["status"] = response.status
                return json.loads(payload) if payload else None
        except urllib.error.HTTPError as error:
            record["status"] = error.code
            raise RuntimeError("Keycloak administration request failed: " + str(error.code)) from None

    plan_result = api("/api/plans", {
        "name": "Keycloak native metadata attribute-policy capability",
        "profile": "browser_sso_idp", "targetKind": "IDP", "targetEntityId": TARGET_ENTITY,
        "metadataSourceKind": "URL",
        "metadataSourceLocation":
            "http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor",
        "suiteMetadataDelivery": "HTTP_URL", "declaredFeatures": {},
        "parameters": {"clockSkewToleranceSeconds": 180, "metadataRefreshWaitSeconds": 300,
                       "testUserHint": "samlscope-m0-user", "requestSigningMode": "REQUIRED"},
        "interaction": {"allowBrowserSteps": True, "allowAttestation": False, "preset": "quick"},
        "authorizedTarget": True,
    })
    save(out / "plan.json", plan_result)
    plan = plan_result["plan"]["plan"]["id"]
    created = api("/api/plans/" + plan + "/runs", {})
    save(out / "created.json", created)
    run = created["run"]["id"]
    if not re.fullmatch(r"plan_[0-9A-HJKMNP-TV-Z]{26}", plan) or not re.fullmatch(
            r"run_[0-9A-HJKMNP-TV-Z]{26}", run):
        raise ValueError("invalid Suite identity")
    save(out / "preflight.json", api("/api/runs/" + run + "/preflight", {}))

    entity = BASE + "/p/" + plan
    lookup = "/clients?clientId=" + urls.quote(entity, safe="")
    before_raw = canonical(admin(lookup))
    (out / "client-before.json").write_bytes(before_raw)
    if json.loads(before_raw):
        raise ValueError("refusing to overwrite an existing client")

    converters = []
    converted_outputs = {}
    converted_control = None
    for label, variant in CONDITIONS:
        folder = out / label
        folder.mkdir()
        state = api("/api/runs/" + run + "/metadata-lab/automatic-polling",
                    {"variants": [variant], "pollingDelaySeconds": 0})
        save(folder / "campaign.json", state)
        with http.urlopen(state["automaticStartUrl"], timeout=30) as response:
            if response.status != 202:
                raise RuntimeError("fixture was dispatched before native conversion")
            response.read()
        with http.urlopen(state["metadataUrl"], timeout=30) as response:
            fixture = response.read()
        (folder / "fixture.xml").write_bytes(fixture)
        converted = admin("/client-description-converter", fixture, "POST", "application/xml")
        converted_raw = canonical(converted)
        (folder / "converter-output.json").write_bytes(converted_raw)
        converters.append({"label": label, "variant": variant, "fixtureSha256": sha(fixture),
                           "converterOutputSha256": sha(converted_raw)})
        converted_outputs[label] = converted
        if label == "baseline":
            converted_control = converted
    save(out / "converter-observations.json", converters)
    if not isinstance(converted_control, dict) or converted_control.get("clientId") != entity:
        raise RuntimeError("native converter did not produce the baseline policy-control client")

    # Metadata-lab fixtures intentionally use campaign keys.  Retain those as the policy
    # originals, but use the Plan's stable metadata for the independent SSO health control so
    # its signing certificate is the one Runner actually uses for AuthnRequest signatures.
    control_folder = out / "normal-control"
    control_folder.mkdir()
    with http.urlopen(entity + "/metadata", timeout=30) as response:
        control_fixture = response.read()
    (control_folder / "fixture.xml").write_bytes(control_fixture)
    converted_control = admin(
        "/client-description-converter", control_fixture, "POST", "application/xml")
    converted_control_raw = canonical(converted_control)
    (control_folder / "converter-output.json").write_bytes(converted_control_raw)
    save(control_folder / "manifest.json", {
        "fixtureSha256": sha(control_fixture),
        "converterOutputSha256": sha(converted_control_raw),
    })
    if not isinstance(converted_control, dict) or converted_control.get("clientId") != entity:
        raise RuntimeError("native converter did not produce the stable SAML control client")

    temporary_id = None
    flow_record = None
    cleanup_failures = []
    restored = False
    after_raw = b""
    try:
        admin("/clients", converted_control, "POST")
        rows = admin(lookup)
        if not isinstance(rows, list) or len(rows) != 1:
            raise RuntimeError("temporary client lookup is ambiguous")
        temporary_id = rows[0]["id"]
        if not re.fullmatch(r"[0-9a-f-]{36}", temporary_id):
            raise ValueError("invalid temporary client identifier")
        detail = admin("/clients/" + temporary_id)
        encoded_detail = canonical(detail)
        safe_detail, redacted_fields = redact_client_credentials(detail)
        if redacted_fields != ["/secret"]:
            raise RuntimeError("unexpected credential field inventory in client representation")
        (out / "configured-client-readback.json").write_bytes(canonical(safe_detail))

        before_ids = {row["id"] for row in api("/api/runs/" + run + "/transcript")}
        status = Client().flow(entity + "/start/m0-roundtrip?run=" + run, None,
            os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user"),
            os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password"))
        after_rows = api("/api/runs/" + run + "/transcript")
        flow_record = {"status": status, "newTranscriptIds":
                       [row["id"] for row in after_rows if row["id"] not in before_ids]}
        save(out / "normal-sso.json", flow_record)
        if status != "recorded" or len(flow_record["newTranscriptIds"]) != 2:
            raise RuntimeError("normal SSO control was not recorded exactly once")
        detail_after_value = admin("/clients/" + temporary_id)
        detail_after = canonical(detail_after_value)
        safe_detail_after, redacted_fields_after = redact_client_credentials(detail_after_value)
        (out / "configured-client-after-sso.json").write_bytes(canonical(safe_detail_after))
        if detail_after != encoded_detail or redacted_fields_after != redacted_fields:
            raise RuntimeError("temporary client configuration changed during normal SSO")
        save(out / "client-readback-redaction.json", {
            "run": run,
            "temporaryClientId": temporary_id,
            "redactedFields": redacted_fields,
            "fullRepresentationsEqualInMemory": True,
            "credentialValuesPersisted": False,
        })
        save(out / "tests-start.json", api("/api/runs/" + run + "/tests/start", {}))
        save(out / "protocol-evidence-before-conclusion.json",
             api("/api/runs/" + run + "/protocol-evidence"))

        capture_runtime(out, token)
    finally:
        try:
            rows = admin(lookup)
            if len(rows) > 1:
                raise RuntimeError("cleanup identity is ambiguous")
            if rows:
                identifier = rows[0]["id"]
                if temporary_id is not None and identifier != temporary_id:
                    raise RuntimeError("cleanup identity changed")
                temporary_id = identifier
                admin("/clients/" + identifier, method="DELETE")
            after_raw = canonical(admin(lookup))
            (out / "client-after.json").write_bytes(after_raw)
            restored = after_raw == before_raw
            if not restored:
                raise RuntimeError("temporary client state was not restored exactly")
        except Exception as error:
            cleanup_failures.append(type(error).__name__ + ":" + str(error))
        restoration_record = {"restored": restored,
             "beforeSha256": sha(before_raw),
             "afterSha256": sha((out / "client-after.json").read_bytes())
                 if (out / "client-after.json").exists() else None,
             "temporaryClientId": temporary_id, "failures": cleanup_failures,
             "existingClientsOverwritten": False}
        operations_record = {"run": run, "adminOperations": admin_operations,
             "metadataConverterCalls": len(converters) + 1,
             "productConfigurationWrites": sum(1 for row in admin_operations
                 if (row["method"], row["path"]) in {("POST", "/clients"),
                                                       ("DELETE", "/clients/" + str(temporary_id))}),
             "productRestarts": 0, "protocolRoundTrips": 1 if flow_record else 0,
             "humanOperations": 0, "restored": restored}
        save(out / "restoration.json", restoration_record)
        save(out / "operations.json", operations_record)
        if cleanup_failures or not restored:
            raise RuntimeError("native client cleanup incomplete")

    # Do not emit product failures until all machine-verifiable prerequisites pass locally.
    for label, _ in CONDITIONS:
        verify_fixture_semantics((out / label / "fixture.xml").read_bytes(), label, entity)
    verify_converter_semantics(converted_outputs, entity)
    verify_normal_control_import(control_fixture, converted_control, entity)
    verify_restoration(operations_record, restoration_record, before_raw, after_raw, run)
    manifest_sha = verify_runtime(out)

    transcript = api("/api/runs/" + run + "/transcript")
    save(out / "transcript.json", transcript)
    manifest = []
    for entry in transcript:
        reference = entry.get("decodedSamlRef")
        if not reference:
            continue
        if not re.fullmatch(r"tx_[0-9A-HJKMNP-TV-Z]{26}", entry["id"]) or Path(reference).is_absolute() \
                or ".." in Path(reference).parts:
            raise ValueError("invalid transcript original reference")
        path = out / "decoded" / (entry["id"] + ".xml")
        path.parent.mkdir(exist_ok=True)
        subprocess.run(["docker", "cp", "samlscope-reference-suite:/data/" + reference,
                        str(path)], check=True, stdout=subprocess.DEVNULL, timeout=60)
        manifest.append({"id": entry["id"], "file": str(path.relative_to(out)),
                         "sha256": sha(path.read_bytes())})
    save(out / "decoded-manifest.json", manifest)
    verify_normal_sso(out, run, entity)

    note = ("Machine-verified Keycloak 26.7.2 runtime evidence: every installed SAML metadata "
            "import path converges on EntityDescriptorDescriptionConverter; the converter drops "
            "mdattr:EntityAttributes and RequestedAttribute/@isRequired, and no installed SAML "
            "attribute-statement mapper can recover those inputs. Evidence manifest sha256=" + manifest_sha)
    for case in CASES:
        save(out / (case + "-configure.json"), api(
            "/api/runs/" + run + "/cases/" + case + "/configure",
            {"value": "capability_absent", "note": note}))
    save(out / "protocol-evidence-after-conclusion.json",
         api("/api/runs/" + run + "/protocol-evidence"))
    save(out / "run-after.json", api("/api/runs/" + run))
    save(out / "result.json", api("/api/runs/" + run + "/result.json"))
    require_same_transcript = api("/api/runs/" + run + "/transcript")
    if require_same_transcript != transcript:
        raise RuntimeError("configuration conclusion unexpectedly changed protocol evidence")
    subprocess.run(["docker", "cp", "samlscope-reference-suite:/data/target-metadata/" + run + ".xml",
                    str(out / "target-metadata.xml")], check=True, stdout=subprocess.DEVNULL, timeout=60)
    print("Recorded Keycloak attribute-policy capability absence for", run,
          "; IDP04.b deliberately left unresolved")


if __name__ == "__main__":
    main()
