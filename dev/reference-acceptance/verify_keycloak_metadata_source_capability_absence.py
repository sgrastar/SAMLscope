#!/usr/bin/env python3
"""Fail-closed verifier for Keycloak MD06.b and MD03.d capability absence.

The campaign combines two independent native metadata imports with two correlated
SAML successes, retained runtime JAR/class/provider originals, and exact deletion
read-back.  It may conclude ``capability_absent`` only when the installed Keycloak
runtime exposes neither a multi-entity import result nor source-scoped metadata
signature trust.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from functools import lru_cache
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from verify_keycloak_attribute_policy_capability_absence import verify_runtime
from verify_md03d_source_scoped_trust_acceptance import verify_signature_originals


SCHEMA = "samlscope-keycloak-metadata-source-capability-absence-v1"
PRODUCT = "keycloak"
VERSION = "26.7.2"
TARGET = "http://localhost:18180/realms/samlscope"
TARGET_IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
SUITE_IMAGE = "sha256:6d22ec7bd5b16e9c9191b42d3d915f92d621a3f670c81b24746dd8b0cd5f9b90"
SUITE_CONFIGURED_IMAGE = "samlscope:reference-combined-v159"
CASES = ["IIP-MD06-b-idp-01", "IIP-MD03-d-idp-01"]
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
PLAN_RE = re.compile(r"plan_[0-9A-HJKMNP-TV-Z]{26}")
MD = "urn:oasis:names:tc:SAML:2.0:metadata"
DS = "http://www.w3.org/2000/09/xmldsig#"
SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"

EXPECTED_TERM_INVENTORY = {
    "keycloak-saml-core-public-runtime.jar": {
        "org/keycloak/saml/common/exceptions/fed/SignatureValidationException.class":
            ["SignatureValidation"],
    },
    "keycloak-services-runtime.jar": {
        "org/keycloak/authentication/authenticators/client/JWTClientAuthenticator.class":
            ["SignatureValidation"],
        "org/keycloak/authentication/authenticators/client/X509ClientAuthenticator.class":
            ["validateCertificate"],
        "org/keycloak/authentication/authenticators/x509/AbstractX509ClientCertificateAuthenticator$CertificateValidatorConfigBuilder.class":
            ["validateCertificate"],
        "org/keycloak/authentication/authenticators/x509/AbstractX509ClientCertificateAuthenticatorFactory.class":
            ["validateCertificate"],
        "org/keycloak/authentication/authenticators/x509/CertificateValidator.class":
            ["trustAnchor"],
        "org/keycloak/authentication/authenticators/x509/X509AuthenticatorConfigModel.class":
            ["validateCertificate"],
        "org/keycloak/broker/saml/SAMLIdentityProviderConfig.class": ["metadataDescriptorUrl"],
        "org/keycloak/keys/JavaKeystoreKeyProviderFactory.class": ["validateCertificate"],
        "org/keycloak/keys/loader/ClientPublicKeyLoader.class": ["SignatureValidation"],
        "org/keycloak/protocol/saml/SamlClient.class":
            ["saml.metadataDescriptorUrl", "saml.useMetadataDescriptorUrl", "metadataDescriptorUrl"],
        "org/keycloak/protocol/saml/SamlConfigAttributes.class":
            ["saml.metadataDescriptorUrl", "saml.useMetadataDescriptorUrl", "metadataDescriptorUrl"],
        "org/keycloak/services/clientpolicy/executor/SecureClientUrisPatternExecutorFactory.class":
            ["saml.metadataDescriptorUrl", "metadataDescriptorUrl"],
        "org/keycloak/services/resources/admin/IdentityProvidersResource.class":
            ["metadataDescriptorUrl"],
        "org/keycloak/services/x509/NginxProxySslClientCertificateLookup.class": ["trustAnchor"],
        "org/keycloak/validation/DefaultClientValidationProvider$FieldMessages.class":
            ["saml.metadataDescriptorUrl", "metadataDescriptorUrl"],
        "org/keycloak/validation/DefaultClientValidationProvider.class":
            ["saml.metadataDescriptorUrl", "metadataDescriptorUrl"],
    },
}


def require(value, message="invalid Keycloak metadata-source capability evidence"):
    if not value:
        raise ValueError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def inside(folder: Path, name: str) -> Path:
    path = (folder / name).resolve()
    require(path.is_relative_to(folder.resolve()) and path.is_file(),
            "evidence reference escaped folder")
    return path


def read(folder: Path, name: str):
    return json.loads(inside(folder, name).read_text())


def case_map(result: dict) -> dict:
    return {case["id"]: case for requirement in result["requirements"]
            for case in requirement["cases"]}


def verify_receipt_identity(receipt: dict) -> None:
    require(receipt["schema"] == SCHEMA and receipt["product"] == PRODUCT
            and receipt["productVersion"] == VERSION and receipt["targetEntityId"] == TARGET
            and receipt["cases"] == CASES
            and RUN_RE.fullmatch(receipt["primaryRun"])
            and RUN_RE.fullmatch(receipt["secondaryRun"])
            and receipt["primaryRun"] != receipt["secondaryRun"], "receipt identity mismatch")
    require(receipt["controls"] == {
        "normal": "two-distinct-peer-correlated-successes-through-native-metadata-url",
        "md06bNegative": "second-peer-requires-second-client-create",
        "md03dNegative":
            "source-b-signed-by-source-a-key-is-accepted-with-no-source-trust-setting",
    }, "control declaration mismatch")


def verify_suite(folder: Path, receipt: dict) -> None:
    start = receipt["suiteRuntime"]
    require(start["containerName"] == "samlscope-reference-suite"
            and start["imageId"] == SUITE_IMAGE
            and start["configuredImage"] == SUITE_CONFIGURED_IMAGE
            and start["running"] is True, "Suite start identity mismatch")
    retained_start = read(folder, "suite-runtime-start.json")
    require(retained_start == start, "Suite receipt/start manifest mismatch")
    final = read(folder, "suite-runtime-final.json")
    for key in ("containerName", "containerId", "imageId", "startedAt", "configuredImage", "running"):
        require(final[key] == start[key], "Suite changed during campaign")
    require(set(start["jars"]) == set(final["jars"]) == {"core", "runner", "saml"},
            "Suite JAR inventory mismatch")
    for phase, runtime in (("start", start), ("final", final)):
        inspect = inside(folder, runtime["inspectFile"]).read_bytes()
        require(sha(inspect) == runtime["inspectSha256"], "Suite inspect hash mismatch")
        values = json.loads(inspect)
        require(isinstance(values, list) and len(values) == 1
                and values[0]["Id"] == runtime["containerId"]
                and values[0]["Image"] == runtime["imageId"]
                and values[0]["State"]["StartedAt"] == runtime["startedAt"]
                and values[0]["State"]["Running"] is True, "Suite inspect identity mismatch")
        for name, item in runtime["jars"].items():
            require(item["path"] == f"/opt/samlscope/lib/{name}-0.1.0.jar"
                    and item["file"] == f"suite-{name}-{phase}.jar"
                    and sha(inside(folder, item["file"]).read_bytes()) == item["sha256"],
                    "Suite JAR original mismatch")
            require(item["sha256"] == start["jars"][name]["sha256"],
                    "Suite JAR changed during campaign")


def verify_target_stability(folder: Path) -> None:
    start = read(folder, "target-runtime-start.json")
    end = read(folder, "target-runtime-end.json")
    require(start["schema"] == end["schema"] == "samlscope-keycloak-metadata-url-runtime-v1"
            and start["phase"] == "start" and end["phase"] == "end"
            and start["product"] == end["product"] == PRODUCT
            and start["productVersion"] == end["productVersion"] == VERSION
            and start["imageId"] == end["imageId"] == TARGET_IMAGE
            and start["runningAtCapture"] is end["runningAtCapture"] is True,
            "target runtime identity mismatch")
    require({key: value for key, value in start.items() if key != "phase"}
            == {key: value for key, value in end.items() if key != "phase"},
            "target runtime changed during campaign")
    require(inside(folder, "keycloak-jars-start.json").read_bytes()
            == inside(folder, "keycloak-jars-end.json").read_bytes()
            and inside(folder, "provider-inventory-start.json").read_bytes()
            == inside(folder, "provider-inventory-end.json").read_bytes()
            and inside(folder, "keycloak-config-start.txt").read_bytes()
            == inside(folder, "keycloak-config-end.txt").read_bytes(),
            "target runtime originals changed")


def service_lines(record: dict) -> set[str]:
    raw = base64.b64decode(record["base64"], validate=True)
    require(sha(raw) == record["sha256"], "service entry hash mismatch")
    return {line.strip() for line in raw.decode().splitlines()
            if line.strip() and not line.lstrip().startswith("#")}


def verify_all_jars_scan(folder: Path, scan: dict | None = None) -> None:
    manifest = read(folder, "all-jars-native-scan-manifest.json")
    require(manifest["schema"] == "samlscope-keycloak-all-jars-native-scan-manifest-v1"
            and manifest["targetImageId"] == TARGET_IMAGE
            and manifest["jarCount"] == 348
            and manifest["execution"] == "disposable-read-only-container-from-target-image"
            and manifest["targetProductWrites"] == manifest["productRestarts"] ==
                manifest["humanOperations"] == 0,
            "all-JAR scan execution manifest mismatch")
    source = inside(folder, manifest["scannerSourceFile"])
    scan_path = inside(folder, manifest["scanFile"])
    jar_manifest_path = inside(folder, manifest["jarManifestFile"])
    require(source.read_bytes() ==
            (Path(__file__).resolve().parents[1] / "keycloak/KeycloakAllJarNativeScan.java").read_bytes()
            and sha(source.read_bytes()) == manifest["scannerSourceSha256"]
            and sha(scan_path.read_bytes()) == manifest["scanSha256"]
            and sha(jar_manifest_path.read_bytes()) == manifest["jarManifestSha256"],
            "all-JAR scan originals mismatch")
    scan = copy.deepcopy(json.loads(scan_path.read_text()) if scan is None else scan)
    jars = json.loads(jar_manifest_path.read_text())
    require(scan["schema"] == "samlscope-keycloak-all-jars-native-scan-v1"
            and scan["root"] == "/opt/keycloak/lib/lib/main"
            and scan["jarCount"] == len(scan["jars"]) == len(jars) == manifest["jarCount"]
            and scan["jars"] == jars and len({row["path"] for row in scan["jars"]}) == len(jars),
            "all 348 runtime JARs are not exactly represented")
    require(inside(folder, "keycloak-jars-end.json").read_bytes() == jar_manifest_path.read_bytes(),
            "full JAR manifest changed during campaign")
    services = scan["serviceEntries"]
    description_suffix = (
        "!META-INF/services/org.keycloak.exportimport.ClientDescriptionConverterFactory")
    registration_suffix = (
        "!META-INF/services/org.keycloak.services.clientregistration.ClientRegistrationProviderFactory")
    descriptions = [record for name, record in services.items() if name.endswith(description_suffix)]
    registrations = [record for name, record in services.items() if name.endswith(registration_suffix)]
    require(len(descriptions) == len(registrations) == 1, "native provider service inventory ambiguous")
    require(service_lines(descriptions[0]) == {
        "org.keycloak.exportimport.KeycloakClientDescriptionConverter",
        "org.keycloak.protocol.oidc.OIDCClientDescriptionConverterFactory",
        "org.keycloak.protocol.saml.EntityDescriptorDescriptionConverter",
    }, "unknown native description converter provider")
    require(service_lines(registrations[0]) == {
        "org.keycloak.services.clientregistration.DefaultClientRegistrationProviderFactory",
        "org.keycloak.services.clientregistration.oidc.OIDCClientRegistrationProviderFactory",
        "org.keycloak.services.clientregistration.AdapterInstallationClientRegistrationProviderFactory",
        "org.keycloak.protocol.saml.clientregistration.EntityDescriptorClientRegistrationProviderFactory",
    }, "unknown native client-registration provider")
    service_jar = "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar!"
    hits = scan["termHits"]
    one_entity = [name for name, terms in hits.items() if "Expected one entity descriptor" in terms]
    require(one_entity == [service_jar
            + "org/keycloak/protocol/saml/EntityDescriptorDescriptionConverter.class"],
            "single-entity native converter path changed")
    saml_provider_hits = {name for name, terms in hits.items()
        if "EntityDescriptorDescriptionConverter" in terms
        or "EntityDescriptorClientRegistrationProvider" in terms
        or "saml2-entity-descriptor" in terms}
    require(saml_provider_hits and all(name.startswith(service_jar) for name in saml_provider_hits),
            "SAML metadata import path exists outside the inventoried services JAR")
    for name, terms in hits.items():
        if "!org/keycloak/protocol/saml/" in name:
            require(not set(terms).intersection({"trustAnchor", "validateCertificate",
                                                "SignatureValidation",
                                                "DynamicHTTPMetadataProvider", "MDQ"}),
                    "native SAML path gained source-scoped trust capability")


def verify_sources(folder: Path, receipt: dict) -> None:
    sources = receipt["sources"]
    require(len(sources) == 2 and [source["label"] for source in sources] == ["source-a", "source-b"]
            and len({source["run"] for source in sources}) == 2
            and len({source["plan"] for source in sources}) == 2
            and len({source["entity"] for source in sources}) == 2
            and receipt["primaryRun"] == sources[0]["run"]
            and receipt["secondaryRun"] == sources[1]["run"], "source set mismatch")
    for source in sources:
        label = source["label"]
        require(RUN_RE.fullmatch(source["run"]) and PLAN_RE.fullmatch(source["plan"])
                and source["entity"] == "http://localhost:18080/p/" + source["plan"],
                "source Run/plan/entity mismatch")
        plan = read(folder, label + "-plan.json")["plan"]["plan"]
        created = read(folder, label + "-created.json")["run"]
        preflight = read(folder, label + "-preflight.json")
        require(plan["id"] == source["plan"] and plan["profile"] == "metadata_idp"
                and plan["target"] == {"kind": "IDP", "entityId": TARGET,
                                       "connectionId": None, "metadataRevisionId": None}
                and created["id"] == source["run"] and created["planId"] == source["plan"]
                and preflight["runId"] == source["run"], "source Run originals mismatch")
        unsigned = inside(folder, source["metadataFile"]).read_bytes()
        signed = inside(folder, source["signedMetadataFile"]).read_bytes()
        unsigned_root, signed_root = ET.fromstring(unsigned), ET.fromstring(signed)
        require(sha(unsigned) == source["metadataSha256"]
                and sha(signed) == source["signedMetadataSha256"]
                and unsigned_root.tag == signed_root.tag == "{" + MD + "}EntityDescriptor"
                and unsigned_root.get("entityID") == signed_root.get("entityID") == source["entity"]
                and len(signed_root.findall("{" + DS + "}Signature")) == 1,
                "source metadata original mismatch")
    verify_signature_originals(folder, receipt)


def walk(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)
    elif isinstance(value, str):
        yield value


def verify_native_paths(folder: Path, receipt: dict) -> None:
    runtime_sha = verify_runtime(folder)
    require(runtime_sha == sha(inside(folder, receipt["runtimeCapabilityFile"]).read_bytes()),
            "runtime capability manifest is not bound")
    term_path = inside(folder, receipt["runtimeTermInventoryFile"])
    require(sha(term_path.read_bytes()) == receipt["runtimeTermInventorySha256"],
            "runtime term inventory hash mismatch")
    inventory = json.loads(term_path.read_text())
    require(inventory == EXPECTED_TERM_INVENTORY, "metadata-source term inventory changed")
    for entry, terms in inventory["keycloak-services-runtime.jar"].items():
        if entry.startswith("org/keycloak/protocol/saml/"):
            require(entry in {
                "org/keycloak/protocol/saml/SamlClient.class",
                "org/keycloak/protocol/saml/SamlConfigAttributes.class",
            } and terms == ["saml.metadataDescriptorUrl", "saml.useMetadataDescriptorUrl",
                            "metadataDescriptorUrl"],
                    "SAML runtime gained source-scoped trust input")

    converter_javap = inside(folder,
        read(folder, receipt["runtimeCapabilityFile"])["classRecords"]["metadataConverter"]["javapFile"]
    ).read_text()
    registration_javap = inside(folder,
        read(folder, receipt["runtimeCapabilityFile"])["classRecords"]["registrationProvider"]["javapFile"]
    ).read_text()
    require(all(token in converter_javap for token in
                ("Expected one entity descriptor", "setClientId", "setAttributes", "loadEntityDescriptors")),
            "native converter single-entity semantics changed")
    require(all(token in registration_javap for token in
                ("saml2-entity-descriptor", "convertToInternal", "create")),
            "native registration path no longer converges on converter/create")

    observations = read(folder, receipt["converterObservationsFile"])
    require(len(observations) == 2
            and [row["source"] for row in observations] == ["source-a", "source-b"],
            "native converter observation set mismatch")
    root_k = base64.b64encode(inside(folder,
        read(folder, receipt["keyMaterialFile"])["keyKCertificateFile"]).read_bytes()).decode()
    forbidden = ("trustanchor", "validatecertificate", "signaturevalidation",
                 "metadata source", "metadatasource")
    for source, observation in zip(receipt["sources"], observations):
        raw = inside(folder, observation["outputFile"]).read_bytes()
        value = json.loads(raw)
        flat = "\n".join(walk(value)).lower()
        require(observation == {
            "source": source["label"], "entityId": source["entity"],
            "fixtureSha256": source["signedMetadataSha256"],
            "outputFile": source["label"] + "-converter-output.json",
            "outputSha256": sha(raw), "clientId": source["entity"], "protocol": "saml",
        } and value.get("clientId") == source["entity"] and value.get("protocol") == "saml",
                "native converter output binding mismatch")
        require(all(token not in flat for token in forbidden) and root_k not in raw.decode(),
                "converter exposed an unreviewed source trust input")


def verify_clients_and_relay(folder: Path, receipt: dict) -> None:
    ids = set()
    for source in receipt["sources"]:
        label, entity = source["label"], source["entity"]
        recipe = read(folder, label + "-client-recipe.json")
        before = inside(folder, label + "-client-before.json").read_bytes()
        final = inside(folder, label + "-client-final.json").read_bytes()
        current_raw = inside(folder, label + "-client-readback.json").read_bytes()
        after_raw = inside(folder, label + "-client-after-sso.json").read_bytes()
        current = json.loads(current_raw)
        ids.add(current["id"])
        expected_url = "http://samlscope-keycloak-source-relay:8081/entities/" + entity.replace(
            ":", "%3A").replace("/", "%2F")
        require(recipe["clientId"] == entity and recipe["protocol"] == "saml"
                and recipe["attributes"]["saml.useMetadataDescriptorUrl"] == "true"
                and recipe["attributes"]["saml.metadataDescriptorUrl"] == expected_url,
                "temporary client recipe mismatch")
        require(current_raw == after_raw and current["clientId"] == entity
                and current["protocol"] == "saml"
                and current["attributes"]["saml.useMetadataDescriptorUrl"] == "true"
                and current["attributes"]["saml.metadataDescriptorUrl"] == expected_url,
                "temporary client read-back mismatch")
        require(before == final == b"[]\n", "temporary client exact restoration mismatch")
        for persisted in (recipe, current, json.loads(after_raw)):
            for key in (item.lower() for item in walk_keys(persisted)):
                require(key not in {"secret", "registrationaccesstoken", "accesstoken", "password",
                                    "saml.signing.private.key"},
                        "credential-bearing client evidence")
            flat = "\n".join(walk(persisted)).lower()
            require("trustanchor" not in flat and "validatecertificate" not in flat
                    and "signaturevalidation" not in flat, "client exposed source trust setting")
    require(len(ids) == 2, "two sources did not require distinct Keycloak clients")
    relay = [json.loads(line) for line in inside(folder, "relay-requests.jsonl").read_text().splitlines()]
    require(len(relay) == 2, "relay fetch count mismatch")
    expected = {(source["entity"], source["signedMetadataSha256"]) for source in receipt["sources"]}
    require({(row["entityId"], row["responseSha256"]) for row in relay} == expected
            and all(row["httpStatus"] == 200 for row in relay), "relay originals mismatch")


def walk_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_keys(item)


def verify_correlations(folder: Path, receipt: dict) -> None:
    correlations = receipt["correlations"]
    require(len(correlations) == 2, "correlation count mismatch")
    for source, correlation in zip(receipt["sources"], correlations):
        require(correlation["run"] == source["run"] and correlation["entityId"] == source["entity"]
                and correlation["flowStatus"] == "recorded"
                and correlation["statusCode"] == "urn:oasis:names:tc:SAML:2.0:status:Success"
                and len(correlation["originals"]) == 2, "correlation summary mismatch")
        rows = {row["id"]: row for row in read(folder, source["label"] + "-transcript.json")}
        request = rows.get(correlation["requestTranscriptId"])
        response = rows.get(correlation["responseTranscriptId"])
        require(request and response and request["runId"] == response["runId"] == source["run"]
                and request["direction"] == "OUTBOUND" and response["direction"] == "INBOUND"
                and request["timestamp"] < response["timestamp"]
                and request["samlSummary"].get("type") == "AuthnRequest"
                and request["samlSummary"].get("id") == correlation["requestId"]
                and response["samlSummary"].get("type") == "Response"
                and response["samlSummary"].get("inResponseTo") == correlation["requestId"]
                and response["samlSummary"].get("statusCode") == correlation["statusCode"],
                "transcript correlation mismatch")
        originals = {item["id"]: item for item in correlation["originals"]}
        require(set(originals) == {request["id"], response["id"]}, "decoded original set mismatch")
        request_raw = inside(folder, originals[request["id"]]["file"]).read_bytes()
        response_raw = inside(folder, originals[response["id"]]["file"]).read_bytes()
        require(sha(request_raw) == originals[request["id"]]["sha256"]
                and sha(response_raw) == originals[response["id"]]["sha256"],
                "decoded original hash mismatch")
        request_xml, response_xml = ET.fromstring(request_raw), ET.fromstring(response_raw)
        status = response_xml.find("{" + SAMLP + "}Status/{" + SAMLP + "}StatusCode")
        require(request_xml.tag == "{" + SAMLP + "}AuthnRequest"
                and request_xml.get("ID") == correlation["requestId"]
                and response_xml.tag == "{" + SAMLP + "}Response"
                and response_xml.get("InResponseTo") == correlation["requestId"]
                and status is not None and status.get("Value") == correlation["statusCode"]
                and len(response_xml.findall(".//{" + SAML + "}Assertion"))
                    + len(response_xml.findall(".//{" + SAML + "}EncryptedAssertion")) == 1,
                "protocol original semantics mismatch")


def verify_operations_and_restoration(folder: Path, receipt: dict,
                                      operations: dict | None = None,
                                      restoration: dict | None = None) -> None:
    operations = copy.deepcopy(operations if operations is not None
                               else read(folder, receipt["operationCountsFile"]))
    require(operations["nativeConverterCalls"] == 2
            and operations["productConfigurationWrites"] == 2
            and operations["restorationWrites"] == 2
            and operations["protocolRoundTrips"] == 2
            and operations["metadataFetches"] == 2
            and operations["productRestarts"] == operations["humanOperations"] == 0
            and operations["restored"] is True, "operation counts mismatch")
    rows = operations["operations"]
    require([row["operation"] for row in rows] == [
        "temporary-relay-start", "product-client-create", "protocol-roundtrip",
        "product-client-create", "protocol-roundtrip", "product-client-delete",
        "product-client-delete", "temporary-relay-stop",
    ] and [row.get("source") for row in rows if row["operation"] == "product-client-create"]
        == ["source-a", "source-b"]
      and [row.get("source") for row in rows if row["operation"] == "product-client-delete"]
        == ["source-b", "source-a"], "operation order mismatch")
    restoration = copy.deepcopy(restoration if restoration is not None
                                else read(folder, receipt["restorationFile"]))
    empty_sha = sha(b"[]\n")
    require(restoration == {
        "restored": True, "failures": [],
        "beforeSha256": {"source-a": empty_sha, "source-b": empty_sha},
        "finalSha256": {"source-a": empty_sha, "source-b": empty_sha},
        "finalClients": {"source-a": [], "source-b": []},
        "temporaryRelayStopped": True,
    }, "restoration record mismatch")


def verify_formal_result(folder: Path, receipt: dict, result: dict | None = None,
                         configure: dict[str, dict] | None = None) -> None:
    receipt_sha = sha(inside(folder, "receipt.json").read_bytes())
    note = ("Machine-verified Keycloak 26.7.2 metadata-source capability absence; receipt sha256="
            + receipt_sha
            + "; native imports require a client per entity and expose no source-scoped trust anchor")
    result = copy.deepcopy(result if result is not None else read(folder, "result.json"))
    configure = copy.deepcopy(configure if configure is not None else
                              {case: read(folder, case + "-configure.json") for case in CASES})
    cases = case_map(result)
    for case_id in CASES:
        configured = configure[case_id]
        require(configured["runId"] == receipt["primaryRun"] and configured["caseId"] == case_id
                and configured["status"] == "FINISHED", "configuration result identity mismatch")
        outcome = configured["outcome"]
        require((outcome["outcome"], outcome["reasonCode"], outcome["evidence"]) ==
                ("VIOLATED", "capability_absent", [])
                and outcome["details"] == {"configuration_issue": "capability_absent",
                                            "configuration_note": note},
                "configuration capability-absence result mismatch")
        case = cases[case_id]
        require((case["outcome"], case["verdict"], case["reason_code"], case["attested"],
                 case["evidence_class"], case["evidence"]) ==
                ("VIOLATED", "FAIL", "capability_absent", False, "SELF_ATTESTED", []),
                "formal capability-absence result mismatch")
    require(result["run"]["id"] == receipt["primaryRun"]
            and result["run"]["conformance"] == "NON_CONFORMANT",
            "formal Run identity/conformance mismatch")


def verify(folder: Path, receipt: dict | None = None, *, formal=True) -> None:
    folder = folder.resolve()
    raw = inside(folder, "receipt.json").read_bytes()
    parsed = json.loads(raw)
    require(raw == canonical(parsed), "receipt is not canonical")
    receipt = copy.deepcopy(parsed if receipt is None else receipt)
    verify_receipt_identity(receipt)
    verify_suite(folder, receipt)
    verify_target_stability(folder)
    verify_all_jars_scan(folder)
    verify_sources(folder, receipt)
    verify_native_paths(folder, receipt)
    verify_clients_and_relay(folder, receipt)
    verify_correlations(folder, receipt)
    verify_operations_and_restoration(folder, receipt)
    if formal:
        verify_formal_result(folder, receipt)


def tamper(folder: Path) -> list[str]:
    original = read(folder, "receipt.json")
    rejected = []

    def reject(label, mutate):
        value = copy.deepcopy(original)
        mutate(value)
        try:
            verify(folder, value, formal=False)
        except (ValueError, KeyError, TypeError, ET.ParseError, json.JSONDecodeError):
            rejected.append(label)
        else:
            raise AssertionError("tamper control accepted: " + label)

    reject("same-source", lambda value: value["sources"].__setitem__(1,
           copy.deepcopy(value["sources"][0])))
    reject("same-run", lambda value: value.__setitem__("secondaryRun", value["primaryRun"]))
    reject("missing-second-correlation", lambda value: value["correlations"].pop())
    reject("non-success-secondary", lambda value: value["correlations"][1].__setitem__(
           "statusCode", "urn:oasis:names:tc:SAML:2.0:status:Responder"))
    reject("converter-observation-reference", lambda value: value.__setitem__(
           "converterObservationsFile", "receipt.json"))
    reject("term-inventory-reference", lambda value: value.__setitem__(
           "runtimeTermInventoryFile", "receipt.json"))
    reject("term-inventory-hash", lambda value: value.__setitem__(
           "runtimeTermInventorySha256", "0" * 64))
    reject("runtime-capability-reference", lambda value: value.__setitem__(
           "runtimeCapabilityFile", "receipt.json"))
    reject("operation-reference", lambda value: value.__setitem__(
           "operationCountsFile", "receipt.json"))
    reject("restoration-reference", lambda value: value.__setitem__(
           "restorationFile", "receipt.json"))
    reject("suite-image", lambda value: value["suiteRuntime"].__setitem__(
           "imageId", "sha256:" + "0" * 64))
    reject("suite-runner-jar", lambda value: value["suiteRuntime"]["jars"]["runner"].__setitem__(
           "sha256", "0" * 64))
    reject("key-material-reference", lambda value: value.__setitem__(
           "keyMaterialFile", "receipt.json"))

    def reject_direct(label, function):
        try:
            function()
        except (ValueError, KeyError, TypeError, ET.ParseError, json.JSONDecodeError):
            rejected.append(label)
        else:
            raise AssertionError("tamper control accepted: " + label)

    scan = read(folder, "all-jars-native-scan.json")
    missing_jar = copy.deepcopy(scan)
    missing_jar["jars"].pop()
    missing_jar["jarCount"] -= 1
    reject_direct("all-jars-missing", lambda: verify_all_jars_scan(folder, missing_jar))
    unknown_provider = copy.deepcopy(scan)
    description_key = next(key for key in unknown_provider["serviceEntries"]
                           if key.endswith("!META-INF/services/org.keycloak.exportimport.ClientDescriptionConverterFactory"))
    raw = base64.b64decode(unknown_provider["serviceEntries"][description_key]["base64"])
    raw += b"\norg.example.HiddenSamlDescriptionConverter\n"
    unknown_provider["serviceEntries"][description_key] = {
        "sha256": sha(raw), "base64": base64.b64encode(raw).decode(),
    }
    reject_direct("unknown-native-provider", lambda: verify_all_jars_scan(folder, unknown_provider))
    operations = read(folder, original["operationCountsFile"])
    one_client = copy.deepcopy(operations)
    one_client["productConfigurationWrites"] = 1
    one_client["operations"] = [row for row in one_client["operations"]
        if not (row["operation"] in {"product-client-create", "product-client-delete"}
                and row.get("source") == "source-b")]
    reject_direct("second-client-not-required", lambda: verify_operations_and_restoration(
        folder, original, one_client, read(folder, original["restorationFile"])))
    formal = read(folder, "result.json")
    configured = {case: read(folder, case + "-configure.json") for case in CASES}
    wrong_reason = copy.deepcopy(configured)
    wrong_reason[CASES[0]]["outcome"]["reasonCode"] = "configuration.evidence-satisfies"
    reject_direct("wrong-approved-reason", lambda: verify_formal_result(
        folder, original, formal, wrong_reason))
    wrong_case = copy.deepcopy(formal)
    case_map(wrong_case)[CASES[1]]["outcome"] = "SATISFIED"
    reject_direct("wrong-formal-outcome", lambda: verify_formal_result(
        folder, original, wrong_case, configured))
    require(len(rejected) == 18, "tamper self-test count mismatch")
    return rejected


@lru_cache(maxsize=None)
def verify_adoption(root: Path | str):
    """Replay the full gate and its tamper controls once for generator adoption."""
    folder = Path(root).resolve()
    if folder.name != "keycloak-metadata-source-capability-absence-v158":
        folder = folder / "keycloak-metadata-source-capability-absence-v158"
    verify(folder)
    rejected = tamper(folder)
    require(rejected == [
        "same-source", "same-run", "missing-second-correlation", "non-success-secondary",
        "converter-observation-reference", "term-inventory-reference", "term-inventory-hash",
        "runtime-capability-reference", "operation-reference", "restoration-reference",
        "suite-image", "suite-runner-jar", "key-material-reference", "all-jars-missing",
        "unknown-native-provider", "second-client-not-required", "wrong-approved-reason",
        "wrong-formal-outcome",
    ], "tamper rejection inventory mismatch")
    result_path = folder / "result.json"
    result = json.loads(result_path.read_text())
    cases = case_map(result)
    require(set(CASES) <= set(cases), "formal result omits an adopted case")
    return result_path, {case: cases[case] for case in CASES}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--tamper", action="store_true")
    args = parser.parse_args()
    folder = args.folder.resolve()
    verify(folder)
    rejected = tamper(folder) if args.tamper else []
    report = {
        "schema": "samlscope-keycloak-metadata-source-capability-acceptance-v1",
        "folder": folder.name,
        "verified": True,
        "adoptedCases": CASES,
        "tamperControlsRejected": rejected,
        "formalReduction": 2,
    }
    (folder / "acceptance-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(folder.name, "verified;", len(rejected), "tamper controls rejected")


if __name__ == "__main__":
    main()
