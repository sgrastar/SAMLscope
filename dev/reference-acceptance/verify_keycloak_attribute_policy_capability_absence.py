#!/usr/bin/env python3
"""Verify Keycloak IDP03.a/IDP04.a capability absence from retained originals.

This verifier fails closed.  A converter output alone is insufficient: both installed
metadata-import paths, the complete installed SAML mapper inventory, implementation bytecode,
all approved fixture conversions, a correlated normal SSO control, formal Run outcomes, and
exact deletion/read-back restoration must agree.  IDP04.b has test-precondition semantics and
is explicitly forbidden from adoption by this verifier.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET
import zipfile

FOLDER = "keycloak-attribute-policy-capability-absence-v159"
TARGET_ENTITY = "http://localhost:18180/realms/samlscope"
IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
CASES = ["IIP-IDP03-a-idp-01", "IIP-IDP04-a-idp-01"]
INELIGIBLE = "IIP-IDP04-b-idp-01"
CONDITIONS = [
    ("entity-present", "attribute-policy-entity-present"),
    ("entity-absent", "attribute-policy-entity-absent"),
    ("requested-required", "attribute-policy-requested-required"),
    ("requested-optional", "attribute-policy-requested-optional"),
    ("requested-absent", "attribute-policy-requested-absent"),
    ("indexed", "attribute-policy-indexed"),
    ("baseline", "control"),
]
UID = "urn:oid:0.9.2342.19200300.100.1.1"
SURNAME = "urn:oid:2.5.4.4"
FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

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
EXPECTED_REFERENCE_INVENTORY = {
    "org/keycloak/protocol/saml/EntityDescriptorDescriptionConverter.class":
        ["RequestedAttribute", "AttributeConsumingService"],
    "org/keycloak/broker/saml/SAMLIdentityProvider.class": ["AttributeConsumingService"],
    "org/keycloak/broker/saml/SAMLIdentityProviderConfig.class": ["AttributeConsumingService"],
    "org/keycloak/broker/saml/mappers/AttributeToRoleMapper.class":
        ["RequestedAttribute", "AttributeConsumingService"],
    "org/keycloak/broker/saml/mappers/XPathAttributeMapper.class":
        ["RequestedAttribute", "AttributeConsumingService"],
    "org/keycloak/broker/saml/mappers/UserAttributeMapper.class":
        ["RequestedAttribute", "AttributeConsumingService"],
    "org/keycloak/broker/saml/SAMLIdentityProviderFactory.class": ["EntityAttributes"],
}


def require(value, message="invalid Keycloak attribute-policy capability evidence"):
    if not value:
        raise ValueError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load(folder: Path, name: str):
    return json.loads((folder / name).read_text())


def inside(folder: Path, relative: str) -> Path:
    path = (folder / relative).resolve()
    require(path.is_relative_to(folder.resolve()) and path.is_file(), "original escaped evidence folder")
    return path


def case_map(result: dict) -> dict:
    return {case["id"]: case for requirement in result["requirements"]
            for case in requirement["cases"]}


def parse_service(raw: bytes) -> set[str]:
    return {line.strip() for line in raw.decode().splitlines()
            if line.strip() and not line.lstrip().startswith("#")}


def fixture_semantics(raw: bytes, label: str, entity: str) -> None:
    md = "urn:oasis:names:tc:SAML:2.0:metadata"
    saml = "urn:oasis:names:tc:SAML:2.0:assertion"
    mdattr = "urn:oasis:names:tc:SAML:metadata:attribute"
    root = ET.fromstring(raw)
    require(root.tag == "{" + md + "}EntityDescriptor" and root.get("entityID") == entity,
            "fixture entity mismatch")
    roles = root.findall("{" + md + "}SPSSODescriptor")
    require(len(roles) == 1, "fixture SP role mismatch")
    entity_attributes = root.findall("{" + md + "}Extensions/{" + mdattr + "}EntityAttributes")
    if label == "entity-present":
        require(len(entity_attributes) == 1 and len(entity_attributes[0]) == 1,
                "EntityAttributes positive fixture is incomplete")
        attribute = entity_attributes[0][0]
        require(attribute.tag == "{" + saml + "}Attribute"
                and attribute.attrib == {"Name": "urn:samlscope:test:release-policy",
                                          "NameFormat": FORMAT}
                and len(attribute) == 1 and attribute[0].text == "release",
                "EntityAttributes content mismatch")
    else:
        require(not entity_attributes, "unexpected EntityAttributes control")
    services = roles[0].findall("{" + md + "}AttributeConsumingService")
    if label in {"requested-required", "requested-optional"}:
        names = [UID]
    elif label == "indexed":
        names = [UID, SURNAME]
    else:
        names = []
    require(len(services) == len(names), "AttributeConsumingService fixture mismatch")
    for index, (service, name) in enumerate(zip(services, names)):
        require(service.get("index") == str(index), "service index mismatch")
        requested = service.findall("{" + md + "}RequestedAttribute")
        require(len(requested) == 1 and not len(requested[0]), "RequestedAttribute fixture mismatch")
        expected = {"Name": name, "NameFormat": FORMAT,
                    "isRequired": "false" if label == "requested-optional" else "true"}
        require(requested[0].attrib == expected, "RequestedAttribute semantics mismatch")


def verify_normal_control_import(raw: bytes, converted: dict, entity: str) -> None:
    md = "urn:oasis:names:tc:SAML:2.0:metadata"
    root = ET.fromstring(raw)
    require(root.tag == "{" + md + "}EntityDescriptor" and root.get("entityID") == entity,
            "normal-control metadata identity mismatch")
    roles = root.findall("{" + md + "}SPSSODescriptor")
    require(len(roles) == 1 and roles[0].find("{" + md + "}AssertionConsumerService") is not None,
            "normal-control metadata lacks an SP endpoint")
    require(converted.get("clientId") == entity and converted.get("protocol") == "saml"
            and converted.get("enabled", True) is True
            and converted.get("attributes", {}).get("saml.client.signature") == "true",
            "stable metadata was not converted into the expected signed SAML client")


def mapper_projection(value: dict) -> dict:
    return {key: value.get(key) for key in ("name", "protocol", "protocolMapper", "config")}


def verify_converter_semantics(outputs: dict[str, dict], entity: str) -> None:
    require(set(outputs) == {label for label, _ in CONDITIONS}, "converter condition set mismatch")
    for label, output in outputs.items():
        require(isinstance(output, dict) and output.get("clientId") == entity
                and output.get("protocol") == "saml", "converter did not create the expected SAML client")
        encoded = json.dumps(output, sort_keys=True)
        require(all(term not in encoded for term in
                    ("EntityAttributes", "isRequired", "AttributeConsumingServiceIndex")),
                "converter retained a policy input")
        mappers = [mapper_projection(value) for value in output.get("protocolMappers") or []]
        if label in {"baseline", "entity-present", "entity-absent", "requested-absent"}:
            require(mappers == [], "converter created an unexpected attribute mapper")
        elif label in {"requested-required", "requested-optional"}:
            require(len(mappers) == 1, "converter did not create exactly one requested mapper")
            mapper = mappers[0]
            require(mapper == {"name": UID, "protocol": "saml",
                               "protocolMapper": "saml-user-attribute-mapper",
                               "config": {"attribute.name": UID,
                                          "attribute.nameformat": "URI Reference"}},
                    "requested mapper semantics changed")
        elif label == "indexed":
            require({mapper["name"] for mapper in mappers} == {UID, SURNAME}
                    and all(mapper["protocol"] == "saml"
                            and mapper["protocolMapper"] == "saml-user-attribute-mapper"
                            and mapper["config"] == {"attribute.name": mapper["name"],
                                                     "attribute.nameformat": "URI Reference"}
                            for mapper in mappers), "indexed mapper semantics changed")
    require([mapper_projection(value) for value in outputs["requested-required"]["protocolMappers"]]
            == [mapper_projection(value) for value in outputs["requested-optional"]["protocolMappers"]],
            "isRequired unexpectedly affects converted state")
    for left, right in (("baseline", "entity-present"), ("baseline", "entity-absent")):
        require((outputs[left].get("protocolMappers") or []) ==
                (outputs[right].get("protocolMappers") or []),
                "EntityAttributes unexpectedly affects converted state")


def verify_runtime(folder: Path) -> str:
    runtime = load(folder, "runtime-capability.json")
    require(runtime["schema"] == "samlscope-keycloak-attribute-policy-capability-v1",
            "runtime manifest schema mismatch")
    require(runtime["imageId"] == IMAGE
            and runtime["configuredImage"] == "quay.io/keycloak/keycloak@" + IMAGE,
            "unrecognized Keycloak image")
    require(runtime["productConfigurationWrites"] == runtime["productRestarts"] ==
            runtime["humanOperations"] == 0, "runtime capture mutated the target")
    inspect_rows = load(folder, "target-container-inspect.json")
    require(isinstance(inspect_rows, list) and len(inspect_rows) == 1, "container inspect ambiguity")
    inspect = inspect_rows[0]
    require(inspect["Id"] == runtime["containerId"] and inspect["Image"] == IMAGE
            and inspect["State"]["Running"] is True
            and inspect["State"]["StartedAt"] == runtime["containerStartedAt"],
            "runtime container identity mismatch")
    for mount in inspect.get("Mounts", []):
        destination = mount.get("Destination", "").rstrip("/")
        for key in ("servicesJarPath", "samlJarPath"):
            path = runtime[key].rstrip("/")
            require(not (path == destination or path.startswith(destination + "/")),
                    "runtime JAR is covered by a host mount")
    image_rows = load(folder, "target-image-inspect.json")
    require(isinstance(image_rows, list) and len(image_rows) == 1 and image_rows[0]["Id"] == IMAGE,
            "image inspect mismatch")
    providers_inventory = (folder / "providers-inventory.txt").read_bytes()
    provider_readme = (folder / "providers-README.md").read_bytes()
    require(providers_inventory == b"./README.md\n"
            and sha(providers_inventory) == runtime["providersInventorySha256"]
            and sha(provider_readme) == runtime["providersReadmeSha256"],
            "custom provider directory is not empty or is unbound")

    jar = folder / "keycloak-services-runtime.jar"
    saml_jar = folder / "keycloak-saml-core-public-runtime.jar"
    require(sha(jar.read_bytes()) == runtime["servicesJarSha256"]
            and sha(saml_jar.read_bytes()) == runtime["samlJarSha256"], "runtime JAR hash mismatch")
    server_path = folder / "serverinfo-native-inventory.json"
    require(sha(server_path.read_bytes()) == runtime["serverInfoSha256"], "server inventory hash mismatch")
    server = json.loads(server_path.read_text())
    expected_path_providers = {
        "client-description-converter": {"keycloak", "saml2-entity-descriptor", "openid-connect"},
        "client-registration": {"default", "install", "saml2-entity-descriptor", "openid-connect"},
    }
    for spi, expected in expected_path_providers.items():
        require(set(server["providers"][spi]["providers"]) == expected,
                "installed native import provider set changed")
    schemas = server["protocolMapperTypes"]["saml"]
    require(isinstance(schemas, list) and {item["id"] for item in schemas} == set(MAPPERS),
            "installed SAML mapper schemas changed")
    require(set(server["providers"]["protocol-mapper"]["providers"]) >= set(MAPPERS),
            "SPI provider inventory omits an installed SAML mapper")
    forbidden_properties = {"EntityAttributes", "RequestedAttribute", "isRequired",
                            "AttributeConsumingService", "AttributeConsumingServiceIndex"}
    for schema in schemas:
        names = {item.get("name") for item in schema.get("properties", [])}
        require(not names.intersection(forbidden_properties),
                "installed mapper exposes an unreviewed metadata-policy input")

    class_records = runtime["classRecords"]
    expected_classes = {**PATH_CLASSES, **{"mapper." + key: value for key, value in MAPPERS.items()}}
    require(set(class_records) == set(expected_classes), "class inventory mismatch")
    disassembly = {}
    with zipfile.ZipFile(jar) as archive:
        for label, class_name in expected_classes.items():
            record = class_records[label]
            entry = class_name.replace(".", "/") + ".class"
            require(record["className"] == class_name and record["jarEntry"] == entry,
                    "class record identity mismatch")
            class_raw = archive.read(entry)
            class_path = inside(folder, record["classFile"])
            require(class_path.read_bytes() == class_raw and sha(class_raw) == record["classSha256"],
                    "retained class is not from the runtime JAR")
            replay = subprocess.check_output(["javap", "-classpath", str(jar), "-c", "-p", class_name])
            javap_path = inside(folder, record["javapFile"])
            require(javap_path.read_bytes() == replay and sha(replay) == record["javapSha256"],
                    "retained disassembly replay mismatch")
            disassembly[label] = replay

        services = {}
        for label, record in runtime["serviceEntries"].items():
            raw = archive.read(record["jarEntry"])
            path = inside(folder, record["file"])
            require(path.read_bytes() == raw and sha(raw) == record["sha256"],
                    "service entry mismatch")
            services[label] = parse_service(raw)
    require(services["descriptionConverterFactories"] == {
        "org.keycloak.exportimport.KeycloakClientDescriptionConverter",
        "org.keycloak.protocol.oidc.OIDCClientDescriptionConverterFactory",
        "org.keycloak.protocol.saml.EntityDescriptorDescriptionConverter",
    }, "description converter factory inventory changed")
    require("org.keycloak.protocol.saml.clientregistration.EntityDescriptorClientRegistrationProviderFactory"
            in services["clientRegistrationFactories"], "SAML registration path is absent")
    require({value for value in services["protocolMappers"] if value in set(MAPPERS.values())}
            == set(MAPPERS.values()), "SAML mapper service inventory mismatch")

    admin = disassembly["adminConverterResource"]
    require(all(token in admin for token in (b"getProviderFactoriesStream", b"ClientDescriptionConverterFactory",
                                               b"isSupported", b"convertToInternal")),
            "administration import path no longer reaches the converter SPI")
    registration = disassembly["registrationProvider"]
    require(all(token in registration for token in
                (b"ClientDescriptionConverter", b"saml2-entity-descriptor", b"convertToInternal")),
            "client-registration import path no longer reaches the SAML converter")
    factory = disassembly["registrationProviderFactory"]
    require(b"saml2-entity-descriptor" in factory, "registration factory ID changed")
    converter = disassembly["metadataConverter"]
    require(all(token in converter for token in
                (b"getAttributeConsumingService", b"getRequestedAttribute", b"RequestedAttributeType.getName",
                 b"RequestedAttributeType.getFriendlyName", b"RequestedAttributeType.getNameFormat")),
            "metadata converter's requested-attribute path changed")
    require(b"isIsRequired" not in converter and b"EntityAttributes" not in converter,
            "metadata converter gained an unreviewed policy input")
    protocol = disassembly["samlProtocol"]
    require(all(token in protocol for token in
                (b"ProtocolMapperUtils.getSortedProtocolMappers", b"populateAttributeStatements",
                 b"SAMLAttributeStatementMapper.transformAttributeStatement", b"ProtocolMapperModel")),
            "SAML output mapper execution path changed")
    for mapper in MAPPERS:
        raw = disassembly["mapper." + mapper]
        if mapper in ATTRIBUTE_OUTPUT_MAPPERS:
            expected_interface = (b"SAMLRoleListMapper" if mapper == "saml-role-list-mapper"
                                  else b"SAMLAttributeStatementMapper")
            require(expected_interface in raw, "declared attribute output mapper changed type")
        require(all(term.encode() not in raw for term in REFERENCE_TERMS),
                "installed mapper directly consumes metadata-policy objects")

    inventory_path = folder / "metadata-reference-inventory.json"
    require(sha(inventory_path.read_bytes()) == runtime["referenceInventorySha256"],
            "reference inventory hash mismatch")
    inventory = json.loads(inventory_path.read_text())
    replay_inventory = {}
    with zipfile.ZipFile(jar) as archive:
        for entry in archive.namelist():
            if entry.endswith(".class"):
                raw = archive.read(entry)
                hits = [term for term in REFERENCE_TERMS if term.encode() in raw]
                if hits:
                    replay_inventory[entry] = hits
    require(inventory == replay_inventory == EXPECTED_REFERENCE_INVENTORY,
            "runtime metadata reference inventory changed")
    require(runtime["installedSamlMappers"] == sorted(MAPPERS)
            and runtime["attributeOutputMappers"] == sorted(ATTRIBUTE_OUTPUT_MAPPERS),
            "runtime mapper classification mismatch")
    return sha((folder / "runtime-capability.json").read_bytes())


def verify_normal_sso(folder: Path, run: str, entity: str) -> None:
    transcript_list = load(folder, "transcript.json")
    transcript = {entry["id"]: entry for entry in transcript_list}
    require(len(transcript) == len(transcript_list)
            and all(entry["runId"] == run for entry in transcript.values()),
            "transcript inventory mismatch")
    originals = {}
    for item in load(folder, "decoded-manifest.json"):
        path = inside(folder, item["file"])
        raw = path.read_bytes()
        require(item["id"] not in originals and item["sha256"] == sha(raw),
                "decoded original hash mismatch")
        originals[item["id"]] = raw
    flow = load(folder, "normal-sso.json")
    refs = flow["newTranscriptIds"]
    require(flow["status"] == "recorded" and len(refs) == 2
            and all(ref in transcript and ref in originals for ref in refs),
            "normal SSO control is incomplete")
    request_ref, response_ref = refs
    request, response = ET.fromstring(originals[request_ref]), ET.fromstring(originals[response_ref])
    protocol = "urn:oasis:names:tc:SAML:2.0:protocol"
    require(request.tag == "{" + protocol + "}AuthnRequest"
            and response.tag == "{" + protocol + "}Response", "normal SSO original types mismatch")
    request_id = request.get("ID")
    require(response.get("InResponseTo") == request_id
            and transcript[request_ref]["correlationId"] ==
                transcript[response_ref]["correlationId"] == request_id,
            "normal SSO correlation mismatch")
    require(transcript[request_ref]["direction"] == "OUTBOUND"
            and transcript[response_ref]["direction"] == "INBOUND"
            and transcript[request_ref]["timestamp"] < transcript[response_ref]["timestamp"],
            "normal SSO direction/order mismatch")
    summaries = transcript[request_ref]["samlSummary"], transcript[response_ref]["samlSummary"]
    require(summaries[0].get("type") == "AuthnRequest"
            and summaries[0].get("id") == request_id
            and summaries[1].get("issuer") == TARGET_ENTITY
            and summaries[1].get("normalFlowAccepted") is True
            and summaries[1].get("inResponseTo") == request_id,
            "normal SSO summary mismatch")
    status = response.find("{" + protocol + "}Status/{" + protocol + "}StatusCode")
    require(status is not None and status.get("Value", "").endswith(":Success"),
            "normal SSO did not return Success")
    baseline = ET.fromstring((folder / "normal-control/fixture.xml").read_bytes())
    acs = {item.get("Location") for item in baseline.iter()
           if item.tag.endswith("AssertionConsumerService")}
    require(response.get("Destination") == transcript[response_ref]["url"]
            and response.get("Destination") in acs, "normal SSO destination mismatch")


def verify_restoration(operations: dict, restoration: dict, before: bytes, after: bytes, run: str) -> None:
    require(operations["run"] == run and operations["metadataConverterCalls"] == len(CONDITIONS) + 1
            and operations["productConfigurationWrites"] == 2
            and operations["productRestarts"] == 0 and operations["protocolRoundTrips"] == 1
            and operations["humanOperations"] == 0 and operations["restored"] is True,
            "operation counts mismatch")
    require(restoration["restored"] is True and restoration["failures"] == []
            and restoration["existingClientsOverwritten"] is False
            and re.fullmatch(r"[0-9a-f-]{36}", restoration["temporaryClientId"] or "")
            and before == after == b"[]\n"
            and restoration["beforeSha256"] == restoration["afterSha256"] == sha(before),
            "exact target restoration is unproven")
    statuses = [(row["method"], row["path"], row["status"]) for row in operations["adminOperations"]]
    require(sum(method == "POST" and path == "/client-description-converter" and status == 200
                for method, path, status in statuses) == len(CONDITIONS) + 1,
            "native converter call inventory mismatch")
    require(sum(method == "POST" and path == "/clients" and status == 201
                for method, path, status in statuses) == 1
            and sum(method == "DELETE" and path.startswith("/clients/") and status == 204
                    for method, path, status in statuses) == 1,
            "temporary client mutation inventory mismatch")
    require(all(status in {200, 201, 204} for _, _, status in statuses),
            "failed native administration operation")


def verify_result_semantics(result: dict, configure: dict[str, dict], manifest_sha: str) -> dict:
    expected_note = ("Machine-verified Keycloak 26.7.2 runtime evidence: every installed SAML metadata "
        "import path converges on EntityDescriptorDescriptionConverter; the converter drops "
        "mdattr:EntityAttributes and RequestedAttribute/@isRequired, and no installed SAML "
        "attribute-statement mapper can recover those inputs. Evidence manifest sha256=" + manifest_sha)
    for case in CASES:
        value = configure[case]
        require(value["caseId"] == case and value["status"] == "FINISHED", "configure result identity mismatch")
        outcome = value["outcome"]
        require((outcome["outcome"], outcome["reasonCode"], outcome["evidence"]) ==
                ("VIOLATED", "capability_absent", []), "configuration outcome mismatch")
        require(outcome["details"] == {"configuration_issue": "capability_absent",
                                       "configuration_note": expected_note},
                "configuration note is not bound to runtime evidence")
    cases = case_map(result)
    for case in CASES:
        value = cases[case]
        require((value["outcome"], value["verdict"], value["reason_code"], value["attested"],
                 value["evidence_class"], value["evidence"]) ==
                ("VIOLATED", "FAIL", "capability_absent", False, "OPERATOR_ASSISTED", []),
                "formal capability-absence result mismatch")
    ineligible = cases[INELIGIBLE]
    require(ineligible["outcome"] == "NOT_VERIFIED" and ineligible["verdict"] == "NOT_VERIFIED"
            and ineligible["reason_code"] != "capability_absent",
            "IDP04.b was incorrectly adopted from test-precondition absence")
    require(result["run"]["conformance"] == "NON_CONFORMANT", "MUST violations did not affect conformance")
    return cases


def run_tamper_controls(outputs: dict[str, dict], server: dict, result: dict,
                        configure: dict[str, dict], operations: dict, restoration: dict,
                        before: bytes, after: bytes, run: str, manifest_sha: str) -> list[str]:
    rejected = []

    def reject(label, function):
        try:
            function()
        except (ValueError, AssertionError, KeyError, TypeError):
            rejected.append(label)
        else:
            raise AssertionError("tamper control accepted: " + label)

    forged = copy.deepcopy(outputs)
    forged["entity-present"].setdefault("protocolMappers", []).append({"name": "forged"})
    reject("entity-attribute-output", lambda: verify_converter_semantics(forged,
           outputs["baseline"]["clientId"]))
    forged = copy.deepcopy(outputs)
    forged["requested-optional"]["protocolMappers"][0]["config"]["required"] = "false"
    reject("is-required-output", lambda: verify_converter_semantics(forged,
           outputs["baseline"]["clientId"]))
    altered_server = copy.deepcopy(server)
    altered_server["protocolMapperTypes"]["saml"].append({"id": "saml-hidden-policy-mapper", "properties": []})
    reject("hidden-installed-mapper", lambda: require(
        {item["id"] for item in altered_server["protocolMapperTypes"]["saml"]} == set(MAPPERS)))
    altered_result = copy.deepcopy(result)
    case_map(altered_result)[INELIGIBLE]["outcome"] = "VIOLATED"
    case_map(altered_result)[INELIGIBLE]["verdict"] = "FAIL"
    case_map(altered_result)[INELIGIBLE]["reason_code"] = "capability_absent"
    reject("idp04b-adoption", lambda: verify_result_semantics(
        altered_result, configure, manifest_sha))
    altered_configure = copy.deepcopy(configure)
    altered_configure[CASES[0]]["outcome"]["details"]["configuration_note"] = "unbound"
    reject("unbound-configuration-note", lambda: verify_result_semantics(
        result, altered_configure, manifest_sha))
    altered_restoration = copy.deepcopy(restoration)
    altered_restoration["restored"] = False
    reject("missing-restoration", lambda: verify_restoration(
        operations, altered_restoration, before, after, run))
    altered_operations = copy.deepcopy(operations)
    altered_operations["productConfigurationWrites"] = 1
    reject("operation-count", lambda: verify_restoration(
        altered_operations, restoration, before, after, run))
    require(len(rejected) == 7, "tamper control inventory mismatch")
    return rejected


def verify_evidence(folder: Path, tamper=False) -> tuple[Path, dict, list[str]]:
    folder = Path(folder).resolve()
    result = load(folder, "result.json")
    run = result["run"]["id"]
    require(re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", run), "invalid Run ID")
    plan = load(folder, "plan.json")["plan"]["plan"]
    require(re.fullmatch(r"plan_[0-9A-HJKMNP-TV-Z]{26}", plan["id"])
            and plan["profile"] == "browser_sso_idp"
            and plan["target"] == {"kind": "IDP", "entityId": TARGET_ENTITY,
                                   "connectionId": None, "metadataRevisionId": None},
            "plan target mismatch")
    require(load(folder, "created.json")["run"]["id"] == run
            and load(folder, "run-after.json")["id"] == run
            and load(folder, "run-after.json")["status"] == "COMPLETED", "Run identity/status mismatch")
    entity = "http://localhost:18080/p/" + plan["id"]

    records = load(folder, "converter-observations.json")
    require([(item["label"], item["variant"]) for item in records] == CONDITIONS,
            "converter observation order mismatch")
    outputs = {}
    for record in records:
        label = record["label"]
        fixture_raw = (folder / label / "fixture.xml").read_bytes()
        output_raw = (folder / label / "converter-output.json").read_bytes()
        require(record["fixtureSha256"] == sha(fixture_raw)
                and record["converterOutputSha256"] == sha(output_raw), "converter original hash mismatch")
        fixture_semantics(fixture_raw, label, entity)
        outputs[label] = json.loads(output_raw)
    verify_converter_semantics(outputs, entity)

    control_manifest = load(folder / "normal-control", "manifest.json")
    control_fixture_raw = (folder / "normal-control/fixture.xml").read_bytes()
    control_output_raw = (folder / "normal-control/converter-output.json").read_bytes()
    require(control_manifest == {"fixtureSha256": sha(control_fixture_raw),
                                 "converterOutputSha256": sha(control_output_raw)},
            "normal-control originals do not match their manifest")
    control_output = json.loads(control_output_raw)
    verify_normal_control_import(control_fixture_raw, control_output, entity)

    configured_raw = (folder / "configured-client-readback.json").read_bytes()
    require((folder / "configured-client-after-sso.json").read_bytes() == configured_raw,
            "temporary client configuration changed during SSO")
    configured = json.loads(configured_raw)
    baseline = control_output
    require(configured["clientId"] == entity and configured["protocol"] == "saml"
            and (configured.get("protocolMappers") or []) == (baseline.get("protocolMappers") or []),
            "created client does not match native baseline conversion")
    encoded_client = configured_raw.lower()
    require(all(token not in encoded_client for token in
                (b'"secret":', b'"registrationaccesstoken":', b'"accesstoken":', b'"password":')),
            "credential-bearing client evidence")
    redaction = load(folder, "client-readback-redaction.json")
    require(redaction == {"run": run,
                          "temporaryClientId": load(folder, "restoration.json")["temporaryClientId"],
                          "redactedFields": ["/secret"],
                          "fullRepresentationsEqualInMemory": True,
                          "credentialValuesPersisted": False},
            "client credential redaction record mismatch")
    require(all(term.encode().lower() not in encoded_client for term in REFERENCE_TERMS),
            "configured client retained metadata-policy objects")

    before = (folder / "client-before.json").read_bytes()
    after = (folder / "client-after.json").read_bytes()
    operations, restoration = load(folder, "operations.json"), load(folder, "restoration.json")
    verify_restoration(operations, restoration, before, after, run)
    manifest_sha = verify_runtime(folder)
    verify_normal_sso(folder, run, entity)

    configure = {case: load(folder, case + "-configure.json") for case in CASES}
    require(not (folder / (INELIGIBLE + "-configure.json")).exists(), "IDP04.b configure record must not exist")
    cases = verify_result_semantics(result, configure, manifest_sha)
    metadata = folder / "target-metadata.xml"
    require(result["target"]["metadata_digest"] == "sha256:" + sha(metadata.read_bytes()),
            "target metadata digest mismatch")
    entities = {element.get("entityID") for element in ET.fromstring(metadata.read_bytes()).iter()
                if element.tag.endswith("EntityDescriptor")}
    require(TARGET_ENTITY in entities, "target metadata entity mismatch")

    rejected = []
    if tamper:
        server = load(folder, "serverinfo-native-inventory.json")
        rejected = run_tamper_controls(outputs, server, result, configure, operations, restoration,
                                       before, after, run, manifest_sha)
    return folder / "result.json", cases, rejected


def verify(root):
    result, cases, _ = verify_evidence(Path(root) / FOLDER, tamper=False)
    return result, cases


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path,
        help="Either the evidence folder itself or its reference-20260930 parent")
    parser.add_argument("--tamper", action="store_true")
    args = parser.parse_args()
    folder = args.root.resolve()
    if folder.name != FOLDER:
        folder = folder / FOLDER
    result, verified, rejected = verify_evidence(folder, tamper=args.tamper)
    report = {"schema": "samlscope-keycloak-attribute-policy-capability-acceptance-v1",
              "result": str(result), "adoptedCases": CASES,
              "ineligibleCases": [INELIGIBLE], "tamperRejections": rejected}
    (folder / "acceptance-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
