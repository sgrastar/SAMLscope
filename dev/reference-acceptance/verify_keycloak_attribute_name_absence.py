"""Adopt Keycloak IDP01.a only from replayable runtime capability evidence.

The approved case allows a product violation for ``normative_capability`` only
when the required configuration capability is absent.  A failed attempt to set
one mapper is therefore insufficient.  This verifier binds the Run result to
the complete installed SAML mapper inventory, the runtime implementation JAR,
all six attribute-producing mapper implementations, an independently replayed
helper harness, the correlated protocol observations, and exact restoration.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile


CASE = "IIP-IDP01-a-idp-01"
FOLDER = "keycloak-attribute-name-capability-absence-v157"
TARGET_ENTITY = "http://localhost:18180/realms/samlscope"
OPTIONS = ["Basic", "URI Reference", "Unspecified"]
PRODUCERS = {
    "saml-group-membership-mapper": "org.keycloak.protocol.saml.mappers.GroupMembershipMapper",
    "saml-hardcode-attribute-mapper": "org.keycloak.protocol.saml.mappers.HardcodedAttributeMapper",
    "saml-role-list-mapper": "org.keycloak.protocol.saml.mappers.RoleListMapper",
    "saml-user-attribute-mapper": "org.keycloak.protocol.saml.mappers.UserAttributeStatementMapper",
    "saml-user-property-mapper": "org.keycloak.protocol.saml.mappers.UserPropertyAttributeStatementMapper",
    "saml-user-session-note-mapper": "org.keycloak.protocol.saml.mappers.UserSessionNoteStatementMapper",
}
EXPECTED_EXECUTION = (
    b"Basic\turn:oasis:names:tc:SAML:2.0:attrname-format:basic\n"
    b"URI Reference\turn:oasis:names:tc:SAML:2.0:attrname-format:uri\n"
    b"Unspecified\turn:oasis:names:tc:SAML:2.0:attrname-format:unspecified\n"
    b"urn:samlscope:test:attribute-name-format\t"
    b"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\n"
)
EXPECTED_SOURCE = b"""import java.util.Map;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
public final class VerifyKCNameFormat {
 public static void main(String[] args) {
  for (String value : new String[]{\"Basic\",\"URI Reference\",\"Unspecified\",\"urn:samlscope:test:attribute-name-format\"}) {
   var model=new ProtocolMapperModel();
   model.setConfig(Map.of(\"attribute.name\",\"urn:samlscope:test:attribute-name\",\"attribute.nameformat\",value));
   var attribute=AttributeStatementHelper.createAttributeType(model);
   System.out.println(value+\"\\t\"+attribute.getNameFormat());
  }
 }
}
"""


def _require(value: object, message: str) -> None:
    if not value:
        raise AssertionError(message)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read(folder: Path, name: str):
    return json.loads((folder / name).read_text())


def _inside(folder: Path, relative: str) -> Path:
    path = (folder / relative).resolve()
    _require(path.parent == (folder / "decoded").resolve(), "decoded original escaped its directory")
    return path


def _case_map(result: dict) -> dict:
    return {case["id"]: case for requirement in result["requirements"] for case in requirement["cases"]}


def _verify_protocol_originals(folder: Path, run: str, plan_id: str, observations: list) -> None:
    transcript_rows = _read(folder, "transcript.json")
    transcript = {row["id"]: row for row in transcript_rows}
    manifest_rows = _read(folder, "decoded-manifest.json")
    manifest = {row["id"]: row for row in manifest_rows}
    refs = [ref for observation in observations for ref in observation["new_transcript_ids"]]
    _require(len(refs) == len(set(refs)) == 4, "expected two distinct request/response pairs")
    _require(set(refs) == set(transcript) == set(manifest), "transcript/original inventory mismatch")

    roots = {}
    for reference in refs:
        row = manifest[reference]
        _require(row["id"] == reference, "decoded manifest ID mismatch")
        path = _inside(folder, row["file"])
        raw = path.read_bytes()
        _require(hashlib.sha256(raw).hexdigest() == row["sha256"], "decoded original hash mismatch")
        entry = transcript[reference]
        _require(entry["runId"] == run, "cross-Run transcript entry")
        _require(entry["decodedSamlBytes"] == len(raw), "decoded original length mismatch")
        _require(entry["decodedSamlRef"].endswith("/" + reference + ".saml.xml"), "decoded reference mismatch")
        roots[reference] = ET.fromstring(raw)

    protocol = "urn:oasis:names:tc:SAML:2.0:protocol"
    expected_acs = f"http://localhost:18080/p/{plan_id}/sp/acs/0"
    for observation in observations:
        request_ref, response_ref = observation["new_transcript_ids"]
        request_entry, response_entry = transcript[request_ref], transcript[response_ref]
        request, response = roots[request_ref], roots[response_ref]
        _require(request.tag == f"{{{protocol}}}AuthnRequest", "outbound original is not AuthnRequest")
        _require(response.tag == f"{{{protocol}}}Response", "inbound original is not Response")
        request_id = request.attrib["ID"]
        _require(request_entry["direction"] == "OUTBOUND" and request_entry["method"] == "GET",
                 "request transcript direction/method mismatch")
        _require(response_entry["direction"] == "INBOUND" and response_entry["method"] == "POST",
                 "response transcript direction/method mismatch")
        _require(request_entry["correlationId"] == response_entry["correlationId"] == request_id,
                 "request/response correlation mismatch")
        _require(response.attrib.get("InResponseTo") == request_id, "Response InResponseTo mismatch")
        _require(request_entry["timestamp"] < response_entry["timestamp"], "response predates request")
        _require(response.attrib.get("Destination") == response_entry["url"] == expected_acs,
                 "Response ACS mismatch")
        status = response.find(f"{{{protocol}}}Status/{{{protocol}}}StatusCode")
        _require(status is not None and status.attrib.get("Value", "").endswith(":Success"),
                 "normal control did not return SAML Success")
        summary = response_entry["samlSummary"]
        _require(summary.get("normalFlowAccepted") is True, "Suite did not accept normal flow")
        _require(summary.get("issuer") == TARGET_ENTITY, "response issuer mismatch")
        _require(summary.get("inResponseTo") == request_id, "summary correlation mismatch")


def _verify_runtime(folder: Path) -> str:
    runtime = _read(folder, "runtime-capability.json")
    _require(runtime["schema"] == "samlscope-keycloak-attribute-nameformat-capability-v1",
             "unexpected capability manifest schema")
    _require(runtime["product_configuration_writes"] == 0, "runtime capture changed product configuration")
    _require(runtime["product_restarts"] == 0 and runtime["human_operations"] == 0,
             "runtime capture was not unattended/non-restarting")
    _require(runtime["accepted_configuration_tokens"] == OPTIONS, "accepted token claim changed")
    _require(runtime["unknown_value_falls_back_to_basic"] is True, "fallback claim missing")

    inspect_rows = _read(folder, "target-container-inspect.json")
    _require(isinstance(inspect_rows, list) and len(inspect_rows) == 1, "container inspect is ambiguous")
    inspect = inspect_rows[0]
    _require(inspect["Id"] == runtime["container_id"], "container identity mismatch")
    _require(inspect["Image"] == runtime["image_id"], "container image mismatch")
    _require(inspect["State"]["Running"] is True and inspect["State"]["StartedAt"] == runtime["container_started_at"],
             "runtime was not the captured running container")
    runtime_path = runtime["runtime_jar_path"].rstrip("/")
    for mount in inspect.get("Mounts", []):
        destination = mount.get("Destination", "").rstrip("/")
        _require(not (runtime_path == destination or runtime_path.startswith(destination + "/")),
                 "runtime JAR was covered by a host mount")

    schemas_path = folder / "saml-protocol-mapper-schemas.json"
    _require(_sha(schemas_path) == runtime["provider_schemas_sha256"], "provider inventory hash mismatch")
    schemas = json.loads(schemas_path.read_text())
    _require(isinstance(schemas, list) and len(schemas) > len(PRODUCERS), "provider inventory is incomplete")
    provider_ids = [provider.get("id") for provider in schemas]
    _require(len(provider_ids) == len(set(provider_ids)), "duplicate mapper provider ID")
    relevant = {}
    for provider in schemas:
        properties = [prop for prop in provider.get("properties", []) if prop.get("name") == "attribute.nameformat"]
        _require(len(properties) <= 1, "ambiguous NameFormat property")
        if properties:
            relevant[provider["id"]] = properties[0]
    _require(set(relevant) == set(PRODUCERS), "installed NameFormat provider set changed")
    _require(runtime["nameformat_provider_ids"] == sorted(PRODUCERS), "manifest provider set mismatch")
    for prop in relevant.values():
        _require(prop.get("type") == "List" and prop.get("options") == OPTIONS,
                 "provider exposes an unrecorded NameFormat choice")

    jar = folder / "keycloak-services-runtime.jar"
    _require(_sha(jar) == runtime["runtime_jar_sha256"], "runtime JAR hash mismatch")
    helper_entry = runtime["helper_class_entry"]
    helper_file = folder / "AttributeStatementHelper.class"
    with zipfile.ZipFile(jar) as archive:
        helper = archive.read(helper_entry)
    _require(helper == helper_file.read_bytes(), "helper class is not from retained runtime JAR")
    _require(hashlib.sha256(helper).hexdigest() == runtime["helper_class_sha256"], "helper class hash mismatch")

    helper_javap = subprocess.check_output([
        "javap", "-classpath", str(jar), "-c", "-p",
        "org.keycloak.protocol.saml.mappers.AttributeStatementHelper",
    ])
    _require(helper_javap == (folder / "AttributeStatementHelper.javap.txt").read_bytes(),
             "helper disassembly replay mismatch")
    _require(hashlib.sha256(helper_javap).hexdigest() == runtime["javap_sha256"],
             "helper disassembly hash mismatch")
    for token in (
        b"createAttributeType(org.keycloak.models.ProtocolMapperModel)",
        b"// String attribute.nameformat", b"// String URI Reference", b"// String Unspecified",
        b"ATTRIBUTE_FORMAT_BASIC", b"ATTRIBUTE_FORMAT_URI", b"ATTRIBUTE_FORMAT_UNSPECIFIED",
        b"AttributeType.setNameFormat",
    ):
        _require(token in helper_javap, "helper no longer proves NameFormat coercion")

    implementations = runtime.get("producer_implementations")
    _require(isinstance(implementations, dict) and set(implementations) == set(PRODUCERS),
             "producer implementation inventory mismatch")
    with zipfile.ZipFile(jar) as archive:
        for provider_id, class_name in PRODUCERS.items():
            record = implementations[provider_id]
            entry = class_name.replace(".", "/") + ".class"
            _require(record["class_name"] == class_name and record["class_entry"] == entry,
                     "producer class identity mismatch")
            class_bytes = archive.read(entry)
            class_file = folder / record["class_file"]
            _require(class_file.name == class_name.rsplit(".", 1)[-1] + ".class",
                     "unexpected producer class filename")
            _require(class_bytes == class_file.read_bytes(), "producer class is not from runtime JAR")
            _require(hashlib.sha256(class_bytes).hexdigest() == record["class_sha256"],
                     "producer class hash mismatch")
            disassembly = subprocess.check_output(["javap", "-classpath", str(jar), "-c", "-p", class_name])
            javap_file = folder / record["javap_file"]
            _require(javap_file.name == class_name.rsplit(".", 1)[-1] + ".javap.txt",
                     "unexpected producer disassembly filename")
            _require(disassembly == javap_file.read_bytes(), "producer disassembly replay mismatch")
            _require(hashlib.sha256(disassembly).hexdigest() == record["javap_sha256"],
                     "producer disassembly hash mismatch")
            _require(b"org/keycloak/protocol/saml/mappers/AttributeStatementHelper." in disassembly,
                     "attribute producer bypasses constrained helper")

    dependencies = runtime["runtime_dependencies"]
    _require(set(dependencies) == {"keycloak-server-spi-runtime.jar", "keycloak-saml-core-public-runtime.jar"},
             "runtime dependency inventory mismatch")
    dependency_paths = []
    for name, record in dependencies.items():
        path = folder / name
        _require(_sha(path) == record["sha256"], "runtime dependency hash mismatch")
        _require(record["runtime_path"].startswith("/opt/keycloak/lib/lib/main/org.keycloak."),
                 "unexpected runtime dependency origin")
        dependency_paths.append(path)

    source = folder / "VerifyKCNameFormat.java"
    retained_class = folder / "VerifyKCNameFormat.class"
    execution = folder / "nameformat-execution.txt"
    _require(source.read_bytes() == EXPECTED_SOURCE, "capability harness source changed")
    _require(_sha(source) == runtime["harness_source_sha256"], "harness source hash mismatch")
    _require(_sha(retained_class) == runtime["harness_class_sha256"], "harness class hash mismatch")
    _require(execution.read_bytes() == EXPECTED_EXECUTION, "retained capability execution changed")
    _require(_sha(execution) == runtime["execution_sha256"], "execution hash mismatch")
    classpath = ":".join(str(path) for path in [jar, *dependency_paths])
    with tempfile.TemporaryDirectory(prefix="samlscope-nameformat-") as temporary:
        compiled = Path(temporary)
        subprocess.run(["javac", "-cp", classpath, "-d", str(compiled), str(source)],
                       check=True, capture_output=True)
        _require((compiled / "VerifyKCNameFormat.class").read_bytes() == retained_class.read_bytes(),
                 "retained harness class does not match source")
        replay = subprocess.check_output([
            "java", "-cp", str(compiled) + ":" + classpath, "VerifyKCNameFormat",
        ])
    _require(replay == EXPECTED_EXECUTION, "runtime capability replay did not reproduce coercion")
    return _sha(folder / "runtime-capability.json")


def verify(root):
    folder = Path(root) / FOLDER
    result = _read(folder, "result.json")
    run = result["run"]["id"]
    _require(re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", run), "invalid Run ID")
    plan = _read(folder, "plan.json")["plan"]["plan"]
    plan_id = plan["id"]
    _require(plan["profile"] == "browser_sso_idp", "wrong test profile")
    _require(plan["target"] == {"kind": "IDP", "entityId": TARGET_ENTITY,
                                "connectionId": None, "metadataRevisionId": None},
             "wrong target")
    _require(_read(folder, "created.json")["run"]["id"] == run, "created Run mismatch")
    _require(_read(folder, "run-after.json")["id"] == run, "final Run mismatch")
    _require(_read(folder, "run-after.json")["status"] == "COMPLETED", "Run is incomplete")

    operations = _read(folder, "operations.json")
    _require(operations["run"] == run, "operation log Run mismatch")
    _require(operations["restored"] is True and operations["failures"] == [], "target was not restored")
    _require(operations["existing_clients_overwritten"] is False and operations["human_operations"] == 0,
             "campaign overwrote a client or required human input")
    client_id = operations["created_client_id"]
    _require(re.fullmatch(r"[a-f0-9-]{36}", client_id), "invalid temporary client ID")
    methods = [(row["method"], row["status"]) for row in operations["admin_operations"]]
    _require(methods.count(("POST", 201)) == 1 and methods.count(("PUT", 204)) == 1
             and methods.count(("DELETE", 204)) == 1, "unexpected configuration mutation count")
    _require(all(row["status"] in {200, 201, 204} for row in operations["admin_operations"]),
             "failed administration operation")

    observations = _read(folder, "observations.json")
    _require(len(observations) == 2, "expected baseline and custom observations")
    baseline, custom = observations
    _require(baseline["condition"] == "baseline" and custom["condition"] == "custom",
             "observation conditions changed")
    _require(baseline["before"]["protocolMappers"] == [], "baseline had attribute mappers")
    for row in observations:
        _require(row["before"] == row["after"] and row["flow"] == "recorded",
                 "configuration changed during protocol observation")
        _require(row["before"]["id"] == client_id, "observation used a different client")
    baseline_projection = dict(baseline["before"])
    custom_projection = dict(custom["before"])
    baseline_projection.pop("protocolMappers")
    mappers = custom_projection.pop("protocolMappers")
    _require(baseline_projection == custom_projection, "custom condition changed unrelated client settings")
    expected_mappers = [
        {
            "name": f"samlscope-capability-{index}", "protocol": "saml",
            "protocolMapper": "saml-user-property-mapper", "consentRequired": False,
            "config": {"user.attribute": "firstName", "attribute.name": name,
                       "attribute.nameformat": "urn:samlscope:test:attribute-name-format"},
        }
        for index, name in enumerate(["urn:samlscope:test:attribute-name", "SAMLscope arbitrary attribute"])
    ]
    _require(sorted(mappers, key=lambda mapper: mapper["name"]) == expected_mappers,
             "custom mapper configuration mismatch")

    control = next(row for row in _read(folder, "control-protocol-evidence.json")["cases"]
                   if row["caseId"] == CASE)
    _require(control["details"]["observed_variants"] == [], "baseline unexpectedly satisfied variants")
    before = next(row for row in _read(folder, "protocol-evidence-before-conclusion.json")["cases"]
                  if row["caseId"] == CASE)
    details = before["details"]
    _require(before["ready"] is False, "all variants unexpectedly observed")
    _require(details["evidence_issues"] == [], "protocol evidence has verification issues")
    _require(details["configuration_confirmation_required"] is True, "configuration gate was bypassed")
    _require(set(details["observed_variants"]) == {"urn-name", "non-uri-name"},
             "arbitrary Name controls were not observed")
    _require(details["missing_variants"] == ["unknown-name-format"],
             "capability diagnosis is not isolated to NameFormat")

    _verify_protocol_originals(folder, run, plan_id, observations)
    manifest_sha = _verify_runtime(folder)
    configure = _read(folder, "configure.json")
    _require(configure["runId"] == run and configure["caseId"] == CASE and configure["status"] == "FINISHED",
             "configuration conclusion identity mismatch")
    outcome = configure["outcome"]
    _require((outcome["outcome"], outcome["reasonCode"], outcome["evidence"]) ==
             ("VIOLATED", "capability_absent", []), "unexpected configuration outcome")
    expected_note = (
        "Machine-verified Keycloak runtime evidence: AttributeStatementHelper coerces every "
        "unrecognized attribute.nameformat value to Basic; installed provider schemas expose only "
        "Basic, URI Reference, and Unspecified. Evidence manifest sha256=" + manifest_sha
    )
    _require(outcome["details"] == {"configuration_note": expected_note,
                                    "configuration_issue": "capability_absent"},
             "configuration note is not bound to runtime evidence")

    cases = _case_map(result)
    case = cases[CASE]
    _require((case["outcome"], case["verdict"], case["reason_code"], case["attested"],
              case["evidence_class"], case["evidence"]) ==
             ("VIOLATED", "FAIL", "capability_absent", False, "OPERATOR_ASSISTED", []),
             "formal result does not preserve capability-absence semantics")
    _require(result["run"]["conformance"] == "NON_CONFORMANT", "MUST failure did not affect conformance")
    metadata = folder / "target-metadata.xml"
    _require(result["target"]["metadata_digest"] == "sha256:" + _sha(metadata),
             "target metadata digest mismatch")
    root = ET.parse(metadata).getroot()
    entities = {element.attrib.get("entityID") for element in root.iter()
                if element.tag.endswith("EntityDescriptor")}
    _require(TARGET_ENTITY in entities, "target metadata does not contain target entity")
    return folder / "result.json", cases


if __name__ == "__main__":
    import sys

    _, verified_cases = verify(sys.argv[1])
    print(CASE, verified_cases[CASE]["verdict"], "machine-verified capability absence")
