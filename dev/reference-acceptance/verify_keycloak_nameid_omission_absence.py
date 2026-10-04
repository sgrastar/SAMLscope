#!/usr/bin/env python3
"""Independently verify Keycloak's installed NameID omission capability evidence."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

REPO = Path(__file__).resolve().parents[2]
CASE = "IIP-IDP11-a-idp-01"
FOLDER = "keycloak-nameid-omission-probe-v2"
TARGET = "http://localhost:18180/realms/samlscope"
IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
NS_P = "{urn:oasis:names:tc:SAML:2.0:protocol}"
NS_A = "{urn:oasis:names:tc:SAML:2.0:assertion}"
EXPECTED_CONDITIONS = ["baseline", "unknown-format", "null-mapper", "restored"]
EXPECTED_STATUS = ["Success", "Success", "Responder", "Success"]
NAMEID_REFS = {
    "org/keycloak/protocol/saml/SamlProtocol.class",
    "org/keycloak/protocol/saml/mappers/UserAttributeNameIdMapper.class",
    "org/keycloak/protocol/saml/mappers/SAMLNameIdMapper.class",
}
RESPONSE_REFS = {
    "org/keycloak/protocol/saml/SamlProtocol.class",
    "org/keycloak/protocol/saml/mappers/SAMLLoginResponseMapper.class",
    "org/keycloak/protocol/saml/mappers/SAMLAudienceProtocolMapper.class",
    "org/keycloak/protocol/saml/mappers/SAMLAudienceResolveProtocolMapper.class",
    "org/keycloak/protocol/saml/mappers/AuthnContextClassRefMapper.class",
}
PREPROCESSOR_REFS = {
    "org/keycloak/services/resources/IdentityBrokerService.class",
    "org/keycloak/protocol/saml/preprocessor/SamlAuthenticationPreprocessor.class",
    "org/keycloak/protocol/saml/preprocessor/SamlAuthenticationPreprocessorSpi.class",
    "org/keycloak/protocol/saml/SamlProtocol.class",
    "org/keycloak/protocol/saml/SamlSessionUtils.class",
    "org/keycloak/protocol/saml/SamlService$BindingProtocol.class",
    "org/keycloak/broker/saml/SAMLIdentityProvider.class",
    "org/keycloak/broker/saml/SAMLEndpoint$Binding.class",
}


def require(value, message):
    if not value: raise AssertionError(message)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def read(folder, name): return json.loads((folder / name).read_text())


def check_scan_shape(scan):
    require(scan["clientPolicySubjectWriters"] == [], "client policy can write SAML Subject")
    for key, expected in (("SAMLNameIdMapper", NAMEID_REFS),
            ("SAMLLoginResponseMapper", RESPONSE_REFS)):
        require({entry.split("!", 1)[1] for entry in scan[key]} == expected,
            "unreviewed installed " + key + " implementation")
        require(all("org.keycloak.keycloak-services-26.7.2.jar!" in entry for entry in scan[key]),
            "extension JAR contains " + key)
    require({entry.split("!", 1)[1] for entry in scan["samlSubjectReferences"]}
        == {"org/keycloak/protocol/saml/SamlService$BindingProtocol.class"},
        "unreviewed Subject writer in SAML service")
    require(scan["preprocessorServiceFiles"] == [] and
        {entry.split("!", 1)[1] for entry in scan["SamlAuthenticationPreprocessor"]}
        == PREPROCESSOR_REFS, "unreviewed SAML response preprocessor")


def check_restoration(restoration, before, after):
    require(restoration["restored"] and restoration["failures"] == [] and
        restoration["beforeSha256"] == restoration["afterSha256"] and before == after == [],
        "temporary Keycloak client not exactly deleted")


def check_correlation(request_row, response_row, request, response):
    require(request_row["direction"] == "OUTBOUND" and response_row["direction"] == "INBOUND"
        and request_row["correlationId"] == response_row["correlationId"] == request.attrib["ID"]
        and response.attrib["InResponseTo"] == request.attrib["ID"],
        "request/response correlation mismatch")


def verify_case_contract():
    import yaml
    cases = yaml.safe_load((REPO / "tests/cases.yaml").read_text())
    approved = [case for case in cases["cases"] if case.get("id") == CASE]
    require(len(approved) == 1, "approved case ambiguous")
    case = approved[0]
    require((case["role"], case["mode"], case["configuration_failure_semantics"])
        == ("idp", "CONFIG", "normative_capability"), "approved case semantics changed")
    require(case["variant_plan"][0]["reference"] == "IIP-IDP11.a#v-c98f3c4755",
        "approved NameID variant changed")
    coverage = yaml.safe_load((REPO / "tests/coverage.yaml").read_text())
    obligations = [ob for section in coverage["requirements"] for ob in section["obligations"]
        if ob.get("key") == "IIP-IDP11.a"]
    require(len(obligations) == 1 and obligations[0]["level"] == "MUST"
        and obligations[0]["configuration_failure_semantics"] == "normative_capability",
        "approved obligation semantics changed")


def verify_runtime(folder):
    binding = read(folder, "runtime-binding.json")
    earlier = read(folder, "runtime.json")
    require(binding["containerId"] == earlier["containerId"] and
        binding["imageId"] == earlier["imageId"] == IMAGE and
        binding["startedAt"] == earlier["startedAt"], "live runtime changed during probe")
    for mount in binding["mounts"]:
        dest = (mount.get("destination") or "").rstrip("/")
        require(not any(path == dest or path.startswith(dest + "/") for path in
            ("/opt/keycloak/lib", "/opt/keycloak/providers")), "host-mounted runtime override")
    require(earlier["providerFiles"] == ["./README.md"] and
        read(folder, "providers.json")["files"] == ["./README.md"], "custom provider present")
    jars = folder / "runtime-lib"
    manifest = read(folder, "runtime-jars.json")
    observed = {"lib/" + str(path.relative_to(jars)): sha(path.read_bytes())
        for path in jars.rglob("*.jar")}
    require(len(observed) == manifest["count"] == 471 and observed == manifest["sha256"],
        "runtime JAR inventory or bytes changed")
    scan = {"SAMLLoginResponseMapper": [], "SAMLNameIdMapper": [],
        "SamlAuthenticationPreprocessor": [], "preprocessorServiceFiles": [],
        "clientPolicySubjectWriters": [], "samlSubjectReferences": []}
    for jar in jars.rglob("*.jar"):
        with zipfile.ZipFile(jar) as archive:
            for entry in archive.namelist():
                if entry.startswith("META-INF/services/") and "SamlAuthenticationPreprocessor" in entry:
                    scan["preprocessorServiceFiles"].append(
                        "lib/" + str(jar.relative_to(jars)) + "!" + entry)
                if not entry.endswith(".class"): continue
                raw = archive.read(entry)
                location = "lib/" + str(jar.relative_to(jars)) + "!" + entry
                for marker in ("SAMLLoginResponseMapper", "SAMLNameIdMapper"):
                    if marker.encode() in raw: scan[marker].append(location)
                if b"SamlAuthenticationPreprocessor" in raw:
                    scan["SamlAuthenticationPreprocessor"].append(location)
                if "clientpolicy" in entry.lower() and any(term in raw for term in
                        (b"NameIDType", b"SubjectType", b"SAML2LoginResponseBuilder", b"SAMLNameIdMapper")):
                    scan["clientPolicySubjectWriters"].append(location)
                if "/protocol/saml/" in entry and b"SubjectType" in raw:
                    scan["samlSubjectReferences"].append(location)
    for value in scan.values(): value.sort()
    require(scan == read(folder, "class-scan.json"), "independent all-JAR rescan differs")
    check_scan_shape(scan)
    for reference in scan["SamlAuthenticationPreprocessor"]:
        jar_rel, entry = reference.split("!", 1)
        class_name = entry.removesuffix(".class").replace("/", ".")
        declaration = subprocess.check_output(["javap", "-classpath",
            str(jars / jar_rel.removeprefix("lib/")), "-p", class_name],
            timeout=20).decode().splitlines()[1]
        require("implements org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor"
            not in declaration, "installed SAML response preprocessor implementation")

    records = read(folder, "disassembly-manifest.json")
    methods = {}
    for label, record in records.items():
        jar = jars / record["jar"].removeprefix("lib/")
        raw = subprocess.check_output(["javap", "-classpath", str(jar), "-c", "-p",
            record["class"]], timeout=30)
        require(sha(raw) == record["sha256"] and raw ==
            (folder / "disassembly" / (label + ".txt")).read_bytes(),
            "bytecode disassembly changed: " + label)
        methods[label] = raw.decode()
    require(set(methods) == {"SamlProtocol", "SamlClient", "SamlConfigAttributes",
        "SamlRepresentationAttributes", "SamlProtocolFactory", "NameIdMapperHelper",
        "UserAttributeNameIdMapper", "SAMLAudienceProtocolMapper",
        "SAMLAudienceResolveProtocolMapper", "AuthnContextClassRefMapper",
        "SAML2LoginResponseBuilder", "SAML2Response", "SamlSessionUtils",
        "SamlAuthenticationPreprocessorSpi"}, "runtime class coverage changed")
    protocol = methods["SamlProtocol"]
    auth = protocol.split("public jakarta.ws.rs.core.Response authenticated(", 1)[1].split(
        "  protected jakarta.ws.rs.core.Response buildAuthenticatedResponse", 1)[0]
    positions = [auth.find(marker) for marker in ("Method getSAMLNameId:", "ifnonnull     414",
        "STATUS_INVALID_NAMEIDPOLICY", "Method samlErrorMessage:",
        "Method org/keycloak/saml/SAML2LoginResponseBuilder.nameIdentifier:",
        "Method org/keycloak/saml/SAML2LoginResponseBuilder.buildModel:",
        "Method transformLoginResponse:")]
    require(all(value >= 0 for value in positions) and positions == sorted(positions),
        "SAML response NameID/error/extension call order changed")
    require("getSamlAuthenticationPreprocessorIterator" in protocol and
        "SamlAuthenticationPreprocessor.beforeSendingResponse" in protocol and
        "getProviderFactoriesStream" in methods["SamlSessionUtils"] and
        "saml-authentication-preprocessor" in methods["SamlAuthenticationPreprocessorSpi"],
        "post-mapper SAML response extension path not audited")
    response = methods["SAML2Response"]
    creation = response.split("createResponseType(", 1)[1].split("  public ", 1)[0]
    require(all(token in creation for token in ("new           #129                // class org/keycloak/dom/saml/v2/assertion/NameIDType",
        "NameIDType.setValue", "SubjectType$STSubType.addBaseID", "SubjectType.setSubType")),
        "response builder does not unconditionally place NameID in Subject")
    require("String saml_name_id_format" in methods["SamlClient"] and
        methods["SamlClient"].count("NAMEID_FORMAT_UNSPECIFIED") >= 2,
        "unknown client NameID format fallback changed")
    require("mapper.nameid.format" in protocol and
        "UserModel.getFirstAttribute" in methods["UserAttributeNameIdMapper"] and
        "NAMEID_FORMAT_UNSPECIFIED" in methods["NameIdMapperHelper"],
        "NameID mapper path changed")
    for label in ("SAMLAudienceProtocolMapper", "SAMLAudienceResolveProtocolMapper",
            "AuthnContextClassRefMapper"):
        require("transformLoginResponse" in methods[label] and
            all(token not in methods[label] for token in ("SubjectType.setSubType",
                "AssertionType.setSubject", "NameIDType.setValue")),
            "an installed response mapper may change Subject")

    server = read(folder, "serverinfo-nameid.json")
    mappers = server["mappers"]
    ids = [item["id"] for item in mappers]
    require(len(ids) == len(set(ids)) == 14 and ids.count("saml-user-attribute-nameid-mapper") == 1,
        "installed SAML mapper inventory changed")
    nameid = next(item for item in mappers if item["id"] == "saml-user-attribute-nameid-mapper")
    props = {item["name"]: item for item in nameid["properties"]}
    require(props["mapper.nameid.format"]["options"] == [
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"],
        "NameID mapper exposes another format")
    require(set(props) == {"mapper.nameid.format", "user.attribute"},
        "NameID mapper has unreviewed configuration")
    ui = read(folder, "admin-ui-nameid.json")
    with zipfile.ZipFile(jars / "lib/main/org.keycloak.keycloak-admin-ui-26.7.2.jar") as archive:
        ui_raw = archive.read(ui["entry"])
    require(sha(ui_raw) == ui["sha256"] and ui_raw == (folder / "admin-ui-nameid.js").read_bytes()
        and ui["optionsToken"].encode() in ui_raw and ui["forceFormatToken"].encode() in ui_raw,
        "admin UI contains unreviewed NameID controls")
    require(b"disableNameId" not in ui_raw and b"omitNameId" not in ui_raw,
        "admin UI has unreviewed disable control")
    for name in ("client-policy-policies.json", "client-policy-profiles.json"):
        data = read(folder, name)
        require(isinstance(data["items"], list), "client policy snapshot unavailable")
    require("clientPolicyExecutors" in server and server["clientPolicyExecutors"],
        "installed policy providers unavailable")
    require(server["samlAuthenticationPreprocessor"] is None,
        "SAML response preprocessor provider is installed")
    return manifest, scan


def verify_protocol(folder):
    operations = read(folder, "operations.json")
    restoration = read(folder, "restoration.json")
    observations = read(folder, "observations.json")
    check_restoration(restoration, read(folder, "client-before.json"), read(folder, "client-after.json"))
    require(operations["restored"] and operations["protocolRoundTrips"] == 4 and
        operations["humanOperations"] == 0 and operations["productRestarts"] == 0,
        "operation count or restoration mismatch")
    writes = [(op["method"], op["path"], op["status"])
        for op in operations["adminOperations"] if op["method"] in ("PUT", "POST", "DELETE")
        and op["path"].startswith("/clients")]
    require(len(writes) == 8 and operations["productConfigurationWrites"] == len(writes)
        and all(status in (201, 204) for _, _, status in writes),
        "unrecorded or failed native configuration operation")
    require([item["condition"] for item in observations] == EXPECTED_CONDITIONS and
        all(item.get("flowStatus") == "recorded" and item["status"] == "recorded" and
            item["beforeClientSha256"] == item["afterClientSha256"] and
            len(item["newTranscriptIds"]) == 2 for item in observations),
        "native SSO controls incomplete")
    original = read(folder, "original-client-redacted.json")
    restored = read(folder, "restored-control-client-redacted.json")
    require(original == restored, "final control did not restore exact client configuration")
    require(read(folder, "unknown-format-client-redacted.json")["attributes"]["saml_name_id_format"] == "none",
        "unknown format was not read back")
    mapped = read(folder, "null-mapper-client-redacted.json")["protocolMappers"]
    require(len(mapped) == 1 and mapped[0]["protocolMapper"] == "saml-user-attribute-nameid-mapper"
        and mapped[0]["config"]["user.attribute"] == "samlscope-absent-nameid-probe-attribute",
        "null NameID mapper not read back")
    require(read(folder, "restore-after-null-mapper-client-redacted.json") == original,
        "mapper was not explicitly removed")
    plan = read(folder, "plan.json")["plan"]["plan"]
    run = read(folder, "created.json")["run"]["id"]
    require(operations["run"] == run and plan["profile"] == "browser_sso_idp"
        and plan["target"]["entityId"] == TARGET, "probe Run identity mismatch")
    transcript = {item["id"]: item for item in read(folder, "transcript.json")}
    manifest = {item["id"]: item for item in read(folder, "decoded-manifest.json")}
    refs = [ident for item in observations for ident in item["newTranscriptIds"]]
    require(len(refs) == len(set(refs)) == 8 and set(refs) == set(transcript) == set(manifest),
        "request/response original inventory mismatch")
    response_files = []
    for index, item in enumerate(observations):
        request_id, response_id = item["newTranscriptIds"]
        request_row, response_row = transcript[request_id], transcript[response_id]
        roots = []
        for ident in (request_id, response_id):
            entry = manifest[ident]
            require(entry["file"] == "decoded/" + ident + ".xml", "unsafe original reference")
            path = folder / entry["file"]
            raw = path.read_bytes()
            require(sha(raw) == entry["sha256"] and transcript[ident]["decodedSamlBytes"] == len(raw)
                and transcript[ident]["runId"] == run, "original hash/length/Run mismatch")
            roots.append(ET.fromstring(raw))
        request, response = roots
        require(request.tag == NS_P + "AuthnRequest" and response.tag == NS_P + "Response",
            "unexpected original document type")
        check_correlation(request_row, response_row, request, response)
        require(request_row["timestamp"] < response_row["timestamp"] and
            response_row["samlSummary"]["issuer"] == TARGET,
            "response time or issuer mismatch")
        status = response.find(NS_P + "Status/" + NS_P + "StatusCode")
        require(status is not None and status.get("Value", "").endswith(":" + EXPECTED_STATUS[index]),
            "observed status differs from control expectation")
        assertion = response.findall(NS_A + "Assertion")
        require(len(assertion) == (0 if index == 2 else 1), "unexpected assertion count")
        if assertion:
            require(len(assertion[0].findall(NS_A + "Subject/" + NS_A + "NameID")) == 1,
                "normal control did not contain NameID")
        response_files.append(str(folder / manifest[response_id]["file"]))
    with tempfile.TemporaryDirectory() as temp:
        subprocess.run(["javac", "-d", temp, str(REPO / "dev/reference-acceptance/VerifyKeycloakNameIdOriginals.java")],
            check=True, stdout=subprocess.DEVNULL)
        command = ["java", "-cp", temp, "VerifyKeycloakNameIdOriginals",
            str(folder / "target-metadata.xml"), *response_files]
        verified = json.loads(subprocess.check_output(command, text=True))
        require(verified == {"statuses": "Success,Success,Responder,Success", "signatures": 7},
            "independent signature verification mismatch")
        baseline = Path(response_files[0]).read_bytes()
        nameid = ET.fromstring(baseline).find(".//" + NS_A + "Subject/" + NS_A + "NameID")
        require(nameid is not None and nameid.text, "baseline identifier missing")
        mutated = baseline.replace(nameid.text.encode(), b"X" + nameid.text.encode(), 1)
        require(mutated != baseline, "signature mutant did not change original")
        tampered = Path(temp) / "tampered.xml"
        tampered.write_bytes(mutated)
        invalid = subprocess.run(command[:5] + [str(tampered), *response_files[1:]],
            capture_output=True, text=True)
        require(invalid.returncode != 0 and "invalid signature" in invalid.stderr,
            "tampered protocol original was accepted")
    return run, {"original-byte-signature-mutant": "rejected"}


def verify_tamper_controls(folder, scan):
    def rejects(action):
        try: action()
        except (AssertionError, KeyError, IndexError): return "rejected"
        raise AssertionError("tamper control was accepted")

    missing_mapper = copy.deepcopy(scan)
    missing_mapper["SAMLNameIdMapper"] = [entry for entry in missing_mapper["SAMLNameIdMapper"]
        if not entry.endswith("UserAttributeNameIdMapper.class")]
    extra_response_mapper = copy.deepcopy(scan)
    extra_response_mapper["SAMLLoginResponseMapper"].append(
        "lib/lib/main/unreviewed.jar!org/example/NoNameIdResponseMapper.class")
    altered_restoration = read(folder, "restoration.json")
    altered_restoration["restored"] = False
    observations = read(folder, "observations.json")
    transcript = {item["id"]: item for item in read(folder, "transcript.json")}
    first, second = observations[0]["newTranscriptIds"]
    request = ET.parse(folder / "decoded" / (first + ".xml")).getroot()
    response = ET.parse(folder / "decoded" / (second + ".xml")).getroot()
    mixed = copy.deepcopy(transcript[second])
    mixed["correlationId"] = "_unrelated_request"
    return {
        "missing-nameid-provider": rejects(lambda: check_scan_shape(missing_mapper)),
        "extra-response-transformer": rejects(lambda: check_scan_shape(extra_response_mapper)),
        "restoration-flag-flipped": rejects(lambda: check_restoration(
            altered_restoration, read(folder, "client-before.json"), read(folder, "client-after.json"))),
        "mixed-request-correlation": rejects(lambda: check_correlation(transcript[first], mixed, request, response)),
    }


def verify(folder):
    folder = Path(folder).resolve()
    verify_case_contract()
    manifest, scan = verify_runtime(folder)
    run, tamper = verify_protocol(folder)
    tamper.update(verify_tamper_controls(folder, scan))
    require(FOLDER in str(folder), "unexpected evidence campaign folder")
    require(read(folder, "result-before-conclusion-unavailable.json") ==
        {"reason": "tests-not-started", "verdictAdopted": False},
        "probe secretly adopted a verdict")
    report = {"schema": "samlscope-keycloak-nameid-absence-verification-v1", "run": run,
        "case": CASE, "installedJars": manifest["count"], "installedSamlMappers": 14,
        "nameIdMapperImplementations": 1, "responseMapperImplementations": 3,
        "tamperControls": tamper, "runtimePathAudit": "passed", "probeControls": "passed",
        "restored": True, "verdictAdopted": False}
    (folder / "independent-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def verify_adoption(root):
    folder = Path(root).resolve() / FOLDER
    report = verify(folder)  # Re-scan every retained runtime JAR and all protocol originals.
    require(report["tamperControls"] == {
        "original-byte-signature-mutant": "rejected", "missing-nameid-provider": "rejected",
        "extra-response-transformer": "rejected", "restoration-flag-flipped": "rejected",
        "mixed-request-correlation": "rejected"}, "internal tamper controls incomplete")
    tamper = read(folder, "tamper-self-test.json")
    require(tamper["schema"] == "samlscope-keycloak-nameid-absence-tamper-v1" and
        tamper["checks"] == {name: "rejected" for name in (
            "runtime-jar-hash", "runtime-jar-count", "custom-provider",
            "null-response-success-assertion", "baseline-nameid-removed",
            "temporary-client-remains", "mapper-inventory")},
        "temporary-copy tamper rejection campaign incomplete")
    event = read(folder, "formal-configuration-event.json")
    require(event["runId"] == report["run"] and event["caseId"] == CASE and
        event["status"] == "FINISHED", "formal configuration event identity changed")
    outcome = event["outcome"]
    require((outcome["outcome"], outcome["reasonCode"], outcome["evidence"])
        == ("VIOLATED", "capability_absent", []), "formal CONFIG outcome changed")
    digest = sha((folder / "independent-verification.json").read_bytes())
    require(outcome["details"]["configuration_issue"] == "capability_absent" and
        outcome["details"]["configuration_note"].endswith("Evidence sha256=" + digest),
        "formal event is not bound to replayed verification")
    def case_map(result):
        return {case["id"]: case for requirement in result["requirements"] for case in requirement["cases"]}
    before = case_map(read(folder, "result-before-conclusion.json"))[CASE]
    require((before["outcome"], before["verdict"], before["reason_code"])
        == ("NOT_VERIFIED", "NOT_VERIFIED", "case.pending-interaction"),
        "case was already concluded before capability audit")
    result = read(folder, "result.json")
    require(result["run"]["id"] == report["run"] and
        result["target"]["metadata_digest"] == "sha256:" + sha(
            (folder / "target-metadata.xml").read_bytes()),
        "formal result Run or target metadata changed")
    cases = case_map(result)
    adopted = cases[CASE]
    require((adopted["outcome"], adopted["verdict"], adopted["reason_code"],
        adopted["attested"], adopted["mode"], adopted["evidence"])
        == ("VIOLATED", "FAIL", "capability_absent", False, "CONFIG", []),
        "formal Keycloak IDP11.a result changed")
    return folder / "result.json", cases


if __name__ == "__main__":
    import sys
    import traceback
    try: print(json.dumps(verify(sys.argv[1]), indent=2))
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
