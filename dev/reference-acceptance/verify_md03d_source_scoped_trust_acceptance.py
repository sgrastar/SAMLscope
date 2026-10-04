#!/usr/bin/env python3
"""Fail-closed acceptance verifier for IDP MD03.d source-scoped trust."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from verify_md06b_multi_peer_acceptance import (
    SUITE_IMAGE, TARGET_IMAGES, canonical, case_map, inside, read, require, sha,
    verify_suite, verify_target,
)

CASE = "IIP-MD03-d-idp-01"
TARGETS = {
    "shibboleth": "http://localhost:18280/idp/shibboleth",
    "simplesamlphp": "http://localhost:18380/idp",
}
MD = "urn:oasis:names:tc:SAML:2.0:metadata"
DS = "http://www.w3.org/2000/09/xmldsig#"
SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
PLAN_RE = re.compile(r"plan_[0-9A-HJKMNP-TV-Z]{26}")


def verify_signature_originals(folder: Path, receipt: dict) -> None:
    material = read(folder, receipt["keyMaterialFile"])
    require(material["temporaryPrivateKeysRemoved"] is True
            and material["helperFile"] == "source-scoped-helper.java"
            and sha(inside(folder, material["helperFile"]).read_bytes()) == material["helperSha256"],
            "signing helper/private-key lifecycle mismatch")
    k = inside(folder, material["keyKCertificateFile"])
    k2 = inside(folder, material["keyK2CertificateFile"])
    require(sha(k.read_bytes()) == material["keyKCertificateSha256"]
            and sha(k2.read_bytes()) == material["keyK2CertificateSha256"]
            and k.read_bytes() != k2.read_bytes(), "trust certificate originals mismatch")
    with tempfile.TemporaryDirectory(prefix="verify-md03d-") as temporary:
        classes = Path(temporary) / "classes"
        classes.mkdir()
        source = Path(temporary) / "SourceScopedMetadata.java"
        source.write_bytes(inside(folder, material["helperFile"]).read_bytes())
        subprocess.run(["javac", "--release", "21", "-d", str(classes),
                        str(source)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        for source in receipt["sources"]:
            signed = inside(folder, source["signedMetadataFile"])
            require(sha(signed.read_bytes()) == source["signedMetadataSha256"],
                    "signed metadata hash mismatch")
            root = ET.fromstring(signed.read_bytes())
            require(root.tag == "{" + MD + "}EntityDescriptor" and root.get("entityID") == source["entity"],
                    "signed metadata identity mismatch")
            signatures = root.findall("{" + DS + "}Signature")
            certificates = root.findall("{" + DS + "}Signature/{" + DS + "}KeyInfo/{" + DS
                                        + "}X509Data/{" + DS + "}X509Certificate")
            require(len(signatures) == len(certificates) == 1
                    and base64.b64decode("".join(certificates[0].itertext()).strip()) == k.read_bytes(),
                    "metadata was not signed with key K")
            marker = Path(temporary) / (source["label"] + ".verified")
            subprocess.run(["java", "-cp", str(classes), "SourceScopedMetadata", "verify",
                            str(signed), str(k), str(marker)], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            require(marker.read_text() == "verified\n", "key K signature did not verify")
            wrong = subprocess.run(["java", "-cp", str(classes), "SourceScopedMetadata", "verify",
                                    str(signed), str(k2), str(marker.with_suffix(".wrong"))],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            require(wrong.returncode != 0, "metadata unexpectedly verified under key K2")


def verify_sources(folder: Path, receipt: dict) -> None:
    sources = receipt["sources"]
    require(len(sources) == 2 and [row["label"] for row in sources] == ["source-a", "source-b"]
            and len({row["run"] for row in sources}) == len({row["plan"] for row in sources}) ==
            len({row["entity"] for row in sources}) == 2
            and receipt["primaryRun"] == sources[0]["run"]
            and receipt["negativeRun"] == sources[1]["run"], "source identity set mismatch")
    for source in sources:
        require(RUN_RE.fullmatch(source["run"]) and PLAN_RE.fullmatch(source["plan"])
                and source["entity"] == "http://localhost:18080/p/" + source["plan"],
                "source Run/plan/entity mismatch")
        unsigned = inside(folder, source["metadataFile"]).read_bytes()
        root = ET.fromstring(unsigned)
        require(root.tag == "{" + MD + "}EntityDescriptor" and root.get("entityID") == source["entity"]
                and sha(unsigned) == source["metadataSha256"], "unsigned metadata original mismatch")


def verify_configuration(folder: Path, receipt: dict) -> None:
    product = receipt["product"]
    config = receipt["configuration"]
    original = inside(folder, config["originalFile"]).read_bytes()
    configured = inside(folder, config["configuredFile"]).read_bytes()
    final = inside(folder, config["finalFile"]).read_bytes()
    require(sha(original) == config["originalSha256"]
            and sha(configured) == config["configuredSha256"]
            and sha(final) == config["finalSha256"] == sha(original)
            and final == original and configured != original, "configuration hashes mismatch")
    require(config["readBackFiles"] == ["configured-readback.bin", "configured-after-source-a.bin",
            "configured-after-source-b.bin"]
            and all(inside(folder, name).read_bytes() == configured for name in config["readBackFiles"]),
            "configuration changed during sources")
    temp = "/tmp/samlscope-md03d-" + receipt["primaryRun"].removeprefix("run_")
    if product == "simplesamlphp":
        overlay = ("\n$config['metadata.sources'] = [['type'=>'flatfile'],"
            "['type'=>'mdq','server'=>'http://127.0.0.1:8081','validateCertificate'=>['" + temp
            + "/k.cert.pem'],'cachelength'=>0],"
            "['type'=>'mdq','server'=>'http://127.0.0.1:8082','validateCertificate'=>['" + temp
            + "/k2.cert.pem'],'cachelength'=>0]];\n").encode()
        require(configured == original + overlay, "SimpleSAMLphp source trust configuration mismatch")
    else:
        namespace = "urn:mace:shibboleth:2.0:metadata"
        old = ET.fromstring(original)
        new = ET.fromstring(configured)
        providers = [node for node in list(new) if node.tag == "{" + namespace + "}MetadataProvider"
                     and (node.get("id") or "").startswith("MD03D")]
        require(len(providers) == 2, "Shibboleth source provider set mismatch")
        for index, provider in enumerate(providers):
            label = "Source-A" if index == 0 else "Source-B"
            require(label in provider.get("id", "")
                    and provider.get("{" + XSI + "}type") == "DynamicHTTPMetadataProvider",
                    "Shibboleth source identity mismatch")
            metadata_filter = provider.find("{" + namespace + "}MetadataFilter")
            template = provider.find("{" + namespace + "}Template")
            require(metadata_filter is not None
                    and metadata_filter.get("{" + XSI + "}type") == "SignatureValidation"
                    and metadata_filter.get("requireSignedRoot") == "true"
                    and metadata_filter.get("certificateFile") == temp
                    + ("/k.cert.pem" if index == 0 else "/k2.cert.pem")
                    and template is not None and template.text == "http://127.0.0.1:"
                    + str(18081 + index) + "/entities/${entityID}",
                    "Shibboleth source trust binding mismatch")
        for provider in providers:
            new.remove(provider)
        require(ET.tostring(new) == ET.tostring(old), "Shibboleth configuration changed beyond sources")
    restoration = read(folder, receipt["restorationFile"])
    require(restoration == {"restored": True, "failures": [],
            "temporarySourceDirectoryRemoved": True, "originalSha256": sha(original),
            "finalSha256": sha(original), "originalBytes": len(original), "finalBytes": len(original)},
            "restoration mismatch")


def verify_native(folder: Path, receipt: dict) -> None:
    product = receipt["product"]
    accepted = read(folder, receipt["nativeAcceptanceFile"])
    rejected = read(folder, receipt["nativeRejectionFile"])
    a_stdout = inside(folder, "source-a-native-lookup.stdout").read_bytes()
    a_stderr = inside(folder, "source-a-native-lookup.stderr").read_bytes()
    b_stdout = inside(folder, "source-b-native-lookup.stdout").read_bytes()
    b_stderr = inside(folder, "source-b-native-lookup.stderr").read_bytes()
    require(accepted == {"exitCode": 0, "expectSuccess": True,
            "stdoutSha256": sha(a_stdout), "stderrSha256": sha(a_stderr)},
            "source A native acceptance record mismatch")
    require(rejected == {"exitCode": 1 if product == "shibboleth" else rejected["exitCode"],
            "expectSuccess": False, "stdoutSha256": sha(b_stdout), "stderrSha256": sha(b_stderr)}
            and rejected["exitCode"] != 0, "source B native rejection record mismatch")
    a_entity = receipt["sources"][0]["entity"]
    b_entity = receipt["sources"][1]["entity"]
    if product == "shibboleth":
        require(a_entity.encode() in a_stdout and b"Not Found" in b_stderr,
                "Shibboleth native accept/reject signal mismatch")
        log = inside(folder, receipt["nativeRejectionProductLog"]).read_bytes()
        require(b_entity.encode() in log
                and b"Signature trust establishment failed for metadata entry" in log
                and ("MD03DSource-B" + receipt["negativeRun"].removeprefix("run_")).encode() in log,
                "Shibboleth explicit signature rejection log missing")
    else:
        require(json.loads(a_stdout).get("entityid") == a_entity
                and b"could not verify signature for entity" in b_stderr
                and b_entity.encode() in b_stderr,
                "SimpleSAMLphp native accept/reject signal mismatch")
        require(inside(folder, receipt["nativeRejectionProductLog"]).read_bytes() == b_stderr,
                "SimpleSAMLphp rejection log mismatch")
    for source in receipt["sources"]:
        rows = [json.loads(line) for line in inside(folder, source["label"] + "-requests.jsonl")
                .read_text().splitlines()]
        require(rows and all(row == {"entityId": source["entity"],
                "responseSha256": source["signedMetadataSha256"], "httpStatus": 200} for row in rows),
                "native source delivery log mismatch")


def verify_protocol(folder: Path, receipt: dict) -> None:
    a = receipt["sourceAAcceptance"]
    source_a = receipt["sources"][0]
    require(a["run"] == source_a["run"] and a["entityId"] == source_a["entity"]
            and a["receipt"] == "recorded" and a["statusCode"] ==
            "urn:oasis:names:tc:SAML:2.0:status:Success"
            and a["assertionForm"] in {"plain", "encrypted"}, "source A protocol summary mismatch")
    rows = {row["id"]: row for row in read(folder, "source-a-transcript.json")}
    request = rows.get(a["requestTranscriptId"])
    response = rows.get(a["responseTranscriptId"])
    require(request and response and request["direction"] == "OUTBOUND"
            and request["samlSummary"].get("id") == a["requestId"]
            and response["direction"] == "INBOUND"
            and response["samlSummary"].get("inResponseTo") == a["requestId"]
            and response["samlSummary"].get("statusCode") == a["statusCode"],
            "source A transcript correlation mismatch")
    original = inside(folder, a["responseOriginal"]).read_bytes()
    root = ET.fromstring(original)
    status = root.find("{" + SAMLP + "}Status/{" + SAMLP + "}StatusCode")
    assertions = root.findall(".//{" + SAML + "}Assertion")
    encrypted = root.findall(".//{" + SAML + "}EncryptedAssertion")
    require(sha(original) == a["responseSha256"] and root.get("InResponseTo") == a["requestId"]
            and status is not None and status.get("Value") == a["statusCode"]
            and len(assertions) + len(encrypted) == 1
            and ((a["assertionForm"] == "plain" and len(assertions) == 1)
                 or (a["assertionForm"] == "encrypted" and len(encrypted) == 1)),
            "source A response original mismatch")
    b = receipt["sourceBRejection"]
    source_b = receipt["sources"][1]
    require(b["run"] == source_b["run"] and b["entityId"] == source_b["entity"]
            and b["correlatedSuccess"] is False and b["correlatedResponseIds"] == []
            and b["correlatedStatusCodes"] == [], "source B protocol rejection mismatch")
    rows_b = {row["id"]: row for row in read(folder, "source-b-transcript.json")}
    request_b = rows_b.get(b["requestTranscriptId"])
    require(request_b and request_b["direction"] == "OUTBOUND"
            and request_b["samlSummary"].get("type") == "AuthnRequest"
            and request_b["samlSummary"].get("id") == b["requestId"],
            "source B request was not recorded")
    require(not any(row["direction"] == "INBOUND" and row["samlSummary"].get("type") == "Response"
                    and row["samlSummary"].get("inResponseTo") == b["requestId"]
                    and row["samlSummary"].get("statusCode") ==
                    "urn:oasis:names:tc:SAML:2.0:status:Success" for row in rows_b.values()),
            "source B has a contradictory Success response")


def verify_operations(folder: Path, receipt: dict) -> None:
    value = read(folder, receipt["operationCountsFile"])
    rows = value["operations"]
    require(value["productConfigurationWrites"] == value["restorationWrites"] == 1
            and value["nativeSourceLookups"] == value["protocolRoundTrips"] == 2
            and value["productRestarts"] == value["humanOperations"] == 0
            and value["restored"] is True
            and sum(row["operation"] == "temporary-source-servers-start" for row in rows) == 1
            and sum(row["operation"] == "temporary-source-servers-stop" for row in rows) == 1,
            "operation inventory mismatch")
    require([(row.get("source"), row.get("accepted")) for row in rows
             if row["operation"] == "native-source-lookup"] == [("A", True), ("B", False)]
            and [(row.get("source"), row.get("success")) for row in rows
                 if row["operation"] == "protocol-roundtrip"] == [("A", True), ("B", False)],
            "control operation sequence mismatch")


def verify_result(folder: Path, receipt: dict) -> None:
    receipt_sha = sha((folder / "receipt.json").read_bytes())
    note = ("Machine-verified MD03.d source-scoped trust campaign; receipt sha256=" + receipt_sha
            + "; source A accepted key K and source B rejected the same key K")
    configured = read(folder, "configure.json")
    attested = read(folder, "attest.json")
    require(configured["runId"] == receipt["primaryRun"] and configured["caseId"] == CASE
            and configured["status"] == "WAITING_ATTESTATION" and configured["outcome"] is None,
            "configuration gate mismatch")
    require(attested["runId"] == receipt["primaryRun"] and attested["caseId"] == CASE
            and attested["status"] == "FINISHED"
            and attested["outcome"]["outcome"] == "SATISFIED"
            and attested["outcome"]["reasonCode"] == "configuration.evidence-satisfies"
            and attested["outcome"]["details"] == {"attested": True,
                "attestation_option": "evidence_satisfies", "attestation_note": note},
            "formal outcome mismatch")
    case = case_map(read(folder, "result.json"))[CASE]
    require((case["outcome"], case["verdict"], case["reason_code"], case["attested"],
             case["evidence_class"]) ==
            ("SATISFIED", "PASS", "configuration.evidence-satisfies", False, "SELF_ATTESTED")
            and case["evidence"] == [{"kind": "attestation",
                "reference": "attestation:" + receipt["primaryRun"] + ":" + CASE}],
            "formal result mismatch")


def verify(folder: Path, receipt: dict | None = None, *, result: bool = True) -> None:
    raw = (folder / "receipt.json").read_bytes()
    require(raw == canonical(json.loads(raw)), "receipt is not canonical")
    receipt = copy.deepcopy(receipt if receipt is not None else json.loads(raw))
    product = receipt["product"]
    require(receipt["schema"] == "samlscope-md03d-source-scoped-trust-receipt-v1"
            and receipt["caseId"] == CASE and product in TARGETS
            and receipt["targetEntityId"] == TARGETS[product]
            and RUN_RE.fullmatch(receipt["primaryRun"]) and RUN_RE.fullmatch(receipt["negativeRun"])
            and receipt["controls"] == {
                "positive": "source-a-signed-k-trusted-k-correlated-success",
                "negative": "source-b-signed-k-trusted-k2-native-signature-rejection"},
            "receipt identity mismatch")
    verify_suite(folder, receipt)
    verify_target(folder, product, receipt)
    verify_sources(folder, receipt)
    verify_signature_originals(folder, receipt)
    verify_configuration(folder, receipt)
    verify_native(folder, receipt)
    verify_protocol(folder, receipt)
    verify_operations(folder, receipt)
    if result:
        verify_result(folder, receipt)


def tamper(folder: Path) -> list[str]:
    original = read(folder, "receipt.json")
    rejected = []

    def reject(label, mutate):
        value = copy.deepcopy(original)
        mutate(value)
        try:
            verify(folder, value, result=False)
        except (ValueError, KeyError, TypeError, ET.ParseError, json.JSONDecodeError,
                subprocess.CalledProcessError):
            rejected.append(label)
        else:
            raise AssertionError("tamper control accepted: " + label)

    reject("same-source", lambda value: value["sources"].__setitem__(1, copy.deepcopy(value["sources"][0])))
    reject("wrong-negative-run", lambda value: value.__setitem__("negativeRun", value["primaryRun"]))
    reject("source-b-success", lambda value: value["sourceBRejection"].__setitem__("correlatedSuccess", True))
    reject("source-a-status", lambda value: value["sourceAAcceptance"].__setitem__("statusCode",
           "urn:oasis:names:tc:SAML:2.0:status:Responder"))
    reject("source-a-response", lambda value: value["sourceAAcceptance"].__setitem__("responseOriginal",
           "source-b-signed-metadata.xml"))
    reject("key-k", lambda value: value.__setitem__("keyMaterialFile", "receipt.json"))
    reject("configured-readback", lambda value: value["configuration"]["readBackFiles"].pop())
    reject("restoration", lambda value: value["configuration"].__setitem__("finalSha256", "0" * 64))
    reject("native-rejection", lambda value: value.__setitem__("nativeRejectionFile",
           value["nativeAcceptanceFile"]))
    reject("suite-image", lambda value: value["suiteRuntime"].__setitem__("imageId", "sha256:" + "0" * 64))
    reject("suite-jar", lambda value: value["suiteRuntime"]["jars"]["runner"].__setitem__("sha256", "0" * 64))
    reject("target-image", lambda value: value["runtime"]["binding"].__setitem__("image_id", "sha256:" + "0" * 64))
    require(len(rejected) == 12, "tamper self-test count mismatch")
    return rejected


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    folder = args.folder.resolve()
    verify(folder)
    rejected = tamper(folder)
    report = {"schema": "samlscope-md03d-source-scoped-trust-acceptance-v1",
              "folder": folder.name, "verified": True,
              "tamperControlsRejected": rejected, "formalReduction": 1}
    (folder / "acceptance-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(folder.name, "verified;", len(rejected), "tamper controls rejected")


if __name__ == "__main__":
    main()
