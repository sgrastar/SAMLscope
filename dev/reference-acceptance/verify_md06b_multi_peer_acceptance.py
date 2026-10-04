#!/usr/bin/env python3
"""Fail-closed acceptance verifier for the IDP MD06.b two-peer campaign."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

CASE = "IIP-MD06-b-idp-01"
SUITE_IMAGE = "sha256:846083123e759f24e88a89f9badba50c4e4cd110b3b13563e8295c9829886cdb"
TARGET_IMAGES = {
    "shibboleth": "sha256:3c1b1f",  # exact prefix is expanded from the retained inspect original
    "simplesamlphp": "sha256:9ae050",
}
TARGETS = {
    "shibboleth": "http://localhost:18280/idp/shibboleth",
    "simplesamlphp": "http://localhost:18380/idp",
}
MD = "urn:oasis:names:tc:SAML:2.0:metadata"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
PLAN_RE = re.compile(r"plan_[0-9A-HJKMNP-TV-Z]{26}")


def require(value, message="invalid MD06.b evidence"):
    if not value:
        raise ValueError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read(folder: Path, name: str):
    return json.loads((folder / name).read_text())


def inside(folder: Path, name: str) -> Path:
    path = (folder / name).resolve()
    require(path.is_relative_to(folder.resolve()) and path.is_file(), "evidence reference escaped folder")
    return path


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def case_map(result: dict) -> dict:
    return {case["id"]: case for requirement in result["requirements"]
            for case in requirement["cases"]}


def verify_suite(folder: Path, receipt: dict) -> None:
    runtime = receipt["suiteRuntime"]
    require(runtime["containerName"] == "samlscope-reference-suite"
            and runtime["imageId"] == SUITE_IMAGE and runtime["running"] is True,
            "Suite runtime identity mismatch")
    raw = inside(folder, runtime["inspectFile"]).read_bytes()
    require(sha(raw) == runtime["inspectSha256"], "Suite inspect hash mismatch")
    values = json.loads(raw)
    require(isinstance(values, list) and len(values) == 1, "Suite inspect ambiguity")
    value = values[0]
    require(value["Id"] == runtime["containerId"] and value["Image"] == runtime["imageId"]
            and value["State"]["StartedAt"] == runtime["startedAt"]
            and value["State"]["Running"] is True,
            "Suite inspect identity mismatch")
    require(set(runtime["jars"]) == {"core", "runner", "saml"}, "Suite JAR inventory mismatch")
    for name, record in runtime["jars"].items():
        require(record["path"] == "/opt/samlscope/lib/" + name + "-0.1.0.jar",
                "Suite JAR path mismatch")
        require(sha(inside(folder, record["file"]).read_bytes()) == record["sha256"],
                "Suite JAR hash mismatch")


def verify_target(folder: Path, product: str, receipt: dict) -> None:
    runtime = receipt["runtime"]
    require(runtime["schema"] == "samlscope-terminal-http-target-runtime-v1"
            and runtime["product"] == product and runtime["phase"] == "start",
            "target runtime manifest mismatch")
    binding = runtime["binding"]
    require(binding["container_name"] == ("samlscope-reference-shibboleth" if product == "shibboleth"
            else "samlscope-reference-ssp") and binding["running_at_capture"] is True
            and binding["host_port_bound"] is True
            and binding["image_id"].startswith(TARGET_IMAGES[product]),
            "target runtime identity mismatch")
    inspect = inside(folder, "target-container-inspect-start.json").read_bytes()
    image = inside(folder, "target-image-inspect-start.json").read_bytes()
    require(sha(inspect) == runtime["docker_inspect_sha256"]
            and sha(image) == runtime["image_inspect_sha256"], "target originals hash mismatch")
    values = json.loads(inspect)
    require(isinstance(values, list) and len(values) == 1 and values[0]["Id"] == binding["container_id"]
            and values[0]["Image"] == binding["image_id"]
            and values[0]["State"]["StartedAt"] == binding["container_started_at"],
            "target inspect identity mismatch")
    version = runtime["runtime_version"]
    require(sha(inside(folder, version["file"]).read_bytes()) == version["sha256"]
            and version["value"], "target version original mismatch")
    source = runtime.get("version_source")
    require(source and sha(inside(folder, source["file"]).read_bytes()) == source["sha256"]
            and source["value"] == version["value"], "target version/source mismatch")
    final = read(folder, "target-runtime-end.json")
    require(final["product"] == product and final["phase"] == "end"
            and final["binding"] == binding
            and final["runtime_version"]["value"] == version["value"]
            and final["version_source"]["value"] == source["value"],
            "target runtime changed")


def verify_configuration(folder: Path, product: str, receipt: dict) -> None:
    config = receipt["configuration"]
    original = inside(folder, config["originalFile"]).read_bytes()
    configured = inside(folder, config["configuredFile"]).read_bytes()
    final = inside(folder, config["finalFile"]).read_bytes()
    require(sha(original) == config["originalSha256"]
            and sha(configured) == config["configuredSha256"]
            and sha(final) == config["finalSha256"] == sha(original)
            and final == original and configured != original,
            "configuration/restoration hash mismatch")
    require(config["readBackFiles"] == ["configured-before-primary.bin",
            "configured-after-primary.bin", "configured-after-secondary.bin"],
            "configuration read-back inventory mismatch")
    require(all(inside(folder, name).read_bytes() == configured for name in config["readBackFiles"]),
            "configuration changed between peers")
    if product == "simplesamlphp":
        overlay = ("\n$config['metadata.sources'] = [['type'=>'flatfile'],"
                   "['type'=>'mdq','server'=>'http://127.0.0.1:8081','cachelength'=>0]];\n").encode()
        require(configured == original + overlay and configured.count(b"127.0.0.1:8081") == 1,
                "SimpleSAMLphp source configuration mismatch")
    else:
        old = ET.fromstring(original)
        new = ET.fromstring(configured)
        namespace = "urn:mace:shibboleth:2.0:metadata"
        candidates = [node for node in list(new)
                      if node.tag == "{" + namespace + "}MetadataProvider"
                      and node.get("{" + XSI + "}type") == "DynamicHTTPMetadataProvider"
                      and (node.get("id") or "").startswith("MD06B")]
        require(len(candidates) == 1, "Shibboleth dynamic provider mismatch")
        template = candidates[0].find("{" + namespace + "}Template")
        require(template is not None and template.text ==
                "http://samlscope-reference-suite:8080/mdq/${entityID}",
                "Shibboleth MDQ template mismatch")
        new.remove(candidates[0])
        require(ET.tostring(new) == ET.tostring(old), "Shibboleth configuration changed beyond source")
    restoration = read(folder, receipt["restorationFile"])
    require(restoration == {"restored": True, "failures": [], "originalSha256": sha(original),
            "finalSha256": sha(original), "originalBytes": len(original), "finalBytes": len(original)},
            "restoration record mismatch")


def verify_peer(folder: Path, peer: dict, correlation: dict) -> None:
    require(peer["label"] in {"primary", "secondary"} and PLAN_RE.fullmatch(peer["plan"])
            and RUN_RE.fullmatch(peer["run"]) and peer["entity"] == "http://localhost:18080/p/" + peer["plan"],
            "peer identity mismatch")
    metadata = inside(folder, peer["metadataFile"]).read_bytes()
    root = ET.fromstring(metadata)
    require(root.tag == "{" + MD + "}EntityDescriptor" and root.get("entityID") == peer["entity"]
            and sha(metadata) == peer["metadataSha256"], "peer metadata original mismatch")
    require(correlation["run"] == peer["run"] and correlation["plan"] == peer["plan"]
            and correlation["entityId"] == peer["entity"] and correlation["receipt"] == "recorded"
            and correlation["statusCode"] == "urn:oasis:names:tc:SAML:2.0:status:Success"
            and correlation["assertionCount"] == 1
            and correlation["assertionForm"] in {"plain", "encrypted"},
            "peer correlation summary mismatch")
    transcript = read(folder, peer["label"] + "-transcript.json")
    rows = {row["id"]: row for row in transcript}
    request = rows.get(correlation["requestTranscriptId"])
    response = rows.get(correlation["responseTranscriptId"])
    require(request and response and request["direction"] == "OUTBOUND"
            and request["samlSummary"].get("type") == "AuthnRequest"
            and request["samlSummary"].get("id") == correlation["requestId"]
            and response["direction"] == "INBOUND"
            and response["samlSummary"].get("type") == "Response"
            and response["samlSummary"].get("inResponseTo") == correlation["requestId"]
            and response["samlSummary"].get("statusCode") == correlation["statusCode"],
            "transcript correlation mismatch")
    original = inside(folder, correlation["responseOriginal"]).read_bytes()
    require(sha(original) == correlation["responseSha256"], "response original hash mismatch")
    parsed = ET.fromstring(original)
    status = parsed.find("{" + SAMLP + "}Status/{" + SAMLP + "}StatusCode")
    require(parsed.tag == "{" + SAMLP + "}Response"
            and parsed.get("InResponseTo") == correlation["requestId"]
            and status is not None and status.get("Value") == correlation["statusCode"]
            and (len(parsed.findall(".//{" + SAML + "}Assertion"))
                 + len(parsed.findall(".//{" + SAML + "}EncryptedAssertion"))) == 1
            and ((correlation["assertionForm"] == "plain"
                  and len(parsed.findall(".//{" + SAML + "}Assertion")) == 1)
                 or (correlation["assertionForm"] == "encrypted"
                     and len(parsed.findall(".//{" + SAML + "}EncryptedAssertion")) == 1)),
            "response original semantics mismatch")


def verify_operations(folder: Path, product: str, receipt: dict) -> None:
    operations = read(folder, receipt["operationCountsFile"])
    rows = operations["operations"]
    require(operations["productConfigurationWrites"] == 1
            and operations["restorationWrites"] == 1
            and operations["protocolRoundTrips"] == 2
            and operations["productRestarts"] == operations["humanOperations"] == 0
            and operations["restored"] is True, "operation counts mismatch")
    require(sum(row["operation"] == "product-config-write" for row in rows) == 1
            and sum(row["operation"] == "product-config-restore" for row in rows) == 1
            and [row.get("peer") for row in rows if row["operation"] == "protocol-roundtrip"] ==
            ["primary", "secondary"], "operation sequence mismatch")
    if product == "shibboleth":
        require(operations["metadataSourceReloads"] == 1
                and operations["nativeSourceLookups"] == 0
                and sum(row["operation"] == "metadata-source-restore-reload" for row in rows) == 1,
                "Shibboleth operation inventory mismatch")
    else:
        require(operations["metadataSourceReloads"] == 0
                and operations["nativeSourceLookups"] == 2
                and sum(row["operation"] == "temporary-relay-start" for row in rows) == 1
                and sum(row["operation"] == "temporary-relay-stop" for row in rows) == 1,
                "SimpleSAMLphp operation inventory mismatch")
        requests = [json.loads(line) for line in inside(folder, "relay-requests.jsonl").read_text().splitlines()]
        entities = [peer["entity"] for peer in receipt["peers"]]
        require(set(row["entityId"] for row in requests) == set(entities)
                and all(row["httpStatus"] == 200 and len(row["responseSha256"]) == 64 for row in requests),
                "SimpleSAMLphp native MDQ fetch log mismatch")
        for peer in receipt["peers"]:
            exit_record = read(folder, peer["label"] + "-native-lookup-exit.json")
            native = json.loads(inside(folder, peer["label"] + "-native-lookup.stdout").read_text())
            require(exit_record == {"exitCode": 0} and native == {"entityid": peer["entity"]},
                    "SimpleSAMLphp native lookup mismatch")


def verify_result(folder: Path, receipt: dict) -> None:
    receipt_sha = sha((folder / "receipt.json").read_bytes())
    expected_note = ("Machine-verified MD06.b multi-peer campaign; receipt sha256=" + receipt_sha
                     + "; secondary peer worked with no additional target input or separate configuration")
    configured = read(folder, "configure.json")
    require(configured["runId"] == receipt["primaryRun"] and configured["caseId"] == CASE
            and configured["status"] == "WAITING_ATTESTATION", "configuration gate mismatch")
    attested = read(folder, "attest.json")
    require(attested["runId"] == receipt["primaryRun"] and attested["caseId"] == CASE
            and attested["status"] == "FINISHED", "attestation identity mismatch")
    outcome = attested["outcome"]
    require((outcome["outcome"], outcome["reasonCode"]) ==
            ("SATISFIED", "configuration.evidence-satisfies")
            and outcome["details"] == {"attested": True, "attestation_option": "evidence_satisfies",
                                       "attestation_note": expected_note},
            "formal case outcome mismatch")
    result = read(folder, "result.json")
    case = case_map(result)[CASE]
    require((case["outcome"], case["verdict"], case["reason_code"], case["attested"],
             case["evidence_class"]) ==
            ("SATISFIED", "PASS", "configuration.evidence-satisfies", False, "SELF_ATTESTED"),
            "formal result mismatch")
    require(case["evidence"] == [{"kind": "attestation",
            "reference": "attestation:" + receipt["primaryRun"] + ":" + CASE}],
            "formal attestation reference mismatch")


def verify(folder: Path, receipt: dict | None = None, *, result: bool = True) -> None:
    raw = (folder / "receipt.json").read_bytes()
    receipt = copy.deepcopy(receipt if receipt is not None else json.loads(raw))
    if receipt is None:
        raise ValueError("missing receipt")
    require(raw == canonical(json.loads(raw)), "receipt is not canonical")
    product = receipt["product"]
    require(receipt["schema"] == "samlscope-md06b-multi-peer-receipt-v1"
            and receipt["caseId"] == CASE and product in TARGETS
            and receipt["targetEntityId"] == TARGETS[product]
            and RUN_RE.fullmatch(receipt["primaryRun"])
            and RUN_RE.fullmatch(receipt["secondaryRun"]), "receipt identity mismatch")
    peers = receipt["peers"]
    correlations = receipt["correlations"]
    require(len(peers) == len(correlations) == 2
            and [peer["label"] for peer in peers] == ["primary", "secondary"]
            and len({peer["entity"] for peer in peers}) == len({peer["plan"] for peer in peers}) ==
            len({peer["run"] for peer in peers}) == 2
            and receipt["primaryRun"] == peers[0]["run"]
            and receipt["secondaryRun"] == peers[1]["run"], "two-peer binding mismatch")
    require(receipt["controls"] == {
        "positive": "both-distinct-peers-correlated-success-with-assertion",
        "negative": "verifier-rejects-extra-peer-configuration-or-missing-secondary",
    }, "control declaration mismatch")
    verify_suite(folder, receipt)
    verify_target(folder, product, receipt)
    verify_configuration(folder, product, receipt)
    for peer, correlation in zip(peers, correlations):
        verify_peer(folder, peer, correlation)
    verify_operations(folder, product, receipt)
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
        except (ValueError, KeyError, TypeError, ET.ParseError, json.JSONDecodeError):
            rejected.append(label)
        else:
            raise AssertionError("tamper control accepted: " + label)

    reject("missing-secondary", lambda value: value["correlations"].pop())
    reject("same-peer", lambda value: value["peers"].__setitem__(1, copy.deepcopy(value["peers"][0])))
    reject("wrong-run", lambda value: value.__setitem__("secondaryRun", value["primaryRun"]))
    reject("response-status", lambda value: value["correlations"][1].__setitem__("statusCode",
           "urn:oasis:names:tc:SAML:2.0:status:Responder"))
    reject("response-original", lambda value: value["correlations"][1].__setitem__("responseOriginal",
           value["correlations"][0]["responseOriginal"]))
    reject("configured-readback", lambda value: value["configuration"]["readBackFiles"].pop())
    reject("restoration", lambda value: value["configuration"].__setitem__("finalSha256", "0" * 64))
    reject("suite-image", lambda value: value["suiteRuntime"].__setitem__("imageId", "sha256:" + "0" * 64))
    reject("suite-jar", lambda value: value["suiteRuntime"]["jars"]["runner"].__setitem__("sha256", "0" * 64))
    reject("target-image", lambda value: value["runtime"]["binding"].__setitem__("image_id", "sha256:" + "0" * 64))
    require(len(rejected) == 10, "tamper self-test count mismatch")
    return rejected


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    folder = args.folder.resolve()
    verify(folder)
    rejected = tamper(folder)
    report = {"schema": "samlscope-md06b-multi-peer-acceptance-v1",
              "folder": folder.name, "verified": True,
              "tamperControlsRejected": rejected, "formalReduction": 1}
    (folder / "acceptance-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(folder.name, "verified;", len(rejected), "tamper controls rejected")


if __name__ == "__main__":
    main()
