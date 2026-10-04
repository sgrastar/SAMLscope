#!/usr/bin/env python3
"""Prove IDP MD06.b with two Suite peers and one product metadata source.

The campaign configures one native dynamic metadata source, then performs a correlated
SSO exchange for two independently-created Suite SP entity IDs without changing the
target configuration between exchanges.  It restores the target byte-for-byte before
submitting the approved CONFIG answers.  The companion verifier, rather than this
recorder, decides whether the evidence is sufficient for adoption.
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
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
from import_metadata_batch import api, save, BASE
from reference_flow import Client
from capture_terminal_http_runtime import capture_target

CASE = "IIP-MD06-b-idp-01"
USER = os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user")
PASSWORD = os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password")
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
SHIB = "samlscope-reference-shibboleth"
SSP = "samlscope-reference-ssp"
SHIB_CONFIG = "/opt/reference-idp/conf/metadata-providers.xml"
SSP_HOST_CONFIG = REPO / "build/acceptance/reference-20260914/ssp-config/config-override.php"
SSP_CONFIG = "/var/simplesamlphp/config/config-override.php"
SSP_RELAY = "/tmp/samlscope-md06b-mdq"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
MD = "urn:oasis:names:tc:SAML:2.0:metadata"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"


def docker(container: str, *args: str, data: bytes | None = None, check: bool = True) -> bytes:
    command = ["docker", "exec", *(["-i"] if data is not None else []), container, *args]
    return subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=check, timeout=90).stdout


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def product(product: str):
    if product == "shibboleth":
        return {
            "container": SHIB,
            "targetEntityId": "http://localhost:18280/idp/shibboleth",
            "targetMetadata": "http://samlscope-reference-shibboleth:8080/idp/shibboleth",
            "health": "http://localhost:18280/idp/shibboleth",
        }
    if product == "simplesamlphp":
        return {
            "container": SSP,
            "targetEntityId": "http://localhost:18380/idp",
            "targetMetadata": "http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata",
            "health": "http://localhost:18380/simplesaml/module.php/saml/idp/metadata",
        }
    raise ValueError("unsupported product")


def require_id(value: str, prefix: str) -> str:
    if not re.fullmatch(prefix + r"_[0-9A-HJKMNP-TV-Z]{26}", value):
        raise ValueError("invalid " + prefix + " identifier")
    return value


def create_peer(label: str, target: dict, out: Path) -> dict:
    created = api("/api/plans", {
        "name": "MD06.b multi-peer " + label,
        "profile": "metadata_idp",
        "targetKind": "IDP",
        "targetEntityId": target["targetEntityId"],
        "metadataSourceKind": "URL",
        "metadataSourceLocation": target["targetMetadata"],
        "suiteMetadataDelivery": "HTTP_URL",
        "declaredFeatures": {},
        "parameters": {"clockSkewToleranceSeconds": 180, "metadataRefreshWaitSeconds": 300,
                       "testUserHint": USER, "requestSigningMode": "REQUIRED"},
        "interaction": {"allowBrowserSteps": True, "allowAttestation": True,
                        "preset": "assisted_with_attestation"},
        "authorizedTarget": True,
    })
    save(out / (label + "-plan.json"), created)
    plan = require_id(created["plan"]["plan"]["id"], "plan")
    run_result = api("/api/plans/" + plan + "/runs", {})
    save(out / (label + "-created.json"), run_result)
    run = require_id(run_result["run"]["id"], "run")
    save(out / (label + "-preflight.json"), api("/api/runs/" + run + "/preflight", {}))
    entity = BASE + "/p/" + plan
    with urllib.request.urlopen(entity + "/metadata", timeout=30) as response:
        metadata = response.read()
    (out / (label + "-metadata.xml")).write_bytes(metadata)
    root = ET.fromstring(metadata)
    if root.tag != "{" + MD + "}EntityDescriptor" or root.get("entityID") != entity:
        raise RuntimeError("Suite peer metadata identity mismatch")
    return {"label": label, "plan": plan, "run": run, "entity": entity,
            "metadataFile": label + "-metadata.xml", "metadataSha256": SHA(metadata)}


def capture_suite(out: Path, label: str) -> dict:
    container = "samlscope-reference-suite"
    inspect_raw = subprocess.check_output(["docker", "inspect", container], timeout=30)
    values = json.loads(inspect_raw)
    if not isinstance(values, list) or len(values) != 1 or values[0]["State"]["Running"] is not True:
        raise RuntimeError("ambiguous or stopped Suite container")
    item = values[0]
    (out / ("suite-container-inspect-" + label + ".json")).write_bytes(inspect_raw)
    jars = {}
    for name in ("core", "runner", "saml"):
        source = "/opt/samlscope/lib/" + name + "-0.1.0.jar"
        destination = out / ("suite-" + name + "-" + label + ".jar")
        subprocess.run(["docker", "cp", container + ":" + source, str(destination)], check=True,
                       stdout=subprocess.DEVNULL, timeout=60)
        jars[name] = {"path": source, "file": destination.name,
                      "sha256": SHA(destination.read_bytes())}
    record = {"containerName": container, "containerId": item["Id"],
              "imageId": item["Image"], "startedAt": item["State"]["StartedAt"],
              "configuredImage": item["Config"]["Image"], "running": True, "jars": jars,
              "inspectFile": "suite-container-inspect-" + label + ".json",
              "inspectSha256": SHA(inspect_raw)}
    save(out / ("suite-runtime-" + label + ".json"), record)
    return record


def health(target: dict, out: Path, label: str) -> None:
    with urllib.request.urlopen(target["health"], timeout=30) as response:
        body = response.read()
        status = response.status
    if status != 200 or not body:
        raise RuntimeError("target health check failed")
    save(out / ("health-" + label + ".json"), {"url": target["health"], "status": status,
                                                "bodySha256": SHA(body)})


def write_shib(raw: bytes) -> None:
    docker(SHIB, "sh", "-c", "cat > " + SHIB_CONFIG, data=raw)
    if docker(SHIB, "cat", SHIB_CONFIG) != raw:
        raise RuntimeError("Shibboleth configuration read-back mismatch")


def reload_shib(out: Path, label: str) -> None:
    log = docker(SHIB, "/opt/reference-idp/bin/reload-service.sh", "-id",
                 "shibboleth.MetadataResolverService", "-u", "http://localhost:8080/idp")
    (out / (label + "-reload.log")).write_bytes(log)


def shib_configuration(original: bytes, campaign: str) -> bytes:
    namespace = "urn:mace:shibboleth:2.0:metadata"
    ET.register_namespace("", namespace)
    ET.register_namespace("xsi", XSI)
    root = ET.fromstring(original)
    provider = ET.Element("{" + namespace + "}MetadataProvider", {
        "id": "MD06B" + campaign.replace("run_", ""),
        "{" + XSI + "}type": "DynamicHTTPMetadataProvider",
    })
    ET.SubElement(provider, "{" + namespace + "}Template", {"encodingStyle": "form"}).text = (
        "http://samlscope-reference-suite:8080/mdq/${entityID}")
    root.insert(0, provider)
    return ET.tostring(root)


def write_ssp_host(raw: bytes) -> None:
    with SSP_HOST_CONFIG.open("r+b") as handle:
        handle.seek(0)
        handle.write(raw)
        handle.truncate()
    if SSP_HOST_CONFIG.read_bytes() != raw:
        raise RuntimeError("SimpleSAMLphp host configuration read-back mismatch")
    for _ in range(30):
        if docker(SSP, "cat", SSP_CONFIG) == raw:
            return
        time.sleep(0.25)
    raise RuntimeError("SimpleSAMLphp product configuration read-back mismatch")


def ssp_router(entities: list[str]) -> bytes:
    encoded = json.dumps(entities, separators=(",", ":"))
    return ("<?php\n$allowed=" + encoded + ";\n"
            "$prefix='/entities/';$path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);\n"
            "if(!str_starts_with($path,$prefix)){http_response_code(404);exit;}\n"
            "$entity=rawurldecode(substr($path,strlen($prefix)));\n"
            "if(!in_array($entity,$allowed,true)){http_response_code(404);exit;}\n"
            "$url='http://samlscope-reference-suite:8080/mdq/'.rawurlencode($entity);\n"
            "$data=file_get_contents($url);if($data===false){http_response_code(502);exit;}\n"
            "$record=['entityId'=>$entity,'sourceUrl'=>$url,'responseSha256'=>hash('sha256',$data),"
            "'httpStatus'=>200,'observedAt'=>(new DateTimeImmutable('now',new DateTimeZone('UTC')))->format('Y-m-d\\TH:i:s.u\\Z')];\n"
            "file_put_contents('" + SSP_RELAY + "/requests.jsonl',json_encode($record).\"\\n\",FILE_APPEND|LOCK_EX);\n"
            "header('Content-Type: application/samlmetadata+xml');echo $data;\n").encode()


def start_ssp_relay(entities: list[str], out: Path) -> bytes:
    router = ssp_router(entities)
    (out / "relay-router.php").write_bytes(router)
    present = subprocess.run(["docker", "exec", SSP, "sh", "-c",
                              "test -e " + SSP_RELAY + "/pid"], timeout=30).returncode == 0
    if present:
        raise RuntimeError("SimpleSAMLphp MDQ relay already exists")
    docker(SSP, "mkdir", "-p", SSP_RELAY)
    docker(SSP, "sh", "-c", "cat > " + SSP_RELAY + "/router.php", data=router)
    if docker(SSP, "cat", SSP_RELAY + "/router.php") != router:
        raise RuntimeError("relay read-back mismatch")
    subprocess.run(["docker", "exec", "-d", SSP, "sh", "-c",
                    "echo $$ > " + SSP_RELAY + "/pid; exec php -S 127.0.0.1:8081 -t "
                    + SSP_RELAY + " " + SSP_RELAY + "/router.php >" + SSP_RELAY
                    + "/server.log 2>&1"], check=True, timeout=30)
    time.sleep(1)
    return router


def stop_ssp_relay(out: Path) -> None:
    for name in ("requests.jsonl", "server.log"):
        raw = docker(SSP, "sh", "-c", "test -e " + SSP_RELAY + "/" + name
                     + " && cat " + SSP_RELAY + "/" + name + " || true")
        (out / ("relay-" + name)).write_bytes(raw)
    docker(SSP, "sh", "-c", "test ! -e " + SSP_RELAY + "/pid || kill \"$(cat "
           + SSP_RELAY + "/pid)\"", check=False)
    docker(SSP, "rm", "-rf", SSP_RELAY)


def ssp_configuration(original: bytes) -> bytes:
    overlay = ("\n$config['metadata.sources'] = [['type'=>'flatfile'],"
               "['type'=>'mdq','server'=>'http://127.0.0.1:8081','cachelength'=>0]];\n").encode()
    if overlay in original:
        raise RuntimeError("MD06.b source already configured")
    return original + overlay


def ssp_native_lookup(entity: str, out: Path, label: str) -> None:
    code = ("require '/var/simplesamlphp/lib/_autoload.php';"
            "$s=\\SimpleSAML\\Metadata\\MetaDataStorageSource::getSource("
            "['type'=>'mdq','server'=>'http://127.0.0.1:8081','cachelength'=>0]);"
            "$m=$s->getMetaData($argv[1],'saml20-sp-remote');"
            "echo json_encode(['entityid'=>$m['entityid']??null]);")
    result = subprocess.run(["docker", "exec", SSP, "php", "-r", code, entity],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
    (out / (label + "-native-lookup.stdout")).write_bytes(result.stdout)
    (out / (label + "-native-lookup.stderr")).write_bytes(result.stderr)
    save(out / (label + "-native-lookup-exit.json"), {"exitCode": result.returncode})
    if result.returncode != 0 or json.loads(result.stdout).get("entityid") != entity:
        raise RuntimeError("SimpleSAMLphp native MDQ lookup failed")


def correlate(peer: dict, out: Path) -> dict:
    before = {row["id"] for row in api("/api/runs/" + peer["run"] + "/transcript")}
    receipt = Client().flow(peer["entity"] + "/start/m0-roundtrip?run=" + peer["run"],
                            None, USER, PASSWORD)
    rows = api("/api/runs/" + peer["run"] + "/transcript")
    new = [row for row in rows if row["id"] not in before]
    requests = [row for row in new if row["direction"] == "OUTBOUND"
                and row["samlSummary"].get("type") == "AuthnRequest"]
    if len(requests) != 1:
        raise RuntimeError("ambiguous multi-peer AuthnRequest")
    request_id = requests[0]["samlSummary"].get("id")
    responses = [row for row in new if row["direction"] == "INBOUND"
                 and row["samlSummary"].get("type") == "Response"
                 and row["samlSummary"].get("inResponseTo") == request_id
                 and row["samlSummary"].get("statusCode") ==
                 "urn:oasis:names:tc:SAML:2.0:status:Success"]
    if receipt != "recorded" or len(responses) != 1:
        raise RuntimeError("correlated multi-peer Success response missing")
    response = responses[0]
    reference = response.get("decodedSamlRef")
    if not reference or Path(reference).is_absolute() or ".." in Path(reference).parts:
        raise RuntimeError("invalid response original reference")
    decoded = out / (peer["label"] + "-response.xml")
    subprocess.run(["docker", "cp", "samlscope-reference-suite:/data/" + reference, str(decoded)],
                   check=True, stdout=subprocess.DEVNULL, timeout=60)
    root = ET.fromstring(decoded.read_bytes())
    assertions = (root.findall(".//{" + SAML + "}Assertion")
                  + root.findall(".//{" + SAML + "}EncryptedAssertion"))
    if len(assertions) != 1:
        raise RuntimeError("correlated response lacks exactly one Assertion")
    save(out / (peer["label"] + "-transcript.json"), rows)
    record = {"run": peer["run"], "plan": peer["plan"], "entityId": peer["entity"],
              "receipt": receipt, "requestTranscriptId": requests[0]["id"],
              "requestId": request_id, "responseTranscriptId": response["id"],
              "responseOriginal": decoded.name, "responseSha256": SHA(decoded.read_bytes()),
              "statusCode": response["samlSummary"]["statusCode"], "assertionCount": 1,
              "assertionForm": "encrypted" if assertions[0].tag.endswith("EncryptedAssertion") else "plain"}
    save(out / (peer["label"] + "-correlation.json"), record)
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", choices=["shibboleth", "simplesamlphp"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    target = product(args.product)
    health(target, out, "start")
    runtime_start = capture_target(out, args.product, "start")
    suite_start = capture_suite(out, "start")
    primary = create_peer("primary", target, out)
    secondary = create_peer("secondary", target, out)
    peers = [primary, secondary]
    operations = []
    relay_started = False
    if args.product == "shibboleth":
        original = docker(SHIB, "cat", SHIB_CONFIG)
        configured = shib_configuration(original, primary["run"])
    else:
        original = SSP_HOST_CONFIG.read_bytes()
        configured = ssp_configuration(original)
    (out / "original-configuration.bin").write_bytes(original)
    (out / "configured-configuration.bin").write_bytes(configured)
    changed = False
    restored = False
    correlations = []
    try:
        if args.product == "shibboleth":
            write_shib(configured)
            operations.append({"operation": "product-config-write", "sha256": SHA(configured),
                               "readBack": True})
            changed = True
            reload_shib(out, "configure")
            operations.append({"operation": "metadata-source-reload", "completed": True})
        else:
            start_ssp_relay([value["entity"] for value in peers], out)
            relay_started = True
            operations.append({"operation": "temporary-relay-start", "completed": True})
            write_ssp_host(configured)
            operations.append({"operation": "product-config-write", "sha256": SHA(configured),
                               "readBack": True})
            changed = True
            time.sleep(2)
            for peer in peers:
                ssp_native_lookup(peer["entity"], out, peer["label"])
                operations.append({"operation": "native-source-lookup", "peer": peer["label"],
                                   "entityId": peer["entity"], "completed": True})
        readback = docker(target["container"], "cat", SHIB_CONFIG if args.product == "shibboleth"
                          else SSP_CONFIG)
        if readback != configured:
            raise RuntimeError("configured state changed before primary exchange")
        (out / "configured-before-primary.bin").write_bytes(readback)
        for peer in peers:
            correlations.append(correlate(peer, out))
            readback = docker(target["container"], "cat", SHIB_CONFIG if args.product == "shibboleth"
                              else SSP_CONFIG)
            (out / ("configured-after-" + peer["label"] + ".bin")).write_bytes(readback)
            if readback != configured:
                raise RuntimeError("target configuration changed between peer exchanges")
            operations.append({"operation": "protocol-roundtrip", "peer": peer["label"],
                               "run": peer["run"], "completed": True})
    finally:
        failures = []
        if changed:
            try:
                current = docker(target["container"], "cat", SHIB_CONFIG if args.product == "shibboleth"
                                 else SSP_CONFIG)
                if current != configured:
                    raise RuntimeError("concurrent configuration change; refusing overwrite")
                if args.product == "shibboleth":
                    write_shib(original)
                    reload_shib(out, "restore")
                    operations.append({"operation": "metadata-source-restore-reload",
                                       "completed": True})
                else:
                    write_ssp_host(original)
                operations.append({"operation": "product-config-restore", "sha256": SHA(original),
                                   "readBack": True})
            except Exception as error:
                failures.append(type(error).__name__ + ":" + str(error))
        if relay_started:
            try:
                stop_ssp_relay(out)
                operations.append({"operation": "temporary-relay-stop", "completed": True})
            except Exception as error:
                failures.append("relay:" + type(error).__name__ + ":" + str(error))
        final = docker(target["container"], "cat", SHIB_CONFIG if args.product == "shibboleth"
                       else SSP_CONFIG)
        (out / "final-configuration.bin").write_bytes(final)
        restored = not failures and final == original
        save(out / "restoration.json", {"restored": restored, "failures": failures,
             "originalSha256": SHA(original), "finalSha256": SHA(final),
             "originalBytes": len(original), "finalBytes": len(final)})
        save(out / "operation-counts.json", {"operations": operations,
             "productConfigurationWrites": sum(row["operation"] == "product-config-write" for row in operations),
             "restorationWrites": sum(row["operation"] == "product-config-restore" for row in operations),
             "metadataSourceReloads": sum(row["operation"] == "metadata-source-reload" for row in operations),
             "protocolRoundTrips": sum(row["operation"] == "protocol-roundtrip" for row in operations),
             "nativeSourceLookups": sum(row["operation"] == "native-source-lookup" for row in operations),
             "productRestarts": 0, "humanOperations": 0, "restored": restored})
        if not restored:
            raise RuntimeError("product restoration failed")
    health(target, out, "final")
    runtime_final = capture_target(out, args.product, "end")
    suite_final = capture_suite(out, "final")
    for key in ("container_name", "container_id", "configured_image", "image_id",
                "container_started_at", "running_at_capture", "host_port_bound"):
        if runtime_start["binding"].get(key) != runtime_final["binding"].get(key):
            raise RuntimeError("target runtime changed during campaign")
    if runtime_start["runtime_version"]["value"] != runtime_final["runtime_version"]["value"]:
        raise RuntimeError("target version changed during campaign")
    if runtime_start.get("version_source", {}).get("value") != runtime_final.get("version_source", {}).get("value"):
        raise RuntimeError("target version source changed during campaign")
    for key in ("containerName", "containerId", "imageId", "startedAt", "configuredImage"):
        if suite_final[key] != suite_start[key]:
            raise RuntimeError("Suite runtime changed during campaign")
    for name in suite_start["jars"]:
        if ({key: suite_start["jars"][name][key] for key in ("path", "sha256")} !=
                {key: suite_final["jars"][name][key] for key in ("path", "sha256")}):
            raise RuntimeError("Suite JAR changed during campaign")
    receipt = {
        "schema": "samlscope-md06b-multi-peer-receipt-v1",
        "caseId": CASE, "product": args.product,
        "primaryRun": primary["run"], "secondaryRun": secondary["run"],
        "targetEntityId": target["targetEntityId"], "runtime": runtime_start,
        "suiteRuntime": suite_start,
        "peers": peers, "correlations": correlations,
        "configuration": {"originalFile": "original-configuration.bin",
                          "originalSha256": SHA(original),
                          "configuredFile": "configured-configuration.bin",
                          "configuredSha256": SHA(configured),
                          "readBackFiles": ["configured-before-primary.bin",
                                            "configured-after-primary.bin",
                                            "configured-after-secondary.bin"],
                          "finalFile": "final-configuration.bin",
                          "finalSha256": SHA(original)},
        "restorationFile": "restoration.json", "operationCountsFile": "operation-counts.json",
        "controls": {"positive": "both-distinct-peers-correlated-success-with-assertion",
                     "negative": "verifier-rejects-extra-peer-configuration-or-missing-secondary"},
    }
    (out / "receipt.json").write_bytes(canonical(receipt))
    receipt_sha = SHA((out / "receipt.json").read_bytes())
    note = ("Machine-verified MD06.b multi-peer campaign; receipt sha256=" + receipt_sha
            + "; secondary peer worked with no additional target input or separate configuration")
    save(out / "tests-start.json", api("/api/runs/" + primary["run"] + "/tests/start", {}))
    save(out / "configure.json", api("/api/runs/" + primary["run"] + "/cases/" + CASE
                                      + "/configure", {"value": "confirmed"}))
    save(out / "attest.json", api("/api/runs/" + primary["run"] + "/cases/" + CASE
                                   + "/attest", {"value": "evidence_satisfies", "note": note}))
    save(out / "result.json", api("/api/runs/" + primary["run"] + "/result.json"))
    save(out / "run-after.json", api("/api/runs/" + primary["run"]))
    print(args.product, primary["run"], secondary["run"], "restored", restored,
          "receipt", receipt_sha)


if __name__ == "__main__":
    main()
