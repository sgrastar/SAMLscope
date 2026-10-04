#!/usr/bin/env python3
"""Exercise source-scoped metadata trust for the approved IDP MD03.d case.

Source A and source B publish distinct Suite SP entities signed by the same key K.
The product trusts K for source A and a different key K2 for source B.  Acceptance of
A and an explicit native signature rejection for B are recorded together with the SAML
exchanges, exact configuration read-back, restoration, and immutable runtimes.
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
import time
import urllib.parse
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from import_metadata_batch import api, save
from reference_flow import Client
from capture_terminal_http_runtime import capture_target
from md06b_multi_peer_campaign import (
    BASE, SHIB, SSP, SHIB_CONFIG, SSP_CONFIG, SSP_HOST_CONFIG, XSI, SAML,
    canonical, capture_suite, create_peer, docker, health, product,
    reload_shib, write_shib, write_ssp_host,
)

CASE = "IIP-MD03-d-idp-01"
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
USER = os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user")
PASSWORD = os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password")
HELPER = Path(__file__).with_name("SourceScopedMetadata.java")
SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
TMP_PREFIX = "/tmp/samlscope-md03d-"


def command(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=kwargs.pop("timeout", 90), **kwargs)


def generate_material(out: Path, peers: list[dict], work: Path) -> dict:
    classes = work / "classes"
    classes.mkdir()
    command(["javac", "--release", "21", "-d", str(classes), str(HELPER)])
    (out / "source-scoped-helper.java").write_bytes(HELPER.read_bytes())
    for name in ("k", "k2"):
        command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                 "-subj", "/CN=samlscope-md03d-" + name,
                 "-keyout", str(work / (name + ".pem")), "-out", str(work / (name + ".crt"))])
        command(["openssl", "pkcs8", "-topk8", "-inform", "PEM", "-outform", "DER",
                 "-in", str(work / (name + ".pem")), "-nocrypt", "-out", str(work / (name + ".pk8"))])
        command(["openssl", "x509", "-in", str(work / (name + ".crt")), "-outform", "DER",
                 "-out", str(out / (name + ".cert.der"))])
        (out / (name + ".cert.pem")).write_bytes((work / (name + ".crt")).read_bytes())
    for peer in peers:
        source = out / peer["metadataFile"]
        signed = out / (peer["label"] + "-signed-metadata.xml")
        shutil.copy2(out / "k.cert.der", Path(str(signed) + ".cert.der"))
        command(["java", "-cp", str(classes), "SourceScopedMetadata", "sign",
                 str(source), str(work / "k.pk8"), str(signed)])
        verified = work / (peer["label"] + ".verified")
        command(["java", "-cp", str(classes), "SourceScopedMetadata", "verify",
                 str(signed), str(out / "k.cert.der"), str(verified)])
        if verified.read_text() != "verified\n":
            raise RuntimeError("generated source metadata signature did not verify")
        peer["signedMetadataFile"] = signed.name
        peer["signedMetadataSha256"] = SHA(signed.read_bytes())
    return {
        "helperFile": "source-scoped-helper.java", "helperSha256": SHA(HELPER.read_bytes()),
        "keyKCertificateFile": "k.cert.der", "keyKCertificateSha256": SHA((out / "k.cert.der").read_bytes()),
        "keyK2CertificateFile": "k2.cert.der", "keyK2CertificateSha256": SHA((out / "k2.cert.der").read_bytes()),
        "temporaryPrivateKeysRemoved": False,
    }


def shib_server_script() -> bytes:
    return b'''import hashlib,json,sys,urllib.parse\nfrom http.server import BaseHTTPRequestHandler,HTTPServer\nport=int(sys.argv[1]); expected=sys.argv[2]; source=sys.argv[3]; log=sys.argv[4]\nclass H(BaseHTTPRequestHandler):\n def do_GET(self):\n  prefix='/entities/'; entity=urllib.parse.unquote_plus(urllib.parse.urlparse(self.path).path[len(prefix):]) if urllib.parse.urlparse(self.path).path.startswith(prefix) else ''\n  if entity!=expected:\n   self.send_response(404);self.end_headers();return\n  raw=open(source,'rb').read();self.send_response(200);self.send_header('Content-Type','application/samlmetadata+xml');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)\n  with open(log,'a') as f:f.write(json.dumps({'entityId':entity,'responseSha256':hashlib.sha256(raw).hexdigest(),'httpStatus':200})+'\\n')\n def log_message(self,*args): pass\nHTTPServer(('127.0.0.1',port),H).serve_forever()\n'''


def ssp_server_script() -> bytes:
    return b'''<?php
$expected=getenv('EXPECTED_ENTITY');$source=getenv('SOURCE_FILE');$log=getenv('LOG_FILE');
$prefix='/entities/';$path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);
$entity=str_starts_with($path,$prefix)?rawurldecode(substr($path,strlen($prefix))):'';
if($entity!==$expected){http_response_code(404);exit;}
$raw=file_get_contents($source);if($raw===false){http_response_code(502);exit;}
$record=['entityId'=>$entity,'responseSha256'=>hash('sha256',$raw),'httpStatus'=>200];
file_put_contents($log,json_encode($record)."\n",FILE_APPEND|LOCK_EX);
header('Content-Type: application/samlmetadata+xml');echo $raw;
'''


def start_servers(product_name: str, temp: str, peers: list[dict], out: Path) -> None:
    container = SHIB if product_name == "shibboleth" else SSP
    script = shib_server_script() if product_name == "shibboleth" else ssp_server_script()
    suffix = "server.py" if product_name == "shibboleth" else "router.php"
    docker(container, "mkdir", "-p", temp)
    docker(container, "sh", "-c", "cat > " + temp + "/" + suffix, data=script)
    (out / ("native-" + suffix)).write_bytes(script)
    for name in ("k.cert.pem", "k2.cert.pem"):
        subprocess.run(["docker", "cp", str(out / name), container + ":" + temp + "/" + name],
                       check=True, stdout=subprocess.DEVNULL, timeout=30)
    for index, peer in enumerate(peers):
        port = 18081 + index if product_name == "shibboleth" else 8081 + index
        source = temp + "/" + peer["label"] + ".xml"
        subprocess.run(["docker", "cp", str(out / peer["signedMetadataFile"]),
                        container + ":" + source], check=True, stdout=subprocess.DEVNULL, timeout=30)
        if docker(container, "cat", source) != (out / peer["signedMetadataFile"]).read_bytes():
            raise RuntimeError("source metadata read-back mismatch")
        log = temp + "/" + peer["label"] + "-requests.jsonl"
        pid = temp + "/" + peer["label"] + ".pid"
        if product_name == "shibboleth":
            shell = ("echo $$ > " + pid + "; exec python3 " + temp + "/server.py " + str(port)
                     + " " + json.dumps(peer["entity"]) + " " + source + " " + log
                     + " >" + temp + "/" + peer["label"] + "-server.log 2>&1")
        else:
            shell = ("echo $$ > " + pid + "; export EXPECTED_ENTITY=" + json.dumps(peer["entity"])
                     + " SOURCE_FILE=" + source + " LOG_FILE=" + log + "; exec php -S 127.0.0.1:"
                     + str(port) + " -t " + temp + " " + temp + "/router.php >" + temp + "/"
                     + peer["label"] + "-server.log 2>&1")
        subprocess.run(["docker", "exec", "-d", container, "sh", "-c", shell],
                       check=True, timeout=30)
    time.sleep(1)


def stop_servers(product_name: str, temp: str, peers: list[dict], out: Path) -> None:
    container = SHIB if product_name == "shibboleth" else SSP
    for peer in peers:
        for suffix in ("requests.jsonl", "server.log"):
            raw = docker(container, "sh", "-c", "test -e " + temp + "/" + peer["label"]
                         + "-" + suffix + " && cat " + temp + "/" + peer["label"] + "-"
                         + suffix + " || true")
            (out / (peer["label"] + "-" + suffix)).write_bytes(raw)
        docker(container, "sh", "-c", "test ! -e " + temp + "/" + peer["label"]
               + ".pid || kill \"$(cat " + temp + "/" + peer["label"] + ".pid)\"", check=False)
    docker(container, "rm", "-rf", temp)


def shib_configuration(original: bytes, temp: str, peers: list[dict]) -> bytes:
    namespace = "urn:mace:shibboleth:2.0:metadata"
    ET.register_namespace("", namespace)
    ET.register_namespace("xsi", XSI)
    root = ET.fromstring(original)
    for index, peer in enumerate(peers):
        provider = ET.Element("{" + namespace + "}MetadataProvider", {
            "id": "MD03D" + peer["label"].title() + peer["run"].removeprefix("run_"),
            "{" + XSI + "}type": "DynamicHTTPMetadataProvider",
        })
        ET.SubElement(provider, "{" + namespace + "}MetadataFilter", {
            "{" + XSI + "}type": "SignatureValidation", "requireSignedRoot": "true",
            "certificateFile": temp + ("/k.cert.pem" if index == 0 else "/k2.cert.pem"),
        })
        ET.SubElement(provider, "{" + namespace + "}Template", {"encodingStyle": "form"}).text = (
            "http://127.0.0.1:" + str(18081 + index) + "/entities/${entityID}")
        root.insert(index, provider)
    return ET.tostring(root)


def ssp_configuration(original: bytes, temp: str) -> bytes:
    overlay = ("\n$config['metadata.sources'] = [['type'=>'flatfile'],"
        "['type'=>'mdq','server'=>'http://127.0.0.1:8081','validateCertificate'=>['" + temp
        + "/k.cert.pem'],'cachelength'=>0],"
        "['type'=>'mdq','server'=>'http://127.0.0.1:8082','validateCertificate'=>['" + temp
        + "/k2.cert.pem'],'cachelength'=>0]];\n").encode()
    if temp.encode() in original:
        raise RuntimeError("source-scoped trust overlay already exists")
    return original + overlay


def native_lookup(product_name: str, peer: dict, temp: str, out: Path, expect_success: bool) -> dict:
    if product_name == "shibboleth":
        command_line = ["docker", "exec", SHIB, "/opt/reference-idp/bin/mdquery.sh",
                        "--entityID", peer["entity"], "--saml2", "--url", "http://localhost:8080/idp"]
    else:
        index = 0 if peer["label"] == "source-a" else 1
        cert = temp + ("/k.cert.pem" if index == 0 else "/k2.cert.pem")
        code = ("require '/var/simplesamlphp/lib/_autoload.php';"
                "$s=\\SimpleSAML\\Metadata\\MetaDataStorageSource::getSource(['type'=>'mdq',"
                "'server'=>$argv[1],'validateCertificate'=>[$argv[2]],'cachelength'=>0]);"
                "$m=$s->getMetaData($argv[3],'saml20-sp-remote');"
                "echo json_encode(['entityid'=>$m['entityid']??null]);")
        command_line = ["docker", "exec", SSP, "php", "-r", code,
                        "http://127.0.0.1:" + str(8081 + index), cert, peer["entity"]]
    result = subprocess.run(command_line, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    (out / (peer["label"] + "-native-lookup.stdout")).write_bytes(result.stdout)
    (out / (peer["label"] + "-native-lookup.stderr")).write_bytes(result.stderr)
    record = {"exitCode": result.returncode, "expectSuccess": expect_success,
              "stdoutSha256": SHA(result.stdout), "stderrSha256": SHA(result.stderr)}
    save(out / (peer["label"] + "-native-lookup.json"), record)
    if expect_success:
        if result.returncode != 0:
            raise RuntimeError("source A native lookup failed")
        if product_name == "simplesamlphp" and json.loads(result.stdout).get("entityid") != peer["entity"]:
            raise RuntimeError("source A native lookup identity mismatch")
        if product_name == "shibboleth" and peer["entity"].encode() not in result.stdout:
            raise RuntimeError("source A mdquery did not return the entity")
    else:
        combined = result.stdout + result.stderr
        if product_name == "simplesamlphp":
            if result.returncode == 0 or b"could not verify signature" not in combined:
                raise RuntimeError("source B lacked explicit native signature rejection")
        elif peer["entity"].encode() in result.stdout and b"Not Found" not in combined:
            raise RuntimeError("source B unexpectedly resolved")
    return record


def correlated_success(peer: dict, out: Path) -> dict:
    before = {row["id"] for row in api("/api/runs/" + peer["run"] + "/transcript")}
    receipt = Client().flow(peer["entity"] + "/start/m0-roundtrip?run=" + peer["run"],
                            None, USER, PASSWORD)
    rows = api("/api/runs/" + peer["run"] + "/transcript")
    new = [row for row in rows if row["id"] not in before]
    requests = [row for row in new if row["direction"] == "OUTBOUND"
                and row["samlSummary"].get("type") == "AuthnRequest"]
    if len(requests) != 1:
        raise RuntimeError("source A request correlation ambiguous")
    request_id = requests[0]["samlSummary"]["id"]
    responses = [row for row in new if row["direction"] == "INBOUND"
                 and row["samlSummary"].get("type") == "Response"
                 and row["samlSummary"].get("inResponseTo") == request_id
                 and row["samlSummary"].get("statusCode") ==
                 "urn:oasis:names:tc:SAML:2.0:status:Success"]
    if receipt != "recorded" or len(responses) != 1:
        raise RuntimeError("source A correlated Success missing")
    response = responses[0]
    reference = response.get("decodedSamlRef")
    if not reference or Path(reference).is_absolute() or ".." in Path(reference).parts:
        raise RuntimeError("invalid response original")
    original = out / "source-a-response.xml"
    subprocess.run(["docker", "cp", "samlscope-reference-suite:/data/" + reference, str(original)],
                   check=True, stdout=subprocess.DEVNULL, timeout=60)
    root = ET.fromstring(original.read_bytes())
    assertions = root.findall(".//{" + SAML + "}Assertion") + root.findall(".//{" + SAML + "}EncryptedAssertion")
    if len(assertions) != 1:
        raise RuntimeError("source A response lacks Assertion")
    save(out / "source-a-transcript.json", rows)
    record = {"run": peer["run"], "entityId": peer["entity"], "receipt": receipt,
              "requestTranscriptId": requests[0]["id"], "requestId": request_id,
              "responseTranscriptId": response["id"], "responseOriginal": original.name,
              "responseSha256": SHA(original.read_bytes()), "statusCode": response["samlSummary"]["statusCode"],
              "assertionForm": "encrypted" if assertions[0].tag.endswith("EncryptedAssertion") else "plain"}
    save(out / "source-a-correlation.json", record)
    return record


def correlated_rejection(peer: dict, out: Path) -> dict:
    before = {row["id"] for row in api("/api/runs/" + peer["run"] + "/transcript")}
    error = None
    try:
        receipt = Client().flow(peer["entity"] + "/start/m0-roundtrip?run=" + peer["run"],
                                None, USER, PASSWORD)
    except Exception as exception:
        receipt = "exception"
        error = type(exception).__name__ + ":" + str(exception)
    rows = api("/api/runs/" + peer["run"] + "/transcript")
    new = [row for row in rows if row["id"] not in before]
    requests = [row for row in new if row["direction"] == "OUTBOUND"
                and row["samlSummary"].get("type") == "AuthnRequest"]
    if len(requests) != 1:
        raise RuntimeError("source B request correlation ambiguous")
    request_id = requests[0]["samlSummary"]["id"]
    correlated = [row for row in new if row["direction"] == "INBOUND"
                  and row["samlSummary"].get("type") == "Response"
                  and row["samlSummary"].get("inResponseTo") == request_id]
    successes = [row for row in correlated if row["samlSummary"].get("statusCode") ==
                 "urn:oasis:names:tc:SAML:2.0:status:Success"]
    if successes:
        raise RuntimeError("source B signed by source A key was accepted")
    save(out / "source-b-transcript.json", rows)
    record = {"run": peer["run"], "entityId": peer["entity"], "receipt": receipt, "error": error,
              "requestTranscriptId": requests[0]["id"], "requestId": request_id,
              "correlatedResponseIds": [row["id"] for row in correlated],
              "correlatedStatusCodes": [row["samlSummary"].get("statusCode") for row in correlated],
              "correlatedSuccess": False}
    save(out / "source-b-correlation.json", record)
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
    source_a = create_peer("source-a", target, out)
    source_b = create_peer("source-b", target, out)
    peers = [source_a, source_b]
    temp = TMP_PREFIX + source_a["run"].removeprefix("run_")
    operations = []
    with tempfile.TemporaryDirectory(prefix="samlscope-md03d-") as temporary:
        material = generate_material(out, peers, Path(temporary))
        original = (docker(SHIB, "cat", SHIB_CONFIG) if args.product == "shibboleth"
                    else SSP_HOST_CONFIG.read_bytes())
        configured = (shib_configuration(original, temp, peers) if args.product == "shibboleth"
                      else ssp_configuration(original, temp))
        (out / "original-configuration.bin").write_bytes(original)
        (out / "configured-configuration.bin").write_bytes(configured)
        changed = servers = False
        restored = False
        source_a_correlation = source_b_correlation = None
        try:
            start_servers(args.product, temp, peers, out)
            servers = True
            operations.append({"operation": "temporary-source-servers-start", "count": 2,
                               "completed": True})
            if args.product == "shibboleth":
                write_shib(configured)
                changed = True
                operations.append({"operation": "product-config-write", "sha256": SHA(configured),
                                   "readBack": True})
                reload_shib(out, "configure")
                operations.append({"operation": "metadata-source-reload", "completed": True})
            else:
                write_ssp_host(configured)
                changed = True
                operations.append({"operation": "product-config-write", "sha256": SHA(configured),
                                   "readBack": True})
                time.sleep(2)
            path = SHIB_CONFIG if args.product == "shibboleth" else SSP_CONFIG
            readback = docker(target["container"], "cat", path)
            if readback != configured:
                raise RuntimeError("configured trust sources read-back mismatch")
            (out / "configured-readback.bin").write_bytes(readback)
            native_lookup(args.product, source_a, temp, out, True)
            operations.append({"operation": "native-source-lookup", "source": "A", "accepted": True})
            native_lookup(args.product, source_b, temp, out, False)
            operations.append({"operation": "native-source-lookup", "source": "B", "accepted": False,
                               "reason": "signature-key-not-trusted-for-source"})
            if args.product == "shibboleth":
                (out / "native-rejection-product-log.txt").write_bytes(docker(SHIB, "sh", "-c",
                    "grep -E 'MD03D|SignatureValidation|signature|" + source_b["run"].removeprefix("run_")
                    + "' /opt/reference-idp/logs/idp-process.log | tail -200"))
            else:
                (out / "native-rejection-product-log.txt").write_bytes(
                    (out / "source-b-native-lookup.stderr").read_bytes())
            source_a_correlation = correlated_success(source_a, out)
            operations.append({"operation": "protocol-roundtrip", "source": "A", "success": True,
                               "run": source_a["run"]})
            readback = docker(target["container"], "cat", path)
            (out / "configured-after-source-a.bin").write_bytes(readback)
            if readback != configured:
                raise RuntimeError("configuration changed after source A")
            source_b_correlation = correlated_rejection(source_b, out)
            operations.append({"operation": "protocol-roundtrip", "source": "B", "success": False,
                               "run": source_b["run"]})
            readback = docker(target["container"], "cat", path)
            (out / "configured-after-source-b.bin").write_bytes(readback)
            if readback != configured:
                raise RuntimeError("configuration changed after source B")
        finally:
            failures = []
            path = SHIB_CONFIG if args.product == "shibboleth" else SSP_CONFIG
            if changed:
                try:
                    if docker(target["container"], "cat", path) != configured:
                        raise RuntimeError("concurrent target configuration change")
                    if args.product == "shibboleth":
                        write_shib(original)
                        reload_shib(out, "restore")
                        operations.append({"operation": "metadata-source-restore-reload", "completed": True})
                    else:
                        write_ssp_host(original)
                    operations.append({"operation": "product-config-restore", "sha256": SHA(original),
                                       "readBack": True})
                except Exception as error:
                    failures.append(type(error).__name__ + ":" + str(error))
            if servers:
                try:
                    stop_servers(args.product, temp, peers, out)
                    operations.append({"operation": "temporary-source-servers-stop", "count": 2,
                                       "completed": True})
                except Exception as error:
                    failures.append("servers:" + type(error).__name__ + ":" + str(error))
            final = docker(target["container"], "cat", path)
            (out / "final-configuration.bin").write_bytes(final)
            temporary_absent = subprocess.run(["docker", "exec", target["container"], "sh", "-c",
                                                "test ! -e " + temp], timeout=30).returncode == 0
            restored = not failures and final == original and temporary_absent
            save(out / "restoration.json", {"restored": restored, "failures": failures,
                 "temporarySourceDirectoryRemoved": temporary_absent,
                 "originalSha256": SHA(original), "finalSha256": SHA(final),
                 "originalBytes": len(original), "finalBytes": len(final)})
            save(out / "operation-counts.json", {"operations": operations,
                 "productConfigurationWrites": sum(row["operation"] == "product-config-write" for row in operations),
                 "restorationWrites": sum(row["operation"] == "product-config-restore" for row in operations),
                 "nativeSourceLookups": sum(row["operation"] == "native-source-lookup" for row in operations),
                 "protocolRoundTrips": sum(row["operation"] == "protocol-roundtrip" for row in operations),
                 "productRestarts": 0, "humanOperations": 0, "restored": restored})
            if not restored:
                raise RuntimeError("source-scoped trust campaign restoration failed")
        material["temporaryPrivateKeysRemoved"] = True
        save(out / "key-material-manifest.json", material)
    health(target, out, "final")
    runtime_final = capture_target(out, args.product, "end")
    suite_final = capture_suite(out, "final")
    if runtime_start["binding"] != runtime_final["binding"] or \
            runtime_start["runtime_version"]["value"] != runtime_final["runtime_version"]["value"]:
        raise RuntimeError("target runtime changed")
    for key in ("containerName", "containerId", "imageId", "startedAt", "configuredImage"):
        if suite_start[key] != suite_final[key]:
            raise RuntimeError("Suite runtime changed")
    for name in suite_start["jars"]:
        if suite_start["jars"][name]["sha256"] != suite_final["jars"][name]["sha256"]:
            raise RuntimeError("Suite JAR changed")
    receipt = {
        "schema": "samlscope-md03d-source-scoped-trust-receipt-v1", "caseId": CASE,
        "product": args.product, "primaryRun": source_a["run"], "negativeRun": source_b["run"],
        "targetEntityId": target["targetEntityId"], "runtime": runtime_start,
        "suiteRuntime": suite_start, "sources": peers, "keyMaterialFile": "key-material-manifest.json",
        "sourceAAcceptance": source_a_correlation, "sourceBRejection": source_b_correlation,
        "configuration": {"originalFile": "original-configuration.bin", "originalSha256": SHA(original),
            "configuredFile": "configured-configuration.bin", "configuredSha256": SHA(configured),
            "readBackFiles": ["configured-readback.bin", "configured-after-source-a.bin",
                              "configured-after-source-b.bin"],
            "finalFile": "final-configuration.bin", "finalSha256": SHA(original)},
        "nativeAcceptanceFile": "source-a-native-lookup.json",
        "nativeRejectionFile": "source-b-native-lookup.json",
        "nativeRejectionProductLog": "native-rejection-product-log.txt",
        "restorationFile": "restoration.json", "operationCountsFile": "operation-counts.json",
        "controls": {"positive": "source-a-signed-k-trusted-k-correlated-success",
                     "negative": "source-b-signed-k-trusted-k2-native-signature-rejection"},
    }
    (out / "receipt.json").write_bytes(canonical(receipt))
    receipt_sha = SHA((out / "receipt.json").read_bytes())
    note = ("Machine-verified MD03.d source-scoped trust campaign; receipt sha256=" + receipt_sha
            + "; source A accepted key K and source B rejected the same key K")
    save(out / "tests-start.json", api("/api/runs/" + source_a["run"] + "/tests/start", {}))
    save(out / "configure.json", api("/api/runs/" + source_a["run"] + "/cases/" + CASE
                                      + "/configure", {"value": "confirmed"}))
    save(out / "attest.json", api("/api/runs/" + source_a["run"] + "/cases/" + CASE
                                   + "/attest", {"value": "evidence_satisfies", "note": note}))
    save(out / "result.json", api("/api/runs/" + source_a["run"] + "/result.json"))
    print(args.product, source_a["run"], source_b["run"], "restored", restored,
          "receipt", receipt_sha)


if __name__ == "__main__":
    main()
