#!/usr/bin/env python3
"""Prove native recurring metadata refresh with an A-to-B signing-key change.

The target reads one stable MDQ URL.  The Suite first serves ``control`` and then changes that
same URL to ``no-valid-until`` whose polling key is disjoint.  The second signed request is not
started until the Run's approved refresh wait has elapsed.  Configuration is always restored.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
from import_metadata_batch import api, flow, save, BASE
sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_mdq_campaign import CONFIG, CONTAINER, RELAY, docker, write_in_place
# native_mdq_campaign imports Keycloak helpers and prepends their directory.  Restore this
# adapter's directory so the product-specific SignatureClient cannot resolve to Keycloak's
# module with the same filename.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from signed_request_observation import SignatureClient
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
from capture_terminal_http_runtime import capture_target

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
VARIANTS = ("control", "no-valid-until")


class RefreshSignatureClient(SignatureClient):
    def __init__(self, records, response_originals):
        super().__init__(records)
        self.response_originals = response_originals

    def request(self, url, fields=None):
        before = len(self.records)
        final, page, status = super().request(url, fields)
        if len(self.records) == before + 1:
            self.response_originals[self.records[-1]["request_id"]] = page.encode()
        return final, page, status


def overlay(wait):
    return ("\n$config['metadata.sources'] = [['type'=>'flatfile'], "
            "['type'=>'mdq','server'=>'http://127.0.0.1:8081','cachelength'=>%d]];\n" % wait).encode()


def relay_script(entity, source):
    return ("<?php\n"
            "$expected=" + json.dumps(entity) + ";\n"
            "$source=" + json.dumps(source) + ";\n"
            "$prefix='/entities/';\n"
            "$path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);\n"
            "if(!str_starts_with($path,$prefix)||rawurldecode(substr($path,strlen($prefix)))!==$expected){http_response_code(404);exit;}\n"
            "$data=file_get_contents($source);if($data===false){http_response_code(502);exit;}\n"
            "$hash=hash('sha256',$data);@mkdir('" + RELAY + "/responses',0700,true);\n"
            "file_put_contents('" + RELAY + "/responses/'.$hash.'.xml',$data,LOCK_EX);\n"
            "$record=['entityId'=>$expected,'sourceUrl'=>$source,'responseSha256'=>$hash,'httpStatus'=>200,"
            "'observedAt'=>(new DateTimeImmutable('now',new DateTimeZone('UTC')))->format('Y-m-d\\TH:i:s.u\\Z')];\n"
            "file_put_contents('" + RELAY + "/requests.jsonl',json_encode($record).\"\\n\",FILE_APPEND|LOCK_EX);\n"
            "header('Content-Type: application/samlmetadata+xml');echo $data;\n").encode()


def transcript_entry(run, entry_id):
    values = [entry for entry in api("/api/runs/" + run + "/transcript") if entry["id"] == entry_id]
    if len(values) != 1:
        raise RuntimeError("Ambiguous transcript reference " + entry_id)
    return values[0]


def arm(run, out, variant):
    state = api("/api/runs/" + run + "/metadata-lab")
    if state["selectedVariant"] != variant:
        raise RuntimeError("Unexpected polling variant")
    with urllib.request.urlopen(state["automaticStartUrl"], timeout=30) as response:
        if response.status != 202:
            raise RuntimeError("Fixture attempt gate did not wait for retrieval")
        response.read()
    # This operator retrieval opens the Suite orchestration gate only.  Adoption requires the
    # separate target relay request and its exact response original.
    with urllib.request.urlopen(state["metadataUrl"], timeout=30) as response:
        (out / (variant + "-operator-fixture.xml")).write_bytes(response.read())
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-wait-seconds", type=int, default=5)
    args = parser.parse_args()
    wait = args.refresh_wait_seconds
    if wait < 2 or wait > 60:
        parser.error("refresh wait must be between 2 and 60 seconds")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)

    original = CONFIG.read_bytes()
    configured = original + overlay(wait)
    (out / "original-config.php").write_bytes(original)
    (out / "configured-config.php").write_bytes(configured)
    capture_target(out, "simplesamlphp", "start")
    created = api("/api/plans", dict(name="SimpleSAMLphp native metadata refresh", profile="metadata_idp",
        targetKind="IDP", targetEntityId="http://localhost:18380/idp", metadataSourceKind="URL",
        metadataSourceLocation="http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata",
        suiteMetadataDelivery="HTTP_URL", declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=wait, testUserHint="samlscope-m0-user", requestSigningMode="REQUIRED"),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset="quick"), authorizedTarget=True))
    save(out / "plan.json", created)
    plan = created["plan"]["plan"]["id"]
    created = api("/api/plans/" + plan + "/runs", {})
    save(out / "created.json", created)
    run = created["run"]["id"]
    save(out / "preflight.json", api("/api/runs/" + run + "/preflight", {}))
    save(out / "campaign.json", api("/api/runs/" + run + "/metadata-lab/automatic-polling",
                                    dict(variants=list(VARIANTS), pollingDelaySeconds=wait)))
    entity = BASE + "/p/" + plan
    source = "http://samlscope-reference-suite:8080/p/" + plan + "/metadata/live?run=" + run
    relay = relay_script(entity, source)
    (out / "proxy-router.php").write_bytes(relay)
    changed = relay_started = False
    operations = []
    try:
        if docker("sh", "-c", "test -e " + RELAY + "/pid && echo present || true").strip():
            raise RuntimeError("Another native MDQ relay is active")
        docker("mkdir", "-p", RELAY)
        docker("sh", "-c", "cat > " + RELAY + "/router.php", data=relay)
        if docker("cat", RELAY + "/router.php") != relay:
            raise RuntimeError("Relay read-back mismatch")
        subprocess.run(["docker", "exec", "-d", CONTAINER, "sh", "-c",
            "echo $$ > " + RELAY + "/pid; exec php -S 127.0.0.1:8081 -t " + RELAY + " "
            + RELAY + "/router.php >" + RELAY + "/server.log 2>&1"], check=True, timeout=20)
        relay_started = True
        time.sleep(1)
        changed = True
        write_in_place(CONFIG, configured)
        operations.append(dict(operation="product-config-write", sha256=SHA(configured), read_back=True))
        # Apache's PHP opcode cache does not necessarily observe the bind-mounted config in the
        # same instant.  The existing native MDQ campaign uses the same bounded reload delay.
        time.sleep(3)
        php = ("require '/var/simplesamlphp/lib/_autoload.php'; "
               "echo json_encode(\\SimpleSAML\\Configuration::getInstance()->getArray('metadata.sources')); ")
        effective = docker("php", "-r", php)
        (out / "effective-source.json").write_bytes(effective)
        sources = json.loads(effective)
        if sources != [{"type": "flatfile"},
                       {"type": "mdq", "server": "http://127.0.0.1:8081", "cachelength": wait}]:
            raise RuntimeError("Native MDQ refresh source read-back differs")

        phase_records = []
        native_http = []
        response_originals = {}
        previous_response_at = None
        for index, variant in enumerate(VARIANTS):
            if previous_response_at is not None:
                delay = previous_response_at + wait + 0.75 - time.time()
                if delay > 0:
                    time.sleep(delay)
            state = arm(run, out, variant)
            phase_path = out / ("phase-%d-%s.json" % (index, variant))
            flow(run, phase_path, suite_signature_control=index == 1,
                 client_factory=(lambda **kwargs: RefreshSignatureClient(native_http, response_originals))
                 if index == 1 else None)
            phase = json.loads(phase_path.read_text())
            if not phase.get("correlated_success") or phase.get("variant") != variant:
                raise RuntimeError("Polling phase lacked correlated Success")
            exchange_ids = phase["positive_exchange"].get("transcript_ids") or []
            exchange = [transcript_entry(run, entry_id) for entry_id in exchange_ids]
            requests = [entry for entry in exchange if entry["direction"] == "OUTBOUND"
                        and entry.get("samlSummary", {}).get("type") == "AuthnRequest"]
            responses = [entry for entry in exchange if entry["direction"] == "INBOUND"
                         and entry.get("samlSummary", {}).get("type") == "Response"]
            if len(requests) != 1 or len(responses) != 1:
                raise RuntimeError("Polling exchange references are ambiguous")
            response = responses[0]
            response_id = response["id"]
            previous_response_at = float(response["timestamp"])
            record = dict(variant=variant, state=state, requestReference=requests[0]["id"],
                          responseReference=response_id)
            if index == 1:
                negative = phase.get("negative_control") or {}
                negative_ids = negative.get("exchange", {}).get("transcript_ids") or []
                invalid = [transcript_entry(run, entry_id) for entry_id in negative_ids]
                invalid = [entry for entry in invalid if entry["direction"] == "OUTBOUND"
                           and entry.get("samlSummary", {}).get("type") == "AuthnRequest"]
                if len(invalid) != 1:
                    raise RuntimeError("Invalid-signature control request is ambiguous")
                native = [item for item in native_http
                          if item.get("request_id") == invalid[0]["samlSummary"]["id"]]
                if len(native) != 1 or native[0].get("native_signature_rejection") != "signature-value-invalid" \
                        or native[0].get("response_status") != 500 \
                        or native[0].get("saml_response_form_present") is not False:
                    raise RuntimeError("Product-native invalid-signature rejection is unavailable")
                record["controlRequestReference"] = invalid[0]["id"]
                save(out / "signature-control.json", native[0])
                raw_response = response_originals.get(native[0]["request_id"])
                if raw_response is None or SHA(raw_response) != native[0]["response_body_sha256"]:
                    raise RuntimeError("Signature-control response original is unavailable")
                (out / "signature-control-response.html").write_bytes(raw_response)
            phase_records.append(record)
            if index == 0:
                save(out / "tests-start.json", api("/api/runs/" + run + "/tests/start", {}))
        save(out / "phase-records.json", phase_records)
        save(out / "native-http-observations.json",
             dict(run=run, records=native_http, product_verdict_assigned=False))
        (out / "proxy-requests.jsonl").write_bytes(docker("cat", RELAY + "/requests.jsonl"))
        (out / "relay-server.log").write_bytes(docker("cat", RELAY + "/server.log"))
    finally:
        if changed:
            if CONFIG.read_bytes() != configured:
                raise RuntimeError("Concurrent product config change; refusing overwrite")
            write_in_place(CONFIG, original)
            operations.append(dict(operation="product-config-restore", sha256=SHA(original), read_back=True))
        (out / "final-config.php").write_bytes(CONFIG.read_bytes())
        restored = CONFIG.read_bytes() == original
        save(out / "restoration.json", dict(restored=restored, original_sha256=SHA(original),
                                             configured_sha256=SHA(configured),
                                             final_sha256=SHA(CONFIG.read_bytes())))
        if relay_started:
            docker("sh", "-c", "kill \"$(cat " + RELAY + "/pid)\"")
            docker("rm", "-rf", RELAY)
            operations.append(dict(operation="temporary-relay-stop", completed=True))
        capture_target(out, "simplesamlphp", "end")
        save(out / "operation-counts.json", dict(operations=operations,
            product_configuration_writes=sum(item["operation"].startswith("product-config") for item in operations),
            restoration_writes=sum(item["operation"] == "product-config-restore" for item in operations),
            product_restarts=0, human_operations=0, restored=restored))
        if not restored:
            raise RuntimeError("Product configuration restoration failed")
    for endpoint, filename in (("result.json", "result-before.json"), ("transcript", "transcript.json")):
        with urllib.request.urlopen(BASE + "/api/runs/" + run + "/" + endpoint, timeout=30) as response:
            (out / filename).write_bytes(response.read())
    print(run, "native A-to-B refresh recorded and configuration restored")


if __name__ == "__main__":
    main()
