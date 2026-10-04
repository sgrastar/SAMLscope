#!/usr/bin/env python3
"""Prove SimpleSAMLphp metadata signature validation through native MDQ and restore exactly."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
from import_metadata_batch import api, flow, save, BASE
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
from capture_run_originals import capture
sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_mdq_campaign import CONFIG, CONTAINER, RELAY, docker, write_in_place
from native_mdq_fixture_campaign import capture_product_runtime

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CAMPAIGN = "metadata-fixture-refresh"
TARGET = "http://localhost:18380/idp"
ADAPTER_LOCAL = REPO / "dev/simplesamlphp/native_metadata_signature_adapter.php"
ADAPTER = "/tmp/samlscope-metadata-signature-adapter.php"
CERT_DIR = "/var/simplesamlphp/cert"
VARIANTS = (
    "control", "unsigned", "bad-signature", "signed-other-key",
    "signed-other-key-primary-keyinfo", "certificate-expired",
    "certificate-not-yet-valid", "certificate-no-digital-signature",
    "certificate-critical-extension",
)
CONSUMER_VARIANTS = ("xpath-identity", "xpath-exclude-role-descriptors",
                     "xpath-exclude-endpoints", "xpath-exclude-key-descriptors", "no-key-info")
ACCEPTED = {
    "control", "signed-other-key-primary-keyinfo", "certificate-expired",
    "certificate-not-yet-valid", "certificate-no-digital-signature",
    "certificate-critical-extension",
}
MD = "urn:oasis:names:tc:SAML:2.0:metadata"
DS = "http://www.w3.org/2000/09/xmldsig#"


def pem(der):
    encoded = base64.b64encode(der).decode()
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(
        encoded[i:i + 64] for i in range(0, len(encoded), 64)
    ) + "\n-----END CERTIFICATE-----\n").encode()


def embedded(raw):
    root = ET.fromstring(raw)
    node = root.find("./{%s}Signature/{%s}KeyInfo/{%s}X509Data/{%s}X509Certificate" %
                     (DS, DS, DS, DS))
    if node is None or not (node.text or "").strip():
        return None
    return base64.b64decode("".join("".join(node.itertext()).split()), validate=True)


def role_certificate(raw):
    root = ET.fromstring(raw)
    node = root.find("./{%s}SPSSODescriptor/{%s}KeyDescriptor/{%s}KeyInfo/"
                     "{%s}X509Data/{%s}X509Certificate" % (MD, MD, DS, DS, DS))
    if node is None or not (node.text or "").strip():
        raise RuntimeError("SP role has no out-of-band signing certificate")
    return base64.b64decode("".join("".join(node.itertext()).split()), validate=True)


def entity_id(raw):
    root = ET.fromstring(raw)
    if root.tag != "{%s}EntityDescriptor" % MD or not root.get("entityID"):
        raise RuntimeError("Fixture is not one EntityDescriptor")
    return root.get("entityID")


def recorder(plan, run):
    return "http://samlscope-reference-suite:8080/p/%s/sp/paos?run=%s" % (plan, run)


def new_entry(run, before, stdout):
    rows = api("/api/runs/" + run + "/transcript")
    added = [row for row in rows if row["id"] not in before and row.get("decodedSamlRef")
             and row["direction"] == "INBOUND" and row.get("method") == "POST"
             and row.get("status") == 204 and "/sp/paos?run=" + run in row.get("url", "")]
    if len(added) != 1:
        raise RuntimeError("Adapter did not create exactly one Recorder original")
    if added[0]["direction"] != "INBOUND" or added[0].get("status") != 204:
        raise RuntimeError("Adapter original is not the product POST")
    return added[0]


def invoke(run, output, label, args, expected=(0,)):
    before = {row["id"] for row in api("/api/runs/" + run + "/transcript")}
    result = subprocess.run(["docker", "exec", CONTAINER, "php", ADAPTER, *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    (output / (label + ".stdout")).write_bytes(result.stdout)
    (output / (label + ".stderr")).write_bytes(result.stderr)
    entry = new_entry(run, before, result.stdout)
    if result.returncode not in expected:
        raise RuntimeError("Adapter %s exit %d: %s" %
                           (label, result.returncode, result.stderr.decode(errors="replace")[:300]))
    return dict(reference=entry["id"], sha256=SHA(result.stdout), exit=result.returncode,
                stdout=label + ".stdout", stderr=label + ".stderr")


def record_file(run, output, label, path, recorder_url):
    return invoke(run, output, label, ["record-file", path, recorder_url])


def configure(run, output, label, original, location, anchor, recorder_url, operations):
    overlay = ("\n$config['metadata.sources'] = [['type'=>'flatfile'], "
               "['type'=>'mdq','server'=>'http://127.0.0.1:8081','cachelength'=>0,"
               "'validateCertificate'=>['%s']]];\n" % location).encode()
    configured = original + overlay
    anchor_path = CERT_DIR + "/" + location
    docker("sh", "-c", "cat > " + anchor_path, data=anchor)
    operations.append(dict(operation="temporary-trust-anchor-write", label=label,
                           path=anchor_path, sha256=SHA(anchor)))
    write_in_place(CONFIG, configured)
    time.sleep(3)
    config = record_file(run, output, label + "-configuration", 
                         "/var/simplesamlphp/config/config-override.php", recorder_url)
    effective = invoke(run, output, label + "-effective", ["record-effective", recorder_url])
    certificate = record_file(run, output, label + "-anchor", anchor_path, recorder_url)
    parsed = json.loads((output / effective["stdout"]).read_text())
    matches = [row for row in parsed if row.get("type") == "mdq"
               and row.get("server") == "http://127.0.0.1:8081"
               and row.get("cachelength") == 0
               and row.get("validateCertificate") == [location]]
    if len(matches) != 1 or docker("cat", anchor_path) != anchor:
        raise RuntimeError("Product signature configuration read-back differs")
    operations.append(dict(operation="product-config-write", label=label,
                           sha256=SHA(configured), anchor_sha256=SHA(anchor), settle_seconds=3))
    encoded = "".join(line for line in anchor.decode().splitlines()
                      if not line.startswith("---"))
    certificate_sha256 = SHA(base64.b64decode(encoded, validate=True))
    return dict(reference=config["reference"], sha256=config["sha256"],
                effectiveReference=effective["reference"], effectiveSha256=effective["sha256"],
                trustAnchorReference=certificate["reference"],
                trustAnchorOriginalSha256=certificate["sha256"],
                trustAnchorCertificateSha256=certificate_sha256,
                certificateLocation=location, containerPath=anchor_path)


def router_script(relay):
    return ("<?php\n"
            "$expected=trim(file_get_contents('%s/entity'));\n" % relay
            + "$source=trim(file_get_contents('%s/source'));\n" % relay
            + "$prefix='/entities/';$path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);\n"
            + "if(!str_starts_with($path,$prefix)||rawurldecode(substr($path,strlen($prefix)))!==$expected){http_response_code(404);exit;}\n"
            + "$data=file_get_contents($source);if($data===false){http_response_code(502);exit;}\n"
            + "file_put_contents('%s/response.xml',$data);\n" % relay
            + "$r=['entityId'=>$expected,'sourceUrl'=>$source,'responseSha256'=>hash('sha256',$data),'httpStatus'=>200];\n"
            + "file_put_contents('%s/requests.jsonl',json_encode($r).\"\\n\",FILE_APPEND|LOCK_EX);\n" % relay
            + "header('Content-Type: application/samlmetadata+xml');echo $data;\n").encode()


def update_relay(entity, source):
    docker("sh", "-c", "cat > " + RELAY + "/entity", data=(entity + "\n").encode())
    docker("sh", "-c", "cat > " + RELAY + "/source", data=(source + "\n").encode())


def native_validate(run, plan, output, label, variant, entity, fixture_path, fixture_hash,
                    configuration, anchor_path, expected_exit):
    cache = RELAY + "/cache-" + re.sub("[^A-Za-z0-9]", "-", label)
    args = ["validate", run, CAMPAIGN, TARGET, variant, entity, anchor_path,
            "http://127.0.0.1:8081", fixture_path, fixture_hash, recorder(plan, run), cache,
            configuration["reference"], configuration["effectiveReference"],
            "/var/simplesamlphp/config/config-override.php"]
    return invoke(run, output, label + "-native", args,
                  expected=expected_exit if isinstance(expected_exit, tuple) else (expected_exit,))


def find_prepared(transcript, variant):
    rows = [row for row in transcript if row["direction"] == "OUTBOUND"
            and row.get("samlSummary", {}).get("type") == "MetadataPrepared"
            and row["samlSummary"].get("variant") == variant]
    if len(rows) != 1:
        raise RuntimeError("Prepared original is ambiguous for " + variant)
    return rows[0]


def correlated_success(transcript, variant):
    requests = [row for row in transcript if row["direction"] == "OUTBOUND"
                and row.get("samlSummary", {}).get("type") == "AuthnRequest"
                and row["samlSummary"].get("variant") == variant]
    if len(requests) != 1:
        raise RuntimeError("Positive request is ambiguous")
    request = requests[0]
    responses = [row for row in transcript if row["direction"] == "INBOUND"
                 and row.get("samlSummary", {}).get("type") == "Response"
                 and row["samlSummary"].get("inResponseTo") == request["samlSummary"]["id"]
                 and row["samlSummary"].get("statusCode") ==
                 "urn:oasis:names:tc:SAML:2.0:status:Success"]
    if len(responses) != 1:
        raise RuntimeError("Positive response is ambiguous")
    return request, responses[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--signature-consumer-variants", action="store_true",
                        help="Include the shared XPath and omitted-KeyInfo observations")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    original = CONFIG.read_bytes()
    (out / "original-config.php").write_bytes(original)
    operations = []
    variants = VARIANTS + (CONSUMER_VARIANTS if args.signature_consumer_variants else ())
    start_runtime = capture_product_runtime(out, "start")
    created = api("/api/plans", dict(name="SimpleSAMLphp native metadata signature campaign",
        profile="metadata_idp", targetKind="IDP", targetEntityId=TARGET,
        metadataSourceKind="URL",
        metadataSourceLocation="http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata",
        suiteMetadataDelivery="HTTP_URL", declaredFeatures={},
        parameters=dict(clockSkewToleranceSeconds=180, metadataRefreshWaitSeconds=300,
                        testUserHint="samlscope-m0-user", requestSigningMode="REQUIRED"),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset="quick"),
        authorizedTarget=True))
    save(out / "plan.json", created)
    plan = created["plan"]["plan"]["id"]
    created = api("/api/plans/" + plan + "/runs", {})
    save(out / "created.json", created)
    run = created["run"]["id"]
    save(out / "preflight.json", api("/api/runs/" + run + "/preflight", {}))
    save(out / "campaign.json", api("/api/runs/" + run + "/metadata-lab/automatic-polling",
                                     dict(variants=list(variants), pollingDelaySeconds=0)))
    recorder_url = recorder(plan, run)
    relay_started = changed = False
    native = {}
    configurations = {}
    flows = {}
    source_refs = {}
    primary = other = None
    temporary_paths = [ADAPTER]
    try:
        docker("sh", "-c", "test ! -e " + RELAY)
        docker("mkdir", "-p", RELAY)
        router = router_script(RELAY)
        (out / "relay-router.php").write_bytes(router)
        docker("sh", "-c", "cat > " + RELAY + "/router.php", data=router)
        subprocess.run(["docker", "exec", "-d", CONTAINER, "sh", "-c",
            "echo $$ > %s/pid; exec php -S 127.0.0.1:8081 -t %s %s/router.php >%s/server.log 2>&1"
            % (RELAY, RELAY, RELAY, RELAY)], check=True, timeout=20)
        relay_started = True
        time.sleep(1)
        docker("sh", "-c", "cat > " + ADAPTER, data=ADAPTER_LOCAL.read_bytes())
        lint = subprocess.run(["docker", "exec", CONTAINER, "php", "-l", ADAPTER],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        (out / "adapter-lint.stdout").write_bytes(lint.stdout)
        (out / "adapter-lint.stderr").write_bytes(lint.stderr)
        if lint.returncode:
            raise RuntimeError("Adapter PHP lint failed")

        source_paths = {
            "samlParser": "/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php",
            "mdq": "/var/simplesamlphp/src/SimpleSAML/Metadata/Sources/MDQ.php",
            "metaLoader": "/var/simplesamlphp/modules/metarefresh/src/MetaLoader.php",
            "configuration": "/var/simplesamlphp/src/SimpleSAML/Configuration.php",
            "adapter": ADAPTER,
        }
        for key, path in source_paths.items():
            source_refs[key] = record_file(run, out, "source-" + key, path, recorder_url)
            source_refs[key]["path"] = path
        before_config = record_file(run, out, "configuration-before",
                                    "/var/simplesamlphp/config/config-override.php", recorder_url)

        for variant in variants:
            state = api("/api/runs/" + run + "/metadata-lab")
            if state["selectedVariant"] != variant:
                raise RuntimeError("Unexpected campaign member")
            folder = out / variant
            folder.mkdir()
            with urllib.request.urlopen(state["automaticStartUrl"], timeout=30) as response:
                if response.status != 202:
                    raise RuntimeError("Fixture gate did not arm")
            with urllib.request.urlopen(state["metadataUrl"], timeout=30) as response:
                fixture = response.read()
            (folder / "fixture.xml").write_bytes(fixture)
            entity = entity_id(fixture)
            certificate = embedded(fixture)
            if variant == "control":
                primary = certificate
            if variant == "signed-other-key":
                other = certificate
            if primary is None:
                raise RuntimeError("Primary control certificate unavailable")
            fixture_container = RELAY + "/fixture-" + variant + ".xml"
            docker("sh", "-c", "cat > " + fixture_container, data=fixture)
            temporary_paths.append(fixture_container)
            # The product receives the exact immutable bytes already fetched and recorded from
            # the Suite, so a second dynamic fixture generation cannot change timestamps/signature.
            update_relay(entity, fixture_container)
            if variant == "signed-other-key-primary-keyinfo":
                if other is None:
                    raise RuntimeError("Separate signer certificate unavailable")
                # Polling fixtures have variant-specific primary credentials. Use this fixture's
                # actual embedded certificate rather than the unrelated control fixture's key.
                embedded_anchor = pem(certificate)
                embedded_config = configure(run, folder, "embedded-control", original,
                    "samlscope-md03-primary.crt", embedded_anchor, recorder_url, operations)
                temporary_paths.append(embedded_config["containerPath"])
                native["embedded-anchor"] = native_validate(run, plan, folder, "embedded-control",
                    variant, entity, fixture_container, SHA(fixture), embedded_config,
                    embedded_config["containerPath"], 3)
                configurations["embedded-anchor"] = embedded_config
                positive_anchor = pem(other)
                positive_config = configure(run, folder, "out-of-band", original,
                    "samlscope-md03-other.crt", positive_anchor, recorder_url, operations)
                temporary_paths.append(positive_config["containerPath"])
                native[variant] = native_validate(run, plan, folder, "out-of-band", variant,
                    entity, fixture_container, SHA(fixture), positive_config,
                    positive_config["containerPath"], 0)
                configurations["positive"] = positive_config
            else:
                chosen = primary if variant in {"unsigned", "signed-other-key"} else certificate
                if variant == "no-key-info":
                    chosen = role_certificate(fixture)
                if chosen is None:
                    raise RuntimeError("Variant certificate unavailable")
                location = "samlscope-md03-%s.crt" % re.sub("[^a-z0-9]", "-", variant)
                config = configure(run, folder, "configured", original, location, pem(chosen),
                                   recorder_url, operations)
                temporary_paths.append(config["containerPath"])
                # An explicit native runtime error remains diagnostic. Complete the shared
                # campaign and preserve it without treating error/absence as product rejection.
                expected = (0, 3, 5) if variant in CONSUMER_VARIANTS else (0 if variant in ACCEPTED else 3)
                native[variant] = native_validate(run, plan, folder, "configured", variant,
                    entity, fixture_container, SHA(fixture), config, config["containerPath"], expected)
                configurations[variant] = config
                if variant == "bad-signature":
                    configurations["invalid-signature"] = config

            accepted = native[variant]["exit"] == 0
            if accepted:
                flow(run, folder / "flow.json", suite_signature_control=False)
                flows[variant] = json.loads((folder / "flow.json").read_text())
                if variant == "control":
                    save(out / "tests-start.json", api("/api/runs/" + run + "/tests/start", {}))
            else:
                pending = api("/api/runs/" + run + "/metadata-lab")
                if pending["campaignIndex"] == state["campaignIndex"]:
                    with urllib.request.urlopen(urllib.request.Request(
                            pending["automaticContinueUrl"], data=b""), timeout=30) as response:
                        response.read()
            print(variant, "accepted" if accepted else
                  ("rejected" if native[variant]["exit"] == 3 else "native-error; not adopted"), flush=True)
        changed = True
    finally:
        if CONFIG.read_bytes() != original:
            write_in_place(CONFIG, original)
            operations.append(dict(operation="product-config-restore", sha256=SHA(original)))
        (out / "final-config.php").write_bytes(CONFIG.read_bytes())
        restored_config = CONFIG.read_bytes() == original
        final_config = None
        try:
            if "run" in locals():
                final_config = record_file(run, out, "configuration-final",
                    "/var/simplesamlphp/config/config-override.php", recorder_url)
        finally:
            for path in sorted(set(temporary_paths), reverse=True):
                docker("rm", "-f", path)
            if relay_started:
                docker("sh", "-c", "kill \"$(cat %s/pid)\"" % RELAY)
                docker("rm", "-rf", RELAY)
        removed = all(not docker("sh", "-c", "test -e %s && echo present || true" % path).strip()
                      for path in set(temporary_paths))
        end_runtime = capture_product_runtime(out, "end")
        runtime_stable = (
            start_runtime["binding"] == end_runtime["binding"]
            and start_runtime["version_source"]["sha256"] == end_runtime["version_source"]["sha256"]
            and start_runtime["version_source"]["value"] == end_runtime["version_source"]["value"]
            and start_runtime["runtime_version"]["value"] == end_runtime["runtime_version"]["value"]
        )
        save(out / "restoration.json", dict(restored=restored_config and removed,
            original_sha256=SHA(original), final_sha256=SHA(CONFIG.read_bytes()),
            temporary_files_removed=removed, runtime_stable=runtime_stable))
        save(out / "operation-counts.json", dict(operations=operations,
            product_configuration_writes=sum(row["operation"] == "product-config-write" for row in operations),
            restoration_writes=sum(row["operation"] == "product-config-restore" for row in operations),
            temporary_trust_anchor_writes=sum(row["operation"] == "temporary-trust-anchor-write" for row in operations),
            native_validation_invocations=sum(1 for path in out.rglob("*-native.stdout")
                if json.loads(path.read_bytes()).get("schema") ==
                "samlscope-simplesamlphp-metadata-signature-validation-v1"),
            protocol_roundtrips=len(flows),
            product_restarts=0, human_operations=0, restored=restored_config and removed))
        save(out / "native-validation-index.json", native)
        save(out / "configuration-index.json", configurations)
        if not (restored_config and removed and runtime_stable):
            raise RuntimeError("Product restoration or runtime stability failed")

    transcript = api("/api/runs/" + run + "/transcript")
    save(out / "transcript-before-receipt.json", transcript)
    manifest = capture(out, run, transcript)
    by_id = {row["id"]: row for row in transcript}
    prepared = {variant: find_prepared(transcript, variant) for variant in variants}
    request, response = correlated_success(transcript, "signed-other-key-primary-keyinfo")
    decoded = {row["id"]: (out / row["file"]).read_bytes() for row in manifest}
    positive_fixture = (out / "signed-other-key-primary-keyinfo/fixture.xml").read_bytes()
    receipt = dict(schema="samlscope-metadata-signature-verification-receipt-v4",
        runId=run, campaignId=CAMPAIGN, targetEntityId=TARGET,
        targetMetadataSha256=SHA((out / "target-metadata.xml").read_bytes()),
        evidenceAdapter="simplesamlphp-runtime",
        configurationReadBack={key: value for key, value in configurations["positive"].items()
                               if key != "containerPath"},
        restorationReadBack=dict(originalReference=before_config["reference"],
            originalSha256=before_config["sha256"], finalReference=final_config["reference"],
            finalSha256=final_config["sha256"]),
        nativeSources={key: dict(reference=value["reference"], sha256=value["sha256"])
                       for key, value in source_refs.items()},
        positive=dict(variant="signed-other-key-primary-keyinfo",
            requestReference=request["id"], responseReference=response["id"],
            requestId=request["samlSummary"]["id"], inResponseTo=request["samlSummary"]["id"],
            responseSha256=SHA(decoded[response["id"]]),
            embeddedKeyInfoCertificateSha256=SHA(embedded(positive_fixture)),
            nativeValidationReference=native["signed-other-key-primary-keyinfo"]["reference"],
            nativeValidationSha256=native["signed-other-key-primary-keyinfo"]["sha256"]),
        negativeControls=[
            dict(kind="invalid-signature", variant="bad-signature",
                 nativeRejectionReference=native["bad-signature"]["reference"],
                 nativeRejectionSha256=native["bad-signature"]["sha256"],
                 configurationReadBack={key: value for key, value in configurations["invalid-signature"].items()
                                        if key != "containerPath"}),
            dict(kind="embedded-anchor", variant="signed-other-key-primary-keyinfo",
                 nativeRejectionReference=native["embedded-anchor"]["reference"],
                 nativeRejectionSha256=native["embedded-anchor"]["sha256"],
                 configurationReadBack={key: value for key, value in configurations["embedded-anchor"].items()
                                        if key != "containerPath"}),
        ])
    save(out / "signature-verification-receipt.json", receipt)
    destination = "/data/metadata-rejection-evidence/" + run + ".signature-verification.json"
    subprocess.run(["docker", "exec", "samlscope-reference-suite", "mkdir", "-p",
                    "/data/metadata-rejection-evidence"], check=True, timeout=30)
    subprocess.run(["docker", "cp", str(out / "signature-verification-receipt.json"),
                    "samlscope-reference-suite:" + destination], check=True, timeout=30)
    installed = subprocess.check_output(["docker", "exec", "samlscope-reference-suite", "cat", destination],
                                        timeout=30)
    if installed != (out / "signature-verification-receipt.json").read_bytes():
        raise RuntimeError("Signature receipt read-back differs")
    save(out / "receipt-installation.json", dict(run=run, path=destination,
        sha256=SHA(installed), read_back=True))
    save(out / "evaluation-signature.json", api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
    save(out / "result-signature.json", api("/api/runs/" + run + "/result.json"))
    transcript_after = api("/api/runs/" + run + "/transcript")
    save(out / "transcript-after-receipt.json", transcript_after)
    if transcript_after != transcript:
        raise RuntimeError("Receipt evaluation changed the Run transcript")
    print("Run", run, "signature receipt installed; product configuration restored", flush=True)


if __name__ == "__main__":
    main()
