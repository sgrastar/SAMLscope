#!/usr/bin/env python3
"""Run fixed-policy attribute comparisons through SimpleSAMLphp's native metadata path.

The product parses every Suite fixture.  One identical per-SP authproc recipe then reads only
the resulting native metadata fields and emits opaque test markers in real SAML responses.
This recorder never assigns a case outcome; the Runner and the independent acceptance verifier
do that from saved originals after exact configuration restoration.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.request

from configuration_batch import ConfigurationBatch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
from import_metadata_batch import BASE, api, flow, save  # noqa: E402

CONTAINER = "samlscope-reference-ssp"
CONFIG = REPO / "build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php"
CONTAINER_CONFIG = "/var/simplesamlphp/metadata/saml20-sp-remote.php"
FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
UID = "urn:oid:0.9.2342.19200300.100.1.1"
SURNAME = "urn:oid:2.5.4.4"
CONDITIONS = [
    ("baseline", "control", None),
    ("entity-present", "attribute-policy-entity-present", None),
    ("entity-absent", "attribute-policy-entity-absent", None),
    ("requested-required", "attribute-policy-requested-required", None),
    ("requested-optional", "attribute-policy-requested-optional", None),
    ("requested-absent", "attribute-policy-requested-absent", None),
    ("index-zero", "attribute-policy-indexed", 0),
    ("index-one", "attribute-policy-indexed", 1),
    ("index-zero-repeat", "attribute-policy-indexed", 0),
]
PRODUCT_SOURCES = {
    "metadata-parser": "/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php",
    "processing-chain": "/var/simplesamlphp/src/SimpleSAML/Auth/ProcessingChain.php",
    "php-filter": "/var/simplesamlphp/modules/core/src/Auth/Process/PHP.php",
    "attribute-limit": "/var/simplesamlphp/modules/core/src/Auth/Process/AttributeLimit.php",
    "idp": "/var/simplesamlphp/src/SimpleSAML/IdP.php",
}

# Priority 40 preserves the fixed input before the product's priority-50 AttributeLimit.
# Priority 90 uses only metadata fields produced by the native parser.  It contains no variant,
# condition, campaign, request-ID or selector switch, so the same recipe is used for every input.
CAPTURE_CODE = (
    "$v=$attributes['uid'][0]??null;"
    "if(!is_string($v)||$v===''){throw new \\RuntimeException('Missing fixed policy input');}"
    "$state['samlscope:attribute-policy-input']=$v;"
)
RELEASE_CODE = (
    "$v=$state['samlscope:attribute-policy-input']??null;"
    "if(!is_string($v)||$v===''){throw new \\RuntimeException('Missing fixed policy input');}"
    "$d=$state['Destination']??[];"
    "$out=['urn:samlscope:test:policy:anchor'=>[$v]];"
    "$ea=$d['EntityAttributes']['urn:samlscope:test:release-policy']??[];"
    "if(is_array($ea)&&in_array('release',$ea,true)){$out['urn:samlscope:test:policy:entity']=[$v];}"
    "$requested=$d['attributes']??[];$required=$d['attributes.required']??[];"
    "if(is_array($requested)&&in_array('" + UID + "',$requested,true)){"
    "$out['urn:samlscope:test:policy:optional']=[$v];"
    "if(is_array($required)&&in_array('" + UID + "',$required,true)){"
    "$out['urn:samlscope:test:policy:required']=[$v];}}"
    "if(is_array($requested)&&in_array('" + SURNAME + "',$requested,true)){"
    "$out['urn:samlscope:test:policy:surname']=[$v];}"
    "$attributes=$out;unset($state['samlscope:attribute-policy-input']);"
)

PARSE_PHP = r'''
require '/var/simplesamlphp/lib/_autoload.php';
$xml=stream_get_contents(STDIN);
(new \SimpleSAML\Utils\XML())->checkSAMLMessage($xml,'saml-meta');
$entities=\SimpleSAML\Metadata\SAMLParser::parseDescriptorsString($xml);
$entity=$argv[1];
if (!isset($entities[$entity])) { throw new \RuntimeException('Expected entity missing'); }
$metadata=$entities[$entity]->getMetadata20SP();
if ($metadata===null) { throw new \RuntimeException('SP descriptor missing'); }
unset($metadata['entityDescriptor'],$metadata['expire']);
$native=[];
foreach (['attributes','attributes.required','attributes.NameFormat','EntityAttributes'] as $key) {
  $native[$key]=$metadata[$key]??null;
}
$metadata['attributes.NameFormat']=$argv[2];
$metadata['authproc']=[
  40=>['class'=>'core:PHP','code'=>$argv[3]],
  90=>['class'=>'core:PHP','code'=>$argv[4]],
];
$selected=[];
foreach (['attributes','attributes.required','attributes.NameFormat','EntityAttributes'] as $key) {
  $selected[$key]=$metadata[$key]??null;
}
echo json_encode(['entity_id'=>$entity,'native_selected'=>$native,'configured_selected'=>$selected,
 'authproc'=>$metadata['authproc'],
 'php'=>'$metadata['.var_export($entity,true).'] = '.var_export($metadata,true).';'],JSON_THROW_ON_ERROR);
'''

READBACK_PHP = r'''
require '/var/simplesamlphp/lib/_autoload.php';
$metadata=[];require $argv[1];$entity=$argv[2];
if (!isset($metadata[$entity])) { throw new \RuntimeException('Configured entity missing'); }
$entry=$metadata[$entity];$selected=[];
foreach (['attributes','attributes.required','attributes.NameFormat','EntityAttributes'] as $key) {
  $selected[$key]=$entry[$key]??null;
}
echo json_encode(['entity_id'=>$entity,'selected'=>$selected,'authproc'=>$entry['authproc']??null],JSON_THROW_ON_ERROR);
'''


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def docker(*args, data=None):
    result = subprocess.run(["docker", "exec", "-i", CONTAINER, *args], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if result.returncode:
        raise RuntimeError("Product command failed: " + result.stderr.decode(errors="replace")[:1000])
    return result.stdout


def native_parse(fixture, entity):
    raw = docker("php", "-r", PARSE_PHP, entity, FORMAT, CAPTURE_CODE, RELEASE_CODE, data=fixture)
    return raw, json.loads(raw)


def native_readback(entity):
    raw = docker("php", "-r", READBACK_PHP, CONTAINER_CONFIG, entity)
    return json.loads(raw)


def copy_transcript_originals(out, run):
    manifest = []
    transcript = json.loads((out / "transcript.json").read_text())
    for entry in transcript:
        reference = entry.get("decodedSamlRef")
        if not reference:
            continue
        if entry.get("runId") != run or not re.fullmatch(r"tx_[0-9A-HJKMNP-TV-Z]{26}", entry["id"]):
            raise ValueError("Invalid transcript scope")
        path = out / "decoded" / (entry["id"] + ".xml")
        path.parent.mkdir(exist_ok=True)
        subprocess.run(["docker", "cp", "samlscope-reference-suite:/data/" + reference, str(path)],
                       check=True, stdout=subprocess.DEVNULL, timeout=120)
        manifest.append({"id": entry["id"], "file": str(path.relative_to(out)),
                         "sha256": sha(path.read_bytes())})
    save(out / "decoded-manifest.json", manifest)
    subprocess.run(["docker", "cp", "samlscope-reference-suite:/data/target-metadata/" + run + ".xml",
                    str(out / "target-metadata.xml")], check=True, stdout=subprocess.DEVNULL, timeout=120)


def capture_product(out):
    originals = out / "product-originals"
    originals.mkdir()
    source_manifest = []
    for label, product_path in PRODUCT_SOURCES.items():
        raw = docker("cat", product_path)
        file = originals / (label + ".php")
        file.write_bytes(raw)
        source_manifest.append({"label": label, "productPath": product_path,
                                "file": str(file.relative_to(out)), "sha256": sha(raw)})
    version = json.loads(docker("php", "-r",
        'require "/var/simplesamlphp/lib/_autoload.php";echo json_encode(Composer\\InstalledVersions::getRootPackage());'))
    inspect = subprocess.run(["docker", "inspect", CONTAINER, "--format", "{{json .}}"],
                             check=True, stdout=subprocess.PIPE, timeout=120)
    container = json.loads(inspect.stdout)
    record = {"container": CONTAINER, "imageId": container["Image"],
              "configuredImage": container["Config"]["Image"], "product": version,
              "sources": source_manifest}
    save(out / "product.json", record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError("Evidence directory must be empty")
    out.mkdir(parents=True, exist_ok=True)
    product = capture_product(out)

    configuration = ConfigurationBatch(CONFIG)
    configuration.container = CONTAINER
    configuration.container_path = CONTAINER_CONFIG
    original = configuration.original
    (out / "configuration-original.php").write_bytes(original)
    if docker("cat", CONTAINER_CONFIG) != original:
        raise RuntimeError("Host/container configuration original mismatch")

    login_inputs = (os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user"),
                    os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password"))
    login_input_binding = secrets.token_hex(32)
    plan_result = api("/api/plans", dict(name="SimpleSAMLphp fixed native attribute policy",
        profile="browser_sso_idp", targetKind="IDP", targetEntityId="http://localhost:18380/idp",
        metadataSourceKind="URL",
        metadataSourceLocation="http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata",
        suiteMetadataDelivery="HTTP_URL", declaredFeatures={},
        parameters=dict(clockSkewToleranceSeconds=180, metadataRefreshWaitSeconds=300,
                        testUserHint="samlscope-m0-user", requestSigningMode="REQUIRED"),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset="quick"),
        authorizedTarget=True))
    save(out / "plan.json", plan_result)
    plan = plan_result["plan"]["plan"]["id"]
    created = api("/api/plans/" + plan + "/runs", {})
    save(out / "created.json", created)
    run = created["run"]["id"]
    entity = BASE + "/p/" + plan
    if not re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", run) or entity.encode() in original:
        raise ValueError("Invalid or pre-existing experiment scope")
    save(out / "preflight.json", api("/api/runs/" + run + "/preflight", {}))

    policy = {"schema": "samlscope-simplesamlphp-attribute-policy-v1",
              "capturePriority": 40, "releasePriority": 90, "attributeNameFormat": FORMAT,
              "captureCode": CAPTURE_CODE, "releaseCode": RELEASE_CODE,
              "nativeInputs": ["EntityAttributes", "attributes", "attributes.required"],
              "sourceAttribute": "uid"}
    policy_raw = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    save(out / "preparation.json", {"run": run, "entity_id": entity, "policy": policy,
        "policy_sha256": sha(policy_raw), "login_input_binding": login_input_binding,
        "login_provenance": "fixed-in-memory-driver-input", "authenticated_principal_verified": False,
        "product_image": product["imageId"]})

    observations = []
    indexed_hash = None
    restored = None
    try:
        for label, variant, selector in CONDITIONS:
            folder = out / label
            folder.mkdir()
            state = api("/api/runs/" + run + "/metadata-lab/automatic-polling",
                        {"variants": [variant], "pollingDelaySeconds": 0})
            save(folder / "campaign.json", state)
            with urllib.request.urlopen(state["automaticStartUrl"], timeout=30) as response:
                if response.status != 202:
                    raise RuntimeError("Fixture was dispatched before native import")
                response.read()
            with urllib.request.urlopen(state["metadataUrl"], timeout=30) as response:
                fixture = response.read()
            (folder / "fixture.xml").write_bytes(fixture)
            fixture_hash = sha(fixture)
            if selector is not None:
                if indexed_hash is not None and indexed_hash != fixture_hash:
                    raise RuntimeError("Indexed fixture changed between selector controls")
                indexed_hash = fixture_hash
            parsed_raw, parsed = native_parse(fixture, entity)
            (folder / "parser-output.json").write_bytes(parsed_raw)
            if parsed["entity_id"] != entity or parsed["authproc"] != {
                    "40": {"class": "core:PHP", "code": CAPTURE_CODE},
                    "90": {"class": "core:PHP", "code": RELEASE_CODE}}:
                raise RuntimeError("Native parser/policy output mismatch")
            if docker("cat", CONTAINER_CONFIG) != configuration.expected:
                raise RuntimeError("Container configuration changed outside this batch")
            configured_hash = configuration.apply(parsed["php"].encode())
            time.sleep(3)
            host_raw = CONFIG.read_bytes()
            container_raw = docker("cat", CONTAINER_CONFIG)
            if host_raw != container_raw or sha(host_raw) != configured_hash:
                raise RuntimeError("Configuration read-back mismatch")
            (folder / "configuration-readback.php").write_bytes(host_raw)
            readback = native_readback(entity)
            (folder / "native-readback.json").write_text(json.dumps(readback, indent=2) + "\n")
            if readback != {"entity_id": entity, "selected": parsed["configured_selected"],
                             "authproc": parsed["authproc"]}:
                raise RuntimeError("Product-native metadata read-back mismatch")
            record = {"label": label, "run": run, "variant": variant, "selector": selector,
                      "fixture_sha256": fixture_hash, "configuration_sha256": configured_hash,
                      "configuration_read_back": True, "container_read_back": True,
                      "parser_output_sha256": sha(parsed_raw), "native_selected": parsed["native_selected"],
                      "native_read_back": readback, "policy_sha256": sha(policy_raw),
                      "login_input_binding": login_input_binding, "status": "incomplete"}
            observations.append(record)
            try:
                flow(run, folder / "flow.json", attribute_service_index=selector, login_inputs=login_inputs)
                record["status"] = "protocol-recorded"
                if label == "baseline":
                    save(out / "tests-start.json", api("/api/runs/" + run + "/tests/start", {}))
            finally:
                after = CONFIG.read_bytes()
                record["configuration_after_sha256"] = sha(after)
                record["configuration_unchanged_during_flow"] = after == host_raw == docker("cat", CONTAINER_CONFIG)
                save(folder / "observation.json", record)
                save(out / "observations.json", observations)
    finally:
        try:
            if docker("cat", CONTAINER_CONFIG) != configuration.expected:
                raise RuntimeError("Container configuration changed outside this batch; refusing restore")
            restored = configuration.restore()
            time.sleep(3)
            (out / "configuration-final.php").write_bytes(CONFIG.read_bytes())
            restored["container_final_sha256"] = sha(docker("cat", CONTAINER_CONFIG))
            restored["container_matches_original"] = docker("cat", CONTAINER_CONFIG) == original
            configured_entities = json.loads(docker("php", "-r",
                'require "' + CONTAINER_CONFIG + '";echo json_encode(array_keys($metadata));'))
            restored["temporary_entity_absent"] = entity not in configured_entities
            restored["restored"] = (restored["restored"] and restored["container_matches_original"]
                                    and restored["temporary_entity_absent"])
        except Exception as error:
            restored = {"restored": False, "reason": str(error)}
        save(out / "restoration.json", restored)
        save(out / "operations.json", {"run": run, "productConfigurationWrites": configuration.write_count,
            "appliedConditions": configuration.applied_count,
            "restorationWrites": configuration.restoration_writes,
            "productRestarts": 0, "humanOperations": 0,
            "protocolRoundTrips": sum(o["status"] == "protocol-recorded" for o in observations),
            "completedConditions": sum(o["status"] == "protocol-recorded" for o in observations),
            "restored": restored.get("restored", False),
            "driverSha256": sha(Path(__file__).read_bytes())})
        if not restored.get("restored"):
            raise RuntimeError("Restoration incomplete; evidence adoption blocked")
        try:
            save(out / "evaluation.json", api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
        except Exception as error:
            save(out / "evaluation-error.json", {"reason": str(error)})
        for endpoint in ["result.json", "transcript", "protocol-evidence"]:
            save(out / (endpoint if "." in endpoint else endpoint + ".json"),
                 api("/api/runs/" + run + "/" + endpoint))
        copy_transcript_originals(out, run)
    print("Recorded", len(observations), "conditions for", run, "; no verdict assigned")


if __name__ == "__main__":
    main()
