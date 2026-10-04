#!/usr/bin/env python3
"""Verify and adopt only exact SimpleSAMLphp native attribute-policy evidence.

This is the product-adapter boundary for a local receipt.  Parser output alone is never enough:
original metadata, product source, unchanged fixed policy, real correlated responses, production
Runner collection, and byte-exact restoration are all required.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import tempfile
import xml.etree.ElementTree as ET

FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
UID = "urn:oid:0.9.2342.19200300.100.1.1"
SURNAME = "urn:oid:2.5.4.4"
PREFIX = "urn:samlscope:test:policy:"
IMAGE = "sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa"
CONDITIONS = [
    ("baseline", "control", None, "BASELINE"),
    ("entity-present", "attribute-policy-entity-present", None, "ENTITY_PRESENT"),
    ("entity-absent", "attribute-policy-entity-absent", None, "ENTITY_ABSENT"),
    ("requested-required", "attribute-policy-requested-required", None, "REQUESTED_REQUIRED"),
    ("requested-optional", "attribute-policy-requested-optional", None, "REQUESTED_OPTIONAL"),
    ("requested-absent", "attribute-policy-requested-absent", None, "REQUESTED_ABSENT"),
    ("index-zero", "attribute-policy-indexed", 0, "INDEX_ZERO"),
    ("index-one", "attribute-policy-indexed", 1, "INDEX_ONE"),
    ("index-zero-repeat", "attribute-policy-indexed", 0, "INDEX_ZERO_REPEAT"),
]
EXPECTED_MARKERS = {
    "baseline": {"anchor"}, "entity-present": {"anchor", "entity"},
    "entity-absent": {"anchor"},
    "requested-required": {"anchor", "required", "optional"},
    "requested-optional": {"anchor", "optional"},
    "requested-absent": {"anchor"},
    # SimpleSAMLphp 2.5.0 promotes the first service and does not select it from the request.
    # These intentionally do not satisfy IDP04-b and must remain NOT_VERIFIED.
    "index-zero": {"anchor", "required", "optional"},
    "index-one": {"anchor", "required", "optional"},
    "index-zero-repeat": {"anchor", "required", "optional"},
}
SOURCE_PATHS = {
    "metadata-parser": "/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php",
    "processing-chain": "/var/simplesamlphp/src/SimpleSAML/Auth/ProcessingChain.php",
    "php-filter": "/var/simplesamlphp/modules/core/src/Auth/Process/PHP.php",
    "attribute-limit": "/var/simplesamlphp/modules/core/src/Auth/Process/AttributeLimit.php",
    "idp": "/var/simplesamlphp/src/SimpleSAML/IdP.php",
}
SOURCE_TOKENS = {
    "metadata-parser": [b"getMetadata20SP", b"EntityAttributes", b"attributes.required",
                        b"getAttributeConsumingService", b"getRequestedAttribute"],
    "processing-chain": [b"array_key_exists('authproc', $spMetadata)", b"self::addFilters"],
    "php-filter": [b"eval($this->code)", b"$function($state['Attributes'], $state)"],
    "attribute-limit": [b"$state['Destination']['attributes']", b"getSPIdPAllowed"],
    "idp": [b"$state['Destination'] = $spMetadata", b"new Auth\\ProcessingChain"],
}
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


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def require(value, message="invalid SimpleSAMLphp attribute-policy evidence"):
    if not value:
        raise ValueError(message)


def load(folder, name):
    return json.loads((Path(folder) / name).read_text())


def children(element, namespace, name):
    return [child for child in element if child.tag == "{" + namespace + "}" + name]


def verify_fixture(path, label, entity):
    md = "urn:oasis:names:tc:SAML:2.0:metadata"
    saml = "urn:oasis:names:tc:SAML:2.0:assertion"
    mdattr = "urn:oasis:names:tc:SAML:metadata:attribute"
    root = ET.fromstring(path.read_bytes())
    require(root.tag == "{" + md + "}EntityDescriptor" and root.get("entityID") == entity)
    roles = root.findall("{" + md + "}SPSSODescriptor")
    require(len(roles) == 1)
    tags = root.findall("{" + md + "}Extensions/{" + mdattr + "}EntityAttributes")
    if label == "entity-present":
        require(len(tags) == 1 and len(tags[0]) == 1)
        attribute = tags[0][0]
        require(attribute.tag == "{" + saml + "}Attribute")
        require(attribute.attrib == {"Name": "urn:samlscope:test:release-policy", "NameFormat": FORMAT})
        require(len(attribute) == 1 and attribute[0].tag == "{" + saml + "}AttributeValue")
        require(attribute[0].text == "release" and not len(attribute[0]))
    else:
        require(not tags)
    services = roles[0].findall("{" + md + "}AttributeConsumingService")
    names = [UID]
    if label.startswith("index-"):
        names.append(SURNAME)
    elif label not in {"requested-required", "requested-optional"}:
        names = []
    require(len(services) == len(names))
    for index, (service, name) in enumerate(zip(services, names)):
        require(service.get("index") == str(index))
        require(service.get("isDefault") == ("true" if index == 0 else "false"))
        attributes = service.findall("{" + md + "}RequestedAttribute")
        require(len(attributes) == 1 and not len(attributes[0]))
        require(attributes[0].attrib == {"Name": name, "NameFormat": FORMAT,
                                         "isRequired": "false" if label == "requested-optional" else "true"})
    return root


def expected_native(label):
    value = {"attributes": None, "attributes.required": None,
             "attributes.NameFormat": None, "EntityAttributes": None}
    if label == "entity-present":
        value["EntityAttributes"] = {"urn:samlscope:test:release-policy": ["release"]}
    if label in {"requested-required", "requested-optional"} or label.startswith("index-"):
        value["attributes"] = [UID]
        value["attributes.NameFormat"] = FORMAT
        if label != "requested-optional":
            value["attributes.required"] = [UID]
    return value


def verify_product(folder, product):
    require(product["container"] == "samlscope-reference-ssp")
    require(product["imageId"] == IMAGE)
    require(product["configuredImage"] == "cirrusid/simplesamlphp@" + IMAGE)
    require(product["product"]["name"] == "simplesamlphp/simplesamlphp")
    require(product["product"]["pretty_version"] == "v2.5.0"
            and product["product"]["version"] == "2.5.0.0")
    sources = {item["label"]: item for item in product["sources"]}
    require(set(sources) == set(SOURCE_PATHS))
    digests = {}
    for label, expected_path in SOURCE_PATHS.items():
        item = sources[label]
        path = (folder / item["file"]).resolve()
        require(path.is_relative_to(folder.resolve()) and path.is_file())
        raw = path.read_bytes()
        require(item["productPath"] == expected_path and item["sha256"] == sha(raw))
        require(all(token in raw for token in SOURCE_TOKENS[label]))
        digests[label] = item["sha256"]
    return digests


def verify_originals(folder, run):
    transcript_list = load(folder, "transcript.json")
    transcript = {entry["id"]: entry for entry in transcript_list}
    require(len(transcript) == len(transcript_list))
    require(all(entry["runId"] == run for entry in transcript.values()))
    originals = {}
    for item in load(folder, "decoded-manifest.json"):
        path = (folder / item["file"]).resolve()
        require(path.is_relative_to(folder.resolve()) and path.is_file())
        raw = path.read_bytes()
        require(item["sha256"] == sha(raw) and item["id"] not in originals)
        originals[item["id"]] = raw
    return transcript, originals


def verify_exchange(folder, label, variant, selector, run, transcript, originals):
    flow = load(folder, label + "/flow.json")
    require(flow["run"] == run and flow["variant"] == variant and flow["correlated_success"])
    require(flow["attribute_consuming_service_index"] == selector)
    require(flow["positive_exchange"]["success"])
    refs = flow["positive_exchange"]["transcript_ids"]
    require(len(refs) == 2 and all(ref in transcript and ref in originals for ref in refs))
    request = ET.fromstring(originals[refs[0]])
    response = ET.fromstring(originals[refs[1]])
    protocol = "urn:oasis:names:tc:SAML:2.0:protocol"
    require(request.tag == "{" + protocol + "}AuthnRequest")
    require(response.tag == "{" + protocol + "}Response")
    require(response.get("InResponseTo") == request.get("ID") == flow["positive_exchange"]["request_id"])
    require((request.get("AttributeConsumingServiceIndex") or "") == ("" if selector is None else str(selector)))
    require(transcript[refs[0]]["direction"] == "OUTBOUND"
            and transcript[refs[1]]["direction"] == "INBOUND")
    require(transcript[refs[0]]["samlSummary"]["variant"] == variant)
    require(transcript[refs[0]]["samlSummary"].get("metadataSignatureControl") == "valid")
    require(transcript[refs[1]]["samlSummary"].get("metadataProbeAccepted") is True)
    require(transcript[refs[1]]["samlSummary"].get("inResponseTo") == request.get("ID"))
    statuses = response.findall("{" + protocol + "}Status/{" + protocol + "}StatusCode")
    require(len(statuses) == 1
            and statuses[0].get("Value") == "urn:oasis:names:tc:SAML:2.0:status:Success")
    require(transcript[refs[0]]["timestamp"] <= transcript[refs[1]]["timestamp"])
    return refs


def verify_evidence(path):
    folder = Path(path).resolve()
    preparation = load(folder, "preparation.json")
    result = load(folder, "result.json")
    plan = load(folder, "plan.json")["plan"]["plan"]
    run = result["run"]["id"]
    entity = preparation["entity_id"]
    require(re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", run) and preparation["run"] == run)
    require(plan["profile"] == "browser_sso_idp"
            and entity == "http://localhost:18080/p/" + plan["id"])
    policy = {"schema": "samlscope-simplesamlphp-attribute-policy-v1",
              "capturePriority": 40, "releasePriority": 90, "attributeNameFormat": FORMAT,
              "captureCode": CAPTURE_CODE, "releaseCode": RELEASE_CODE,
              "nativeInputs": ["EntityAttributes", "attributes", "attributes.required"],
              "sourceAttribute": "uid"}
    policy_hash = sha(encode(policy))
    require(preparation["policy"] == policy and preparation["policy_sha256"] == policy_hash)
    require(preparation["login_provenance"] == "fixed-in-memory-driver-input"
            and not preparation["authenticated_principal_verified"])
    require(re.fullmatch(r"[0-9a-f]{64}", preparation["login_input_binding"]))
    product = load(folder, "product.json")
    source_hashes = verify_product(folder, product)
    require(preparation["product_image"] == IMAGE)

    original = (folder / "configuration-original.php").read_bytes()
    final = (folder / "configuration-final.php").read_bytes()
    restoration = load(folder, "restoration.json")
    operations = load(folder, "operations.json")
    require(original == final and restoration["restored"] and restoration["container_matches_original"]
            and restoration["temporary_entity_absent"])
    require(restoration["original_sha256"] == restoration["final_sha256"] == sha(original)
            == restoration["container_final_sha256"])
    require(operations == {"run": run, "productConfigurationWrites": 10, "appliedConditions": 9,
        "restorationWrites": 1, "productRestarts": 0, "humanOperations": 0,
        "protocolRoundTrips": 9, "completedConditions": 9, "restored": True,
        "driverSha256": operations["driverSha256"]})
    require(re.fullmatch(r"[0-9a-f]{64}", operations["driverSha256"]))
    observations = load(folder, "observations.json")
    require(len(observations) == len(CONDITIONS))
    transcript, originals = verify_originals(folder, run)
    indexed = set()
    exchanges = []
    configured_hashes = []
    for observation, (label, variant, selector, condition) in zip(observations, CONDITIONS):
        require(observation["label"] == label and observation["variant"] == variant
                and observation["selector"] == selector and observation["run"] == run)
        require(observation["status"] == "protocol-recorded"
                and observation["configuration_read_back"] and observation["container_read_back"]
                and observation["configuration_unchanged_during_flow"])
        fixture = folder / label / "fixture.xml"
        verify_fixture(fixture, label, entity)
        fixture_hash = sha(fixture.read_bytes())
        require(observation["fixture_sha256"] == fixture_hash)
        if selector is not None:
            indexed.add(fixture_hash)
        parser_path = folder / label / "parser-output.json"
        parser_raw = parser_path.read_bytes()
        parsed = json.loads(parser_raw)
        require(observation["parser_output_sha256"] == sha(parser_raw))
        require(parsed["entity_id"] == entity and parsed["native_selected"] == expected_native(label))
        authproc = {"40": {"class": "core:PHP", "code": CAPTURE_CODE},
                    "90": {"class": "core:PHP", "code": RELEASE_CODE}}
        require(parsed["authproc"] == authproc)
        configured_selected = copy.deepcopy(expected_native(label))
        configured_selected["attributes.NameFormat"] = FORMAT
        require(parsed["configured_selected"] == configured_selected)
        expected_config = original + b"\n" + parsed["php"].encode() + b"\n"
        configured_path = folder / label / "configuration-readback.php"
        require(configured_path.read_bytes() == expected_config)
        configured_hash = sha(expected_config)
        require(observation["configuration_sha256"] == configured_hash
                == observation["configuration_after_sha256"])
        configured_hashes.append(configured_hash)
        readback = load(folder, label + "/native-readback.json")
        require(readback == observation["native_read_back"]
                == {"entity_id": entity, "selected": configured_selected, "authproc": authproc})
        require(observation["native_selected"] == expected_native(label)
                and observation["policy_sha256"] == policy_hash
                and observation["login_input_binding"] == preparation["login_input_binding"])
        request, response = verify_exchange(folder, label, variant, selector, run, transcript, originals)
        exchanges.append({"condition": condition, "requestReference": request,
            "responseReference": response, "policyFingerprint": policy_hash,
            "loginInputFingerprint": preparation["login_input_binding"]})
    require(len(indexed) == 1 and len(set(configured_hashes)) == 7)

    target = (folder / "target-metadata.xml").read_bytes()
    target_entity = ET.fromstring(target).get("entityID")
    target_hash = sha(target)
    require(result["target"]["metadata_digest"] == "sha256:" + target_hash)
    proof = load(folder, "verified-attribute-evidence.json")
    production = load(folder, "production-observation.json")
    require(proof["run"] == production["run"] == run)
    require(proof["target_metadata_sha256"] == target_hash
            and proof["result_sha256"] == sha((folder / "result.json").read_bytes()))
    require(not proof["plaintext_persisted"] and not proof["private_key_exported"])
    require(not production["issues"] and production["same_attribute_input"]
            and not production["authenticated_principal_verified"] and not production["verdict_adopted"])
    require(production["result_sha256"] == sha((folder / "result.json").read_bytes())
            and production["transcript_sha256"] == sha((folder / "transcript.json").read_bytes()))
    verified = {item["request"]: item for item in proof["observations"]}
    observed = {item["evidence"][-2]["reference"]: item for item in production["observations"]}
    require(len(verified) == len(observed) == 9)
    for (label, variant, selector, _), exchange in zip(CONDITIONS, exchanges):
        item = verified[exchange["requestReference"]]
        require(item["response"] == exchange["responseReference"] and item["variant"] == variant)
        require(item["attribute_service_index"] == ("" if selector is None else str(selector)))
        require(item["response_signature_verified"] and item["decrypted_assertions"] >= 0)
        markers = {attribute["name"].removeprefix(PREFIX) for attribute in item["attributes"]
                   if attribute["name"].startswith(PREFIX)}
        require(markers == EXPECTED_MARKERS[label])
        require(all(attribute["name_format"] == FORMAT for attribute in item["attributes"]
                    if attribute["name"].startswith(PREFIX)))
        require(exchange["requestReference"] in observed)
        production_item = observed[exchange["requestReference"]]
        require(production_item["variant"] == variant
                and production_item["selector"] == ("" if selector is None else str(selector))
                and production_item["metadata_sha256"]
                    == load(folder, label + "/observation.json")["fixture_sha256"]
                and set(production_item["markers"]) == EXPECTED_MARKERS[label])

    stable = sha(encode({"policy": policy_hash, "entity": entity, "productImage": IMAGE,
                         "productSources": source_hashes, "configurationOriginal": sha(original)}))
    for exchange in exchanges:
        exchange["stableInputFingerprint"] = stable
    raw_evidence = [{"reference": item["id"], "sha256": item["sha256"]}
                    for item in load(folder, "decoded-manifest.json")]
    receipt = {"schema": "samlscope-native-attribute-policy-receipt-v1", "runId": run,
        "targetEntityId": target_entity, "targetMetadataSha256": target_hash,
        "preparation": {"runId": run, "experimentId": "native-ssp-policy-" + run,
                        "exchanges": exchanges}, "rawEvidence": raw_evidence}
    return {"folder": folder, "run": run, "entity": entity, "receipt": receipt,
            "eligibleCases": ["IIP-IDP03-a-idp-01", "IIP-IDP04-a-idp-01"],
            "ineligibleCases": ["IIP-IDP04-b-idp-01"], "sourceHashes": source_hashes}


def write_receipt(verified, output):
    raw = json.dumps(verified["receipt"], indent=2, ensure_ascii=False).encode() + b"\n"
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        require(not output.is_symlink() and output.read_bytes() == raw, "receipt is immutable")
    else:
        with output.open("xb") as stream:
            stream.write(raw)
    return sha(raw)


def verify_receipt(verified, path):
    require(json.loads(Path(path).read_text()) == verified["receipt"], "receipt mismatch")


def verify_evaluation(verified, evaluation):
    evaluation = Path(evaluation)
    result = load(evaluation, "result.json")
    require(result["run"]["id"] == verified["run"])
    cases = {case["id"]: case for requirement in result["requirements"] for case in requirement["cases"]}
    for case_id in verified["eligibleCases"]:
        case = cases[case_id]
        require((case["outcome"], case["verdict"], case["reason_code"], case["attested"]) ==
                ("SATISFIED", "PASS", "configuration.attribute-policy.comparison-observed", False))
        configured = load(evaluation, case_id + "-configure.json")["outcome"]
        require(configured["outcome"] == "SATISFIED"
                and configured["details"]["configuration_confirmed"]
                and configured["details"]["preparation_source"] == "local-native-adapter")
    unresolved = cases[verified["ineligibleCases"][0]]
    require(unresolved["outcome"] == "NOT_VERIFIED" and unresolved["verdict"] == "NOT_VERIFIED")
    return cases


def tamper_receipt(verified, receipt_path):
    original = copy.deepcopy(verified["receipt"])
    mutations = []
    mutation_functions = [
        ("run", lambda x: x.update(runId="run_00000000000000000000000000")),
        ("target", lambda x: x.update(targetMetadataSha256="0" * 64)),
        ("entity", lambda x: x.update(targetEntityId="https://wrong.example")),
        ("condition", lambda x: x["preparation"]["exchanges"][1].update(condition="ENTITY_ABSENT")),
        ("request", lambda x: x["preparation"]["exchanges"][0].update(requestReference="tx_00000000000000000000000000")),
        ("response", lambda x: x["preparation"]["exchanges"][0].update(responseReference="tx_00000000000000000000000000")),
        ("policy", lambda x: x["preparation"]["exchanges"][0].update(policyFingerprint="0" * 64)),
        ("login", lambda x: x["preparation"]["exchanges"][0].update(loginInputFingerprint="0" * 64)),
        ("stable", lambda x: x["preparation"]["exchanges"][0].update(stableInputFingerprint="0" * 64)),
        ("raw-hash", lambda x: x["rawEvidence"][0].update(sha256="0" * 64)),
        ("raw-ref", lambda x: x["rawEvidence"][0].update(reference="tx_00000000000000000000000000")),
        ("drop-control", lambda x: x["preparation"]["exchanges"].pop(2)),
    ]
    for name, mutate in mutation_functions:
        value = copy.deepcopy(original)
        mutate(value)
        with tempfile.NamedTemporaryFile("w", delete=False) as stream:
            json.dump(value, stream)
            temporary = Path(stream.name)
        try:
            try:
                verify_receipt(verified, temporary)
            except ValueError:
                mutations.append(name)
            else:
                raise AssertionError("receipt mutation accepted: " + name)
        finally:
            temporary.unlink()
    require(mutations == [name for name, _ in mutation_functions])
    verify_receipt(verified, receipt_path)
    return mutations


def verify(root):
    """Fail-closed adoption entry point used by the generated comparison ledger."""
    root = Path(root)
    evidence = root / "simplesamlphp-attribute-policy-v152-r2"
    receipt = evidence / "qualified-preparation.json"
    evaluation = root / "simplesamlphp-attribute-policy-evaluation-v153"
    verified = verify_evidence(evidence)
    verify_receipt(verified, receipt)
    expected_mutations = {
        "run", "target", "entity", "condition", "request", "response",
        "policy", "login", "stable", "raw-hash", "raw-ref", "drop-control",
    }
    require(set(tamper_receipt(verified, receipt)) == expected_mutations)
    cases = verify_evaluation(verified, evaluation)
    report = load(evidence, "acceptance-verification.json")
    require(report["run"] == verified["run"] and report["evaluationVerified"] is True)
    require(report["receiptSha256"] == sha(receipt.read_bytes()))
    require(set(report["tamperRejections"]) == expected_mutations)
    return evaluation / "result.json", cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--evaluation", type=Path)
    parser.add_argument("--tamper", action="store_true")
    args = parser.parse_args()
    verified = verify_evidence(args.evidence)
    receipt_hash = write_receipt(verified, args.receipt)
    tampered = tamper_receipt(verified, args.receipt) if args.tamper else []
    cases = verify_evaluation(verified, args.evaluation) if args.evaluation else None
    report = {"schema": "samlscope-ssp-attribute-policy-acceptance-v1", "run": verified["run"],
        "receiptSha256": receipt_hash, "eligibleCases": verified["eligibleCases"],
        "ineligibleCases": verified["ineligibleCases"], "tamperRejections": tampered,
        "evaluationVerified": cases is not None}
    output = args.evidence / "acceptance-verification.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
