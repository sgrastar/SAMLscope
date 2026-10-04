#!/usr/bin/env python3
"""Fail-closed gate for the four-profile IIP-EXT01.b reference campaign."""
import argparse
import hashlib
import json
import shutil
import re
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from verify_terminal_http_acceptance import (
    EVALUATION, PRODUCT, _verify_configuration_restoration, _verify_suite_runtime,
    _verify_target_runtime, find_case, parsed_time,
)


CASE = "IIP-EXT01-b-idp-01"
PROFILES = ("browser_sso_idp", "ecp_idp", "metadata_idp", "single_logout_idp")
FIXTURES = ("baseline-success", "unknown-extension", "unknown-advice-extension",
            "unknown-metadata-extension")
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
ACTION_RE = re.compile(r"action_[0-9a-f]{32}")
P = "{urn:oasis:names:tc:SAML:2.0:protocol}"
A = "{urn:oasis:names:tc:SAML:2.0:assertion}"
MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
UNKNOWN = "{urn:samlscope:probe:unknown-extension}UnknownExtension"
FOREIGN = "{urn:samlscope:probe:unknown-attribute}fixture"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
TARGET_IMAGES = {
    "keycloak": "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067",
    "shibboleth": "sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a",
    "simplesamlphp": "sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa",
}

# Exact Suite identities for each sealed product campaign. The common runtime verifier reads every
# JAR back from the running container and binds its digest to each independently created Run.
ACCEPTED_SUITE_BY_PRODUCT = {
    "keycloak": {
        "image_id": "sha256:846083123e759f24e88a89f9badba50c4e4cd110b3b13563e8295c9829886cdb",
        "jars": {
            "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe",
            "runner": "94dca2c3c134cf2ad3c30fb4a271448b729c7327b464bff0070a83b45b157dae",
            "saml": "cbfdb79f54ed967f58c8153eb8d0dda350016030c552d0aaee3fc30988d3bf73",
        },
    },
    "shibboleth": {
        "image_id": "sha256:f8ab01c6612c3ceb15949dbe29dae8fd18b1d24700121899c8cceee200107c49",
        "jars": {
            "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe",
            "runner": "a9dfd87300dfc418698ca1de14b67a64dc11ddc85978f2430d87523a9d465ca2",
            "saml": "cbfdb79f54ed967f58c8153eb8d0dda350016030c552d0aaee3fc30988d3bf73",
        },
    },
    "simplesamlphp": {
        "image_id": "sha256:846083123e759f24e88a89f9badba50c4e4cd110b3b13563e8295c9829886cdb",
        "jars": {
            "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe",
            "runner": "94dca2c3c134cf2ad3c30fb4a271448b729c7327b464bff0070a83b45b157dae",
            "saml": "cbfdb79f54ed967f58c8153eb8d0dda350016030c552d0aaee3fc30988d3bf73",
        },
    },
}


def require(value, detail):
    if not value:
        raise ValueError(detail)


def read(path):
    return json.loads(Path(path).read_text())


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_xml(raw):
    require(b"<!DOCTYPE" not in raw.upper() and b"<!ENTITY" not in raw.upper(),
            "DTD/entity in Recorder XML original")
    return ET.fromstring(raw)


def direct(parent, tag):
    return [child for child in list(parent) if child.tag == tag]


def decoded_originals(folder):
    manifest = read(folder / "decoded-manifest.json")
    require(isinstance(manifest, list) and manifest, "decoded original manifest is empty")
    result = {}
    for item in manifest:
        require(set(item) == {"id", "file", "sha256"}, "unexpected decoded manifest fields")
        path = folder / item["file"]
        raw = path.read_bytes()
        require(path.resolve().is_relative_to((folder / "decoded").resolve()),
                "decoded original escaped evidence directory")
        require(sha(raw) == item["sha256"] and item["id"] not in result,
                "decoded original hash/identity mismatch")
        result[item["id"]] = raw
    return result


def verify_ext_runtime(folder):
    runtime = read(folder / "suite-runtime-terminal-http.json")
    runner = folder / runtime["jars"]["runner"]["file"]
    saml = folder / runtime["jars"]["saml"]["file"]
    with zipfile.ZipFile(runner) as archive:
        outer = archive.read(
            "com/samlscope/runner/cases/IdpExecutableBrowserFixtureScenarioTestCase.class")
        fixture = archive.read(
            "com/samlscope/runner/cases/IdpExecutableBrowserFixtureScenarioTestCase$PartialFixture.class")
        require(all(value in outer for value in (
                    b"IIP-EXT01-b-idp-01", b"UNKNOWN_ADVICE_EXTENSION",
                    b"UNKNOWN_METADATA_EXTENSION", b"UNKNOWN_ATTRIBUTE_ANY_ATTRIBUTE")),
                "running Runner lacks complete EXT01 fixture registration")
        require(b"partial-observation-v8" in fixture and b"browser_fixture_satisfied" in outer,
                "running Runner lacks the success-only EXT01 oracle")
    with zipfile.ZipFile(saml) as archive:
        factory = archive.read(
            "com/samlscope/saml/normal/SamlErrorProbeRequestFactory.class")
        require(all(value in factory for value in (
                    b"protocol-extensions", b"assertion-advice", b"metadata-extensions")),
                "running SAML module lacks the approved EXT01.b placements")


def verify_request(fixture, root):
    require(root.tag == P + "AuthnRequest" and root.get("ID"), "fixture is not an AuthnRequest")
    unknown = root.findall(".//" + UNKNOWN)
    foreign = [value for value in root.iter() if FOREIGN in value.attrib]
    if fixture == "baseline-success":
        require(not unknown and not foreign, "baseline contains an EXT01 trigger")
        return
    require(len(unknown) == 1 and not foreign, "wrong unknown-extension trigger cardinality")
    marker = unknown[0]
    expected = {
        "unknown-extension": "protocol-extensions",
        "unknown-advice-extension": "assertion-advice",
        "unknown-metadata-extension": "metadata-extensions",
    }[fixture]
    require(marker.get("placement") == expected, "wrong extension placement marker")
    if fixture == "unknown-extension":
        containers = direct(root, P + "Extensions")
        require(len(containers) == 1 and marker in list(containers[0]),
                "unknown element is not directly in samlp:Extensions")
    elif fixture == "unknown-advice-extension":
        advice = root.findall(".//" + A + "Advice")
        require(len(advice) == 1 and marker in list(advice[0]),
                "unknown element is not directly in saml:Advice")
    else:
        extensions = root.findall(".//" + MD + "Extensions")
        require(len(extensions) == 1 and marker in list(extensions[0])
                and len(root.findall(".//" + MD + "EntityDescriptor")) == 1,
                "unknown element is not directly in md:Extensions")


def verify_profile(folder, product, profile, pins):
    plan_envelope = read(folder / "plan.json")
    plan = plan_envelope["plan"]["plan"]
    created = read(folder / "created.json")["run"]
    run = created["id"]
    require(RUN_RE.fullmatch(run) and created["planId"] == plan["id"], "Plan/Run identity mismatch")
    require(plan["profile"] == profile and plan["target"]["kind"] == "IDP"
            and plan["target"]["entityId"] == PRODUCT[product]["target_entity"],
            "wrong product/profile Plan")
    require(plan.get("requestSigningMode") == "REQUIRED", "unexpected Plan signing mode")

    _verify_target_runtime(folder, product, float(created["createdAt"]))
    start_runtime = read(folder / "target-runtime-start.json")
    require(start_runtime["binding"]["image_id"] == TARGET_IMAGES[product],
            "untrusted target image")
    _verify_suite_runtime(folder, run, float(created["createdAt"]), pins)
    verify_ext_runtime(folder)
    _verify_configuration_restoration(folder, product)

    transcript = read(folder / "transcript.json")
    evaluation = folder / EVALUATION
    require(transcript == read(evaluation / "transcript-before.json")
            == read(evaluation / "transcript.json"), "formal re-evaluation transcript mismatch")
    require(all(entry.get("runId") == run for entry in transcript), "foreign Run transcript entry")
    originals = decoded_originals(folder)

    outbound = [entry for entry in transcript
                if entry.get("direction") == "OUTBOUND"
                and entry.get("samlSummary", {}).get("scenario_case_id") == CASE]
    require(len(outbound) == len(FIXTURES), "wrong EXT01.b outbound fixture count")
    by_fixture = {}
    inbound_ids = []
    for entry in outbound:
        summary = entry.get("samlSummary", {})
        fixture = summary.get("fixture_id")
        require(fixture in FIXTURES and fixture not in by_fixture, "duplicate/unknown EXT01.b fixture")
        action = summary.get("action_id")
        require(ACTION_RE.fullmatch(action or "") and entry.get("correlationId") == action,
                "fixture action correlation mismatch")
        require(entry["id"] in originals and entry.get("decodedSamlBytes") == len(originals[entry["id"]]),
                "missing outbound Recorder original")
        request = safe_xml(originals[entry["id"]])
        verify_request(fixture, request)
        request_id = request.get("ID")
        responses = [candidate for candidate in transcript
                     if candidate.get("direction") == "INBOUND"
                     and candidate.get("samlSummary", {}).get("inResponseTo") == request_id]
        require(len(responses) == 1, "fixture lacks one unique correlated SAML response")
        response_entry = responses[0]
        require(response_entry["id"] in originals
                and response_entry.get("decodedSamlBytes") == len(originals[response_entry["id"]]),
                "missing response Recorder original")
        response = safe_xml(originals[response_entry["id"]])
        require(response.tag == P + "Response" and response.get("InResponseTo") == request_id,
                "response original correlation mismatch")
        status = direct(response, P + "Status")
        codes = direct(status[0], P + "StatusCode") if len(status) == 1 else []
        require(len(codes) == 1 and codes[0].get("Value") == SUCCESS,
                "fixture did not receive a SAML Success response")
        require(len(direct(response, A + "Assertion")) + len(direct(response, A + "EncryptedAssertion")) > 0,
                "Success response has no assertion")
        destination = response.get("Destination")
        require(destination == response_entry.get("url"), "response Destination/Recorder URL mismatch")
        parsed = urllib.parse.urlsplit(destination)
        require(parsed.hostname in {"localhost", "127.0.0.1"}
                and parsed.port == 18080 and f"/p/{plan['id']}/sp/acs/" in parsed.path,
                "response did not return to this Plan's Suite ACS")
        inbound_ids.append(response_entry["id"])
        by_fixture[fixture] = entry["id"]
    require(tuple(by_fixture) == FIXTURES, "EXT01.b fixture order changed")

    result = read(evaluation / "result.json")
    case = find_case(result, CASE)
    require(case.get("outcome") == "SATISFIED" and case.get("verdict") == "PASS"
            and case.get("reason_code") == "browser_fixture_satisfied",
            "formal EXT01.b result is not satisfied")
    evidence = {value.get("reference") for value in case.get("evidence", [])
                if value.get("kind") == "transcript"}
    require(evidence == set(inbound_ids), "case evidence does not bind every and only fixture response")
    # Public result.json deliberately omits internal CaseOutcome details.  The complete all-of set
    # is therefore attested by the exact four response evidence references after the verifier has
    # independently rebound each one to its fixture/action/request original above.
    require(len(evidence) == len(FIXTURES),
            "formal result does not attest the complete all-of fixture set")
    return {"profile": profile, "run": run, "fixtures": list(FIXTURES),
            "responses": inbound_ids}


def verify_batch(root, product, pins=None):
    if pins is None:
        require(product in ACCEPTED_SUITE_BY_PRODUCT, "Suite identity is not approved for this product")
        pins = ACCEPTED_SUITE_BY_PRODUCT[product]
    batch = read(root / "batch.json")
    require(batch == {"schema": "samlscope-ext01b-batch-v1", "product": product,
                      "profiles": list(PROFILES), "case": CASE,
                      "completed": batch.get("completed"), "verdict_adopted": False},
            "invalid EXT01.b batch manifest")
    require([value.get("profile") for value in batch["completed"]] == list(PROFILES),
            "four-profile campaign is incomplete")
    results = [verify_profile(root / profile, product, profile, pins) for profile in PROFILES]
    require([value.get("run") for value in batch["completed"]] == [value["run"] for value in results]
            and len({value["run"] for value in results}) == len(PROFILES),
            "profile Runs are not independently and exactly bound")
    return {"schema": "samlscope-ext01b-acceptance-v1", "product": product,
            "case": CASE, "observations": results, "count": len(results)}


def tamper_self_test(root, product, pins=None):
    if pins is None:
        require(product in ACCEPTED_SUITE_BY_PRODUCT, "Suite identity is not approved for this product")
        pins = ACCEPTED_SUITE_BY_PRODUCT[product]
    source = root / PROFILES[0]

    def rejected(name, mutate):
        with tempfile.TemporaryDirectory(prefix="samlscope-ext01b-tamper-") as temporary:
            folder = Path(temporary) / "fixture"
            shutil.copytree(source, folder)
            mutate(folder)
            try:
                verify_profile(folder, product, PROFILES[0], pins)
            except (ValueError, KeyError, FileNotFoundError, ET.ParseError, zipfile.BadZipFile):
                return name
            raise AssertionError("tamper was accepted: " + name)

    def response_original(folder):
        transcript = read(folder / "transcript.json")
        outbound = next(entry for entry in transcript
                        if entry.get("samlSummary", {}).get("scenario_case_id") == CASE)
        request = safe_xml(decoded_originals(folder)[outbound["id"]])
        response = next(entry for entry in transcript
                        if entry.get("samlSummary", {}).get("inResponseTo") == request.get("ID"))
        manifest = read(folder / "decoded-manifest.json")
        item = next(value for value in manifest if value["id"] == response["id"])
        path = folder / item["file"]
        raw = path.read_bytes()
        require(b"Success" in raw, "self-test response lacks Success")
        path.write_bytes(raw.replace(b"Success", b"Failure", 1))

    def placement(folder):
        transcript = read(folder / "transcript.json")
        entry = next(value for value in transcript
                     if value.get("samlSummary", {}).get("scenario_case_id") == CASE
                     and value.get("samlSummary", {}).get("fixture_id") == "unknown-extension")
        manifest = read(folder / "decoded-manifest.json")
        item = next(value for value in manifest if value["id"] == entry["id"])
        path = folder / item["file"]
        raw = path.read_bytes()
        require(b"protocol-extensions" in raw, "self-test request lacks placement marker")
        raw = raw.replace(b"protocol-extensions", b"protocol-extensionX", 1)
        require(len(raw) == entry["decodedSamlBytes"], "self-test mutation changed request length")
        path.write_bytes(raw)
        item["sha256"] = sha(raw)
        (folder / "decoded-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    def formal_result(folder):
        path = folder / EVALUATION / "result.json"
        value = read(path)
        case = find_case(value, CASE)
        case["outcome"] = "NOT_VERIFIED"
        case["verdict"] = "NOT_VERIFIED"
        path.write_text(json.dumps(value, indent=2) + "\n")

    def restoration(folder):
        path = folder / "restoration.json"
        value = read(path)
        value["restored"] = False
        path.write_text(json.dumps(value, indent=2) + "\n")

    def profile_binding(folder):
        path = folder / "plan.json"
        value = read(path)
        value["plan"]["plan"]["profile"] = "metadata_idp"
        path.write_text(json.dumps(value, indent=2) + "\n")

    return [rejected(name, mutation) for name, mutation in (
        ("response-original", response_original),
        ("approved-placement", placement),
        ("formal-result", formal_result),
        ("restoration", restoration),
        ("profile-run-binding", profile_binding),
    )]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--product", choices=tuple(PRODUCT), required=True)
    parser.add_argument("--tamper-self-test", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    result = verify_batch(root, args.product)
    if args.tamper_self_test:
        result["tamper_rejected"] = tamper_self_test(root, args.product)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
