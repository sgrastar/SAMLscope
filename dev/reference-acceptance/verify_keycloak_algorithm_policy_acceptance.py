#!/usr/bin/env python3
"""Verify native Keycloak algorithm prevention and its formal browser adoption.

The production Reader is rerun with the Suite's own private key in its data
volume. Native configuration 400 originals, allowed protocol controls, set
changes and exact restoration are all required. No-response is never proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
from attribute_policy_capability_absence import product_token

FOLDER = "keycloak-alg08-native-policy-v163-r4"
SUITE = "samlscope-reference-suite"
KEYCLOAK = "samlscope-reference-keycloak"
IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
CASES = ("IIP-ALG08-a-idp-01", "IIP-ALG08-b-idp-01")
CLASSES = ("com/samlscope/runner/cases/AlgorithmPreventionEvidenceFile.class",
           "com/samlscope/runner/cases/KeycloakAlgorithmPreventionEvidenceFile.class",
           "com/samlscope/runner/cases/AlgorithmPreventionConfigurationTestCase.class")


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def case_rows(value):
    return {case["id"]: case for requirement in value["requirements"] for case in requirement["cases"]}


def replay(folder, runtime_jar=None, helper_name="VerifyKeycloakAlgorithmPreventionEvidence"):
    """Compile only a verifier; execute the Reader actually installed in the Suite."""
    with tempfile.TemporaryDirectory(prefix="samlscope-keycloak-alg08-") as temp:
        temp_path = Path(temp)
        if runtime_jar is None:
            jar = temp_path / "runner.jar"
            subprocess.run(["docker", "cp", SUITE + ":/opt/samlscope/lib/runner-0.1.0.jar", str(jar)],
                           check=True, capture_output=True)
        else:
            jar = runtime_jar
        pins = load(folder / "runtime/pins.json")
        with zipfile.ZipFile(jar) as archive:
            require(all(sha(archive.read(name)) == pins["classes"][name] for name in CLASSES),
                    "live production Reader class hashes differ")
        require(helper_name in {"VerifyKeycloakAlgorithmPreventionEvidence", "VerifyKeycloakEcpAlgorithmPreventionEvidence"},
                "unknown production replay helper")
        helper = REPO / ("dev/reference-acceptance/" + helper_name + ".java")
        classpath_file = Path("/private/tmp/samlscope-runner-runtime-classpath.txt")
        require(classpath_file.is_file(), "runtime dependency classpath has not been prepared")
        subprocess.run(["javac", "-cp", str(jar) + ":" + classpath_file.read_text().strip(),
                        "-d", str(temp_path / "classes"), str(helper)], check=True, capture_output=True)
        identity = "alg08-" + sha(folder.as_posix().encode())[:20]
        remote = "/tmp/" + identity
        subprocess.run(["docker", "exec", "--user", "0", SUITE, "rm", "-rf", remote], check=True, capture_output=True)
        subprocess.run(["docker", "exec", SUITE, "mkdir", "-p", remote], check=True, capture_output=True)
        try:
            subprocess.run(["docker", "cp", str(temp_path / "classes"), SUITE + ":" + remote + "/classes"], check=True, capture_output=True)
            subprocess.run(["docker", "cp", str(jar), SUITE + ":" + remote + "/runner.jar"], check=True, capture_output=True)
            subprocess.run(["docker", "cp", str(folder), SUITE + ":" + remote + "/campaign"], check=True, capture_output=True)
            subprocess.run(["docker", "exec", SUITE, "rm", "-f", remote + "/replay.json"], check=True, capture_output=True)
            subprocess.run(["docker", "exec", SUITE, "java", "-cp", remote + "/runner.jar:" + remote + "/classes:/opt/samlscope/lib/*",
                "com.samlscope.runner.cases." + helper_name, remote + "/campaign", "/data", remote + "/replay.json"],
                check=True, capture_output=True, timeout=90)
            subprocess.run(["docker", "cp", SUITE + ":" + remote + "/replay.json", str(temp_path / "replay.json")], check=True, capture_output=True)
            return load(temp_path / "replay.json")
        finally:
            subprocess.run(["docker", "exec", "--user", "0", SUITE, "rm", "-rf", remote], check=True, capture_output=True)


def verify(folder, formal=True, live=True, profile="browser_sso_idp",
           helper_name="VerifyKeycloakAlgorithmPreventionEvidence"):
    receipt = load(folder / "algorithm-prevention-receipt.json")
    operations = load(folder / "operations.json")
    run = receipt["runId"]
    require(re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", run) and operations["run"] == run
            and receipt["profile"] == operations["profile"] == profile
            and receipt["schema"] == "samlscope-keycloak-algorithm-prevention-v1",
            "campaign identity differs")
    require(operations["restored"] is True and operations["failures"] == []
            and operations["campaignErrors"] == [] and operations["humanOperations"] == 0
            and operations["productRestarts"] == 0, "native restoration or campaign failed")
    require((folder / "profiles-original.json").read_bytes() == (folder / "profiles-restored.json").read_bytes()
            and (folder / "policies-original.json").read_bytes() == (folder / "policies-restored.json").read_bytes()
            and load(folder / "client-after.json") == [], "original native policy/profile state differs")
    rows = load(folder / "transcript.json")
    transcript = {row["id"]: row for row in rows}
    require(len(rows) == len(transcript) and all(row["runId"] == run for row in rows), "transcript identity ambiguous")
    originals = {}
    for item in load(folder / "decoded-manifest.json"):
        path = (folder / item["file"]).resolve()
        require(path.parent == (folder / "decoded").resolve() and item["id"] not in originals,
                "unsafe original path/duplicate")
        raw = path.read_bytes()
        require(sha(raw) == item["sha256"], "wire/native original hash differs")
        originals[item["id"]] = raw
    writes = [row for row in operations["adminOperations"] if row["method"] in {"POST", "PUT", "DELETE"}]
    require(receipt["operationCounts"] == dict(productConfigurationWrites=len(writes),
            protocolOperations=7, productRestarts=0, humanOperations=0), "operation count differs")
    for row in operations["adminOperations"]:
        descriptor = row.get("original")
        if descriptor is None:
            require(row["method"] == "GET" and row["path"] in {"/client-policies/profiles", "/client-policies/policies"},
                    "mutation native original missing")
            continue
        raw = originals[descriptor["reference"]]
        require(sha(raw) == descriptor["sha256"], "native request/response original hash differs")
        native = json.loads(raw)
        require(native["runId"] == run and native["campaignId"] == "keycloak-algorithm-prevention"
                and native["method"] == row["method"] and native["path"] == row["path"]
                and native["httpStatus"] == row["status"], "native request/response binding differs")
    check = load(folder / "native-reader-replay.json")
    pins = load(folder / "runtime/pins.json")
    require(pins["helperSha256"] == sha((REPO / ("dev/reference-acceptance/" + helper_name + ".java")).read_bytes())
            and pins["runnerJarSha256"] == sha((folder / "runtime/runner.jar").read_bytes()), "immutable runtime/helper pins differ")
    with zipfile.ZipFile(folder / "runtime/runner.jar") as jar:
        require(set(pins["classes"]) == set(CLASSES)
                and all(sha(jar.read(name)) == pins["classes"][name] for name in CLASSES), "immutable Reader class hashes differ")
    require(replay(folder, runtime_jar=folder / "runtime/runner.jar", helper_name=helper_name) == check,
            "archived production Reader regeneration differs")
    require(check["runId"] == run and check["result"] == "SATISFIED" and check["privateKeyExported"] is False
            and check["plaintextPersisted"] is False and len(check["checks"]) == (22 if profile == "ecp_idp" else 20)
            and check["checks"]["complete-native-campaign"] == "SATISFIED"
            and all(value == "NOT_VERIFIED" for name, value in check["checks"].items() if name != "complete-native-campaign"),
            "production replay/control inventory differs")
    if live:
        inspected = json.loads(subprocess.check_output(["docker", "inspect", KEYCLOAK]))[0]
        require(inspected["Image"] == IMAGE and inspected["State"]["Running"] is True, "native product runtime differs")
        token = product_token()
        for kind in ("profiles", "policies"):
            request = urllib.request.Request("http://localhost:18180/admin/realms/samlscope/client-policies/" + kind,
                headers={"Authorization": "Bearer " + token})
            with urllib.request.urlopen(request, timeout=30) as response:
                current = json.load(response)
            require(current == load(folder / (kind + "-original.json")), "live native state was not restored")
        lookup = urllib.request.Request("http://localhost:18180/admin/realms/samlscope/clients?clientId="
            + urllib.parse.quote("http://localhost:18080/p/" + operations["plan"], safe=""),
            headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(lookup, timeout=30) as response:
            require(json.load(response) == [], "temporary native client remains")
        require(replay(folder, helper_name=helper_name) == check, "production reader regeneration differs")
    if formal:
        result_path = folder / "result-adopted.json"
        result = load(result_path)
        indexed = case_rows(result)
        require(result["run"]["id"] == run and result["profile"]["id"]
                == ("ecp-idp" if profile == "ecp_idp" else "browser-sso-idp"), "formal result scope differs")
        receipt_sha = sha((folder / "algorithm-prevention-receipt.json").read_bytes())
        for name in CASES:
            row = indexed[name]
            require(row["verdict"] == "PASS" and row["reason_code"] == "configuration.algorithm-prevention.observed"
                    and row["attested"] is False and len(row["evidence"]) == check["evidenceCount"]
                    and all(ref["kind"] == "transcript" and ref["reference"].removeprefix("transcript:") in transcript for ref in row["evidence"]),
                    name + " formal verdict/evidence differs")
        require(load(folder / "transcript-after-adoption.json") == rows, "adoption changed transcript")
        require(sha((folder / "installed-receipt-readback.json").read_bytes()) == receipt_sha, "installed receipt differs")
        return result_path, {name: indexed[name] for name in CASES}
    return {"runId": run, "verifiedNativePrevention": True, "verdictAdopted": False,
            "operationCounts": receipt["operationCounts"], "replayChecks": len(check["checks"])}


def verify_adoption(root, live=True):
    return verify(Path(root) / FOLDER, live=live)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--diagnostic", action="store_true")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    result = verify(args.folder.resolve(), formal=not args.diagnostic, live=not args.offline)
    if isinstance(result, tuple):
        print(result[0], "native prevention adopted", len(result[1]))
    else:
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
