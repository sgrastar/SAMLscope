#!/usr/bin/env python3
"""Replay native parser originals, install receipts, and verify four formal same-Run conclusions.

Every verification invokes the immutable deployed production reader and native parser again.
No product configuration, authentication, protocol submission, or outcome cache is used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import urllib.request

REPO = Path(__file__).resolve().parents[2]
SUITE = "samlscope-reference-suite"
BASE = "http://localhost:18080"
DESTINATION = "/data/extension-attribute-parser-evidence"
CASE = "IIP-EXT01-c-idp-01"
PROFILES = ("browser_sso_idp", "ecp_idp", "metadata_idp", "single_logout_idp")
HELPERS = ("VerifyExtensionAttributeParserEvidence", "ReadExtensionAttributeParserStoredConclusion")
HISTORY = REPO / "build/acceptance/reference-20260930/ext01c-keycloak-v157-r2"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def require(value, why):
    if not value:
        raise ValueError(why)


def command(args, timeout=90):
    return subprocess.run(list(map(str, args)), capture_output=True, check=True, timeout=timeout)


def save(path, value):
    require(not path.exists(), "Immutable original already exists")
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def api(path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(BASE + path, data=data, headers={} if data is None else {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.load(response)


def case(result):
    rows = [row for requirement in result["requirements"] for row in requirement["cases"] if row["id"] == CASE]
    require(len(rows) == 1, "Approved case missing or duplicated")
    return rows[0]


def historical_scope(root):
    from verify_ext01c_keycloak_acceptance import diagnose_affiliation
    original = diagnose_affiliation(HISTORY)
    observed = {row["profile"]: row for row in original["observations"]}
    for profile in PROFILES:
        folder = root / profile
        manifest = read(folder / "manifest.json")
        source = HISTORY / profile
        prefix = read(source / "metadata/transcript.json")
        require(observed[profile]["run"] == manifest["runId"] and observed[profile]["restored"]
                and read(folder / "transcript.json")[:len(prefix)] == prefix
                and (folder / "target-metadata.xml").read_bytes() == (source / "active/target-metadata.xml").read_bytes()
                and (root / "receipts" / (manifest["runId"] + ".extension-attribute-parser/input.xml")).read_bytes()
                    == (source / "metadata/foreign-attribute-affiliation/fixture.xml").read_bytes(),
                "Historical protocol, parser-input or restoration scope differs")
    return original


def archive(root, generation):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+", generation), "Unsafe evaluation generation")
    directory = root / ("reader-" + generation)
    directory.mkdir(exist_ok=False)
    command(["docker", "cp", SUITE + ":/opt/samlscope/lib", directory / "lib"])
    jars = sorted((directory / "lib").glob("*.jar"))
    require(jars and all(path.stat().st_nlink == 1 and not path.is_symlink() for path in jars), "Reader archive must have independent bytes")
    pins = {str(path.relative_to(directory)): sha(path.read_bytes()) for path in jars}
    classes = directory / "classes"
    classes.mkdir()
    sources = []
    for helper in HELPERS:
        source = directory / (helper + ".java")
        shutil.copyfile(REPO / "dev/reference-acceptance" / source.name, source)
        pins[source.name] = sha(source.read_bytes())
        sources.append(source)
    command(["javac", "--release", "21", "-sourcepath", "", "-cp", ":".join(map(str, jars)), "-d", classes, *sources])
    require(all(any(path.name.startswith(helper) for helper in HELPERS) for path in classes.rglob("*.class")), "Helper shadows production reader")
    pins.update({str(path.relative_to(directory)): sha(path.read_bytes()) for path in classes.rglob("*.class")})
    save(directory / "pins.json", dict(files=pins, generation=generation, productionReaderArchived=True,
                                      nativeParserReplayedEveryEvaluation=True, outcomeCaching=False))
    live_runtime(directory)
    return directory


def classpath(directory):
    pins = read(directory / "pins.json")
    actual = {str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file() and path != directory / "pins.json"}
    require(actual == set(pins["files"]), "Reader archive contains added or missing files")
    for name, digest in pins["files"].items():
        require(not (directory / name).is_symlink(), "Reader archive contains a symlink")
        require(sha((directory / name).read_bytes()) == digest, "Immutable reader/dependency bytes changed")
    return str(directory / "classes") + ":" + ":".join(map(str, sorted((directory / "lib").glob("*.jar"))))


def live_runtime(directory):
    jars = {Path(name).name: digest for name, digest in read(directory / "pins.json")["files"].items() if name.startswith("lib/")}
    lines = command(["docker", "exec", SUITE, "sha256sum", *["/opt/samlscope/lib/" + name for name in sorted(jars)]]).stdout.decode().splitlines()
    actual = {Path(line.split()[1]).name: line.split()[0] for line in lines}
    require(actual == jars, "Deployed Suite runtime differs from immutable replay libraries")


def replay(root, directory, profile, output):
    require(not output.exists(), "Replay output must be fresh")
    folder = root / profile
    command(["java", "-cp", classpath(directory), "com.samlscope.runner.cases.VerifyExtensionAttributeParserEvidence",
             folder, root / "receipts", output], timeout=180)
    value = read(output)
    require(value["profile"] == profile and value["outcome"]["outcome"] == "SATISFIED"
            and len(value["calibrationMutationsRejected"]) == 14 and value["controlsAreProductObservations"] is False,
            "Full native/matrix/control replay incomplete")
    return value


def stored(directory, run):
    live_runtime(directory)
    remote = "/tmp/ext-parser-readback-" + secrets.token_hex(6)
    command(["docker", "exec", SUITE, "mkdir", remote])
    try:
        command(["docker", "cp", directory / "classes", SUITE + ":" + remote + "/classes"])
        raw = command(["docker", "exec", SUITE, "java", "-cp", remote + "/classes:/opt/samlscope/lib/*",
                       "com.samlscope.runner.cases.ReadExtensionAttributeParserStoredConclusion", run]).stdout
    finally:
        command(["docker", "exec", "-u", "0", SUITE, "rm", "-rf", "--", remote])
    value = json.loads(raw)
    require(value["runId"] == run and value["caseId"] == CASE, "Stored readback differs")
    return value


def install(root, generation):
    historical_scope(root)
    directory = root / ("reader-" + generation)
    if directory.exists():
        classpath(directory)
        live_runtime(directory)
    else:
        directory = archive(root, generation)
    evaluation = root / ("evaluation-" + generation)
    evaluation.mkdir(exist_ok=True)
    completed = []
    for profile in PROFILES:
        folder = root / profile
        run = read(folder / "manifest.json")["runId"]
        require(re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", run), "Unsafe original Run")
        out = evaluation / profile
        if (out / "stored-after.json").exists():
            proof = replay(root, directory, profile, out / ("resume-replay-" + secrets.token_hex(8) + ".json"))
            require(proof == read(out / "reader-replay.json"), "Resumed native replay changed")
            row = case(read(out / "result.json"))
            require((row["outcome"], row["verdict"], row["reason_code"], row["mode"], row["attested"], row["evidence_class"])
                    == ("SATISFIED", "PASS", "browser_fixture_satisfied", "BROWSER", False, "OPERATOR_ASSISTED")
                    and row["evidence"] == proof["outcome"]["evidence"], "Resumed formal outcome/provenance differs")
            completed.append(dict(profile=profile, runId=run, caseId=CASE, formalOutcome="SATISFIED", formalVerdict="PASS"))
            if not (out / "completed.json").exists():
                save(out / "completed.json", completed[-1])
            print(profile + " original formal conclusion resumed without another POST", flush=True)
            continue
        out.mkdir(exist_ok=False)
        proof = replay(root, directory, profile, out / "reader-replay.json")
        expected_plan = read(folder / "plan.json")
        require(api("/api/runs/" + run)["planId"] == expected_plan["id"]
                and api("/api/plans/" + expected_plan["id"])["plan"] == expected_plan
                and expected_plan["profile"] == profile, "Actual source Run/profile binding changed")
        before = api("/api/runs/" + run + "/transcript")
        require(before == read(folder / "transcript.json"), "Actual history changed after qualification")
        result_before = api("/api/runs/" + run + "/result.json")
        require(case(result_before)["outcome"] == "NOT_VERIFIED", "Receipt installation requires the original incomplete outcome")
        save(out / "result-before.json", result_before)
        save(out / "stored-before.json", stored(directory, run))
        save(out / "transcript-before.json", before)
        receipt_path = root / "receipts" / (run + ".extension-attribute-parser.json")
        receipt = read(receipt_path)
        source = root / "receipts" / (run + ".extension-attribute-parser")
        for name, digest in receipt["files"].items():
            require(re.fullmatch(r"[A-Za-z0-9_.-]+", name) and sha((source / name).read_bytes()) == digest,
                    "Bound parser original differs")
        command(["docker", "exec", SUITE, "test", "!", "-e", DESTINATION + "/" + receipt_path.name])
        command(["docker", "exec", "-u", "0", SUITE, "mkdir", "-p", DESTINATION])
        command(["docker", "cp", source, SUITE + ":" + DESTINATION + "/" + source.name])
        command(["docker", "cp", receipt_path, SUITE + ":" + DESTINATION + "/" + receipt_path.name])
        uid = command(["docker", "exec", SUITE, "id", "-u"]).stdout.decode().strip()
        command(["docker", "exec", "-u", "0", SUITE, "chown", "-R", uid + ":" + uid,
                 DESTINATION + "/" + source.name, DESTINATION + "/" + receipt_path.name])
        require(command(["docker", "exec", SUITE, "cat", DESTINATION + "/" + receipt_path.name]).stdout == receipt_path.read_bytes(), "Installed receipt changed")
        for name, digest in receipt["files"].items():
            actual = command(["docker", "exec", SUITE, "sha256sum", DESTINATION + "/" + source.name + "/" + name]).stdout.decode().split()[0]
            require(actual == digest, "Installed original changed")
        save(out / "receipt-readback.json", dict(runId=run, sha256=sha(receipt_path.read_bytes()), files=receipt["files"], allReadBack=True))
        live_runtime(directory)
        save(out / "evaluate.json", api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
        result = api("/api/runs/" + run + "/result.json")
        after = api("/api/runs/" + run + "/transcript")
        require(after == before, "Formal evidence evaluation changed original history")
        save(out / "transcript.json", after)
        save(out / "result.json", result)
        save(out / "stored-after.json", stored(directory, run))
        row = case(result)
        require((row["outcome"], row["verdict"], row["reason_code"], row["mode"], row["attested"], row["evidence_class"])
                == ("SATISFIED", "PASS", "browser_fixture_satisfied", "BROWSER", False, "OPERATOR_ASSISTED")
                and row["evidence"] == proof["outcome"]["evidence"], "Formal outcome/provenance differs")
        completed.append(dict(profile=profile, runId=run, caseId=CASE, formalOutcome="SATISFIED", formalVerdict="PASS"))
        save(out / "completed.json", completed[-1])
        print(profile + " formal parser observation verified", flush=True)
    save(root / "adopted.json", dict(generation=generation, evaluation=evaluation.name, reader=directory.name, observations=completed,
                                    targetConfigurationWrites=0, protocolSubmissions=0, humanOperations=0, outcomeCaching=False))
    verify_adoption(root, live=True)


def verify_adoption(root, live=False, formal=True):
    root = Path(root).resolve()
    historical_scope(root)
    adopted = read(root / "adopted.json")
    directory = root / adopted["reader"]
    classpath(directory)
    selected = {}
    for profile in PROFILES:
        evaluation = root / adopted["evaluation"] / profile
        proof_path = evaluation / ("replay-" + secrets.token_hex(8) + ".json")
        proof = replay(root, directory, profile, proof_path)
        original = read(evaluation / "reader-replay.json")
        require(proof == original, "Full original/control replay changed")
        if not formal:
            continue
        result = read(evaluation / "result.json")
        row = case(result)
        run = read(root / profile / "manifest.json")["runId"]
        before, after = read(evaluation / "stored-before.json"), read(evaluation / "stored-after.json")
        require(after["status"] == "FINISHED" and after["revision"] == before["revision"] + 1
                and before["outboxCount"] == after["outboxCount"], "Formal reevaluation changed action count/revision")
        outcome = dict(after["outcome"])
        details = dict(outcome["details"])
        previous = details.pop("previous_recorded_evidence_result", None)
        require(previous is not None and previous["revision"] == before["revision"]
                and previous["outcome"] == before["outcome"]["outcome"] == "NOT_VERIFIED"
                and previous["updated_at"] == before["updatedAtIso"]
                and {key: previous[key] for key in ("outcome", "not_verified_reason", "reason_code", "reason_message_key", "evidence", "details")}
                == dict(outcome=before["outcome"]["outcome"], not_verified_reason=before["outcome"]["notVerifiedReason"],
                        reason_code=before["outcome"]["reasonCode"], reason_message_key=before["outcome"]["reasonMessageKey"],
                        evidence=before["outcome"]["evidence"], details=before["outcome"]["details"]), "Original prior-result audit missing")
        outcome["details"] = details
        require(outcome == proof["outcome"] and row["evidence"] == outcome["evidence"] and row["verdict"] == after["verdict"] == "PASS",
                "Stored reader/central evaluator differs")
        require((row["outcome"], row["reason_code"], row["mode"], row["attested"], row["evidence_class"])
                == ("SATISFIED", "browser_fixture_satisfied", "BROWSER", False, "OPERATOR_ASSISTED"), "Formal provenance changed")
        require(result["run"]["id"] == run and result["target"]["metadata_digest"] == "sha256:" + sha((root / profile / "target-metadata.xml").read_bytes())
                and result["profile"]["id"] == profile.replace("_", "-"), "Formal Run/target/profile differs")
        require(read(evaluation / "transcript-before.json") == read(evaluation / "transcript.json") == read(root / profile / "transcript.json"), "Formal original history differs")
        if live:
            live_runtime(directory)
            require(api("/api/runs/" + run + "/transcript") == read(root / profile / "transcript.json"), "Live original history changed")
            require(case(api("/api/runs/" + run + "/result.json")) == row, "Live formal case differs from archived conclusion")
        selected[profile] = (evaluation / "result.json", {CASE: row})
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("install", "verify"))
    parser.add_argument("--folder", required=True, type=Path)
    parser.add_argument("--generation")
    args = parser.parse_args()
    if args.mode == "install":
        if not args.generation:
            parser.error("--generation is required for one immutable deployment")
        install(args.folder.resolve(), args.generation)
    else:
        verify_adoption(args.folder, live=True)


if __name__ == "__main__":
    main()
