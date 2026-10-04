#!/usr/bin/env python3
"""Adopt only MD02.a proven by original Shibboleth recurring HTTP refresh evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from verify_metadata_refresh_acceptance import verify_signatures
from verify_terminal_http_acceptance import _verify_target_runtime, _verify_suite_runtime, find_case, parsed_time
from acceptance_dependency_discovery import runtime_classpath

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/shibboleth"))
from install_metadata_refresh_receipt import FILES, HASH_FIELDS

CASE = "IIP-MD02-a-idp-01"
FOLDER = "shibboleth-native-refresh-v164-r1"
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
# Pinned after the coordinated runtime deployment and formal evidence re-evaluation.
ACCEPTED_SUITE = {
    "image_id": "sha256:85f3309f6e22c7ed7df485487da8e877b5240a0dcf6d36d6cda5db8e7bb19541",
    "jars": {
        "core": "1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe",
        "runner": "3b2b18af36288fab951aca48e9096ae563a1ec3f173962142ea444b04861d3b1",
        "saml": "49c87837124dc6ebcf3b94e9221df7a08cf577f37b2bb98b9744c3085a019d97",
    },
}


def read(path):
    return json.loads(Path(path).read_text())


def require(value, detail):
    if not value:
        raise ValueError(detail)


def decoded_originals(folder, transcript):
    entries = {entry["id"]: entry for entry in transcript}
    originals = {}
    for row in read(folder / "decoded-manifest.json"):
        path = (folder / row["file"]).resolve()
        require(path.parent == (folder / "decoded").resolve(), "Decoded original escaped folder")
        raw = path.read_bytes()
        entry = entries.get(row["id"])
        require(entry and row["id"] not in originals and row["sha256"] == SHA(raw)
                and len(raw) == entry["decodedSamlBytes"]
                and entry["decodedSamlRef"] == "transcripts/" + entry["runId"] + "/" + entry["id"] + ".saml.xml",
                "Decoded original hash/size/source differs")
        originals[row["id"]] = raw
    require(set(originals) == {entry["id"] for entry in transcript if entry.get("decodedSamlRef")},
            "Decoded original manifest incomplete")
    return originals


def replay(folder, retain=False):
    helper = Path(__file__).with_name("VerifyShibbolethMetadataRefreshEvidence.java")
    runtime = read(folder / "suite-runtime-terminal-http.json")
    store = read(folder / "store-runtime.json")
    jars = [folder / runtime["jars"][name]["file"] for name in ("runner", "core", "saml")]
    jars.append(folder / store["file"])
    require(store["path"] == "/opt/samlscope/lib/store-0.1.0.jar"
            and store["sha256"] == SHA(jars[-1].read_bytes()), "Store runtime original changed")
    with tempfile.TemporaryDirectory(prefix="samlscope-shib-refresh-verifier-") as temporary:
        temporary = Path(temporary)
        dependency_classpath = runtime_classpath(REPO)
        require(dependency_classpath, "Runtime dependency classpath unavailable")
        classpath = ":".join(str(jar) for jar in jars) + ":" + dependency_classpath
        classes = temporary / "classes"
        classes.mkdir()
        subprocess.run(["javac", "-cp", classpath, "-d", str(classes), str(helper)],
                       cwd=REPO, check=True, capture_output=True)
        report = temporary / "replay.json"
        subprocess.run(["java", "-cp", str(classes) + ":" + classpath,
            "com.samlscope.runner.cases.VerifyShibbolethMetadataRefreshEvidence",
            str(folder), str(report)], cwd=REPO, check=True, capture_output=True)
        regenerated = report.read_bytes()
    retained = folder / "production-replay-v2.json"
    if retain:
        require(not retained.exists(), "Refusing to replace retained production replay")
        retained.write_bytes(regenerated)
    else:
        require(retained.read_bytes() == regenerated, "Production-reader replay differs from retained evidence")
    result = json.loads(regenerated)
    require(result["productionOutcome"] == "SATISFIED" and len(result["tamperControls"]) == 23
            and set(result["tamperControls"].values()) == {"NOT_VERIFIED"}, "Tamper controls incomplete")
    return result


def verify(root):
    folder = Path(root) / FOLDER
    manifest = read(folder / "metadata-refresh-manifest.json")
    run = read(folder / "created.json")["run"]["id"]
    require(manifest["schema"] == "samlscope-native-metadata-refresh-v1"
            and manifest["adapter"] == "shibboleth-native-http-refresh-v1"
            and manifest["runId"] == run, "Wrong refresh receipt")
    for name, field in HASH_FIELDS.items():
        require(manifest[field] == SHA((folder / name).read_bytes()), "Original changed: " + name)
    transcript = read(folder / "transcript.json")
    entries = {entry["id"]: entry for entry in transcript}
    require(len(entries) == len(transcript) and all(entry["runId"] == run for entry in transcript),
            "Transcript Run/identity mismatch")
    originals = decoded_originals(folder, transcript)
    for phase, name in (("phaseA", "metadata-a.xml"), ("phaseB", "metadata-b.xml")):
        require(originals[manifest[phase]["preparedReference"]] == (folder / name).read_bytes(),
                "Native served metadata original differs")
    verify_signatures(folder, manifest)
    _verify_target_runtime(folder, "shibboleth", min(float(entry["timestamp"]) for entry in transcript
                                                  if entry["id"] == manifest["phaseA"]["fetchReference"]))
    counts = read(folder / "operation-counts.json")
    require((counts["product_configuration_writes"], counts["restoration_writes"], counts["product_restarts"],
             counts["product_reloads"], counts["human_operations"], counts["protocol_operations"], counts["restored"])
            == (4, 2, 2, 0, 0, 3, True), "Operation counts differ")
    require(counts["operations"] == read(folder / "operations.json"), "Operation originals differ")
    for kind in ("providers", "audit"):
        require((folder / f"original-{kind}.xml").read_bytes() == (folder / f"final-{kind}.xml").read_bytes(),
                "Original product configuration was not restored")
    installed = read(folder / "metadata-refresh-receipt-install.json")
    require(installed["runId"] == run and installed["target"]
            == "/data/metadata-rejection-evidence/" + run + ".refresh"
            and installed["readBackSha256"] == [*[SHA((folder / name).read_bytes()) for name in FILES],
                                                 SHA((folder / "metadata-refresh-manifest.json").read_bytes())],
            "Receipt placement read-back differs")
    evaluation = folder / "evaluation-terminal-http-v1"
    require(read(evaluation / "transcript-before.json") == read(evaluation / "transcript.json") == transcript,
            "Formal re-evaluation changed the transcript")
    formal = read(folder / "formal-evaluation.json")
    require(formal["runId"] == run and formal["transcriptUnchanged"] is True
            and parsed_time(formal["startedAt"]) < parsed_time(formal["finishedAt"]),
            "Formal evaluation record is incomplete")
    # The updated reader re-evaluates an older immutable Run. Its runtime must predate the formal
    # evaluation; it is not falsely asserted to have produced the original protocol transcript.
    _verify_suite_runtime(folder, run, parsed_time(formal["startedAt"]), ACCEPTED_SUITE)
    with zipfile.ZipFile(folder / read(folder / "suite-runtime-terminal-http.json")["jars"]["runner"]["file"]) as archive:
        require(b"shibboleth-native-http-refresh-v1" in archive.read(
            "com/samlscope/runner/cases/ShibbolethMetadataRefreshEvidenceFile.class"), "Native refresh reader missing")
    result_path = evaluation / "result.json"
    result = read(result_path)
    require(result["run"]["id"] == run, "Formal result belongs to another Run")
    case = find_case(result, CASE)
    require((case["outcome"], case["verdict"], case["reason_code"], case["attested"])
            == ("SATISFIED", "PASS", "metadata.native-refresh-observed", False)
            and formal["case"] == case, "Formal refresh conclusion differs")
    references = {entry["reference"] for entry in case["evidence"]}
    required = {"transcript:" + manifest[phase][field] for phase in ("phaseA", "phaseB")
                for field in ("fetchReference", "preparedReference", "requestReference", "responseReference")}
    required.add("transcript:" + manifest["phaseB"]["controlRequestReference"])
    required.add(run + ".refresh/manifest.json")
    require(references == required, "Formal evidence references differ")
    replayed = replay(folder)
    require(replayed["runId"] == run, "Production replay belongs to another Run")
    return result_path, {CASE: case}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--retain-replay", action="store_true")
    args = parser.parse_args()
    if args.retain_replay:
        print(replay(args.root / FOLDER, retain=True))
    else:
        path, cases = verify(args.root)
        print(path, {name: case["verdict"] for name, case in cases.items()})
