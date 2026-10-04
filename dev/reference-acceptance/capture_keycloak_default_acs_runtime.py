#!/usr/bin/env python3
"""Capture immutable Keycloak and Suite originals for a default-ACS campaign.

The capture writes only into an empty named evidence slot.  It records the actual
container inspection and `kc.sh --version` output rather than trusting labels in
the campaign driver.  The verifier replays those originals and rejects a target
that changed between the two captures.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

from capture_run_originals import capture


BASE = "http://localhost:18080"
TARGET = "samlscope-reference-keycloak"
SUITE = "samlscope-reference-suite"
RUNNER_JAR = "/opt/samlscope/lib/runner-0.1.0.jar"
SAML_JAR = "/opt/samlscope/lib/saml-0.1.0.jar"


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def output(command):
    return subprocess.check_output(command, timeout=60)


def read_run(folder):
    return json.loads((folder / "created.json").read_text())["run"]


def capture_target(folder, phase):
    if phase not in {"start", "end"}:
        raise ValueError("target phase must be start or end")
    inspect_path = folder / f"target-container-inspect-{phase}.json"
    version_path = folder / f"target-version-runtime-{phase}.txt"
    summary_path = folder / f"target-runtime-{phase}.json"
    if any(path.exists() for path in (inspect_path, version_path, summary_path)):
        raise RuntimeError(f"Refusing to overwrite target {phase} originals")
    inspect = output(["docker", "inspect", TARGET])
    version = output(["docker", "exec", TARGET, "/opt/keycloak/bin/kc.sh", "--version"])
    data = json.loads(inspect)
    if not isinstance(data, list) or len(data) != 1:
        raise RuntimeError("target docker inspect did not return one container")
    item = data[0]
    ports = item.get("NetworkSettings", {}).get("Ports", {}).get("8080/tcp") or []
    binding = {
        "container_name": item["Name"].removeprefix("/"),
        "container_id": item["Id"],
        "image_id": item["Image"],
        "container_started_at": item["State"]["StartedAt"],
        "running_at_capture": item["State"]["Running"],
        "host_port": 18180,
        "host_port_bound": any(row.get("HostIp") == "127.0.0.1"
                                 and row.get("HostPort") == "18180" for row in ports),
    }
    inspect_path.write_bytes(inspect)
    version_path.write_bytes(version)
    summary_path.write_text(json.dumps({
        "binding": binding,
        "docker_inspect_sha256": sha256(inspect),
        "runtime_version": {
            "file": version_path.name,
            "sha256": sha256(version),
            "value": version.decode().strip(),
        },
    }, ensure_ascii=False, indent=2) + "\n")


def api(path, body=None):
    payload = None if body is None else json.dumps(body).encode()
    headers = {} if payload is None else {"Content-Type": "application/json"}
    request = urllib.request.Request(BASE + path, data=payload, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


def capture_suite(folder):
    runtime_path = folder / "suite-runtime.json"
    saml_runtime_path = folder / "suite-saml-runtime.json"
    evaluation = folder / "evaluation-v139"
    if runtime_path.exists() or saml_runtime_path.exists() or evaluation.exists():
        raise RuntimeError("Refusing to overwrite Suite runtime evidence")
    run = read_run(folder)["id"]
    transcript = json.loads((folder / "transcript.json").read_text())
    manifest = capture(folder, run, transcript)
    target_metadata = (folder / "target-metadata.xml").read_bytes()
    (folder / "original-capture.json").write_text(json.dumps({
        "run": run,
        "originals": len(manifest),
        "target_metadata_sha256": sha256(target_metadata),
    }, ensure_ascii=False, indent=2) + "\n")

    inspect = output(["docker", "inspect", SUITE])
    inspected = json.loads(inspect)[0]
    jar = folder / "suite-runner-0.1.0.jar"
    subprocess.run(["docker", "cp", f"{SUITE}:{RUNNER_JAR}", str(jar)], check=True, timeout=60)
    saml_jar = folder / "suite-saml-0.1.0.jar"
    subprocess.run(["docker", "cp", f"{SUITE}:{SAML_JAR}", str(saml_jar)], check=True, timeout=60)
    runtime_path.write_text(json.dumps({
        "run": run,
        "container": {
            "name": inspected["Name"].removeprefix("/"),
            "id": inspected["Id"],
            "image": inspected["Image"],
            "started_at": inspected["State"]["StartedAt"],
        },
        "runner_jar": {"path": RUNNER_JAR, "sha256": sha256(jar.read_bytes())},
        "docker_inspect_sha256": sha256(inspect),
    }, ensure_ascii=False, indent=2) + "\n")
    (folder / "suite-container-inspect.json").write_bytes(inspect)
    saml_runtime_path.write_text(json.dumps({
        "path": SAML_JAR,
        "sha256": sha256(saml_jar.read_bytes()),
    }, ensure_ascii=False, indent=2) + "\n")

    evaluation.mkdir()
    before = api(f"/api/runs/{run}/transcript")
    evaluation_result = api(f"/api/runs/{run}/protocol-evidence/evaluate", {})
    after = api(f"/api/runs/{run}/transcript")
    if {entry["id"]: entry for entry in before} != {entry["id"]: entry for entry in after}:
        raise RuntimeError("formal re-evaluation changed the transcript")
    result = api(f"/api/runs/{run}/result.json")
    for name, value in {
        "transcript-before.json": before,
        "evaluation.json": evaluation_result,
        "transcript.json": after,
        "result.json": result,
    }.items():
        (evaluation / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("action", choices=("target-start", "target-end", "suite"))
    args = parser.parse_args()
    folder = args.folder.resolve()
    if args.action == "suite":
        capture_suite(folder)
    else:
        capture_target(folder, args.action.removeprefix("target-"))


if __name__ == "__main__":
    main()
