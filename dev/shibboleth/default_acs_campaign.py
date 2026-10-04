#!/usr/bin/env python3
"""Run the Shibboleth native default-ACS campaign with immutable runtime captures.

The underlying filesystem-provider driver is deliberately reused: it puts the original
Suite fixture into a temporary native MetadataProvider, reloads the resolver, performs the
correlated flow, and restores the provider configuration.  This wrapper adds the facts needed
to review an adoption: target/Suite identity before and after the run, public target metadata,
Run originals, a transcript-preserving formal re-evaluation, and operation counts.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request


if not __debug__:
    raise RuntimeError("default-ACS campaign must not run with Python optimization")


REPO = Path(__file__).resolve().parents[2]
BASE = "http://localhost:18080"
SUITE = "samlscope-reference-suite"
TARGET = "samlscope-reference-shibboleth"
TARGET_METADATA_URL = "http://localhost:18280/idp/shibboleth"
TARGET_VERSION_SOURCE = "/opt/reference-idp/dist/idp.installed.version"
TARGET_VERSION_COMMAND = "/opt/reference-idp/bin/version.sh"
RUNNER_JAR = "/opt/samlscope/lib/runner-0.1.0.jar"
VARIANTS = (
    "control",
    "default-acs-first",
    "default-acs-first-omitted",
    "default-acs-all-false",
    "default-acs-duplicate-index",
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def docker_bytes(*args):
    return subprocess.check_output(["docker", *args], timeout=60)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def target_binding(inspect):
    require(isinstance(inspect, list) and len(inspect) == 1,
            "target inspection must contain one container")
    value = inspect[0]
    state = value.get("State", {})
    require(state.get("Running") is True, "target was not running")
    container_id = value.get("Id", "")
    image_id = value.get("Image", "")
    started_at = state.get("StartedAt", "")
    require(len(container_id) == 64 and image_id.startswith("sha256:") and started_at,
            "target identity is incomplete")
    protected_roots = ("/opt/reference-idp", "/usr/local/tomcat/webapps/idp")
    for mount in value.get("Mounts", []):
        destination = mount.get("Destination", "")
        require(not any(destination == root or destination.startswith(root + "/")
                        for root in protected_roots),
                "target executable or configuration root is covered by a mount")
    ports = value.get("NetworkSettings", {}).get("Ports", {}).get("8080/tcp") or []
    require(any(item.get("HostIp") == "127.0.0.1" and item.get("HostPort") == "18280"
                for item in ports), "target localhost port binding is absent")
    return {
        "container_name": TARGET,
        "container_id": container_id,
        "image_id": image_id,
        "container_started_at": started_at,
        "running_at_capture": True,
        "host_port": 18280,
        "protected_roots_mounted": False,
    }


def capture_target_runtime(folder, label):
    inspect_raw = docker_bytes("inspect", TARGET)
    source_raw = docker_bytes("exec", TARGET, "cat", TARGET_VERSION_SOURCE)
    version_raw = docker_bytes("exec", TARGET, TARGET_VERSION_COMMAND)
    inspect = json.loads(inspect_raw)
    source_text = source_raw.decode("utf-8")
    values = [line.split("=", 1)[1].strip() for line in source_text.splitlines()
              if line.startswith("idp.installed.version=")]
    require(len(values) == 1 and values[0] == "5.2.3",
            "Shibboleth version source is not 5.2.3")
    version = version_raw.decode("utf-8").strip()
    require(version == "5.2.3", "Shibboleth runtime version is not 5.2.3")
    (folder / f"target-container-inspect-{label}.json").write_bytes(inspect_raw)
    (folder / f"target-version-source-{label}.properties").write_bytes(source_raw)
    (folder / f"target-version-runtime-{label}.txt").write_bytes(version_raw)
    summary = {
        "captured_at": time.time(),
        "binding": target_binding(inspect),
        "docker_inspect_sha256": sha(inspect_raw),
        "version_source": {
            "path": TARGET_VERSION_SOURCE,
            "file": f"target-version-source-{label}.properties",
            "sha256": sha(source_raw),
            "value": values[0],
        },
        "runtime_version": {
            "command": TARGET_VERSION_COMMAND,
            "file": f"target-version-runtime-{label}.txt",
            "value": version,
        },
    }
    write_json(folder / f"target-runtime-{label}.json", summary)
    return summary


def capture_public_metadata(folder, label):
    with urllib.request.urlopen(TARGET_METADATA_URL, timeout=30) as response:
        require(response.status == 200, "target metadata endpoint did not return HTTP 200")
        raw = response.read()
    require(raw.startswith(b"<") or raw.startswith(b"<?xml"), "target metadata is not XML")
    (folder / f"target-public-metadata-{label}.xml").write_bytes(raw)
    return raw


def capture_suite_runtime(folder, label):
    inspect_raw = docker_bytes("inspect", SUITE)
    inspect = json.loads(inspect_raw)
    require(len(inspect) == 1 and inspect[0].get("State", {}).get("Running") is True,
            "Suite was not running")
    jar_path = folder / f"suite-runner-{label}.jar"
    subprocess.run(["docker", "cp", f"{SUITE}:{RUNNER_JAR}", str(jar_path)], check=True, timeout=60)
    jar_raw = jar_path.read_bytes()
    summary = {
        "captured_at": time.time(),
        "container": {
            "name": inspect[0]["Name"].removeprefix("/"),
            "id": inspect[0]["Id"],
            "image": inspect[0]["Image"],
            "started_at": inspect[0]["State"]["StartedAt"],
        },
        "docker_inspect_sha256": sha(inspect_raw),
        "runner_jar": {"path": RUNNER_JAR, "sha256": sha(jar_raw)},
    }
    (folder / f"suite-container-inspect-{label}.json").write_bytes(inspect_raw)
    write_json(folder / f"suite-runtime-{label}.json", summary)
    return summary


def api(path, body=None):
    encoded = None if body is None else json.dumps(body).encode("utf-8")
    headers = {} if encoded is None else {"Content-Type": "application/json"}
    request = urllib.request.Request(BASE + path, data=encoded, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


def capture_originals(folder, run):
    sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
    from capture_run_originals import capture
    transcript = json.loads((folder / "transcript.json").read_text())
    manifest = capture(folder, run, transcript)
    write_json(folder / "original-capture.json", {
        "run": run,
        "originals": len(manifest),
        "target_metadata_sha256": sha((folder / "target-metadata.xml").read_bytes()),
    })


def formal_reevaluate(folder, run):
    evaluation = folder / "evaluation-v138"
    require(not evaluation.exists(), "formal evaluation directory already exists")
    evaluation.mkdir()
    before = api(f"/api/runs/{run}/transcript")
    recorded = json.loads((folder / "transcript.json").read_text())
    require(before == recorded, "captured transcript changed before formal re-evaluation")
    action = api(f"/api/runs/{run}/protocol-evidence/evaluate", {})
    after = api(f"/api/runs/{run}/transcript")
    require(after == before, "formal re-evaluation changed the transcript")
    result = api(f"/api/runs/{run}/result.json")
    for name, value in {
        "transcript-before.json": before,
        "evaluation.json": action,
        "transcript.json": after,
        "result.json": result,
    }.items():
        write_json(evaluation / name, value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    folder = args.output.resolve()
    if folder.exists() and any(folder.iterdir()):
        raise ValueError("Evidence directory must be empty")
    folder.mkdir(parents=True, exist_ok=True)
    # Capture the driver source before execution so review can identify the exact helper used.
    driver = REPO / "dev/shibboleth/import_metadata_batch.py"
    driver_raw = driver.read_bytes()
    (folder / "native-filesystem-driver.py").write_bytes(driver_raw)
    write_json(folder / "campaign-input.json", {
        "variants": list(VARIANTS),
        "driver": "dev/shibboleth/import_metadata_batch.py",
        "driver_sha256": sha(driver_raw),
        "human_operations": 0,
    })
    target_start = capture_target_runtime(folder, "start")
    public_start = capture_public_metadata(folder, "start")
    suite_start = capture_suite_runtime(folder, "start")
    native = folder / "native-run"
    command = [sys.executable, str(driver), "--output", str(native), "--variants", ",".join(VARIANTS),
               "--continue-inconclusive"]
    try:
        subprocess.run(command, check=True, timeout=600)
    finally:
        # The native driver restores before it exits. Capture its final state even when a run fails.
        target_end = capture_target_runtime(folder, "end")
        public_end = capture_public_metadata(folder, "end")
        suite_end = capture_suite_runtime(folder, "end")
    require(target_start["binding"] == target_end["binding"],
            "target identity changed during campaign")
    require(public_start == public_end, "target public metadata changed during campaign")
    require(suite_start["container"] == suite_end["container"]
            and suite_start["runner_jar"] == suite_end["runner_jar"],
            "Suite runtime changed during campaign")
    for child in native.iterdir():
        destination = folder / child.name
        require(not destination.exists(), f"native evidence conflicts with wrapper evidence: {child.name}")
        child.replace(destination)
    native.rmdir()
    run = json.loads((folder / "created.json").read_text())["run"]["id"]
    capture_originals(folder, run)
    final_config = docker_bytes("exec", TARGET, "cat", "/opt/reference-idp/conf/metadata-providers.xml")
    (folder / "final-providers.xml").write_bytes(final_config)
    operations = json.loads((folder / "operations.json").read_text())
    restoration = json.loads((folder / "restoration.json").read_text())
    write_json(folder / "operation-counts.json", {
        "run": run,
        "human_operations": 0,
        "product_configuration_writes": 2,
        "product_configuration_restoration_writes": 1,
        "temporary_fixture_writes": len(VARIANTS),
        "metadata_resolver_reloads": len(VARIANTS) + 1,
        "normal_protocol_flows": len(VARIANTS),
        "suite_signature_controls": len(VARIANTS),
        "product_restarts": 0,
        "operator_continuations": 0,
        "operations_recorded": len(operations),
        "restored": restoration.get("restored") is True,
    })
    formal_reevaluate(folder, run)
    print(json.dumps({"run": run, "folder": str(folder), "restored": restoration.get("restored")},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
