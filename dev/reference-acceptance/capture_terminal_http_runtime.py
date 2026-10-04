#!/usr/bin/env python3
"""Capture immutable product/Suite evidence for Recorder-backed HTTP terminal campaigns.

The browser-chain drivers call :func:`capture_target` immediately before and after changing
their temporary SP registration.  ``suite`` is run only after the driver restored the target;
it binds the already-exported transcript originals to the exact Suite container/JARs and saves
one formal, transcript-preserving re-evaluation.
"""

import argparse
import hashlib
import json
import re
import subprocess
import urllib.request
from pathlib import Path


BASE = "http://localhost:18080"
SUITE = "samlscope-reference-suite"
SUITE_JARS = {
    "core": "/opt/samlscope/lib/core-0.1.0.jar",
    "runner": "/opt/samlscope/lib/runner-0.1.0.jar",
    "saml": "/opt/samlscope/lib/saml-0.1.0.jar",
}
TARGETS = {
    "keycloak": {
        "container": "samlscope-reference-keycloak",
        "container_port": "8080/tcp",
        "host_port": 18180,
        "version_command": ["/opt/keycloak/bin/kc.sh", "--version"],
        "version_source": None,
    },
    "shibboleth": {
        "container": "samlscope-reference-shibboleth",
        "container_port": "8080/tcp",
        "host_port": 18280,
        "version_command": ["/opt/reference-idp/bin/version.sh"],
        "version_source": "/opt/reference-idp/dist/idp.installed.version",
    },
    "simplesamlphp": {
        "container": "samlscope-reference-ssp",
        "container_port": "80/tcp",
        "host_port": 18380,
        "version_command": [
            "php", "-r",
            "require '/var/simplesamlphp/lib/_autoload.php'; "
            "echo \\SimpleSAML\\Configuration::VERSION;",
        ],
        "version_source": "/var/simplesamlphp/src/SimpleSAML/Configuration.php",
    },
}
EVALUATION = "evaluation-terminal-http-v1"
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def output(command):
    return subprocess.check_output(command, timeout=60)


def api(path, payload=None):
    body = None if payload is None else json.dumps(payload).encode()
    headers = {} if body is None else {"Content-Type": "application/json"}
    request = urllib.request.Request(BASE + path, data=body, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


def _one_inspect(raw, name):
    value = json.loads(raw)
    if not isinstance(value, list) or len(value) != 1:
        raise RuntimeError(name + " docker inspect did not return exactly one container")
    return value[0]


def capture_target(output_dir, product, phase):
    if product not in TARGETS or phase not in {"start", "end"}:
        raise ValueError("Unsupported product or target capture phase")
    output_dir = Path(output_dir)
    target = TARGETS[product]
    inspect_path = output_dir / f"target-container-inspect-{phase}.json"
    image_path = output_dir / f"target-image-inspect-{phase}.json"
    version_path = output_dir / f"target-version-runtime-{phase}.txt"
    source_path = output_dir / f"target-version-source-{phase}.txt"
    summary_path = output_dir / f"target-runtime-{phase}.json"
    paths = [inspect_path, image_path, version_path, summary_path]
    if target["version_source"]:
        paths.append(source_path)
    if any(path.exists() for path in paths):
        raise RuntimeError("Refusing to overwrite target runtime originals")

    inspect_raw = output(["docker", "inspect", target["container"]])
    item = _one_inspect(inspect_raw, "target")
    version_raw = output([
        "docker", "exec", target["container"], *target["version_command"]
    ])
    source_raw = None
    if target["version_source"]:
        source_raw = output([
            "docker", "exec", target["container"], "cat", target["version_source"]
        ])
    image_raw = output(["docker", "image", "inspect", item["Image"]])
    image = json.loads(image_raw)
    if not isinstance(image, list) or len(image) != 1:
        raise RuntimeError("Target image inspect did not return exactly one image")
    ports = item.get("NetworkSettings", {}).get("Ports", {}).get(target["container_port"]) or []
    host_port = str(target["host_port"])
    binding = {
        "container_name": item["Name"].removeprefix("/"),
        "container_id": item["Id"],
        "configured_image": item["Config"]["Image"],
        "image_id": item["Image"],
        "repo_digests": sorted(image[0].get("RepoDigests") or []),
        "container_started_at": item["State"]["StartedAt"],
        "running_at_capture": item["State"]["Running"],
        "container_port": target["container_port"],
        "host_port": target["host_port"],
        "host_port_bound": any(
            row.get("HostIp") == "127.0.0.1" and row.get("HostPort") == host_port
            for row in ports
        ),
    }
    inspect_path.write_bytes(inspect_raw)
    image_path.write_bytes(image_raw)
    version_path.write_bytes(version_raw)
    summary = {
        "schema": "samlscope-terminal-http-target-runtime-v1",
        "product": product,
        "phase": phase,
        "binding": binding,
        "docker_inspect_sha256": sha(inspect_raw),
        "image_inspect_sha256": sha(image_raw),
        "runtime_version": {
            "command": target["version_command"],
            "file": version_path.name,
            "sha256": sha(version_raw),
            "value": version_raw.decode().strip(),
        },
    }
    if source_raw is not None:
        source_path.write_bytes(source_raw)
        source_value = source_raw.decode(errors="strict")
        if product == "simplesamlphp":
            match = re.search(
                r"public\s+const(?:\s+string)?\s+VERSION\s*=\s*['\"]([^'\"]+)['\"]\s*;",
                source_value,
            )
            if match is None or match.group(1) != version_raw.decode().strip():
                raise RuntimeError("SimpleSAMLphp runtime/source version mismatch")
            source_value = match.group(1)
        elif product == "shibboleth":
            match = re.search(r"^idp\.installed\.version=(.+)$", source_value, re.MULTILINE)
            if match is None or match.group(1).strip() != version_raw.decode().strip():
                raise RuntimeError("Shibboleth runtime/source version mismatch")
            source_value = match.group(1).strip()
        else:
            source_value = source_value.strip()
            if source_value != version_raw.decode().strip():
                raise RuntimeError("Target runtime/source version mismatch")
        summary["version_source"] = {
            "path": target["version_source"],
            "file": source_path.name,
            "sha256": sha(source_raw),
            "value": source_value,
        }
    write_json(summary_path, summary)
    return summary


# Browser-chain drivers use the same three-argument call shape as the older IDP12.b helper.
capture = capture_target


def capture_suite(output_dir):
    output_dir = Path(output_dir)
    evaluation = output_dir / EVALUATION
    runtime_path = output_dir / "suite-runtime-terminal-http.json"
    inspect_path = output_dir / "suite-container-inspect-terminal-http.json"
    jar_paths = {name: output_dir / f"suite-{name}-0.1.0.jar" for name in SUITE_JARS}
    if any(path.exists() for path in [evaluation, runtime_path, inspect_path, *jar_paths.values()]):
        raise RuntimeError("Refusing to overwrite Suite runtime originals")
    created = json.loads((output_dir / "created.json").read_text())["run"]
    run = created["id"]
    if RUN_RE.fullmatch(run) is None:
        raise ValueError("Invalid Run identifier")
    exported = json.loads((output_dir / "transcript.json").read_text())
    current = api(f"/api/runs/{run}/transcript")
    if exported != current:
        raise RuntimeError("Exported transcript differs from the live Run before re-evaluation")

    inspect_raw = output(["docker", "inspect", SUITE])
    inspected = _one_inspect(inspect_raw, "Suite")
    jars = {}
    for name, source in SUITE_JARS.items():
        destination = jar_paths[name]
        subprocess.run(
            ["docker", "cp", f"{SUITE}:{source}", str(destination)],
            check=True, timeout=60, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        jars[name] = {"path": source, "file": destination.name, "sha256": sha(destination.read_bytes())}
    inspect_path.write_bytes(inspect_raw)
    write_json(runtime_path, {
        "schema": "samlscope-terminal-http-suite-runtime-v1",
        "run": run,
        "container": {
            "name": inspected["Name"].removeprefix("/"),
            "id": inspected["Id"],
            "configured_image": inspected["Config"]["Image"],
            "image_id": inspected["Image"],
            "started_at": inspected["State"]["StartedAt"],
            "running_at_capture": inspected["State"]["Running"],
        },
        "docker_inspect_file": inspect_path.name,
        "docker_inspect_sha256": sha(inspect_raw),
        "jars": jars,
    })

    evaluation.mkdir()
    before = current
    evaluation_result = api(f"/api/runs/{run}/protocol-evidence/evaluate", {})
    after = api(f"/api/runs/{run}/transcript")
    if before != after:
        raise RuntimeError("Formal re-evaluation changed the transcript")
    result = api(f"/api/runs/{run}/result.json")
    for name, value in {
        "transcript-before.json": before,
        "evaluation.json": evaluation_result,
        "transcript.json": after,
        "result.json": result,
    }.items():
        write_json(evaluation / name, value)
    return runtime_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("action", choices=("target-start", "target-end", "suite"))
    parser.add_argument("--product", choices=tuple(TARGETS))
    args = parser.parse_args()
    if args.action == "suite":
        if args.product is not None:
            parser.error("--product is not used for suite capture")
        capture_suite(args.folder.resolve())
    else:
        if args.product is None:
            parser.error("--product is required for target capture")
        capture_target(args.folder.resolve(), args.product, args.action.removeprefix("target-"))


if __name__ == "__main__":
    main()
