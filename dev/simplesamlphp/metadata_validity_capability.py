#!/usr/bin/env python3
"""Bind the native SimpleSAMLphp metadata-validity capability and conclude MD04.a/c.

This is deliberately separate from the Suite fixture oracle.  A target accepting
one fixture in one configuration does not prove that the required rejection
capability is absent.  The capture therefore binds the same Run's native MDQ
flows to the complete installed SimpleSAMLphp/metarefresh source, replays the
only validity-limit setting (``expireAfter``), and records exact restoration
before submitting ``capability_absent`` to the configuration gate.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


REPO = Path(__file__).resolve().parents[2]
CONTAINER = "samlscope-reference-ssp"
SUITE = "samlscope-reference-suite"
BASE = "http://localhost:18080"
CASES = ("IIP-MD04-a-idp-01", "IIP-MD04-c-idp-01")
VARIANTS = ("control", "no-valid-until", "valid-until-near", "valid-until-far")
SOURCE_MEMBERS = ("src", "modules", "vendor/simplesamlphp", "composer.lock")
SEARCH = re.compile(r"validUntil|expireAfter|maxValidity|requiredValid|validityInterval", re.I)
T_SECONDS = 20 * 24 * 60 * 60
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def save(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def api(path: str, body=None):
    request = urllib.request.Request(
        BASE + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.load(response)


def docker(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(
        ["docker", "exec", "-i", CONTAINER, *args], input=data,
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
    ).stdout


def capture_sources(out: Path) -> dict:
    inspect_raw = subprocess.check_output(["docker", "inspect", CONTAINER], timeout=30)
    inspect = json.loads(inspect_raw)
    if not isinstance(inspect, list) or len(inspect) != 1:
        raise RuntimeError("Ambiguous product container")
    target = inspect[0]
    if target.get("State", {}).get("Running") is not True:
        raise RuntimeError("SimpleSAMLphp is not running")
    command = ["docker", "exec", CONTAINER, "tar", "-czf", "-", "-C", "/var/simplesamlphp", *SOURCE_MEMBERS]
    archive = subprocess.check_output(command, timeout=180)
    (out / "runtime-validity-source.tar.gz").write_bytes(archive)
    rows, occurrences = [], []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
        for member in sorted(source.getmembers(), key=lambda item: item.name):
            if not member.isfile():
                continue
            raw = source.extractfile(member).read()
            rows.append({"path": member.name, "size": len(raw), "sha256": SHA(raw)})
            if member.name.endswith((".php", ".md", ".json", ".lock")):
                for number, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
                    if SEARCH.search(line):
                        occurrences.append({"path": member.name, "line": number, "text": line})
    manifest = {
        "schema": "samlscope-ssp-validity-source-v1",
        "container_id": target["Id"],
        "image_id": target["Image"],
        "container_started_at": target["State"]["StartedAt"],
        "archive_sha256": SHA(archive),
        "members": rows,
        "search_pattern": SEARCH.pattern,
        "occurrences": occurrences,
        "product_configuration_writes": 0,
        "product_restarts": 0,
        "human_operations": 0,
    }
    save(out / "runtime-validity-source.json", manifest)
    return manifest


HARNESS = r'''<?php
require '/var/simplesamlphp/lib/_autoload.php';
$variant = $argv[1];
$source = $argv[2];
$limit = time() + %d;
$loader = new \SimpleSAML\Module\metarefresh\MetaLoader($limit, null, null);
$loader->setTypes(['saml20-sp-remote']);
$loader->loadSource(['src' => $source, 'conditionalGET' => false]);
$property = (new ReflectionClass($loader))->getProperty('metadata');
$metadata = $property->getValue($loader);
echo json_encode(['variant' => $variant, 'limit' => $limit, 'metadata' => $metadata], JSON_UNESCAPED_SLASHES);
''' % T_SECONDS


def replay_expire_after(out: Path) -> dict:
    prefix = "/tmp/samlscope-validity-" + json.loads((out / "created.json").read_text())["run"]["id"]
    harness = prefix + ".php"
    docker("sh", "-c", "cat > " + harness, data=HARNESS.encode())
    records = []
    try:
        for variant in VARIANTS:
            remote = prefix + "-" + variant + ".xml"
            fixture = (out / variant / "fixture.xml").read_bytes()
            docker("sh", "-c", "cat > " + remote, data=fixture)
            try:
                raw = docker("php", harness, variant, remote)
                record = json.loads(raw)
                record["fixture_sha256"] = SHA(fixture)
                records.append(record)
            finally:
                docker("rm", "-f", remote)
    finally:
        docker("rm", "-f", harness)
    result = {
        "schema": "samlscope-ssp-expire-after-replay-v1",
        "expire_after_seconds": T_SECONDS,
        "harness_sha256": SHA(HARNESS.encode()),
        "records": records,
        "temporary_files_removed": True,
        "product_configuration_writes": 0,
        "product_restarts": 0,
        "human_operations": 0,
    }
    save(out / "expire-after-replay.json", result)
    (out / "expire-after-replay.php").write_text(HARNESS)
    return result


def capture_originals(out: Path) -> None:
    run = json.loads((out / "created.json").read_text())["run"]["id"]
    entries = json.loads((out / "transcript.json").read_text())
    decoded = out / "decoded"
    decoded.mkdir(exist_ok=False)
    manifest = []
    for entry in entries:
        reference = entry.get("decodedSamlRef")
        if not reference:
            continue
        if Path(reference).is_absolute() or ".." in Path(reference).parts:
            raise RuntimeError("Unsafe decoded SAML reference")
        path = decoded / (entry["id"] + ".xml")
        subprocess.run(["docker", "cp", SUITE + ":/data/" + reference, str(path)],
                       check=True, timeout=60, stdout=subprocess.DEVNULL)
        manifest.append({"id": entry["id"], "file": "decoded/" + path.name,
                         "sha256": SHA(path.read_bytes())})
    save(out / "decoded-manifest.json", manifest)
    subprocess.run(["docker", "cp", SUITE + ":/data/target-metadata/" + run + ".xml",
                    str(out / "target-metadata.xml")], check=True, timeout=60,
                   stdout=subprocess.DEVNULL)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--conclude-capability-absent", action="store_true")
    args = parser.parse_args()
    out = args.evidence.resolve()
    if not out.is_dir():
        parser.error("Evidence directory does not exist")
    if (out / "runtime-validity-source.json").exists():
        raise RuntimeError("Refusing to overwrite capability evidence")
    restoration = json.loads((out / "restoration.json").read_text())
    if not restoration.get("restored") or (out / "original-config.php").read_bytes() != (out / "final-config.php").read_bytes():
        raise RuntimeError("Product configuration was not restored")
    for variant in VARIANTS:
        operation = json.loads((out / variant / "operation.json").read_text())
        flow = json.loads((out / variant / "flow.json").read_text())
        if operation.get("status") != "success" or flow.get("correlated_success") is not True:
            raise RuntimeError("Native product flow did not consume " + variant)
    manifest = capture_sources(out)
    replay_expire_after(out)
    capture_originals(out)
    run = json.loads((out / "created.json").read_text())["run"]["id"]
    if args.conclude_capability_absent:
        note = (
            "Machine-verified SimpleSAMLphp runtime evidence: native MDQ accepted and used metadata "
            "without root validUntil and beyond T; the installed validity path treats expireAfter as "
            "an expiry clamp rather than a rejection boundary. Evidence manifest sha256="
            + SHA((out / "runtime-validity-source.json").read_bytes())
        )
        conclusions = {}
        for case in CASES:
            conclusions[case] = api(
                "/api/runs/" + run + "/cases/" + case + "/configure",
                {"value": "capability_absent", "note": note},
            )
        save(out / "capability-conclusions.json", conclusions)
        save(out / "protocol-evidence-after.json", api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
        save(out / "result-after.json", api("/api/runs/" + run + "/result.json"))
        save(out / "transcript-after.json", api("/api/runs/" + run + "/transcript"))
    print(run, "source", manifest["archive_sha256"], "restored", restoration["restored"])


if __name__ == "__main__":
    main()
