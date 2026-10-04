#!/usr/bin/env python3
"""Run seven independent verifier rejection checks against temporary evidence copies."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

VERIFIER = Path(__file__).with_name("verify_keycloak_nameid_omission_absence.py")
FOLDER = "keycloak-nameid-omission-probe-v2"
NS_P = "{urn:oasis:names:tc:SAML:2.0:protocol}"
NS_A = "{urn:oasis:names:tc:SAML:2.0:assertion}"


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def amend_original(root, condition, mutate):
    observations = json.loads((root / "observations.json").read_text())
    ident = next(item["newTranscriptIds"][1] for item in observations
        if item["condition"] == condition)
    path = root / "decoded" / (ident + ".xml")
    tree = ET.parse(path)
    mutate(tree.getroot())
    tree.write(path, encoding="utf-8", xml_declaration=True)
    raw = path.read_bytes()
    manifest_path = root / "decoded-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    next(item for item in manifest if item["id"] == ident)["sha256"] = hashlib.sha256(raw).hexdigest()
    write_json(manifest_path, manifest)
    transcript_path = root / "transcript.json"
    transcript = json.loads(transcript_path.read_text())
    next(item for item in transcript if item["id"] == ident)["decodedSamlBytes"] = len(raw)
    write_json(transcript_path, transcript)


def mutate_null_response(root):
    observations = json.loads((root / "observations.json").read_text())
    baseline_id = observations[0]["newTranscriptIds"][1]
    baseline = ET.parse(root / "decoded" / (baseline_id + ".xml")).getroot()
    assertion = baseline.find(NS_A + "Assertion")
    def mutate(response):
        response.find(NS_P + "Status/" + NS_P + "StatusCode").set("Value",
            "urn:oasis:names:tc:SAML:2.0:status:Success")
        response.append(assertion)
    amend_original(root, "null-mapper", mutate)


def mutate_baseline(root):
    def mutate(response):
        assertion = response.find(NS_A + "Assertion")
        subject = assertion.find(NS_A + "Subject")
        subject.remove(subject.find(NS_A + "NameID"))
    amend_original(root, "baseline", mutate)


def main(source):
    source = Path(source).resolve()
    output = {}
    cases = [
        ("runtime-jar-hash", lambda root: damage_jar(root), "runtime JAR inventory or bytes changed"),
        ("runtime-jar-count", lambda root: remove_jar(root), "runtime JAR inventory or bytes changed"),
        ("custom-provider", lambda root: add_provider(root), "custom provider present"),
        ("null-response-success-assertion", mutate_null_response, "observed status differs"),
        ("baseline-nameid-removed", mutate_baseline, "normal control did not contain NameID"),
        ("temporary-client-remains", lambda root: leave_client(root), "temporary Keycloak client not exactly deleted"),
        ("mapper-inventory", lambda root: remove_mapper(root), "installed SAML mapper inventory changed"),
    ]
    for label, mutate, expected in cases:
        with tempfile.TemporaryDirectory(prefix="samlscope-keycloak-nameid-tamper-") as temp:
            root = Path(temp) / FOLDER
            def clone_file(source_path, target_path):
                if source_path.endswith(".jar"):
                    try: os.link(source_path, target_path); return target_path
                    except OSError: pass
                return shutil.copy2(source_path, target_path)
            shutil.copytree(source, root, copy_function=clone_file)
            mutate(root)
            result = subprocess.run([sys.executable, str(VERIFIER), str(root)],
                capture_output=True, text=True, timeout=120)
            if result.returncode == 0 or expected not in result.stderr:
                raise AssertionError(label + " was not rejected for the expected reason:\n" + result.stderr[-1200:])
            output[label] = "rejected"
    report = {"schema": "samlscope-keycloak-nameid-absence-tamper-v1", "checks": output}
    write_json(source / "tamper-self-test.json", report)
    print(json.dumps(report, indent=2))


def damage_jar(root):
    jar = root / "runtime-lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar"
    raw = jar.read_bytes()
    jar.unlink()  # Break the temporary hardlink before writing; preserve the evidence original.
    jar.write_bytes(raw + b"tampered")


def remove_jar(root):
    (root / "runtime-lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar").unlink()


def add_provider(root):
    path = root / "providers.json"
    value = json.loads(path.read_text())
    value["files"].append("./unreviewed.jar")
    write_json(path, value)


def leave_client(root):
    write_json(root / "client-after.json", [{"clientId": "unremoved"}])


def remove_mapper(root):
    path = root / "serverinfo-nameid.json"
    value = json.loads(path.read_text())
    value["mappers"] = [item for item in value["mappers"]
        if item["id"] != "saml-user-attribute-nameid-mapper"]
    write_json(path, value)


if __name__ == "__main__":
    if len(sys.argv) != 2: raise SystemExit("usage: test_keycloak_nameid_absence_tamper.py EVIDENCE_DIR")
    main(sys.argv[1])
