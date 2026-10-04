#!/usr/bin/env python3
"""Collect four independent SimpleSAMLphp IIP-EXT01.c observations.

Each profile first records the three active protocol fixtures through the existing browser
chain.  The same Run is then extended with the control and all thirteen approved metadata
attribute placements, parsed by the installed SimpleSAMLphp parser and loaded through its
native PHP metadata configuration.  This recorder never assigns a verdict.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


REPO = Path(__file__).resolve().parents[2]
PROFILES = ("browser_sso_idp", "ecp_idp", "metadata_idp", "single_logout_idp")
CASE = "IIP-EXT01-c-idp-01"
VARIANTS = (
    "control",
    "foreign-attribute-entity",
    "foreign-attribute-organization",
    "foreign-attribute-contact",
    "foreign-attribute-role",
    "foreign-attribute-single-logout",
    "foreign-attribute-single-sign-on",
    "foreign-attribute-manage-nameid",
    "foreign-attribute-nameid-mapping",
    "foreign-attribute-assertion-id",
    "foreign-attribute-authn-query",
    "foreign-attribute-authz",
    "foreign-attribute-attribute-service",
    "foreign-attribute-affiliation",
)
HOST_CONFIG = REPO / "build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php"
CONTAINER = "samlscope-reference-ssp"
CONTAINER_CONFIG = "/var/simplesamlphp/metadata/saml20-sp-remote.php"


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def product_config():
    return subprocess.check_output(
        ["docker", "exec", CONTAINER, "cat", CONTAINER_CONFIG], timeout=30)


def run(command):
    subprocess.run(command, cwd=REPO, check=True)


def state_record(profile, run_id):
    host = HOST_CONFIG.read_bytes()
    product = product_config()
    return {
        "profile": profile,
        "run": run_id,
        "host_sha256": sha(host),
        "product_sha256": sha(product),
        "bytes": len(host),
        "host_product_equal": host == product,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    if root.exists() and any(root.iterdir()):
        raise ValueError("Evidence directory must be empty")
    root.mkdir(parents=True, exist_ok=True)

    completed = []
    batch = {
        "schema": "samlscope-ext01c-simplesamlphp-batch-v1",
        "product": "simplesamlphp",
        "profiles": list(PROFILES),
        "case": CASE,
        "metadata_variants": list(VARIANTS),
        "completed": completed,
        "verdict_adopted": False,
    }
    save(root / "batch.json", batch)

    for profile in PROFILES:
        folder = root / profile
        active = folder / "active"
        metadata = folder / "metadata"
        runtime = folder / "supplemental-runtime"
        command = [
            sys.executable, str(REPO / "dev/simplesamlphp/browser_chain_campaign.py"),
            "--output", str(active), "--profile", profile,
            "--stop-after-case", CASE, "--no-idp-initiated-sso",
        ]
        run(command)
        created = json.loads((active / "created.json").read_text())["run"]
        run_id = created["id"]
        before = state_record(profile, run_id)
        save(folder / "supplemental-before.json", before)
        if not before["host_product_equal"]:
            raise RuntimeError("SimpleSAMLphp host/product config differed before supplemental batch")

        runtime.mkdir(parents=True)
        run([
            sys.executable,
            str(REPO / "dev/reference-acceptance/capture_terminal_http_runtime.py"),
            str(runtime), "target-start", "--product", "simplesamlphp",
        ])
        run([
            sys.executable, str(REPO / "dev/simplesamlphp/import_metadata_batch.py"),
            "--output", str(metadata), "--run", run_id, "--profile", profile,
            "--variants", ",".join(VARIANTS),
        ])
        after = state_record(profile, run_id)
        save(folder / "supplemental-after.json", after)
        if after != before:
            raise RuntimeError("Supplemental metadata campaign did not restore SimpleSAMLphp exactly")
        run([
            sys.executable,
            str(REPO / "dev/reference-acceptance/capture_terminal_http_runtime.py"),
            str(runtime), "target-end", "--product", "simplesamlphp",
        ])

        sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
        from capture_run_originals import capture as capture_saml  # noqa: PLC0415
        from capture_browser_originals import capture as capture_browser  # noqa: PLC0415
        entries = json.loads((metadata / "transcript.json").read_text())
        capture_saml(metadata, run_id, entries)
        capture_browser(metadata, entries)
        shutil.copy2(active / "target-metadata.xml", metadata / "target-metadata.xml")
        run([
            sys.executable,
            str(REPO / "dev/reference-acceptance/capture_terminal_http_runtime.py"),
            str(metadata), "suite",
        ])

        active_counts = json.loads((active / "operation-counts.json").read_text())
        metadata_counts = json.loads((metadata / "operation-counts.json").read_text())
        operations = json.loads((metadata / "operations.json").read_text())
        save(folder / "operation-counts.json", {
            "restored": True,
            "human_operations": 0,
            "product_restarts": 0,
            "active_configuration_write_attempts": active_counts["configuration_write_attempts"],
            "active_restoration_write_attempts": active_counts["restoration_write_attempts"],
            "active_protocol_roundtrips": 3,
            "metadata_native_parser_invocations": len(operations),
            "metadata_configuration_apply_writes": metadata_counts["configuration_apply_writes"],
            "metadata_restoration_writes": metadata_counts["restoration_writes"],
            "metadata_protocol_roundtrips": metadata_counts["protocol_roundtrips"],
            "verdict_adopted": False,
        })
        completed.append({"profile": profile, "run": run_id})
        save(root / "batch.json", batch)

    print("Recorded SimpleSAMLphp EXT01.c profiles:", len(completed))


if __name__ == "__main__":
    main()
