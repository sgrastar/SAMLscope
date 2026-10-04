#!/usr/bin/env python3
"""Collect four Run-bound Shibboleth IIP-EXT01.c observations.

For each approved profile the normal browser-chain driver first records the three active
AuthnRequest placements.  The exact same Run is then extended with the metadata control and all
thirteen ``foreign-attribute-*`` fixtures through Shibboleth's own
``FilesystemMetadataProvider``.  This coordinator records originals and restoration facts but
never assigns a target verdict.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.request


REPO = Path(__file__).resolve().parents[2]
PROFILES = ("browser_sso_idp", "ecp_idp", "metadata_idp", "single_logout_idp")
CASE = "IIP-EXT01-c-idp-01"
CONFIG = "/opt/reference-idp/conf/metadata-providers.xml"
CONTAINER = "samlscope-reference-shibboleth"
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


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run(command):
    subprocess.run(command, cwd=REPO, check=True)


def docker(*args):
    return subprocess.check_output(["docker", "exec", CONTAINER, *args], timeout=90)


def api(path, body=None):
    payload = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        "http://localhost:18080" + path, data=payload,
        headers={} if payload is None else {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def product_state(run_id):
    config = docker("cat", CONFIG)
    temporary = "/opt/reference-idp/metadata/algorithm-" + run_id + ".xml"
    exists = bool(docker("sh", "-c", "if test -e " + temporary + "; then echo exists; fi").strip())
    return {
        "run": run_id,
        "configuration_path": CONFIG,
        "configuration_sha256": sha(config),
        "configuration_bytes": len(config),
        "temporary_path": temporary,
        "temporary_path_absent": not exists,
    }, config


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
        "schema": "samlscope-ext01c-shibboleth-batch-v1",
        "product": "shibboleth",
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
        run([
            sys.executable, str(REPO / "dev/shibboleth/browser_chain_campaign.py"),
            "--output", str(active), "--profile", profile,
            "--stop-after-case", CASE,
        ])
        created = json.loads((active / "created.json").read_text())["run"]
        run_id = created["id"]
        before, before_raw = product_state(run_id)
        if not before["temporary_path_absent"]:
            raise RuntimeError("Supplemental provider file existed before the campaign")
        save(folder / "supplemental-before.json", before)

        runtime.mkdir(parents=True)
        run([
            sys.executable,
            str(REPO / "dev/reference-acceptance/capture_terminal_http_runtime.py"),
            str(runtime), "target-start", "--product", "shibboleth",
        ])
        run([
            sys.executable, str(REPO / "dev/shibboleth/import_metadata_batch.py"),
            "--output", str(metadata), "--run", run_id, "--profile", profile,
            "--variants", ",".join(VARIANTS),
        ])
        # The approved metadata campaign API distinguishes "evidence is ready" from "every
        # selected product refresh was attempted".  The native operation/read-back records above
        # prove the latter automatically.  Confirmation never supplies a product verdict, and the
        # Runner remains responsible for deriving every outcome from the Transcript.
        confirmation = api(
            "/api/runs/" + run_id + "/protocol-evidence/confirm-attempts", {})
        ext01c = [item for item in confirmation.get("completed", [])
                  if item.get("caseId") == CASE]
        if ext01c != [{"caseId": CASE, "outcome": "SATISFIED"}]:
            raise RuntimeError("Runner did not derive EXT01.c from the completed native campaign")
        if any(item.get("caseId") != CASE and item.get("outcome") != "NOT_VERIFIED"
               for item in confirmation.get("completed", [])):
            raise RuntimeError("Attempt confirmation changed an unrelated case conclusively")
        save(metadata / "attempt-confirmation.json", confirmation)
        after, after_raw = product_state(run_id)
        save(folder / "supplemental-after.json", after)
        if after != before or after_raw != before_raw:
            raise RuntimeError("Supplemental metadata campaign did not exactly restore Shibboleth")
        run([
            sys.executable,
            str(REPO / "dev/reference-acceptance/capture_terminal_http_runtime.py"),
            str(runtime), "target-end", "--product", "shibboleth",
        ])

        sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
        from capture_run_originals import capture as capture_saml  # noqa: PLC0415
        from capture_browser_originals import capture as capture_browser  # noqa: PLC0415

        entries = json.loads((metadata / "transcript.json").read_text())
        capture_saml(metadata, run_id, entries)
        capture_browser(metadata, entries)
        run([
            sys.executable,
            str(REPO / "dev/reference-acceptance/capture_terminal_http_runtime.py"),
            str(metadata), "suite",
        ])

        active_counts = json.loads((active / "operation-counts.json").read_text())
        metadata_counts = json.loads((metadata / "operation-counts.json").read_text())
        save(folder / "operation-counts.json", {
            "restored": active_counts["restored"] and metadata_counts["restored"],
            "human_operations": 0,
            "product_restarts": 0,
            "active_configuration_writes": active_counts["configuration_write_attempts"],
            "active_restoration_writes": active_counts["restoration_write_attempts"],
            "active_reloads": active_counts["reloads"],
            "active_protocol_roundtrips": 3,
            "metadata_fixture_writes": metadata_counts["metadata_fixture_writes"],
            "metadata_provider_apply_writes": metadata_counts["provider_apply_writes"],
            "metadata_restoration_writes": metadata_counts["restoration_writes"],
            "metadata_reloads": metadata_counts["reloads"],
            "metadata_protocol_roundtrips": metadata_counts["protocol_roundtrips"],
            "protocol_attempt_confirmation_calls": 1,
            "verdict_adopted": False,
        })
        completed.append({"profile": profile, "run": run_id})
        save(root / "batch.json", batch)


if __name__ == "__main__":
    main()
