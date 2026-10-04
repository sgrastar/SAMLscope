#!/usr/bin/env python3
"""Collect four independent Keycloak IIP-EXT01.c observations.

For each profile this first completes the three request/response fixtures with the normal
browser-chain driver.  It then reuses that exact Run for the control plus every approved
``foreign-attribute-*`` metadata fixture, importing each original through Keycloak's own
console and deleting it with Admin API read-back.  This coordinator never assigns a verdict;
it only seals the originals needed by the independent acceptance verifier.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.parse
import urllib.request


REPO = Path(__file__).resolve().parents[2]
BASE = "http://localhost:18080"
ADMIN = "http://localhost:18180/admin/realms/samlscope"
TOKEN_URL = "http://localhost:18180/realms/master/protocol/openid-connect/token"
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


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def admin_token():
    body = urllib.parse.urlencode({
        "client_id": "admin-cli", "username": "admin", "password": "admin",
        "grant_type": "password",
    }).encode()
    request = urllib.request.Request(TOKEN_URL, data=body)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)["access_token"]


def client_query(client_id):
    request = urllib.request.Request(
        ADMIN + "/clients?clientId=" + urllib.parse.quote(client_id, safe=""),
        headers={"Authorization": "Bearer " + admin_token()},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def run(command):
    subprocess.run(command, cwd=REPO, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--playwright-modules", type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    modules = args.playwright_modules.resolve()
    if root.exists() and any(root.iterdir()):
        raise ValueError("Evidence directory must be empty")
    if not (modules / "playwright").is_dir():
        raise ValueError("Playwright module directory does not contain playwright")
    root.mkdir(parents=True, exist_ok=True)

    completed = []
    batch = {
        "schema": "samlscope-ext01c-keycloak-batch-v1",
        "product": "keycloak",
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
            sys.executable, str(REPO / "dev/keycloak/browser_chain_campaign.py"),
            "--output", str(active), "--profile", profile,
            "--stop-after-case", CASE, "--playwright-modules", str(modules),
        ])
        created = json.loads((active / "created.json").read_text())["run"]
        run_id = created["id"]
        plan_id = created["planId"]
        entity_id = BASE + "/p/" + plan_id
        before = client_query(entity_id)
        if before != []:
            raise RuntimeError("Active campaign did not restore the temporary Keycloak client")
        save(folder / "supplemental-before.json", {
            "run": run_id, "entity_id": entity_id, "client_query": before,
            "canonical_sha256": sha(json.dumps(before, sort_keys=True, separators=(",", ":")).encode()),
        })
        runtime.mkdir(parents=True)
        run([
            sys.executable,
            str(REPO / "dev/reference-acceptance/capture_terminal_http_runtime.py"),
            str(runtime), "target-start", "--product", "keycloak",
        ])
        run([
            sys.executable, str(REPO / "dev/keycloak/import_metadata_batch.py"),
            "--output", str(metadata), "--run", run_id, "--profile", profile,
            "--variants", ",".join(VARIANTS), "--playwright-modules", str(modules),
        ])
        after = client_query(entity_id)
        save(folder / "supplemental-after.json", {
            "run": run_id, "entity_id": entity_id, "client_query": after,
            "canonical_sha256": sha(json.dumps(after, sort_keys=True, separators=(",", ":")).encode()),
        })
        if after != before:
            raise RuntimeError("Supplemental metadata campaign did not restore Keycloak")
        run([
            sys.executable,
            str(REPO / "dev/reference-acceptance/capture_terminal_http_runtime.py"),
            str(runtime), "target-end", "--product", "keycloak",
        ])

        # The metadata driver exports the final transcript but not Recorder originals.
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

        operations = json.loads((metadata / "operations.json").read_text())
        save(folder / "operation-counts.json", {
            "restored": True,
            "human_operations": 0,
            "product_restarts": 0,
            "active_configuration_apply_writes": 3,
            "active_restoration_writes": 3,
            "metadata_console_import_writes": len(operations),
            "metadata_delete_writes": len(operations),
            "active_protocol_roundtrips": 3,
            "metadata_protocol_roundtrips": len(operations),
            "verdict_adopted": False,
        })
        completed.append({"profile": profile, "run": run_id})
        save(root / "batch.json", batch)


if __name__ == "__main__":
    main()
