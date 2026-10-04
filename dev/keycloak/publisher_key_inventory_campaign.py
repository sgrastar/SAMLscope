#!/usr/bin/env python3
"""Collect two current native RS256 keys and signed SAML A/B/A controls.

This collector does not decide conformance or treat OIDC encryption keys as SAML
role keys. Native provider priority restoration/removal is verified in finally.
Private provider config and administrative credentials exist only in memory.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request

REPO = Path(__file__).resolve().parents[2]
from import_metadata_batch import api, save, BASE
from attribute_policy_capability_absence import product_token
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
from capture_run_originals import capture
ADMIN = "http://localhost:18180/admin/realms/samlscope"
PUBLIC_PROVIDER_FIELDS = {"algorithm", "priority", "active", "enabled", "keySize"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def public_provider(row):
    return {**{key: row.get(key) for key in ["id", "name", "parentId", "providerId", "providerType"]},
            "config": {key: value for key, value in row.get("config", {}).items() if key in PUBLIC_PROVIDER_FIELDS}}


def normalized_keys(value):
    return {**value, "keys": sorted(value["keys"], key=lambda key: key["kid"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--playwright-modules", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    stage = out / "driver"
    stage.mkdir()
    shutil.copy2(Path(__file__).with_name("console_import.mjs"), stage / "console_import.mjs")
    (stage / "node_modules").symlink_to(args.playwright_modules.resolve(), target_is_directory=True)
    operations, phases = [], []
    run = plan = temporary_id = None
    owned_name = None
    original_keys = original_providers = None
    final_providers = []
    restored = False

    def admin(path, body=None, method="GET"):
        # Never record request bodies: provider representations may include keys.
        request = urllib.request.Request(ADMIN + path, data=None if body is None else canonical(body), method=method,
            headers={"Authorization": "Bearer " + product_token(), "Content-Type": "application/json"})
        row = dict(method=method, path=path.split("?")[0], status="attempted")
        operations.append(row)
        save(out / "operations.json", operations)
        with urllib.request.urlopen(request, timeout=40) as response:
            row["status"] = response.status
            raw = response.read()
        save(out / "operations.json", operations)
        return json.loads(raw) if raw else None

    provider_path = "/components?type=" + urllib.parse.quote("org.keycloak.keys.KeyProvider", safe="")
    try:
        original_providers = admin(provider_path)
        original_keys = admin("/keys")
        signing = [key for key in original_keys["keys"] if key.get("use") == "SIG" and key.get("algorithm") == "RS256"]
        if len(signing) != 1 or signing[0]["status"] != "ACTIVE" or original_keys["active"].get("RS256") != signing[0]["kid"]:
            raise ValueError("Campaign requires exactly one original active native RS256 key")
        original_provider = next(row for row in original_providers if row["id"] == signing[0]["providerId"])
        if original_provider["providerId"] != "rsa-generated" or {row["providerId"] for row in original_providers} - {
                "rsa-generated", "rsa-enc-generated", "hmac-generated", "aes-generated"}:
            raise ValueError("Unexpected native key provider; do not infer SAML role scope")
        priority = int(original_provider.get("config", {}).get("priority", ["100"])[0])
        save(out / "original-public-providers.json", sorted(map(public_provider, original_providers), key=lambda row: row["id"]))
        save(out / "original-public-keys.json", normalized_keys(original_keys))
        owned_name = "samlscope-native-publisher-" + sha(str(out).encode())[:20]
        if any(row.get("name") == owned_name for row in original_providers):
            raise ValueError("Temporary provider already exists")
        wanted = dict(name=owned_name, parentId=original_provider["parentId"], providerId="rsa-generated",
            providerType="org.keycloak.keys.KeyProvider", config=dict(algorithm=["RS256"], priority=[str(priority - 1)],
                active=["true"], enabled=["true"], keySize=["2048"]))
        admin("/components", wanted, "POST")
        providers = admin(provider_path)
        owned = [row for row in providers if row.get("name") == owned_name]
        if len(owned) != 1:
            raise ValueError("Native temporary provider creation ambiguous")
        temporary_id = owned[0]["id"]
        current = admin("/keys")
        new_keys = [key for key in current["keys"] if key["providerId"] == temporary_id]
        if len(new_keys) != 1 or new_keys[0].get("algorithm") != "RS256" or new_keys[0].get("use") != "SIG" or new_keys[0].get("status") != "ACTIVE":
            raise ValueError("Second current native signing key not established")
        save(out / "temporary-provider-public.json", public_provider(owned[0]))
        save(out / "two-current-public-keys.json", normalized_keys(current))
        plan_result = api("/api/plans", dict(name="Native Keycloak publisher current-key inventory", profile="metadata_idp",
            targetKind="IDP", targetEntityId="http://localhost:18180/realms/samlscope", metadataSourceKind="URL",
            metadataSourceLocation="http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor",
            suiteMetadataDelivery="HTTP_URL", declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
                metadataRefreshWaitSeconds=300, testUserHint="samlscope-m0-user", requestSigningMode="REQUIRED"),
            interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset="quick"), authorizedTarget=True))
        save(out / "plan.json", plan_result)
        plan = plan_result["plan"]["plan"]["id"]
        created = api("/api/plans/" + plan + "/runs", {})
        save(out / "created.json", created)
        run = created["run"]["id"]
        save(out / "preflight.json", api("/api/runs/" + run + "/preflight", {}))
        entity = BASE + "/p/" + plan
        for label, desired_priority, expected_kid in [("a-before", priority - 1, signing[0]["kid"]),
                ("b-current", priority + 1, new_keys[0]["kid"]), ("a-after", priority - 1, signing[0]["kid"])]:
            folder = out / label
            folder.mkdir()
            native = admin("/components/" + temporary_id)
            if native.get("config", {}).get("priority") != [str(desired_priority)]:
                changed = copy.deepcopy(native)
                changed["config"]["priority"] = [str(desired_priority)]
                admin("/components/" + temporary_id, changed, "PUT")
            readback = admin("/components/" + temporary_id)
            keys = admin("/keys")
            if keys["active"].get("RS256") != expected_kid or readback.get("config", {}).get("priority") != [str(desired_priority)]:
                raise ValueError("Native signing priority/readback differs")
            save(folder / "provider-public-readback.json", public_provider(readback))
            save(folder / "key-inventory-readback.json", normalized_keys(keys))
            with urllib.request.urlopen("http://localhost:18180/realms/samlscope/protocol/saml/descriptor", timeout=30) as response:
                (folder / "target-metadata-original.xml").write_bytes(response.read())
            campaign = api("/api/runs/" + run + "/metadata-lab/automatic-polling", dict(variants=["control"], pollingDelaySeconds=0))
            save(folder / "campaign.json", campaign)
            with urllib.request.urlopen(campaign["automaticStartUrl"], timeout=30) as response:
                if response.status != 202:
                    raise ValueError("Fixture fetch gate missing")
            with urllib.request.urlopen(campaign["metadataUrl"], timeout=30) as response:
                (folder / "fixture.xml").write_bytes(response.read())
            command = shlex.join([sys.executable, str(Path(__file__).with_name("import_metadata_batch.py")), "--flow-run", run,
                                "--output", str(folder / "flow.json"), "--suite-signature-control"])
            row = dict(phase=label, expected_native_signer_kid=expected_kid, driver_exit=None,
                       client_removed=False, import_attempted=True)
            phases.append(row)
            save(out / "phases.json", phases)
            executed = subprocess.run(["node", str(stage / "console_import.mjs"), "--fixture", str(folder / "fixture.xml"),
                "--record", str(folder / "import.json"), "--entity-id", entity, "--verify-command", command, "--delete"],
                capture_output=True, text=True, timeout=420)
            (folder / "driver.log").write_text(executed.stdout + executed.stderr)
            imported = json.loads((folder / "import.json").read_bytes())
            row.update(driver_exit=executed.returncode,
                       client_removed=imported.get("cleanup", {}).get("read_back_absent") is True)
            save(out / "phases.json", phases)
            if executed.returncode or not row["client_removed"]:
                raise ValueError("Native publisher signing control incomplete")
            print(label + " signed native response recorded; temporary client removed", flush=True)
    finally:
        failures = []
        if temporary_id is None and owned_name is not None:
            try:
                found = [row for row in admin(provider_path) if row.get("name") == owned_name]
                if len(found) == 1:
                    temporary_id = found[0]["id"]
                elif found:
                    failures.append("temporary-provider-ambiguous")
            except Exception:
                failures.append("temporary-provider-recovery-failed")
        if temporary_id is not None:
            try:
                admin("/components/" + temporary_id, method="DELETE")
            except Exception:
                failures.append("temporary-provider-removal-failed")
        try:
            final_providers = admin(provider_path)
            final_keys = admin("/keys")
            restored = original_providers is not None and sorted(final_providers,key=lambda row:row["id"]) == sorted(original_providers,key=lambda row:row["id"]) and normalized_keys(final_keys) == normalized_keys(original_keys)
            save(out / "final-public-providers.json", sorted(map(public_provider, final_providers), key=lambda row: row["id"]))
            save(out / "final-public-keys.json", normalized_keys(final_keys))
            if not restored:
                failures.append("original-native-state-differs")
        except Exception:
            failures.append("native-restoration-readback-failed")
        save(out / "restoration.json", dict(restored=restored and not failures, failures=failures,
            temporary_provider_removed=temporary_id is None or all(row["id"] != temporary_id for row in final_providers)))
        save(out / "operation-counts.json", dict(native_admin_gets=sum(row["method"] == "GET" for row in operations),
            native_provider_creates=sum(row["method"] == "POST" for row in operations),
            native_priority_write_attempts=sum(row["method"] == "PUT" for row in operations),
            native_provider_removals=sum(row["method"] == "DELETE" for row in operations),
            imported_clients=len(phases), imported_clients_removed=sum(row["client_removed"] for row in phases),
            protocol_operation_pairs_attempted=len(phases), product_restarts=0, human_operations=0,
            restored=restored and not failures, verdict_adopted=False))
        if run is not None:
            entries = api("/api/runs/" + run + "/transcript")
            save(out / "transcript.json", entries)
            capture(out, run, entries)
            subprocess.run(["docker", "cp", "samlscope-reference-suite:/data/target-metadata/" + run + ".xml", str(out / "target-metadata.xml")],
                check=True, capture_output=True, timeout=30)
        if failures:
            raise ValueError("Native restoration failed: " + ",".join(failures))
    print("Native current-key A/B/A originals recorded and restored; no verdict assigned", flush=True)


if __name__ == "__main__":
    main()
