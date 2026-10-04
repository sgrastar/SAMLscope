#!/usr/bin/env python3
"""Record Keycloak's ACS-URL selection behavior after native console import.

This is a reference-only campaign.  It imports the Suite SP through Keycloak's
own console, temporarily adds the already published secondary POST ACS to the
imported client's accepted redirect URI list, reads the change back, runs to
IIP-IDP12-e-idp-01, then restores and deletes the temporary client.  It never
writes a verdict; the Suite and the paired fail-closed verifier decide whether
this evidence may be adopted.
"""
import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse as urls
import urllib.request as http
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
from import_metadata_batch import api, save, BASE  # noqa: E402
from reference_flow import Client  # noqa: E402

ADMIN = "http://localhost:18180/admin/realms/samlscope"
TOKEN_URL = "http://localhost:18180/realms/master/protocol/openid-connect/token"
CASE = "IIP-IDP12-e-idp-01"
USER = os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user")
PASSWORD = os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def token():
    body = urls.urlencode(dict(client_id="admin-cli", username=os.environ.get("KEYCLOAK_ADMIN_USERNAME", "admin"),
                               password=os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"),
                               grant_type="password")).encode()
    with http.urlopen(http.Request(TOKEN_URL, data=body), timeout=30) as response:
        return json.load(response)["access_token"]


def local_admin(access_token, operations):
    def request(path, body=None, method="GET"):
        request_body = None if body is None else canonical(body)
        req = http.Request(ADMIN + path,
            data=request_body,
            method=method, headers={"Authorization": "Bearer " + access_token,
                                     "Content-Type": "application/json"})
        record = {"method": method, "path": path.split("?", 1)[0], "status": "attempted"}
        if request_body is not None:
            record["request_json_sha256"] = sha(request_body)
        operations.append(record)
        try:
            with http.urlopen(req, timeout=30) as response:
                raw = response.read(); record["status"] = response.status
                if not raw:
                    return None
                value = json.loads(raw)
                # Bind a captured read-back to this exact Admin API response without
                # retaining a second, mutable copy in the operation log.
                record["response_json_sha256"] = sha(canonical(value))
                return value
        except urllib.error.HTTPError as error:
            record["status"] = error.code
            raise RuntimeError(f"Keycloak Admin API {method} {record['path']} returned {error.code}") from None
    return request


def client_lookup(admin, entity):
    found = admin("/clients?clientId=" + urls.quote(entity, safe=""))
    if len(found) > 1:
        raise ValueError("ambiguous Keycloak client lookup")
    if not found:
        return None
    identifier = found[0].get("id", "")
    if re.fullmatch(r"[a-f0-9-]{36}", identifier) is None:
        raise ValueError("invalid Keycloak temporary client identifier")
    detail = admin("/clients/" + identifier)
    if detail.get("id") != identifier or detail.get("clientId") != entity:
        raise ValueError("Keycloak client read-back identity mismatch")
    return detail


def safe_restore(admin, identifier, entity, original, output):
    current = admin("/clients/" + identifier)
    if current.get("clientId") != entity:
        raise ValueError("temporary client identity changed before restore")
    admin("/clients/" + identifier, original, "PUT")
    restored = admin("/clients/" + identifier)
    # The only supported intervention is the accepted redirect URI list.  Restore
    # that field exactly and also require all returned attributes to return exactly.
    restored_ok = (restored.get("redirectUris") == original.get("redirectUris")
                   and restored.get("attributes") == original.get("attributes")
                   and restored.get("clientId") == entity)
    restoration = {
        "original_sha256": sha(canonical(original)),
        "restored_sha256": sha(canonical(restored)),
        "redirect_uris_restored": restored.get("redirectUris") == original.get("redirectUris"),
        "attributes_restored": restored.get("attributes") == original.get("attributes"),
        "restored": restored_ok,
    }
    save(output / "client-restoration.json", restoration)
    if not restored_ok:
        raise RuntimeError("temporary Keycloak client did not restore its imported configuration")
    return restoration


def capture_runtime(output, action):
    subprocess.run([sys.executable, str(REPO / "dev/reference-acceptance/capture_keycloak_default_acs_runtime.py"),
                    str(output), action], check=True, timeout=180)


def export_run(output, run):
    entries = api("/api/runs/" + run + "/transcript")
    # The paired verifier consumes this unmodified transcript; formal
    # re-evaluation is captured separately by the runtime helper.
    save(output / "transcript.json", entries)
    for suffix in ("result.json", "report.html", "protocol-evidence"):
        try:
            with http.urlopen(BASE + "/api/runs/" + run + "/" + suffix, timeout=60) as response:
                (output / suffix).write_bytes(response.read())
        except Exception as error:
            save(output / (suffix.replace(".", "-") + "-unavailable.json"), {"reason": type(error).__name__})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--playwright-modules", required=True, type=Path)
    parser.add_argument("--max-probes", type=int, default=125)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError("refusing to overwrite evidence")
    out.mkdir(parents=True, exist_ok=True)
    operations, steps = [], []
    admin = local_admin(token(), operations)
    plan_result = api("/api/plans", dict(
        name="Keycloak ACS URL selection with native import", profile="browser_sso_idp", targetKind="IDP",
        targetEntityId="http://localhost:18180/realms/samlscope", metadataSourceKind="URL",
        metadataSourceLocation="http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor",
        suiteMetadataDelivery="HTTP_URL", declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
            metadataRefreshWaitSeconds=300, testUserHint=USER, requestSigningMode="REQUIRED"),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset="quick"), authorizedTarget=True))
    save(out / "plan.json", plan_result)
    plan = plan_result["plan"]["plan"]["id"]
    created = api("/api/plans/" + plan + "/runs", {})
    save(out / "created.json", created)
    run = created["run"]["id"]
    if re.fullmatch(r"plan_[0-9A-HJKMNP-TV-Z]{26}", plan) is None or re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", run) is None:
        raise ValueError("Suite issued an invalid plan or Run identifier")
    save(out / "preflight.json", api("/api/runs/" + run + "/preflight", {}))
    entity = BASE + "/p/" + plan
    with http.urlopen(entity + "/metadata", timeout=60) as response:
        fixture = response.read()
    (out / "suite-sp-metadata.xml").write_bytes(fixture)
    if client_lookup(admin, entity) is not None:
        raise ValueError("refusing to overwrite pre-existing Keycloak client")

    stage = out / "driver"; stage.mkdir()
    shutil.copyfile(REPO / "dev/keycloak/console_import.mjs", stage / "console_import.mjs")
    (stage / "node_modules").symlink_to(args.playwright_modules.resolve(), target_is_directory=True)
    identifier = None
    target_captured_start = False
    try:
        capture_runtime(out, "target-start"); target_captured_start = True
        imported = subprocess.run(["node", str(stage / "console_import.mjs"), "--fixture", str(out / "suite-sp-metadata.xml"),
            "--record", str(out / "import.json"), "--entity-id", entity], capture_output=True, text=True, timeout=300)
        (out / "console-import.log").write_text(imported.stdout + imported.stderr)
        if imported.returncode:
            raise RuntimeError("native Keycloak console import failed")
        original = client_lookup(admin, entity)
        if original is None:
            raise RuntimeError("native Keycloak console import did not create a client")
        identifier = original["id"]
        (out / "client-original.json").write_bytes(canonical(original))
        original_redirects = original.get("redirectUris")
        if not isinstance(original_redirects, list):
            raise ValueError("imported Keycloak client has no redirect URI list")
        primary, secondary = entity + "/sp/acs/0", entity + "/sp/acs/1"
        if primary not in original_redirects:
            raise ValueError("native console import did not preserve the primary POST ACS")
        if secondary in original_redirects:
            raise ValueError("native console import already accepts the secondary ACS")
        configured = copy.deepcopy(original)
        configured["redirectUris"] = sorted(set(original_redirects) | {secondary})
        admin("/clients/" + identifier, configured, "PUT")
        readback = client_lookup(admin, entity)
        # Store the full canonical product read-back before a browser request.  A
        # summary cannot prove which client the product actually configured.
        if readback is None:
            raise RuntimeError("Keycloak returned no temporary client read-back")
        (out / "client-configured-readback.json").write_bytes(canonical(readback))
        if readback is None or set(readback.get("redirectUris", [])) != set(configured["redirectUris"]):
            raise RuntimeError("Keycloak did not read back the temporary secondary ACS registration")
        if readback.get("attributes") != original.get("attributes"):
            raise RuntimeError("secondary ACS registration changed unrelated SAML attributes")
        save(out / "client-configuration.json", {
            "entity_id": entity, "client_database_id": identifier,
            "original_sha256": sha(canonical(original)), "original_redirect_uris": original_redirects,
            "configured_redirect_uris": readback.get("redirectUris"),
            "configured_readback_sha256": sha(canonical(readback)),
            "added_redirect_uri": secondary,
            "configuration_scope": "temporary existing console-imported client redirectUris only",
        })

        initial = Client().flow(entity + "/start/m0-roundtrip?run=" + run, None, USER, PASSWORD)
        save(out / "initial-login.json", {"receipt": initial})
        if initial != "recorded":
            raise RuntimeError("baseline Keycloak login did not record")
        save(out / "tests-start.json", api("/api/runs/" + run + "/tests/start", {}))
        target_seen = False
        for ordinal in range(args.max_probes):
            status = api("/api/runs/" + run + "/active-probe")
            case = status.get("caseId")
            if target_seen and case != CASE:
                steps.append({"ordinal": ordinal, "caseId": CASE, "action": "target-complete", "nextCaseId": case,
                              "state": status.get("state")})
                break
            if case == CASE:
                target_seen = True
            if status.get("state") == "AWAITING_RESPONSE":
                api("/api/runs/" + run + "/active-probe/abort", {})
                steps.append({"ordinal": ordinal, "caseId": case, "actionId": status.get("actionId"), "action": "abort"})
                save(out / "steps.json", steps)
                continue
            if status.get("state") != "READY":
                raise RuntimeError("active probe stopped in " + str(status.get("state")))
            result = Client().flow(status["startUrl"], None, USER, PASSWORD)
            after = api("/api/runs/" + run + "/active-probe")
            row = {"ordinal": ordinal, "caseId": case, "actionId": status.get("actionId"), "receipt": result,
                   "nextState": after.get("state"), "nextCaseId": after.get("caseId"), "nextActionId": after.get("actionId")}
            steps.append(row); save(out / "steps.json", steps)
            if after.get("actionId") == status.get("actionId") and after.get("state") == "AWAITING_RESPONSE":
                api("/api/runs/" + run + "/active-probe/abort", {})
                row["abort_after_unrecorded_terminal"] = True
                save(out / "steps.json", steps)
        else:
            raise RuntimeError("target ACS URL case not reached before probe limit")
        if not target_seen:
            raise RuntimeError("target ACS URL case was not reached")
        save(out / "evaluation-request.json", api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
        export_run(out, run)
    finally:
        cleanup = {"restore_attempted": False, "delete_attempted": False,
                   "redirect_uris_restored": False, "attributes_restored": False,
                   "read_back_absent": False, "restored": False}
        try:
            # A long browser campaign can outlive the original short-lived token.
            # Cleanup deliberately acquires a fresh token rather than reusing the
            # closure that performed the configuration write.
            admin = local_admin(token(), operations)
            found = client_lookup(admin, entity)
            if found is not None:
                identifier = found["id"]
                original_path = out / "client-configuration.json"
                if original_path.exists():
                    # Source-of-truth original is captured by this script, never re-created from metadata.
                    original_record = json.loads(original_path.read_text())
                    # Persisted SHA binds the original we captured; re-read it from its raw evidence.
                    raw_original = json.loads((out / "client-original.json").read_text()) if (out / "client-original.json").exists() else None
                    if raw_original is None or sha(canonical(raw_original)) != original_record["original_sha256"]:
                        raise RuntimeError("missing or altered original Keycloak client evidence")
                    cleanup["restore_attempted"] = True
                    restoration = safe_restore(admin, identifier, entity, raw_original, out)
                    cleanup["redirect_uris_restored"] = restoration["redirect_uris_restored"]
                    cleanup["attributes_restored"] = restoration["attributes_restored"]
                cleanup["delete_attempted"] = True
                admin("/clients/" + identifier, method="DELETE")
            cleanup["read_back_absent"] = client_lookup(admin, entity) is None
            cleanup["restored"] = cleanup.get("read_back_absent") is True
        except Exception as error:
            cleanup["error"] = type(error).__name__
        save(out / "cleanup.json", cleanup)
        # This is the authoritative array consumed by the verifier.  operations.json
        # repeats it only as a human-readable operation summary.
        save(out / "admin-operations.json", operations)
        save(out / "operations.json", {"run": run, "admin_operations": operations,
            "product_configuration_writes": sum(1 for operation in operations if operation["method"] == "PUT"),
            "temporary_client_delete": cleanup, "product_restarts": 0, "human_operations": 0,
            "protocol_starts": sum(1 for row in steps if "receipt" in row), "verdict_adopted": False})
        try:
            if target_captured_start:
                capture_runtime(out, "target-end")
        except Exception as error:
            save(out / "target-runtime-end-unavailable.json", {"reason": type(error).__name__})
        try:
            # Capture originals and a formal result only after cleanup.  This helper checks that
            # re-evaluation did not alter the transcript.
            capture_runtime(out, "suite")
        except Exception as error:
            save(out / "suite-capture-unavailable.json", {"reason": type(error).__name__})
        if not cleanup.get("restored"):
            raise RuntimeError("temporary Keycloak client cleanup was not verified")
    print("Keycloak IDP12.e campaign recorded", run)


if __name__ == "__main__":
    main()
