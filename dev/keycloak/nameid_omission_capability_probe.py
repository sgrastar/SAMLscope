#!/usr/bin/env python3
"""Reference-only Keycloak NameID configuration probes with exact temporary-client cleanup.

This recorder does not assign a verdict. It uses one new Suite Run and one temporary
Keycloak SAML client, preserving credentials only in memory.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse as urls
import urllib.request as http

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attribute_policy_capability_absence import product_token, redact_client_credentials
from import_metadata_batch import BASE, api, save
from reference_flow import Client

ADMIN = "http://localhost:18180/admin/realms/samlscope"
TARGET = "http://localhost:18180/realms/samlscope"
CONTAINER = "samlscope-reference-keycloak"


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    token = product_token()
    operations = []

    def admin(path, body=None, method="GET", content_type="application/json"):
        raw = None if body is None else (body if isinstance(body, bytes) else canonical(body))
        record = {"method": method, "path": path.split("?")[0], "status": "attempted"}
        operations.append(record)
        request = http.Request(ADMIN + path, data=raw, method=method, headers={
            "Authorization": "Bearer " + token, "Content-Type": content_type})
        try:
            with http.urlopen(request, timeout=40) as response:
                data = response.read()
                record["status"] = response.status
                return json.loads(data) if data else None
        except urllib.error.HTTPError as error:
            record["status"] = error.code
            record["error"] = error.read().decode(errors="replace")[:500]
            return None

    inspect = json.loads(subprocess.check_output(["docker", "inspect", CONTAINER]))[0]
    if not inspect["State"]["Running"] or inspect["Image"] != (
            "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"):
        raise RuntimeError("unexpected Keycloak runtime")
    save(out / "runtime.json", {"containerId": inspect["Id"], "imageId": inspect["Image"],
        "startedAt": inspect["State"]["StartedAt"],
        "providerFiles": subprocess.check_output(["docker", "exec", CONTAINER, "sh", "-c",
            "cd /opt/keycloak/providers && find . -type f -print | LC_ALL=C sort"]).decode().splitlines()})

    plan_result = api("/api/plans", {"name": "Keycloak NameID omission capability probe",
        "profile": "browser_sso_idp", "targetKind": "IDP", "targetEntityId": TARGET,
        "metadataSourceKind": "URL", "metadataSourceLocation":
            "http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor",
        "suiteMetadataDelivery": "HTTP_URL", "declaredFeatures": {},
        "parameters": {"clockSkewToleranceSeconds": 180, "metadataRefreshWaitSeconds": 300,
            "testUserHint": "samlscope-m0-user", "requestSigningMode": "REQUIRED"},
        "interaction": {"allowBrowserSteps": True, "allowAttestation": False, "preset": "quick"},
        "authorizedTarget": True})
    save(out / "plan.json", plan_result)
    plan = plan_result["plan"]["plan"]["id"]
    created = api("/api/plans/" + plan + "/runs", {})
    save(out / "created.json", created)
    run = created["run"]["id"]
    if not re.fullmatch(r"plan_[0-9A-HJKMNP-TV-Z]{26}", plan) or not re.fullmatch(
            r"run_[0-9A-HJKMNP-TV-Z]{26}", run):
        raise ValueError("invalid Suite identity")
    save(out / "preflight.json", api("/api/runs/" + run + "/preflight", {}))
    entity = BASE + "/p/" + plan
    lookup = "/clients?clientId=" + urls.quote(entity, safe="")
    before = admin(lookup)
    if before != []:
        raise RuntimeError("refusing existing client overwrite or failed lookup")
    save(out / "client-before.json", before)
    with http.urlopen(entity + "/metadata", timeout=30) as response:
        metadata = response.read()
    (out / "sp-metadata.xml").write_bytes(metadata)
    recipe = admin("/client-description-converter", metadata, "POST", "application/xml")
    if not isinstance(recipe, dict) or recipe.get("clientId") != entity:
        raise RuntimeError("native SAML converter did not return expected client")
    save(out / "client-converter-output.json", recipe)
    # Keep the temporary SSO control legible in the signed protocol original.
    # The production baseline still comes from the native metadata converter.
    recipe.setdefault("attributes", {})["saml.encrypt"] = "false"
    save(out / "client-recipe.json", recipe)

    owned = None
    original = None
    observations = []
    cleanup_errors = []
    try:
        if admin("/clients", recipe, "POST") is not None or operations[-1]["status"] != 201:
            raise RuntimeError("temporary client creation failed")
        rows = admin(lookup)
        if not isinstance(rows, list) or len(rows) != 1:
            raise RuntimeError("temporary client lookup ambiguous")
        owned = rows[0]["id"]
        if not re.fullmatch(r"[0-9a-f-]{36}", owned):
            raise RuntimeError("unexpected temporary client identifier")
        original = admin("/clients/" + owned)
        if not isinstance(original, dict) or original.get("clientId") != entity:
            raise RuntimeError("temporary client read-back failed")
        safe, redacted = redact_client_credentials(original)
        save(out / "original-client-redacted.json", safe)
        save(out / "redaction.json", {"removedPaths": redacted, "credentialsPersisted": False})

        def readback(label):
            value = admin("/clients/" + owned)
            if not isinstance(value, dict) or value.get("clientId") != entity:
                raise RuntimeError("temporary client changed identity")
            safe_value, redacted_value = redact_client_credentials(value)
            save(out / (label + "-client-redacted.json"), safe_value)
            if redacted_value != redacted:
                raise RuntimeError("client credential field shape changed")
            return value

        def set_client(value, label):
            if admin("/clients/" + owned, value, "PUT") is not None or operations[-1]["status"] != 204:
                raise RuntimeError(label + " client update failed")
            return readback(label)

        def flow(label):
            prior = {entry["id"] for entry in api("/api/runs/" + run + "/transcript")}
            record = {"condition": label, "beforeClientSha256": sha(canonical(
                redact_client_credentials(readback(label + "-before"))[0])), "status": "attempted"}
            observations.append(record)
            save(out / "observations.json", observations)
            try:
                record["flowStatus"] = Client().flow(entity + "/start/m0-roundtrip?run=" + run,
                    None, os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user"),
                    os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password"))
            except Exception as error:
                record["flowError"] = type(error).__name__ + ":" + str(error)[:300]
            finally:
                record["afterClientSha256"] = sha(canonical(
                    redact_client_credentials(readback(label + "-after"))[0]))
                record["newTranscriptIds"] = [entry["id"] for entry in
                    api("/api/runs/" + run + "/transcript") if entry["id"] not in prior]
                record["status"] = "recorded"
                save(out / "observations.json", observations)

        flow("baseline")
        unknown = copy.deepcopy(original)
        unknown.setdefault("attributes", {})["saml_name_id_format"] = "none"
        unknown["attributes"]["saml_force_name_id_format"] = "true"
        unknown_actual = set_client(unknown, "unknown-format")
        if unknown_actual.get("attributes", {}).get("saml_name_id_format") != "none":
            raise RuntimeError("unknown NameID format did not persist")
        flow("unknown-format")
        set_client(original, "restore-after-unknown")
        mapper = {"name": "samlscope-nameid-null-probe", "protocol": "saml",
            "protocolMapper": "saml-user-attribute-nameid-mapper", "consentRequired": False,
            "config": {"mapper.nameid.format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "user.attribute": "samlscope-absent-nameid-probe-attribute"}}
        mapped = copy.deepcopy(original)
        mapped.setdefault("attributes", {})["saml_name_id_format"] = "username"
        mapped["attributes"]["saml_force_name_id_format"] = "true"
        mapped.setdefault("protocolMappers", []).append(mapper)
        mapped_actual = set_client(mapped, "null-mapper")
        if not any(item.get("name") == mapper["name"] for item in mapped_actual.get("protocolMappers", [])):
            raise RuntimeError("NameID mapper did not persist")
        flow("null-mapper")
        installed = readback("null-mapper-before-delete").get("protocolMappers", [])
        matching = [item for item in installed if item.get("name") == mapper["name"]]
        if len(matching) != 1 or not re.fullmatch(r"[0-9a-f-]{36}", matching[0].get("id", "")):
            raise RuntimeError("cannot identify temporary NameID mapper for deletion")
        admin("/clients/" + owned + "/protocol-mappers/models/" + matching[0]["id"], method="DELETE")
        if operations[-1]["status"] != 204:
            raise RuntimeError("temporary NameID mapper deletion failed")
        set_client(original, "restore-after-null-mapper")
        current_safe, _ = redact_client_credentials(readback("restored-control"))
        original_safe, _ = redact_client_credentials(original)
        if current_safe != original_safe:
            raise RuntimeError("original client representation was not restored before final SSO")
        flow("restored")
    finally:
        if owned is None:
            rows = admin(lookup)
            if isinstance(rows, list) and len(rows) == 1:
                owned = rows[0]["id"]
        if owned is not None:
            try:
                current = admin("/clients/" + owned)
                if not isinstance(current, dict) or current.get("clientId") != entity:
                    raise RuntimeError("cleanup identity changed")
                if original is not None:
                    admin("/clients/" + owned, original, "PUT")
                    if operations[-1]["status"] != 204:
                        raise RuntimeError("cleanup update failed")
                admin("/clients/" + owned, method="DELETE")
                if operations[-1]["status"] != 204:
                    raise RuntimeError("temporary client deletion failed")
            except Exception as error:
                cleanup_errors.append(type(error).__name__ + ":" + str(error)[:300])
        after = admin(lookup)
        restored = before == after == [] and not cleanup_errors
        save(out / "client-after.json", after)
        save(out / "restoration.json", {"restored": restored, "temporaryClientId": owned,
            "beforeSha256": sha(canonical(before)), "afterSha256": sha(canonical(after)),
            "failures": cleanup_errors})
        save(out / "operations.json", {"run": run, "adminOperations": operations,
            "productConfigurationWrites": sum(op["method"] in ("POST", "PUT", "DELETE") and
                op["path"].startswith("/clients") for op in operations),
            "protocolRoundTrips": len(observations), "humanOperations": 0, "productRestarts": 0,
            "restored": restored})
        if not restored:
            raise RuntimeError("temporary Keycloak client was not restored")

    entries = api("/api/runs/" + run + "/transcript")
    save(out / "transcript.json", entries)
    manifest = []
    for entry in entries:
        ref = entry.get("decodedSamlRef")
        if not ref:
            continue
        if not re.fullmatch(r"tx_[0-9A-HJKMNP-TV-Z]{26}", entry["id"]) or Path(ref).is_absolute() or ".." in Path(ref).parts:
            raise RuntimeError("unsafe transcript reference")
        path = out / "decoded" / (entry["id"] + ".xml")
        path.parent.mkdir(exist_ok=True)
        subprocess.run(["docker", "cp", "samlscope-reference-suite:/data/" + ref, str(path)],
            check=True, stdout=subprocess.DEVNULL)
        manifest.append({"id": entry["id"], "file": str(path.relative_to(out)), "sha256": sha(path.read_bytes())})
    save(out / "decoded-manifest.json", manifest)
    save(out / "run-before-conclusion.json", api("/api/runs/" + run))
    try:
        save(out / "result-before-conclusion.json", api("/api/runs/" + run + "/result.json"))
    except RuntimeError:
        save(out / "result-before-conclusion-unavailable.json", {"reason": "tests-not-started",
            "verdictAdopted": False})
    print("Recorded", len(observations), "conditions; no verdict assigned; run", run)


if __name__ == "__main__":
    main()
