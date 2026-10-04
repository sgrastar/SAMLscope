#!/usr/bin/env python3
"""Prove a native Keycloak logout completed while no IdP-issued SAML LogoutRequest arrived.

The product is driven through its browser logout endpoint.  Admin API reads are used only to
prove that the same authenticated user session existed before, and disappeared after, the
logout.  Tokens, passwords, cookies, browser pages, and raw session identifiers are never
persisted.  The Suite still owns the SAML transcript and the final case outcomes.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse as urls
import urllib.request as http
from html.parser import HTMLParser
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))

from import_metadata_batch import BASE, api, save  # noqa: E402
from reference_flow import Client, parse_forms  # noqa: E402
from capture_run_originals import capture  # noqa: E402
from capture_terminal_http_runtime import capture as capture_runtime, capture_suite  # noqa: E402

ADMIN = "http://localhost:18180/admin/realms/samlscope"
TOKEN_URL = "http://localhost:18180/realms/master/protocol/openid-connect/token"
LOGOUT_URL = "http://localhost:18180/realms/samlscope/protocol/openid-connect/logout"
TARGET_ENTITY = "http://localhost:18180/realms/samlscope"
USER = os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user")
PASSWORD = os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password")
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def admin_token() -> str:
    body = urls.urlencode(dict(client_id="admin-cli", username="admin", password="admin",
                               grant_type="password")).encode()
    with http.urlopen(http.Request(TOKEN_URL, data=body), timeout=30) as response:
        return json.load(response)["access_token"]


def admin(token: str, path: str, body=None, method: str = "GET"):
    encoded = None if body is None else canonical(body)
    request = http.Request(ADMIN + path, data=encoded, method=method,
                           headers={"Authorization": "Bearer " + token,
                                    "Content-Type": "application/json"})
    with http.urlopen(request, timeout=30) as response:
        raw = response.read()
    return None if not raw else json.loads(raw)


def find_client(token: str, client_id: str):
    rows = admin(token, "/clients?clientId=" + urls.quote(client_id, safe=""))
    exact = [row for row in rows if row.get("clientId") == client_id]
    if len(exact) > 1:
        raise RuntimeError("Ambiguous Keycloak client read-back")
    return exact[0] if exact else None


def client_detail(token: str, client_id: str):
    row = find_client(token, client_id)
    return None if row is None else admin(token, "/clients/" + row["id"])


def redact_client(value):
    """Retain product read-back structure without persisting credentials."""
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if key.lower() in {"secret", "registrationaccesstoken"}
                      else redact_client(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_client(item) for item in value]
    return value


def user_id(token: str) -> str:
    rows = admin(token, "/users?exact=true&username=" + urls.quote(USER, safe=""))
    exact = [row for row in rows if row.get("username") == USER]
    if len(exact) != 1:
        raise RuntimeError("Expected exactly one reference user")
    return exact[0]["id"]


def user_sessions(token: str, identifier: str):
    rows = admin(token, "/users/" + identifier + "/sessions")
    if not isinstance(rows, list):
        raise RuntimeError("Unexpected Keycloak session response")
    return rows


def sanitized_sessions(rows, imported_internal_id: str):
    result = []
    for row in rows:
        session_id = str(row.get("id", ""))
        clients = row.get("clients") or {}
        if not isinstance(clients, dict):
            raise RuntimeError("Unexpected Keycloak clients map")
        result.append({
            "session_id_sha256": SHA(session_id.encode()),
            "started": row.get("start"),
            "last_access": row.get("lastAccess"),
            "imported_client_present": imported_internal_id in clients,
            "client_internal_ids_sha256": sorted(SHA(str(key).encode()) for key in clients),
        })
    return sorted(result, key=lambda value: value["session_id_sha256"])


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def page_diagnostics(document: str):
    title = re.search(r"<title[^>]*>(.*?)</title>", document, re.I | re.S)
    parsed_forms = parse_forms(document)
    return {
        "title": " ".join(re.sub(r"<[^>]+>", " ", title.group(1)).split())[:120]
        if title else "",
        "form_field_names": [sorted(form.fields) for form in parsed_forms],
        "has_frontchannel_message": "frontchannel-logout" in document,
        "has_logout_confirm_form": "kc-logout-confirm" in document,
    }


class _FrameParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.sources = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "iframe":
            return
        source = dict(attrs).get("src")
        if source:
            self.sources.append(source)


def confirm_logout(client: Client):
    started_at = now()
    cookies_before = sorted({cookie.name for cookie in client.jar})
    url, page, status = client.request(LOGOUT_URL)
    initial = {"url": url, "status": status, "body_sha256": SHA(page.encode()),
               "diagnostics": page_diagnostics(page)}
    forms = parse_forms(page)
    candidates = [form for form in forms if "logout" in form.action.lower()
                  or "session_code" in form.fields or "confirmLogout" in form.fields]
    if len(candidates) != 1:
        raise RuntimeError("Keycloak logout confirmation form was not uniquely identified")
    form = candidates[0]
    fields = dict(form.fields)
    # Preserve the product-emitted submit value.  The fallback is used only when an
    # HTML parser omits the submit control.
    fields.setdefault("confirmLogout", "Logout")
    final_url, final_page, final_status = client.request(urls.urljoin(url, form.action), fields)
    continuation = []
    terminal_url, terminal_page, terminal_status = final_url, final_page, final_status
    for _ in range(8):
        saml_forms = [candidate for candidate in parse_forms(terminal_page)
                      if "SAMLRequest" in candidate.fields or "SAMLResponse" in candidate.fields]
        if not saml_forms:
            break
        if len(saml_forms) != 1:
            raise RuntimeError("Ambiguous SAML logout continuation forms")
        continuation_form = saml_forms[0]
        kind = "SAMLRequest" if "SAMLRequest" in continuation_form.fields else "SAMLResponse"
        action = urls.urljoin(terminal_url, continuation_form.action)
        parsed_action = urls.urlsplit(action)
        if parsed_action.hostname not in {"localhost", "127.0.0.1"}:
            raise RuntimeError("Refusing a nonlocal SAML logout continuation")
        terminal_url, terminal_page, terminal_status = client.request(action,
                                                                       continuation_form.fields)
        continuation.append({
            "message_kind": kind,
            "action_url_sha256": SHA(action.encode()),
            "action_origin_path":
                f"{parsed_action.scheme}://{parsed_action.hostname}:{parsed_action.port}{parsed_action.path}",
            "response_status": terminal_status,
            "response_body_sha256": SHA(terminal_page.encode()),
        })
    else:
        raise RuntimeError("SAML logout continuation exceeded hop limit")
    frames = _FrameParser()
    frames.feed(terminal_page)
    frontchannel = []
    for source in frames.sources:
        frame_url = urls.urljoin(terminal_url, source)
        parsed = urls.urlsplit(frame_url)
        if parsed.hostname not in {"localhost", "127.0.0.1"}:
            raise RuntimeError("Refusing a nonlocal front-channel logout frame")
        receipt = client.flow(frame_url, None, USER, PASSWORD)
        frontchannel.append({
            "url_sha256": SHA(frame_url.encode()),
            "origin_path": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}{parsed.path}",
            "receipt": receipt,
        })
    return {
        "started_at": started_at,
        "completed_at": now(),
        "initial": initial,
        "final": {"url": final_url, "status": final_status,
                  "body_sha256": SHA(final_page.encode()),
                  "diagnostics": page_diagnostics(final_page)},
        "frontchannel_frames": frontchannel,
        "saml_continuation": continuation,
        "terminal": {"status": terminal_status,
                     "body_sha256": SHA(terminal_page.encode()),
                     "diagnostics": page_diagnostics(terminal_page)},
        "cookie_names_before": cookies_before,
        "cookie_names_after": sorted({cookie.name for cookie in client.jar}),
        "confirmation_submitted": True,
    }


def fetch_bytes(path: str) -> bytes:
    with http.urlopen(BASE + path, timeout=40) as response:
        return response.read()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--playwright-modules", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError("Evidence directory must be empty")
    out.mkdir(parents=True, exist_ok=True)
    stage = out / "driver"
    stage.mkdir()
    shutil.copy2(REPO / "dev/keycloak/console_import.mjs", stage / "console_import.mjs")
    (stage / "node_modules").symlink_to(args.playwright_modules.resolve(), target_is_directory=True)

    operations = {
        "product_configuration_writes": 0,
        "product_configuration_restorations": 0,
        "product_restarts": 0,
        "product_session_reads": 0,
        "browser_logins": 0,
        "browser_logouts": 0,
        "human_operations": 0,
    }
    plan_request = {
        "name": "Keycloak native target logout absence",
        "profile": "single_logout_idp",
        "targetKind": "IDP",
        "targetEntityId": TARGET_ENTITY,
        "metadataSourceKind": "URL",
        "metadataSourceLocation": "http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor",
        "suiteMetadataDelivery": "HTTP_URL",
        "declaredFeatures": {},
        "parameters": {"clockSkewToleranceSeconds": 180, "metadataRefreshWaitSeconds": 300,
                       "testUserHint": USER, "requestSigningMode": "REQUIRED"},
        "interaction": {"allowBrowserSteps": True, "allowAttestation": False, "preset": "quick"},
        "authorizedTarget": True,
    }
    save(out / "plan-request.json", plan_request)
    plan_result = api("/api/plans", plan_request)
    save(out / "plan.json", plan_result)
    plan = plan_result["plan"]["plan"]["id"]
    created = api("/api/plans/" + plan + "/runs", {})
    save(out / "created.json", created)
    run = created["run"]["id"]
    if re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", run) is None:
        raise RuntimeError("Unsafe Run identifier")
    save(out / "preflight.json", api("/api/runs/" + run + "/preflight", {}))
    entity = BASE + "/p/" + plan
    metadata = fetch_bytes("/p/" + plan + "/metadata")
    (out / "suite-sp-metadata.xml").write_bytes(metadata)

    token = admin_token()
    if client_detail(token, entity) is not None:
        raise RuntimeError("Refusing to overwrite an existing Suite SP client")
    imported_id = None
    initial_absence = canonical(admin(token, "/clients?clientId=" + urls.quote(entity, safe="")))
    (out / "initial-client-absence.json").write_bytes(initial_absence)
    if json.loads(initial_absence) != []:
        raise RuntimeError("Suite SP client was not initially absent")
    capture_runtime(out, "keycloak", "start")
    try:
        imported = subprocess.run([
            "node", str(stage / "console_import.mjs"),
            "--fixture", str(out / "suite-sp-metadata.xml"),
            "--record", str(out / "console-import.json"),
            "--entity-id", entity,
        ], text=True, capture_output=True, timeout=300)
        (out / "console-import.log").write_text(imported.stdout + imported.stderr)
        if imported.returncode:
            raise RuntimeError("Keycloak native console import failed")
        operations["product_configuration_writes"] += 1
        token = admin_token()
        detail = client_detail(token, entity)
        if detail is None or detail.get("clientId") != entity:
            raise RuntimeError("Imported Suite SP client was not read back")
        imported_id = detail["id"]
        (out / "imported-client-readback.json").write_bytes(canonical(redact_client(detail)))

        browser = Client()
        login = browser.flow(entity + "/start/m0-roundtrip?run=" + run, None, USER, PASSWORD)
        operations["browser_logins"] += 1
        save(out / "initial-login.json", {"run": run, "receipt": login})
        if login != "recorded":
            raise RuntimeError("Initial SAML login did not complete")
        save(out / "tests-start.json", api("/api/runs/" + run + "/tests/start", {}))
        save(out / "target-intent.json", api("/api/runs/" + run + "/target-initiated",
                                              {"kind": "TARGET_LOGOUT"}))

        token = admin_token()
        uid = user_id(token)
        before = user_sessions(token, uid)
        operations["product_session_reads"] += 1
        sanitized_before = sanitized_sessions(before, imported_id)
        save(out / "sessions-before.json", sanitized_before)
        matching = [row for row in sanitized_before if row["imported_client_present"]]
        if not matching:
            raise RuntimeError("No product session was bound to the imported Suite SP")
        before_hashes = {row["session_id_sha256"] for row in matching}
        transcript_before = api("/api/runs/" + run + "/transcript")
        save(out / "transcript-before-logout.json", transcript_before)

        logout = confirm_logout(browser)
        operations["browser_logouts"] += 1
        save(out / "logout-browser.json", logout)
        deadline = time.monotonic() + 30
        while True:
            token = admin_token()
            current = user_sessions(token, uid)
            operations["product_session_reads"] += 1
            safe = sanitized_sessions(current, imported_id)
            current_hashes = {row["session_id_sha256"] for row in safe}
            if before_hashes.isdisjoint(current_hashes):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Authenticated product session remained after native logout")
            time.sleep(0.5)
        save(out / "sessions-after.json", safe)
        logout["session_absence_observed_at"] = now()
        save(out / "logout-browser.json", logout)

        save(out / "target-conclude.json",
             api("/api/runs/" + run + "/target-initiated/conclude", {}))
        save(out / "protocol-evaluation.json",
             api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
        transcript_after = api("/api/runs/" + run + "/transcript")
        save(out / "transcript.json", transcript_after)
        capture(out, run, transcript_after)
        (out / "result.json").write_bytes(fetch_bytes("/api/runs/" + run + "/result.json"))
        (out / "report.html").write_bytes(fetch_bytes("/api/runs/" + run + "/report.html"))
    finally:
        cleanup = {"attempted": True, "initially_absent": True, "deleted": False,
                   "final_absence": False}
        try:
            token = admin_token()
            current = client_detail(token, entity)
            if current is not None:
                if imported_id is not None and current.get("id") != imported_id:
                    raise RuntimeError("Concurrent Suite SP client replacement detected")
                admin(token, "/clients/" + current["id"], method="DELETE")
                operations["product_configuration_restorations"] += 1
                cleanup["deleted"] = True
            final = admin(token, "/clients?clientId=" + urls.quote(entity, safe=""))
            (out / "final-client-absence.json").write_bytes(canonical(final))
            cleanup["final_absence"] = final == []
            if not cleanup["final_absence"]:
                raise RuntimeError("Suite SP client remained after cleanup")
        finally:
            save(out / "cleanup.json", cleanup)
            save(out / "operation-counts.json", operations)
            try:
                capture_runtime(out, "keycloak", "end")
            except Exception as error:
                save(out / "final-runtime-capture-error.json", {"type": type(error).__name__})

    capture_suite(out)
    print("Keycloak native target logout evidence collected", run)


if __name__ == "__main__":
    main()
