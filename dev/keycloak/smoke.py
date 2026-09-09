#!/usr/bin/env python3
"""Complete the pinned Keycloak SAML login and verify that the SAMLscope Run finishes."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import quote, urlencode
from urllib.parse import urlparse
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener


@dataclass
class HtmlForm:
    action: str
    method: str
    fields: dict[str, str] = field(default_factory=dict)


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[HtmlForm] = []
        self.current: HtmlForm | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value or "" for key, value in attrs}
        if tag.lower() == "form":
            self.current = HtmlForm(values.get("action", ""), values.get("method", "get").lower())
            self.forms.append(self.current)
        elif tag.lower() == "input" and self.current is not None:
            name = values.get("name")
            input_type = values.get("type", "text").lower()
            if name and input_type not in {"button", "image", "reset", "submit"}:
                self.current.fields[name] = values.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self.current = None


def parse_forms(document: str) -> list[HtmlForm]:
    parser = FormParser()
    parser.feed(document)
    return parser.forms


def require_form(document: str, required_fields: set[str]) -> HtmlForm:
    for form in parse_forms(document):
        if required_fields <= set(form.fields):
            if not form.action:
                raise RuntimeError(f"form containing {sorted(required_fields)} has no action")
            return form
    raise RuntimeError(f"no form contains required fields {sorted(required_fields)}")


def permit_localhost_http_cookies(cookie_jar: http.cookiejar.CookieJar, page_url: str) -> None:
    """Mirror browsers' localhost exception for Secure cookies in this local-only fixture."""
    if urlparse(page_url).hostname not in {"localhost", "127.0.0.1", "::1"}:
        return
    for cookie in cookie_jar:
        # Python's CookieJar canonicalizes host-only localhost cookies to localhost.local.
        if cookie.domain.lstrip(".") in {"localhost", "localhost.local", "127.0.0.1", "::1"}:
            cookie.secure = False


def require_samlscope_completion_page(document: str) -> None:
    """Accept the current ACS receipt while remaining compatible with older M0 fixtures."""
    markers = ("SAML Response recorded", "M0 SSO round trip completed")
    if not any(marker in document for marker in markers):
        raise RuntimeError("SAMLscope ACS did not return the completion marker")


def request_text(opener, url: str, fields: dict[str, str] | None = None) -> tuple[str, str]:
    data = urlencode(fields).encode("utf-8") if fields is not None else None
    request = Request(url, data=data, headers={
        "User-Agent": "SAMLscope-Keycloak-Smoke/1",
        "Content-Type": "application/x-www-form-urlencoded",
    })
    try:
        with opener.open(request, timeout=30) as response:
            return response.geturl(), response.read().decode("utf-8", errors="replace")
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"request to {url} returned HTTP {error.code}: {detail}") from error


def request_bytes(
    opener,
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    content_type: str | None = None,
    headers: dict[str, str] | None = None,
) -> bytes:
    request_headers = {"User-Agent": "SAMLscope-Keycloak-Smoke/1", **(headers or {})}
    if content_type:
        request_headers["Content-Type"] = content_type
    request = Request(url, data=body, headers=request_headers, method=method)
    try:
        with opener.open(request, timeout=30) as response:
            return response.read()
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} returned HTTP {error.code}: {detail}") from error


def complete_round_trip(start_url: str, run_url: str, username: str, password: str) -> dict:
    cookie_jar = http.cookiejar.CookieJar()
    opener = build_opener(HTTPCookieProcessor(cookie_jar))
    login_url, login_page = request_text(opener, start_url)
    permit_localhost_http_cookies(cookie_jar, login_url)
    login = require_form(login_page, {"username", "password"})
    login.fields.update({"username": username, "password": password})

    _, saml_post_page = request_text(opener, login.action, login.fields)
    saml_post = require_form(saml_post_page, {"SAMLResponse"})
    _, completion_page = request_text(opener, saml_post.action, saml_post.fields)
    require_samlscope_completion_page(completion_page)

    _, run_document = request_text(opener, run_url)
    run = json.loads(run_document)
    if run.get("status") != "COMPLETED":
        raise RuntimeError(f"Run did not complete: status={run.get('status')!r}")
    context = run.get("context") or {}
    if context.get("m0RoundTrip") != "completed":
        raise RuntimeError("Run lacks the m0RoundTrip completion evidence")
    return run


def configure_keycloak_client(document: bytes) -> bytes:
    client = json.loads(document)
    if client.get("protocol") != "saml":
        raise RuntimeError("Keycloak metadata converter did not produce a SAML client")
    attributes = client.setdefault("attributes", {})
    # Keycloak 26.7.2's converter enables this even when the imported metadata says
    # AuthnRequestsSigned="false". Keep the fixture aligned with the actual metadata declaration.
    attributes["saml.client.signature"] = "false"
    return json.dumps(client).encode("utf-8")


def require_preflight_success(document: bytes) -> dict:
    report = json.loads(document)
    failures = [
        check for check in report.get("checks", [])
        if check.get("status") == "FAIL"
    ]
    if failures:
        details = "; ".join(
            f"{check.get('code', 'unknown')}: {check.get('message', 'preflight failed')}"
            for check in failures
        )
        raise RuntimeError(f"SAMLscope preflight failed: {details}")
    return report


def prepare_fixture(samlscope_base: str, keycloak_base: str, target_metadata_url: str) -> tuple[str, str]:
    opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
    token_body = urlencode({
        "client_id": "admin-cli",
        "username": "admin",
        "password": "admin",
        "grant_type": "password",
    }).encode("utf-8")
    token = json.loads(request_bytes(
        opener,
        f"{keycloak_base}/realms/master/protocol/openid-connect/token",
        method="POST",
        body=token_body,
        content_type="application/x-www-form-urlencoded",
    ))["access_token"]

    plan_request = {
        "name": "Keycloak 26.7.2 IdP smoke",
        "profile": "browser_sso_idp",
        "targetKind": "IDP",
        "targetEntityId": f"{keycloak_base}/realms/samlscope",
        "metadataSourceKind": "URL",
        "metadataSourceLocation": target_metadata_url,
        "suiteMetadataDelivery": "HTTP_URL",
        "declaredFeatures": {},
        "parameters": {
            "clockSkewToleranceSeconds": 180,
            "metadataRefreshWaitSeconds": 300,
            "testUserHint": "samlscope-m0-user",
        },
        "interaction": {"allowBrowserSteps": True, "allowAttestation": False, "preset": "quick"},
        "authorizedTarget": True,
    }
    plan_document = json.loads(request_bytes(
        opener,
        f"{samlscope_base}/api/plans",
        method="POST",
        body=json.dumps(plan_request).encode("utf-8"),
        content_type="application/json",
    ))
    plan_id = plan_document["plan"]["plan"]["id"]

    metadata = request_bytes(opener, f"{samlscope_base}/p/{quote(plan_id)}/metadata")
    converted_client = request_bytes(
        opener,
        f"{keycloak_base}/admin/realms/samlscope/client-description-converter",
        method="POST",
        body=metadata,
        content_type="application/xml",
        headers={"Authorization": f"Bearer {token}"},
    )
    client = configure_keycloak_client(converted_client)
    request_bytes(
        opener,
        f"{keycloak_base}/admin/realms/samlscope/clients",
        method="POST",
        body=client,
        content_type="application/json",
        headers={"Authorization": f"Bearer {token}"},
    )

    run = json.loads(request_bytes(
        opener,
        f"{samlscope_base}/api/plans/{quote(plan_id)}/runs",
        method="POST",
        body=b"",
    ))
    run_id = run["run"]["id"]
    preflight = request_bytes(
        opener,
        f"{samlscope_base}/api/runs/{quote(run_id)}/preflight",
        method="POST",
        body=b"",
    )
    require_preflight_success(preflight)
    return (
        f"{samlscope_base}/p/{quote(plan_id)}/start/m0-roundtrip?run={quote(run_id)}",
        f"{samlscope_base}/api/runs/{quote(run_id)}",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    round_trip = subparsers.add_parser("round-trip")
    round_trip.add_argument("--start-url", required=True)
    round_trip.add_argument("--run-url", required=True)
    fixture = subparsers.add_parser("fixture")
    fixture.add_argument("--samlscope-base", required=True)
    fixture.add_argument("--keycloak-base", required=True)
    fixture.add_argument("--target-metadata-url", required=True)
    fixture.add_argument("--manual", action="store_true")
    for command in (round_trip, fixture):
        command.add_argument("--username", default="samlscope-m0-user")
        command.add_argument("--password", default="samlscope-m0-password")
    args = parser.parse_args()
    if args.command == "fixture":
        start_url, run_url = prepare_fixture(
            args.samlscope_base, args.keycloak_base, args.target_metadata_url
        )
        if args.manual:
            print(f"Open: {start_url}")
            print(f"Run: {run_url}")
            return 0
    else:
        start_url, run_url = args.start_url, args.run_url
    run = complete_round_trip(start_url, run_url, args.username, args.password)
    print(f"Keycloak SAML round trip: PASS (run={run.get('id')}, status={run.get('status')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
