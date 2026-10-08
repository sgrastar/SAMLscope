#!/usr/bin/env python3
"""Qualify owned synthetic metadata through the deployed Suite's public API and real M0.

Only --execute creates Plans/Runs or sends HTTP. The caller must start the reviewed
in-memory SyntheticAdditionalMetadataFixture after authorizing the campaign.
Evidence is never adopted into a reference-product ledger.
"""
import argparse
import base64
import hashlib
import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from synthetic_public_evidence_guards import assert_public_json, public_json_document, persist_public_json


CASE = "IIP-MD05-a8-idp-01"
P = "urn:oasis:names:tc:SAML:2.0:protocol"
SCENARIOS = {"match": "SATISFIED", "mismatch": "VIOLATED", "html": None,
             "redirect": None, "unreachable": None, "unknown": None}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Form(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = {"action": attrs.get("action"), "method": attrs.get("method"), "fields": {}}
            self.forms.append(self.current)
        elif tag == "input" and self.current is not None:
            name = attrs.get("name")
            if name in self.current["fields"]:
                raise ValueError("Duplicate synthetic response field")
            self.current["fields"][name] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


def parse_form(html, suite, plan, run):
    form = Form()
    form.feed(html)
    if len(form.forms) != 1:
        raise ValueError("Exactly one normal response form required")
    result = form.forms[0]
    if result["action"] != f"{suite}/p/{plan}/sp/acs/0" or result["method"] != "post":
        raise ValueError("Normal response does not target the actual Suite ACS")
    if set(result["fields"]) != {"SAMLResponse", "RelayState"} or result["fields"]["RelayState"] != run:
        raise ValueError("Normal response RelayState is not bound to the actual Run")
    raw = base64.b64decode(result["fields"]["SAMLResponse"], validate=True)
    root = ET.fromstring(raw)
    if root.tag != f"{{{P}}}Response" or root.attrib.get("Destination") != result["action"]:
        raise ValueError("Synthetic response original has wrong type/Destination")
    return result, raw


def checked_origin(value):
    url = urllib.parse.urlsplit(value)
    if url.scheme not in {"http", "https"} or url.hostname not in {"localhost", "127.0.0.1", "host.docker.internal"} or url.username or url.password or url.path not in {"", "/"} or url.query or url.fragment:
        raise ValueError("Explicit owned local origin required")
    return value.rstrip("/")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="Required explicit gate for all HTTP/Run creation")
    parser.add_argument("--self-check", action="store_true", help="Verify form scope controls without HTTP")
    parser.add_argument("--suite", default="http://localhost:18080")
    parser.add_argument("--fixture", default="http://127.0.0.1:18936")
    parser.add_argument("--fixture-target", help="Fixture origin reachable by deployed Docker Suite; default is --fixture")
    parser.add_argument("--data-root")
    parser.add_argument("--docker-container", help="Owned Suite container only; reads its /data in place")
    parser.add_argument("--container-helper-dir", help="Fresh /tmp/samlscope-synthetic-* helper directory")
    parser.add_argument("--compiled-helper-root", default="build/synthetic-additional-fixture")
    parser.add_argument("--classpath", default="build/synthetic-additional-fixture:api/build/install/samlscope/lib/*")
    parser.add_argument("--output")
    parser.add_argument("--scenarios", nargs="+", choices=list(SCENARIOS), default=["match", "mismatch", "html", "redirect", "unreachable"])
    args = parser.parse_args()
    if args.self_check:
        suite, plan, run = "http://localhost:18080", "plan_0123456789ABCDEFGHJKMNPQRS", "run_0123456789ABCDEFGHJKMNPQRS"
        acs = f"{suite}/p/{plan}/sp/acs/0"
        raw = f"<p:Response xmlns:p='{P}' ID='_r' Version='2.0' Destination='{acs}'/>".encode()
        html = f"<form method='post' action='{acs}'><input name='SAMLResponse' value='{base64.b64encode(raw).decode()}'/><input name='RelayState' value='{run}'/></form>"
        parse_form(html, suite, plan, run)
        controls = [html.replace(run, "run_1123456789ABCDEFGHJKMNPQRS"), html.replace("/sp/acs/0", "/sp/acs/1", 1), html + html, html.replace("</form>", f"<input name='RelayState' value='{run}'/></form>")]
        for invalid in controls:
            try:
                parse_form(invalid, suite, plan, run)
            except ValueError:
                continue
            raise AssertionError("Counterexample was accepted")
        print(json.dumps({"selfCheck": "passed", "scopeCounterexamplesRejected": len(controls), "httpOperations": 0, "runsCreated": 0}))
        return
    if not args.execute:
        print(json.dumps({"prepared": True, "httpOperations": 0, "runsCreated": 0,
                          "requiredGate": "--execute after root GO", "plannedScenarios": args.scenarios}))
        return
    if not args.output or bool(args.data_root) == bool(args.docker_container):
        parser.error("--output and exactly one read mode (--data-root or --docker-container) are required with --execute")
    if args.docker_container:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.docker_container) or "samlscope" not in args.docker_container.lower():
            parser.error("Explicit owned Suite container name required")
        if not args.container_helper_dir or not re.fullmatch(r"/tmp/samlscope-synthetic-[a-z0-9-]+", args.container_helper_dir):
            parser.error("Fresh /tmp/samlscope-synthetic-* helper directory required")
    suite, fixture = checked_origin(args.suite), checked_origin(args.fixture)
    target = checked_origin(args.fixture_target or args.fixture)
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    opener = urllib.request.build_opener(NoRedirect)
    counts = {"suiteApiRequests": 0, "normalStartRequests": 0, "normalTargetRequests": 0,
              "normalResponseSubmissions": 0, "milestoneStartRequests": 0,
              "configurationConfirmations": 0, "manualAttestations": 0,
              "productCredentialPosts": 0, "productSettingWrites": 0,
              "suiteDockerExecAttempts": 0, "suiteDockerExecSuccesses": 0,
              "suiteHelperCopyAttempts": 0, "suiteHelperCopySuccesses": 0,
              "suiteHelperRemovalAttempts": 0, "suiteHelperRemovalSuccesses": 0}
    helper_installed = False

    def save(folder, name, value):
        assert_public_json(value)
        (folder / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")

    def http(url, method="GET", body=None, content_type=None):
        headers = {"Content-Type": content_type} if content_type else {}
        request = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            response = opener.open(request, timeout=45)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(6 * 1024 * 1024 + 1)
            if len(raw) > 6 * 1024 * 1024:
                raise ValueError("Oversize public response")
            return response.status, dict(response.headers), raw

    def api(path, method="GET", document=None):
        counts["suiteApiRequests"] += 1
        body = json.dumps(document).encode() if document is not None else (b"" if method == "POST" else None)
        status, response_headers, raw = http(suite + path, method, body, "application/json" if document is not None else None)
        operation = output / "api-operations"
        operation.mkdir(exist_ok=True)
        index = f"{counts['suiteApiRequests']:04d}"
        content_type = next((value for name, value in response_headers.items() if name.lower() == "content-type"), "")
        retained = False
        try:
            if "json" not in content_type.lower():
                raise ValueError("API response is not public JSON")
            document = persist_public_json(raw, operation / (index + ".response.json"))
            retained = True
        except ValueError:
            save(operation, index + ".operation.json", {"method": method, "path": path, "status": status,
                                                        "responseSha256": hashlib.sha256(raw).hexdigest(),
                                                        "responseBytes": len(raw), "responseRetained": False,
                                                        "nonPublicBodyOmitted": True})
            raise ValueError(f"Suite API {method} {path} returned {status}; non-public response omitted") from None
        save(operation, index + ".operation.json", {"method": method, "path": path, "status": status,
                                                    "responseSha256": hashlib.sha256(raw).hexdigest(),
                                                    "responseBytes": len(raw), "responseRetained": retained,
                                                    "nonPublicBodyOmitted": False})
        if not 200 <= status < 300:
            raise ValueError(f"Suite API {method} {path} returned {status}; public JSON original retained")
        return document

    def read_native(run, mode):
        if args.docker_container:
            counts["suiteDockerExecAttempts"] += 1
            completed = subprocess.run(["docker", "exec", args.docker_container, "java", "-cp",
                                        args.container_helper_dir + ":/opt/samlscope/lib/*",
                                        "com.samlscope.api.ReadSyntheticAdditionalRuntime", "/data", run, mode],
                                       check=True, capture_output=True, text=True)
            counts["suiteDockerExecSuccesses"] += 1
        else:
            completed = subprocess.run(["java", "-cp", args.classpath,
                                        "com.samlscope.api.ReadSyntheticAdditionalRuntime", args.data_root, run, mode],
                                       check=True, capture_output=True, text=True)
        return json.loads(completed.stdout)

    try:
        if args.docker_container:
            compiled = Path(args.compiled_helper_root).resolve() / "com/samlscope/api/ReadSyntheticAdditionalRuntime.class"
            if not compiled.is_file():
                raise ValueError("Reviewed compiled read-only helper is absent")
            # mkdir without -p refuses an existing path. Only this fresh owned helper
            # directory is copied or removed; the Suite data volume is never copied.
            counts["suiteDockerExecAttempts"] += 1
            subprocess.run(["docker", "exec", args.docker_container, "mkdir", args.container_helper_dir], check=True, capture_output=True)
            counts["suiteDockerExecSuccesses"] += 1
            helper_installed = True
            counts["suiteDockerExecAttempts"] += 1
            subprocess.run(["docker", "exec", args.docker_container, "mkdir", "-p", args.container_helper_dir + "/com/samlscope/api"], check=True, capture_output=True)
            counts["suiteDockerExecSuccesses"] += 1
            counts["suiteHelperCopyAttempts"] += 1
            subprocess.run(["docker", "cp", str(compiled), args.docker_container + ":" + args.container_helper_dir + "/com/samlscope/api/ReadSyntheticAdditionalRuntime.class"], check=True, capture_output=True)
            counts["suiteHelperCopySuccesses"] += 1
            save(output, "container-helper-placement.json", {"container": args.docker_container, "directory": args.container_helper_dir,
                                                             "classSha256": hashlib.sha256(compiled.read_bytes()).hexdigest(),
                                                             "readMode": "sqlite-mode-ro-query-only-in-place", "databaseCopied": False,
                                                             "sourceReadScope": "explicit-owned-synthetic-Run-only"})
    
        save(output, "profiles-before.json", api("/api/profiles"))
        reports = []
        for scenario in args.scenarios:
            folder = output / scenario
            folder.mkdir()
            before_stats = json.loads(http(fixture + "/stats")[2])
            plan_write = {"name": f"Synthetic runtime a8 {scenario}; no product adoption", "profile": "metadata_idp",
                          "targetKind": "IDP", "targetEntityId": target + "/entity",
                          "metadataSourceKind": "URL", "metadataSourceLocation": target + "/metadata/" + scenario,
                          "suiteMetadataDelivery": "MANUAL", "declaredFeatures": {},
                          "parameters": {"clockSkewToleranceSeconds": 180, "metadataRefreshWaitSeconds": 300,
                                         "testUserHint": "synthetic-public-principal"},
                          "interaction": {"allowBrowserSteps": True, "allowAttestation": False, "preset": "assisted"},
                          "authorizedTarget": True}
            created = api("/api/plans", "POST", plan_write)
            plan = created["plan"]["plan"]["id"]
            run_created = api(f"/api/plans/{plan}/runs", "POST")
            run = run_created["run"]["id"]
            save(folder, "created.json", {"plan": created, "run": run_created, "input": plan_write})
            save(folder, "native-scope-before-m0.json", read_native(run, "scope"))
            preflight = api(f"/api/runs/{run}/preflight", "POST")
            save(folder, "preflight.json", preflight)
            if any(check["status"] == "FAIL" for check in preflight["checks"]):
                raise ValueError("Synthetic metadata preflight failed")
            counts["normalStartRequests"] += 1
            status, headers, _ = http(f"{suite}/p/{plan}/start/m0-roundtrip?run={run}")
            location = headers.get("Location")
            if status != 302 or not location or urllib.parse.urlsplit(location)._replace(query="", fragment="").geturl() != target + "/sso":
                raise ValueError("Actual Suite M0 redirect does not target the owned synthetic IdP")
            counts["normalTargetRequests"] += 1
            # Docker and the host may use different aliases for this same owned
            # listener. Preserve the complete signature-covered raw query.
            parsed_location = urllib.parse.urlsplit(location)
            local_sso = fixture + parsed_location.path + "?" + parsed_location.query
            save(folder, "m0-target-network-alias.json", {"suiteOriginalRedirect": location, "collectorConnection": local_sso, "queryPreservedByteForByte": urllib.parse.urlsplit(local_sso).query == parsed_location.query})
            status, _, html = http(local_sso)
            if status != 200:
                raise ValueError("Synthetic IdP rejected the actual normal request")
            response, original = parse_form(html.decode(), suite, plan, run)
            (folder / "m0-signed-response.xml").write_bytes(original)
            counts["normalResponseSubmissions"] += 1
            status, _, receipt = http(response["action"], "POST", urllib.parse.urlencode(response["fields"]).encode(), "application/x-www-form-urlencoded")
            if status != 200:
                raise ValueError("Real Suite ACS did not record the synthetic normal response")
            completed = api(f"/api/runs/{run}")
            if completed["status"] != "COMPLETED" or completed["context"].get("m0RoundTrip") != "completed":
                raise ValueError("The real Run did not complete M0")
            save(folder, "m0-completed-run.json", completed)
            counts["milestoneStartRequests"] += 1
            save(folder, "m2-start.json", api(f"/api/runs/{run}/milestones/M2/start", "POST"))
            # A direct read-only snapshot is taken before any API that may reconcile
            # evidence. A positive/negative conclusion must already exist here.
            time.sleep(0.25)
            native = read_native(run, "runtime")
            save(folder, "native-before-result-api.json", native)
            execution = native["caseExecution"]
            if SCENARIOS[scenario] is not None and (execution["status"] != "FINISHED" or execution["outcome"]["outcome"] != SCENARIOS[scenario]):
                raise ValueError("First automatic M2 action did not produce the expected synthetic outcome")
            if SCENARIOS[scenario] is None and execution["status"] != "WAITING_CONFIG":
                raise ValueError("Unavailable/HTML/unknown observation did not remain a configuration wait")
            after_stats = json.loads(http(fixture + "/stats")[2])
            if before_stats["credentialHeaders"] != after_stats["credentialHeaders"]:
                raise ValueError("Fixture received credential/cookie headers")
            endpoint = "GET /additional/" + scenario
            additional_gets = after_stats["operations"].get(endpoint, 0) - before_stats["operations"].get(endpoint, 0)
            if scenario != "unknown" and additional_gets != 1:
                raise ValueError("Duplicate AML declarations did not share one GET original")
            if scenario == "redirect" and after_stats["operations"].get("GET /additional/match", 0) != before_stats["operations"].get("GET /additional/match", 0):
                raise ValueError("AML redirect was followed")
            if scenario == "html" and any(e["bodyBytes"] != 0 for e in native["transcriptOriginals"] if e["summary"].get("type") == "MetadataFetchResponse"):
                raise ValueError("Synthetic HTML response body was retained")
            if scenario == "unreachable" and any(e["sendResult"].get("http_status") != 503 for e in native["outbox"]):
                raise ValueError("The actual 503 original is unproven")
            save(folder, "fixture-operation-counts.json", {"before": before_stats, "after": after_stats, "additionalGets": additional_gets})
            result = api(f"/api/runs/{run}/result.json")
            save(folder, "result.json", result)
            case_result = next(c for requirement in result["requirements"] for c in requirement["cases"] if c["id"] == CASE)
            if SCENARIOS[scenario] is None and case_result["outcome"] != "NOT_VERIFIED":
                raise ValueError("Unavailable/HTML/unknown observation became a product conclusion")
            save(folder, "transcript.json", api(f"/api/runs/{run}/transcript"))
            reports.append({"scenario": scenario, "runId": run, "planId": plan,
                            "initialStoredStatus": execution["status"], "additionalGets": additional_gets,
                            "conclusionWithoutSecondOperatorAction": SCENARIOS[scenario] is not None,
                            "caseId": CASE, "syntheticOnly": True, "productEvidenceAdoption": False})
        save(output, "operation-counts.json", counts)
        save(output, "qualification.json", {"schema": "samlscope-synthetic-additional-qualification-v1", "campaigns": reports,
                                            "productEvidenceAdoption": False, "credentialsPersisted": False,
                                            "noSecondOperatorDeclaration": True})
        print(json.dumps({"output": str(output), "campaigns": reports}))
    finally:
        cleanup = {"requested": bool(args.docker_container), "helperInstalled": helper_installed,
                   "dataVolumeModifiedByHelper": False, "databaseCopied": False}
        if helper_installed:
            counts["suiteHelperRemovalAttempts"] += 1
            counts["suiteDockerExecAttempts"] += 1
            removed = subprocess.run(["docker", "exec", args.docker_container, "rm", "-r", "--", args.container_helper_dir], capture_output=True)
            cleanup["success"] = removed.returncode == 0
            cleanup["exitCode"] = removed.returncode
            if removed.returncode == 0:
                counts["suiteHelperRemovalSuccesses"] += 1
                counts["suiteDockerExecSuccesses"] += 1
        save(output, "container-helper-cleanup.json", cleanup)
        save(output, "operation-counts.json", counts)



if __name__ == "__main__":
    main()
