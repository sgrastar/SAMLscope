#!/usr/bin/env python3
"""Public-API Artifact qualification against an isolated owned Suite and synthetic IdP.

No credentials, product configuration, DB writes, cached verdicts, or saved-Run
membership changes. All actual SAML bytes are exported by a query-only reader.
"""
import argparse
import base64
import hashlib
import json
import re
import subprocess
import time
import urllib.parse
from pathlib import Path
from synthetic_additional_runtime_smoke import Form, NoRedirect, checked_origin
from synthetic_public_evidence_guards import assert_public_json, public_json_document, persist_public_json, validate_selected_export
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

CASE = "IIP-IDP12-f-idp-01"
P = "urn:oasis:names:tc:SAML:2.0:protocol"
FIXTURES = ["post-binding-control", "redirect-binding", "unsupported-binding", "artifact-binding"]


def sole_form(raw):
    parser = Form()
    parser.feed(raw.decode())
    if len(parser.forms) != 1 or parser.forms[0]["method"].lower() != "post":
        raise ValueError("Exactly one public SAML POST form required")
    return parser.forms[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--suite", default="http://localhost:18081")
    parser.add_argument("--fixture", default="http://127.0.0.1:18937")
    parser.add_argument("--fixture-target", default="http://host.docker.internal:18937")
    parser.add_argument("--docker-container", default="samlscope-synthetic-artifact-v236-20261008")
    parser.add_argument("--container-helper-dir", required=True)
    parser.add_argument("--compiled-helper-root", default="build/synthetic-additional-fixture")
    parser.add_argument("--output", required=True)
    parser.add_argument("--modes", nargs="+", choices=["signed", "unsigned"], default=["signed", "unsigned"])
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({"prepared": True, "httpOperations": 0, "runsCreated": 0}))
        return
    suite, fixture, target = map(checked_origin, (args.suite, args.fixture, args.fixture_target))
    if suite != "http://localhost:18081" or not re.fullmatch(r"samlscope-synthetic-artifact-[a-z0-9-]+", args.docker_container):
        raise ValueError("Explicit isolated owned Artifact Suite required")
    if not re.fullmatch(r"/tmp/samlscope-synthetic-artifact-[a-z0-9-]+", args.container_helper_dir):
        raise ValueError("Fresh owned temporary helper directory required")
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    opener = urllib.request.build_opener(NoRedirect)
    counts = {"httpAttempts": 0, "suiteApiAttempts": 0, "normalStartAttempts": 0,
              "normalTargetAttempts": 0, "normalResponseSubmissions": 0,
              "selectedTargetAttempts": 0, "selectedResponseSubmissions": 0,
              "skippedBeforeTargetSubmission": 0, "probePreparationAttempts": 0,
              "suiteDockerExecAttempts": 0, "suiteDockerExecSuccesses": 0,
              "helperCopyAttempts": 0, "helperCopySuccesses": 0,
              "helperRemovalAttempts": 0, "helperRemovalSuccesses": 0,
              "credentialPosts": 0, "productConfigurationWrites": 0, "operatorVerdictAnswers": 0}
    installed = False

    def save(folder, name, value):
        assert_public_json(value)
        (folder / name).write_text(json.dumps(value, indent=2) + "\n")

    def http(url, method="GET", body=None, content_type=None, api=False):
        counts["httpAttempts"] += 1
        if api:
            counts["suiteApiAttempts"] += 1
        request = urllib.request.Request(url, method=method, data=body,
                                         headers={"Content-Type": content_type} if content_type else {})
        try:
            response = opener.open(request, timeout=45)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                raise ValueError("Oversize public response")
            headers = dict(response.headers)
            status = response.status
        if api or status >= 400:
            folder = output / "http-operations"
            folder.mkdir(exist_ok=True)
            index = f"{counts['httpAttempts']:04d}"
            kind = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
            retained, denied = False, False
            if "json" in kind.lower():
                try:
                    persist_public_json(raw, folder / (index + ".response.body"))
                    retained = True
                except ValueError:
                    denied = True
            elif api:
                denied = True
            save(folder, index + ".operation.json", {"method": method, "url": url, "status": status,
                                                      "contentType": kind, "responseBytes": len(raw),
                                                      "responseSha256": hashlib.sha256(raw).hexdigest(),
                                                      "responseRetained": retained, "nonPublicBodyOmitted": not retained})
            if denied:
                raise ValueError(f"Suite API returned {status}; non-public response omitted") from None
        return status, headers, raw

    def api(path, document=None, post=False):
        body = json.dumps(document).encode() if document is not None else (b"" if post else None)
        status, _, raw = http(suite + path, "POST" if post else "GET", body,
                             "application/json" if document is not None else None, True)
        if not 200 <= status < 300:
            raise ValueError(f"Suite API {path} returned {status}; first original retained")
        return public_json_document(raw)

    def docker_exec(*command):
        counts["suiteDockerExecAttempts"] += 1
        completed = subprocess.run(["docker", "exec", args.docker_container, *command], check=True, capture_output=True, text=True)
        counts["suiteDockerExecSuccesses"] += 1
        return completed.stdout

    def copy_public(source, destination):
        counts["helperCopyAttempts"] += 1
        subprocess.run(["docker", "cp", str(source), args.docker_container + ":" + destination], check=True, capture_output=True)
        counts["helperCopySuccesses"] += 1

    def read_native(run, mode, public_metadata=None):
        command = ["java", "-cp", args.container_helper_dir + ":/opt/samlscope/lib/*",
                   "com.samlscope.api.ReadSyntheticArtifactRuntime", "/data", run, mode]
        if public_metadata:
            command.append(public_metadata)
        return json.loads(docker_exec(*command))

    def local_target(url, path):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme + "://" + parsed.netloc != target or parsed.path != path or parsed.fragment:
            raise ValueError("Target form escaped the owned synthetic endpoint")
        return fixture + path + ("?" + parsed.query if parsed.query else "")

    try:
        compiled = Path(args.compiled_helper_root).resolve() / "com/samlscope/api"
        classes = sorted(compiled.glob("ReadSyntheticArtifactRuntime*.class"))
        if not classes:
            raise ValueError("Reviewed read-only Artifact helper is unavailable")
        docker_exec("mkdir", args.container_helper_dir)
        installed = True
        docker_exec("mkdir", "-p", args.container_helper_dir + "/com/samlscope/api")
        for compiled_class in classes:
            copy_public(compiled_class, args.container_helper_dir + "/com/samlscope/api/" + compiled_class.name)
        save(output, "helper-placement.json", {"container": args.docker_container, "directory": args.container_helper_dir,
                                               "classes": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in classes},
                                               "databaseCopied": False, "readerMode": "sqlite-mode-ro-query-only"})
        reports = []
        for mode in args.modes:
            folder = output / mode
            folder.mkdir()
            stats_before = json.loads(http(fixture + "/stats")[2])
            document = {"name": "Synthetic artifact runtime " + mode, "profile": "browser_sso_idp", "targetKind": "IDP",
                        "targetEntityId": target + "/" + mode + "/entity", "metadataSourceKind": "URL",
                        "metadataSourceLocation": target + "/" + mode + "/metadata", "suiteMetadataDelivery": "MANUAL",
                        "declaredFeatures": {"artifact_binding": True},
                        "parameters": {"clockSkewToleranceSeconds": 180, "metadataRefreshWaitSeconds": 300,
                                       "testUserHint": "synthetic-public-principal", "requestSigningMode": "REQUIRED"},
                        "interaction": {"allowBrowserSteps": True, "allowAttestation": False, "preset": "assisted"},
                        "authorizedTarget": True}
            created = api("/api/plans", document, True)
            plan = created["plan"]["plan"]["id"]
            run_created = api(f"/api/plans/{plan}/runs", post=True)
            run = run_created["run"]["id"]
            save(folder, "created.json", {"plan": created, "run": run_created, "input": document})
            save(folder, "native-scope-before-m0.json", read_native(run, "scope"))
            status, _, metadata = http(f"{suite}/p/{plan}/metadata")
            if status != 200:
                raise ValueError("Public Suite Plan metadata unavailable")
            (folder / "suite-public-metadata.xml").write_bytes(metadata)
            metadata_in_container = args.container_helper_dir + "/" + mode + "-suite-public-metadata.xml"
            copy_public(folder / "suite-public-metadata.xml", metadata_in_container)
            preflight = api(f"/api/runs/{run}/preflight", post=True)
            save(folder, "preflight.json", preflight)
            if any(c["status"] == "FAIL" for c in preflight["checks"]):
                raise ValueError("Synthetic Artifact preflight failed")
            counts["normalStartAttempts"] += 1
            status, headers, _ = http(f"{suite}/p/{plan}/start/m0-roundtrip?run={run}")
            location = next((v for k, v in headers.items() if k.lower() == "location"), None)
            if status != 302 or not location:
                raise ValueError("Real M0 redirect missing")
            counts["normalTargetAttempts"] += 1
            status, _, page = http(local_target(location, f"/{mode}/sso"))
            if status != 200:
                raise ValueError("Synthetic IdP rejected the real M0 request")
            normal = sole_form(page)
            if normal["action"] != f"{suite}/p/{plan}/sp/acs/0" or set(normal["fields"]) != {"SAMLResponse", "RelayState"} or normal["fields"]["RelayState"] != run:
                raise ValueError("Normal response form escaped the actual Run/Plan")
            normal_bytes = base64.b64decode(normal["fields"]["SAMLResponse"], validate=True)
            (folder / "m0-signed-response.xml").write_bytes(normal_bytes)
            counts["normalResponseSubmissions"] += 1
            status, _, _ = http(normal["action"], "POST", urllib.parse.urlencode(normal["fields"]).encode(), "application/x-www-form-urlencoded")
            if status != 200 or api(f"/api/runs/{run}")["status"] != "COMPLETED":
                raise ValueError("Real M0 did not complete")
            save(folder, "m1-start.json", api(f"/api/runs/{run}/milestones/M1/start", post=True))
            seen = set()
            observed = []
            steps = []
            for attempt in range(200):
                active = api(f"/api/runs/{run}/active-probe")
                if active["state"] != "READY":
                    save(folder, "terminal-active-probe.json", active)
                    break
                action = active["actionId"]
                if action in seen or active["planId"] != plan:
                    raise ValueError("Duplicate or foreign prepared action")
                seen.add(action)
                start = active["startUrl"]
                if start != f"{suite}/p/{plan}/probe/{action}?run={run}":
                    raise ValueError("Probe URL is not the actual bound action")
                counts["probePreparationAttempts"] += 1
                status, _, handoff = http(start, "POST", urllib.parse.urlencode({"freshSessionConfirmed": "true" if active["requiresFreshSession"] else "false"}).encode(), "application/x-www-form-urlencoded")
                if status != 200:
                    raise ValueError("Public probe preparation failed")
                if active["caseId"] != CASE:
                    api(f"/api/runs/{run}/active-probe/abort", post=True)
                    counts["skippedBeforeTargetSubmission"] += 1
                    steps.append({"caseId": active["caseId"], "actionId": action, "targetSubmitted": False})
                    continue
                request = sole_form(handoff)
                if set(request["fields"]) != {"SAMLRequest", "RelayState"}:
                    raise ValueError("Unexpected selected AuthnRequest form fields")
                raw = base64.b64decode(request["fields"]["SAMLRequest"], validate=True)
                root = ET.fromstring(raw)
                if root.attrib.get("ID") != "_" + action:
                    raise ValueError("Actual signed request has wrong action ID")
                expected_fixture = FIXTURES[len(observed)] if len(observed) < len(FIXTURES) else None
                if expected_fixture is None:
                    raise ValueError("Unexpected fifth selected protocol operation")
                (folder / (expected_fixture + "-authn-request.xml")).write_bytes(raw)
                counts["selectedTargetAttempts"] += 1
                status, _, reply_page = http(local_target(request["action"], f"/{mode}/sso"), "POST", urllib.parse.urlencode(request["fields"]).encode(), "application/x-www-form-urlencoded")
                if status != 200:
                    raise ValueError("Synthetic IdP rejected the actual selected request")
                reply = sole_form(reply_page)
                field = "SAMLart" if expected_fixture == "artifact-binding" else "SAMLResponse"
                expected_acs = f"{suite}/p/{plan}/sp/acs/" + ("4" if field == "SAMLart" else "0")
                if reply["action"] != expected_acs or set(reply["fields"]) != {field, "RelayState"} or reply["fields"]["RelayState"] != request["fields"]["RelayState"]:
                    raise ValueError("Actual selected response escaped the action/ACS")
                if field == "SAMLResponse":
                    (folder / (expected_fixture + "-signed-response.xml")).write_bytes(base64.b64decode(reply["fields"][field], validate=True))
                else:
                    save(folder, "artifact-callback-input.json", {"endpoint": reply["action"], "fields": reply["fields"], "actionId": action})
                counts["selectedResponseSubmissions"] += 1
                status, _, _ = http(reply["action"], "POST", urllib.parse.urlencode(reply["fields"]).encode(), "application/x-www-form-urlencoded")
                if status != 200:
                    raise ValueError("Actual Suite selected callback failed")
                observed.append(expected_fixture)
                steps.append({"caseId": CASE, "actionId": action, "fixture": expected_fixture, "targetSubmitted": True})
                if expected_fixture == "artifact-binding":
                    # The public callback runs the direct outbox resolution. Do
                    # not call a second evidence-evaluation operation to finish it.
                    break
            save(folder, "public-probe-steps.json", steps)
            time.sleep(0.25)
            native = read_native(run, "runtime", metadata_in_container)
            save(folder, "native-before-result-api.json", native)
            originals = folder / "originals"
            originals.mkdir()
            for original in native["transcriptOriginals"]:
                if not re.fullmatch(r"tx_[0-9A-HJKMNP-TV-Z]{26}", original["id"]):
                    raise ValueError("Original reference has unsafe filename")
                for field, suffix in [("bodyBase64", ".body"), ("decodedSamlBase64", ".saml.xml")]:
                    if original.get(field):
                        (originals / (original["id"] + suffix)).write_bytes(base64.b64decode(original[field], validate=True))
            selected_gate = validate_selected_export(native, folder)
            save(folder, "selected-export-gate.json", selected_gate)
            save(folder, "transcript.json", api(f"/api/runs/{run}/transcript"))
            save(folder, "result.json", api(f"/api/runs/{run}/result.json"))
            stats_after = json.loads(http(fixture + "/stats")[2])
            save(folder, "fixture-operation-counts.json", {"before": stats_before, "after": stats_after})
            if observed != FIXTURES:
                raise ValueError("Approved conditional Artifact case did not observe all four fixtures")
            if stats_after["credentialHeaders"] != stats_before["credentialHeaders"] or stats_after["resolutions"] - stats_before["resolutions"] != 1:
                raise ValueError("Credential-free single Artifact resolution unproven")
            execution = native["caseExecution"]
            if execution["status"] != "FINISHED" or execution["outcome"]["outcome"] != "SATISFIED":
                raise ValueError("Real conditional Artifact case remains unverified; first originals preserved")
            if native.get("runtimeProofVerified") is not True:
                raise ValueError("Independent original-backed Artifact runtime proof unavailable")
            expected_auth = "trusted-xml-signature" if mode == "signed" else "closed-pkix-hostname-tls"
            if execution["outcome"]["details"].get("artifact_authentication") != expected_auth:
                raise ValueError("Real Artifact authentication mode differs")
            reports.append({"mode": mode, "runId": run, "planId": plan, "approvedFixtures": observed,
                            "outcome": "SATISFIED", "artifactAuthentication": expected_auth,
                            "requiredSelectedOriginalsExported": selected_gate["requiredSelectedOriginalsExported"], "wholeRunExportClaimed": False, "productEvidenceAdoption": False})
        save(output, "qualification.json", {"schema": "samlscope-synthetic-artifact-runtime-qualification-v1",
                                             "campaigns": reports, "productEvidenceAdoption": False})
        print(json.dumps({"output": str(output), "campaigns": reports}))
    finally:
        cleanup = {"helperInstalled": installed, "databaseCopied": False, "dataVolumeModifiedByReader": False}
        if installed:
            counts["helperRemovalAttempts"] += 1
            counts["suiteDockerExecAttempts"] += 1
            removed = subprocess.run(["docker", "exec", args.docker_container, "rm", "-r", "--", args.container_helper_dir], capture_output=True)
            cleanup["success"] = removed.returncode == 0
            cleanup["exitCode"] = removed.returncode
            if removed.returncode == 0:
                counts["helperRemovalSuccesses"] += 1
                counts["suiteDockerExecSuccesses"] += 1
        save(output, "helper-cleanup.json", cleanup)
        save(output, "operation-counts.json", counts)


if __name__ == "__main__":
    main()
