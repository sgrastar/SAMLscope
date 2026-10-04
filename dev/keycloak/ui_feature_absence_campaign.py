#!/usr/bin/env python3
"""Prove Keycloak's native nonuse of selected optional metadata UI features.

The campaign imports Suite originals through the product console, exercises a correlated SSO
round trip, reads the full product state, and restores it after both the baseline and target
variant.  It emits evidence only; Runner remains the outcome authority.
"""

import argparse
import base64
import hashlib
import html
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPO = pathlib.Path(__file__).resolve().parents[2]
BASE = "http://localhost:18080"
ADMIN = "http://localhost:18180/admin/realms/samlscope"
TOKEN = "http://localhost:18180/realms/master/protocol/openid-connect/token"
CONTAINER = "samlscope-reference-keycloak"
VARIANTS = ["control", "ui-consumer-display-all"]
PROVEN_CASES = ["IIP-MD05-fb-idp-01", "IIP-MD05-fj-idp-01"]
CLASS_PATHS = {
    "converterClass": "org/keycloak/protocol/saml/EntityDescriptorDescriptionConverter.class",
    "samlProtocolClass": "org/keycloak/protocol/saml/SamlProtocol.class",
    "samlServiceClass": "org/keycloak/protocol/saml/SamlService.class",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def save(path, value):
    pathlib.Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def api(path, body=None):
    request = urllib.request.Request(
        BASE + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Suite API {error.code}: {error.read().decode()[:800]}") from None


def admin_token():
    data = urllib.parse.urlencode(
        {"client_id": "admin-cli", "username": "admin", "password": "admin", "grant_type": "password"}
    ).encode()
    with urllib.request.urlopen(urllib.request.Request(TOKEN, data=data), timeout=30) as response:
        return json.load(response)["access_token"]


def admin(path, method="GET"):
    request = urllib.request.Request(
        ADMIN + path,
        method=method,
        headers={"Authorization": "Bearer " + admin_token()},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
        return None if not raw else json.loads(raw)


def client_lookup(entity_id):
    return admin("/clients?clientId=" + urllib.parse.quote(entity_id, safe=""))


def client_detail(entity_id):
    rows = client_lookup(entity_id)
    if len(rows) != 1:
        raise RuntimeError(f"Expected exactly one imported client, got {len(rows)}")
    return admin("/clients/" + rows[0]["id"])


def recorded_exchange(run, variant, previous_ids):
    entries = api("/api/runs/" + run + "/transcript")
    requests = [
        entry
        for entry in entries
        if entry["id"] not in previous_ids
        and entry["direction"] == "OUTBOUND"
        and entry["samlSummary"].get("type") == "AuthnRequest"
        and entry["samlSummary"].get("variant") == variant
    ]
    if len(requests) != 1:
        raise RuntimeError("Expected exactly one newly issued request")
    request = requests[0]
    request_id = request["samlSummary"].get("id")
    responses = [
        entry
        for entry in entries
        if entry["direction"] == "INBOUND"
        and entry["samlSummary"].get("metadataProbeAccepted") is True
        and entry["samlSummary"].get("inResponseTo") == request_id
    ]
    statuses = {entry["samlSummary"].get("statusCode") for entry in responses}
    return {
        "success": statuses == {"urn:oasis:names:tc:SAML:2.0:status:Success"},
        "request_id": request_id,
        "transcript_ids": [request["id"], *[entry["id"] for entry in responses]],
    }


def flow_mode(args):
    sys.path.insert(0, str(REPO / "dev/keycloak"))
    import reference_flow

    state = api("/api/runs/" + args.flow_run + "/metadata-lab")
    variant = state["selectedVariant"]
    if variant != args.expected_variant:
        raise RuntimeError("Unexpected selected variant")
    start_url = state["automaticStartUrl"]
    before_ids = {entry["id"] for entry in api("/api/runs/" + args.flow_run + "/transcript")}
    observation = {}

    class ObservedClient(reference_flow.Client):
        def request(self, url, fields=None):
            final_url, page, code = super().request(url, fields)
            parsed = urllib.parse.urlparse(final_url)
            forms = reference_flow.parse_forms(page)
            login = next((form for form in forms if "password" in form.fields), None)
            if (
                not observation
                and parsed.port == 18180
                and parsed.path == "/realms/samlscope/login-actions/authenticate"
                and login is not None
            ):
                links = sorted(
                    set(
                        html.unescape(value)
                        for value in re.findall(r"href=[\"']([^\"']*/broker/[^\"']+)[\"']", page, re.I)
                    )
                )
                aliases = sorted(
                    set(
                        match
                        for link in links
                        for match in re.findall(r"/broker/([^/]+)/", urllib.parse.urlparse(link).path)
                    )
                )
                action = urllib.parse.urljoin(final_url, login.action)
                observation.update(
                    loginPageUrl=urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")),
                    loginPageSha256=sha(page.encode()),
                    loginFormActionPath=urllib.parse.urlparse(action).path,
                    loginFormActionSha256=sha(action.encode()),
                    identityProviderLinks=links,
                    identityProviderAliases=aliases,
                )
            return final_url, page, code

    username = os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user")
    password = os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password")
    result = ObservedClient().flow(start_url, None, username, password)
    exchange = recorded_exchange(args.flow_run, variant, before_ids)
    after = api("/api/runs/" + args.flow_run + "/metadata-lab")
    completed = exchange["success"] and after["campaignIndex"] == state["campaignIndex"] + 1
    if not observation or not completed:
        raise RuntimeError("Request-bound login decision or correlated Success is incomplete")
    observation.update(
        entityId=args.entity_id,
        requestUrl=start_url,
        authenticatedFlowCompleted=True,
    )
    save(args.flow_record, {"run": args.flow_run, "variant": variant, "result": result,
                            "exchange": exchange, "decision": observation})


def blob(raw, path):
    return {"path": path, "sha256": sha(raw), "base64": base64.b64encode(raw).decode()}


def native_converter(output, fixture):
    probe = REPO / "dev/reference-acceptance/ProbeKeycloakAttributePolicyImport.java"
    classes = output / "native-probe-classes"
    classes.mkdir(exist_ok=True)
    subprocess.run(["javac", "-d", str(classes), str(probe)], check=True, timeout=60)
    subprocess.run(["docker", "cp", str(classes / "ProbeKeycloakAttributePolicyImport.class"),
                    CONTAINER + ":/tmp/ProbeKeycloakAttributePolicyImport.class"], check=True, timeout=30)
    subprocess.run(["docker", "cp", str(fixture), CONTAINER + ":/tmp/ui-feature-fixture.xml"],
                   check=True, timeout=30)
    result = subprocess.run(
        ["docker", "exec", CONTAINER, "java", "-cp",
         "/tmp:/opt/keycloak/lib/lib/main/*:/opt/keycloak/lib/lib/boot/*",
         "ProbeKeycloakAttributePolicyImport", "/tmp/ui-feature-fixture.xml"],
        check=True, capture_output=True, timeout=60,
    )
    value = json.loads(result.stdout)
    if not isinstance(value, list) or len(value) != 1:
        raise RuntimeError("Native converter output was ambiguous")
    return value


def capture_runtime(output):
    inspected = json.loads(subprocess.run(
        ["docker", "inspect", CONTAINER], check=True, capture_output=True, timeout=30
    ).stdout)[0]
    jar = output / "keycloak-services-26.7.2.jar"
    subprocess.run(["docker", "cp", CONTAINER + ":/opt/keycloak/lib/lib/main/"
                    "org.keycloak.keycloak-services-26.7.2.jar", str(jar)], check=True, timeout=30)
    values = {}
    with zipfile.ZipFile(jar) as archive:
        for name, path in CLASS_PATHS.items():
            raw = archive.read(path)
            class_file = output / pathlib.Path(path).name
            class_file.write_bytes(raw)
            values[name] = blob(raw, path)
    return {
        "containerName": CONTAINER,
        "containerId": inspected["Id"],
        "imageId": inspected["Image"],
        "startedAt": inspected["State"]["StartedAt"],
        "runningAtCapture": inspected["State"]["Running"],
        "productVersion": "26.7.2",
        **values,
    }


def transcript_entry(entries, direction, kind, variant):
    values = [
        entry for entry in entries
        if entry["direction"] == direction
        and entry["samlSummary"].get("type") == kind
        and entry["samlSummary"].get("variant") == variant
    ]
    if len(values) != 1:
        raise RuntimeError(f"Expected one {direction} {kind} for {variant}, got {len(values)}")
    return values[0]


def main_mode(args):
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("Output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    stage = output / "driver"
    stage.mkdir()
    shutil.copy2(REPO / "dev/keycloak/console_import.mjs", stage / "console_import.mjs")
    (stage / "node_modules").symlink_to(args.playwright_modules.resolve(), target_is_directory=True)

    plan = api("/api/plans", {
        "name": "Keycloak native UI feature nonuse campaign",
        "profile": "metadata_idp",
        "targetKind": "IDP",
        "targetEntityId": "http://localhost:18180/realms/samlscope",
        "metadataSourceKind": "URL",
        "metadataSourceLocation": "http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor",
        "suiteMetadataDelivery": "HTTP_URL",
        "declaredFeatures": {},
        "parameters": {"clockSkewToleranceSeconds": 180, "metadataRefreshWaitSeconds": 300,
                       "testUserHint": "samlscope-m0-user", "requestSigningMode": "REQUIRED"},
        "interaction": {"allowBrowserSteps": True, "allowAttestation": False, "preset": "quick"},
        "authorizedTarget": True,
    })
    save(output / "plan.json", plan)
    plan_id = plan["plan"]["plan"]["id"]
    created = api("/api/plans/" + plan_id + "/runs", {})
    save(output / "created.json", created)
    run = created["run"]["id"]
    save(output / "preflight.json", api("/api/runs/" + run + "/preflight", {}))
    save(output / "campaign.json", api("/api/runs/" + run + "/metadata-lab/automatic-polling",
                                       {"variants": VARIANTS, "pollingDelaySeconds": 0}))
    entity_id = BASE + "/p/" + plan_id
    original = canonical(client_lookup(entity_id))
    if json.loads(original) != []:
        raise RuntimeError("Refusing to modify an existing client")
    (output / "client-before.json").write_bytes(original)
    operations = []
    target_folder = None
    try:
        for variant in VARIANTS:
            state = api("/api/runs/" + run + "/metadata-lab")
            if state["selectedVariant"] != variant:
                raise RuntimeError("Campaign variant mismatch")
            folder = output / variant
            folder.mkdir()
            with urllib.request.urlopen(state["automaticStartUrl"], timeout=30) as response:
                if response.status != 202:
                    raise RuntimeError("Unexpected fixture dispatch status")
                response.read()
            with urllib.request.urlopen(state["metadataUrl"], timeout=30) as response:
                fixture = response.read()
            fixture_path = folder / "fixture.xml"
            fixture_path.write_bytes(fixture)
            flow_record = folder / "flow.json"
            follow = shlex.join([
                sys.executable, str(pathlib.Path(__file__).resolve()),
                "--flow-run", run, "--expected-variant", variant,
                "--entity-id", entity_id, "--flow-record", str(flow_record),
            ])
            command = ["node", str(stage / "console_import.mjs"), "--fixture", str(fixture_path),
                       "--record", str(folder / "import.json"), "--entity-id", entity_id,
                       "--verify-command", follow]
            result = subprocess.run(command, capture_output=True, text=True, timeout=420)
            (folder / "driver.log").write_text(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError(f"Console import/flow failed for {variant}")
            imported = json.loads((folder / "import.json").read_text())
            if imported.get("status") != "success":
                raise RuntimeError("Console import did not report success")
            detail = client_detail(entity_id)
            (folder / "configured-read-back.json").write_bytes(canonical(detail))
            providers = admin("/identity-provider/instances")
            (folder / "identity-provider-read-back.json").write_bytes(canonical(providers))
            converter = native_converter(folder, fixture_path)
            (folder / "converter-output.json").write_bytes(canonical(converter))
            client_id = detail["id"]
            admin("/clients/" + client_id, method="DELETE")
            after = canonical(client_lookup(entity_id))
            (folder / "client-after.json").write_bytes(after)
            if after != original:
                raise RuntimeError("Client deletion did not restore the original state")
            operations.append({
                "variant": variant, "fixtureSha256": sha(fixture), "importExit": result.returncode,
                "configurationWrites": 2, "metadataImports": 1, "protocolRoundTrips": 1,
                "productRestarts": 0, "humanOperations": 0, "restored": True,
            })
            save(output / "operations.json", operations)
            if variant == "control":
                save(output / "tests-start.json", api("/api/runs/" + run + "/tests/start", {}))
            else:
                target_folder = folder
    finally:
        remaining = client_lookup(entity_id)
        recovery_deletes = 0
        for row in remaining:
            admin("/clients/" + row["id"], method="DELETE")
            recovery_deletes += 1
        final = canonical(client_lookup(entity_id))
        (output / "client-final.json").write_bytes(final)
        if recovery_deletes:
            save(output / "recovery-restoration.json", {
                "entityId": entity_id, "deletedTemporaryClients": recovery_deletes,
                "finalSha256": sha(final), "restored": final == original,
            })
        if final != original:
            save(output / "restoration-failure.json", {"entityId": entity_id, "remaining": json.loads(final)})

    if target_folder is None or (output / "client-final.json").read_bytes() != original:
        raise RuntimeError("Campaign did not finish in the original product state")
    entries = api("/api/runs/" + run + "/transcript")
    save(output / "transcript.json", entries)
    sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
    import capture_run_originals
    manifest = capture_run_originals.capture(output, run, entries)
    manifest_by_id = {item["id"]: item for item in manifest}
    fetch = transcript_entry(entries, "INBOUND", "MetadataFetch", VARIANTS[-1])
    prepared = transcript_entry(entries, "OUTBOUND", "MetadataPrepared", VARIANTS[-1])
    request = transcript_entry(entries, "OUTBOUND", "AuthnRequest", VARIANTS[-1])
    request_id = request["samlSummary"]["id"]
    responses = [entry for entry in entries if entry["direction"] == "INBOUND"
                 and entry["samlSummary"].get("type") == "Response"
                 and entry["samlSummary"].get("inResponseTo") == request_id
                 and entry["samlSummary"].get("metadataProbeAccepted") is True]
    if len(responses) != 1:
        raise RuntimeError("Target response correlation is ambiguous")
    response = responses[0]
    for item in (prepared, request, response):
        if item["id"] not in manifest_by_id:
            raise RuntimeError("Decoded original missing from manifest")
    flow = json.loads((target_folder / "flow.json").read_text())
    decision = flow["decision"]
    providers_raw = (target_folder / "identity-provider-read-back.json").read_bytes()
    decision["identityProviderReadBack"] = blob(
        providers_raw, "ui-consumer-display-all/identity-provider-read-back.json")
    receipt = {
        "schema": "samlscope-native-ui-feature-absence-v1",
        "runId": run,
        "targetEntityId": "http://localhost:18180/realms/samlscope",
        "targetMetadataSha256": sha((output / "target-metadata.xml").read_bytes()),
        "evidenceAdapter": "keycloak-native-client-import",
        "provenCases": PROVEN_CASES,
        "fixture": {
            "variant": VARIANTS[-1], "fetchReference": fetch["id"],
            "metadataReference": prepared["id"],
            "metadataSha256": manifest_by_id[prepared["id"]]["sha256"],
        },
        "exchange": {
            "requestReference": request["id"], "responseReference": response["id"],
            "requestSha256": manifest_by_id[request["id"]]["sha256"],
            "responseSha256": manifest_by_id[response["id"]]["sha256"],
        },
        "nativeImport": {
            "uiImportRecord": blob((target_folder / "import.json").read_bytes(),
                                   "ui-consumer-display-all/import.json"),
            "converterOutput": blob((target_folder / "converter-output.json").read_bytes(),
                                    "ui-consumer-display-all/converter-output.json"),
            "configuredReadBack": blob((target_folder / "configured-read-back.json").read_bytes(),
                                       "ui-consumer-display-all/configured-read-back.json"),
        },
        "runtime": capture_runtime(output),
        "requestBoundDecision": decision,
        "restoration": {
            "beforeReadBack": blob((output / "client-before.json").read_bytes(), "client-before.json"),
            "afterReadBack": blob((output / "client-final.json").read_bytes(), "client-final.json"),
            "deletedClientId": entity_id, "restored": True,
        },
        "operationCounts": {
            "productConfigurationWrites": 4, "productRestarts": 0,
            "metadataImports": 2, "protocolRoundTrips": 2, "humanOperations": 0,
        },
    }
    save(output / "receipt.json", receipt)
    save(output / "campaign-summary.json", {
        "runId": run, "entityId": entity_id, "receiptSha256": sha(canonical(receipt)),
        "restored": True, "operationCounts": receipt["operationCounts"],
        "verdictAdopted": False,
    })
    print(run)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--playwright-modules", type=pathlib.Path)
    parser.add_argument("--flow-run")
    parser.add_argument("--expected-variant")
    parser.add_argument("--entity-id")
    parser.add_argument("--flow-record", type=pathlib.Path)
    args = parser.parse_args()
    if args.flow_run:
        if not all((args.expected_variant, args.entity_id, args.flow_record)):
            parser.error("flow mode requires variant, entity and record")
    elif not all((args.output, args.playwright_modules)):
        parser.error("campaign mode requires output and playwright modules")
    return args


if __name__ == "__main__":
    arguments = parse_args()
    flow_mode(arguments) if arguments.flow_run else main_mode(arguments)
