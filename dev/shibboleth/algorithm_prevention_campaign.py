#!/usr/bin/env python3
"""Run one Run-bound Shibboleth ALG08 RSA-1.5 prevention A/B/A campaign.

The target is changed only after its originals and live readiness have been captured. Every
write is followed by byte-exact read-back, every restart gets a fresh runtime capture, and the
finally block restores all target files before a receipt can be installed into the Suite.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
import xml.etree.ElementTree as ET


if not __debug__:
    raise RuntimeError("algorithm-prevention campaign must not run with Python optimization")

REPO = Path(__file__).resolve().parents[2]
BASE = "http://localhost:18080"
TARGET = "samlscope-reference-shibboleth"
SUITE = "samlscope-reference-suite"
TARGET_ENTITY = "http://localhost:18280/idp/shibboleth"
TARGET_METADATA = "http://samlscope-reference-shibboleth:8080/idp/shibboleth"
SSO = "http://localhost:18280/idp/profile/SAML2/Redirect/SSO"
GLOBAL = "/opt/reference-idp/conf/global.xml"
RELYING = "/opt/reference-idp/conf/relying-party.xml"
PROVIDERS = "/opt/reference-idp/conf/metadata-providers.xml"
VERSION = "/opt/reference-idp/bin/version.sh"
IMAGE = "sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a"
SUITE_JARS = ("api-0.1.0.jar", "runner-0.1.0.jar", "saml-0.1.0.jar")
SUITE_CLASSES = (
    "com/samlscope/runner/cases/AlgorithmPreventionEvidenceFile.class",
    "com/samlscope/runner/cases/AlgorithmPreventionConfigurationTestCase.class",
    "com/samlscope/runner/cases/SuiteRunProfileLookup.class",
)
RSA15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
TRIPLEDES = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
AES128 = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
AES256 = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
CONFIG_ID = "samlscope.AlgorithmPreventionEncryptionConfiguration"
SECURITY_CONFIG_ID = "samlscope.AlgorithmPreventionSecurityConfiguration"
GLOBAL_MARKER = "<!-- samlscope-algorithm-prevention-set -->"
RELYING_MARKER = "<!-- samlscope-algorithm-prevention-policy -->"
PHASES = (("allowed-before", False), ("blocked", True), ("allowed-after", False))
RUN_RE = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}")
PLAN_RE = re.compile(r"plan_[0-9A-HJKMNP-TV-Z]{26}")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def blob(raw):
    return {"base64": base64.b64encode(raw).decode(), "sha256": sha(raw)}


def api(path, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(BASE + path, data=data,
                                     headers={} if data is None else {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.loads(response.read())


def docker(*args, data=None, timeout=90):
    return subprocess.run(["docker", *args], input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True, timeout=timeout).stdout


def read(path):
    return docker("exec", TARGET, "cat", path)


def write(path, raw):
    docker("exec", "-i", TARGET, "sh", "-c", "cat > " + path, data=raw)
    require(read(path) == raw, "native configuration read-back mismatch: " + path)


def path_exists(path):
    value = docker("exec", TARGET, "sh", "-c",
                   "if test -e " + path + "; then echo exists; else echo absent; fi").strip()
    require(value in {b"exists", b"absent"}, "native path check was ambiguous: " + path)
    return value == b"exists"


def configured_global(original, blocked):
    text = original.decode()
    closing = "</beans>"
    require(GLOBAL_MARKER not in text and closing in text, "global.xml is not an unmodified supported input")
    overlay = ("\n    " + GLOBAL_MARKER + "\n"
        + "    <util:set id=\"shibboleth.IncludedEncryptionAlgorithms\"><value>" + AES128
        + "</value>" + (("<value>" + RSA15 + "</value>") if not blocked else "")
        + "<value>" + OAEP + "</value></util:set>\n"
        + "    <util:set id=\"shibboleth.ExcludedEncryptionAlgorithms\"><value>" + TRIPLEDES + "</value>"
        + (("<value>" + RSA15 + "</value>") if blocked else "") + "</util:set>\n")
    index = text.rfind(closing)
    return (text[:index] + overlay + text[index:]).encode()


def configured_relying(original):
    text = original.decode()
    closing = "</beans>"
    default = '<bean id="shibboleth.DefaultRelyingParty" parent="RelyingParty">'
    require(RELYING_MARKER not in text and CONFIG_ID not in text and SECURITY_CONFIG_ID not in text
            and text.count(default) == 1 and closing in text,
            "relying-party.xml is not an unmodified supported input")
    text = text.replace(default, '<bean id="shibboleth.DefaultRelyingParty" parent="RelyingParty"'
                        + ' p:securityConfiguration-ref="' + SECURITY_CONFIG_ID + '">')
    overlay = ("\n    " + RELYING_MARKER + "\n"
        + "    <bean id=\"" + CONFIG_ID + "\" parent=\"shibboleth.BasicEncryptionConfiguration\""
        + " p:keyTransportKeyInfoGeneratorManager-ref=\"NamedKeyInfoGeneratorManager\">\n"
        + "      <property name=\"dataEncryptionAlgorithms\"><list><value>" + AES128
        + "</value></list></property>\n"
        + "      <property name=\"keyTransportEncryptionAlgorithms\"><list><value>" + RSA15
        + "</value><value>" + OAEP + "</value></list></property>\n"
        + "    </bean>\n"
        + "    <bean id=\"" + SECURITY_CONFIG_ID + "\" parent=\"shibboleth.DefaultSecurityConfiguration\""
        + " p:encryptionConfiguration-ref=\"" + CONFIG_ID + "\" />\n")
    index = text.rfind(closing)
    return (text[:index] + overlay + text[index:]).encode()


def configured_providers(original, run):
    text = original.decode()
    closing = "</MetadataProvider>"
    index = text.rfind(closing)
    require(index >= 0 and ("AlgorithmPrevention" + run) not in text,
            "metadata provider input is ambiguous")
    overlay = ("\n    <MetadataProvider id=\"AlgorithmPrevention" + run
        + "\" xsi:type=\"FilesystemMetadataProvider\" metadataFile=\"/opt/reference-idp/metadata/algorithm-prevention-"
        + run + ".xml\" />\n")
    return (text[:index] + overlay + text[index:]).encode()


def runtime_blob():
    inspect = docker("inspect", TARGET)
    parsed = json.loads(inspect)
    require(len(parsed) == 1 and parsed[0]["Name"] == "/" + TARGET, "target container identity changed")
    require(parsed[0]["Image"] == IMAGE and parsed[0]["State"]["Running"], "unexpected target image or state")
    version = docker("exec", TARGET, VERSION)
    require(version.decode().strip() == "5.2.3", "unexpected target runtime version")
    return {"inspect": blob(inspect), "version": blob(version)}


def suite_runtime_blob():
    inspect = docker("inspect", SUITE)
    parsed = json.loads(inspect)
    require(len(parsed) == 1 and parsed[0]["Name"] == "/" + SUITE
            and parsed[0]["State"]["Running"], "Suite container identity changed")
    jars = {}
    for name in SUITE_JARS:
        raw = docker("exec", SUITE, "cat", "/opt/samlscope/lib/" + name)
        jars[name] = sha(raw)
    classes = {}
    for name in SUITE_CLASSES:
        with zipfile.ZipFile(io.BytesIO(docker("exec", SUITE, "cat",
                "/opt/samlscope/lib/runner-0.1.0.jar"))) as archive:
            raw = archive.read(name)
        require(raw, "Suite class is absent: " + name)
        classes[name] = sha(raw)
    return {"inspect": blob(inspect), "jars": jars, "classes": classes}


def same_suite_runtime(left, right):
    def identity(value):
        raw = base64.b64decode(value["inspect"]["base64"], validate=True)
        require(sha(raw) == value["inspect"]["sha256"], "Suite inspect blob hash differs")
        item = json.loads(raw)[0]
        return item["Id"], item["Image"], item["State"]["StartedAt"], item["State"]["Running"]
    return identity(left) == identity(right) and left["jars"] == right["jars"] \
        and left["classes"] == right["classes"]


def readiness(out, label):
    inspect = json.loads(docker("inspect", TARGET))[0]
    health = inspect.get("State", {}).get("Health", {}).get("Status", "absent")
    checks = {}
    for name, url in (("metadata", TARGET_ENTITY), ("sso", SSO)):
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                raw = response.read(262145)
                checks[name] = {"status": response.status, "bytes": len(raw), "sha256": sha(raw)}
        except urllib.error.HTTPError as error:
            raw = error.read(262145)
            checks[name] = {"status": error.code, "bytes": len(raw), "sha256": sha(raw)}
    require(checks.get("metadata", {}).get("status") == 200, "metadata endpoint is not live")
    # This is deliberately a bare endpoint reachability probe. Shibboleth returns its local
    # error page with HTTP 500 when no SAMLRequest is supplied; the phase exchange below is the
    # acceptance oracle for a valid SSO operation. Any concrete HTTP response proves that this
    # endpoint is reachable, while a transport exception remains a failed precondition.
    require(checks.get("sso", {}).get("status") in range(200, 600), "SSO endpoint is unreachable")
    record = {"docker_health": health, "container_running": inspect["State"]["Running"],
              "checks": checks, "sso_probe_kind": "bare-endpoint-reachability",
              "sso_probe_is_acceptance_oracle": False, "healthcheck_is_acceptance_oracle": False}
    save(out / ("readiness-" + label + ".json"), record)
    return record


def restart(out, label):
    docker("restart", TARGET, timeout=120)
    # The reference container deliberately has a long-lived `sleep` entrypoint so campaigns can
    # replace configuration without replacing the container. A Docker restart therefore has to be
    # followed by the product's native Tomcat startup; otherwise the container is running while the
    # IdP is absent. Container StartedAt still gives each product runtime a fresh, ordered identity.
    docker("exec", TARGET, "/usr/local/tomcat/bin/startup.sh", timeout=120)
    deadline = time.time() + 120
    while True:
        try:
            state = readiness(out, label)
            break
        except Exception:
            if time.time() >= deadline:
                raise
            time.sleep(2)
    value = runtime_blob()
    save(out / ("runtime-" + label + ".json"), value)
    return value, state


def create_run(out, profile):
    plan_value = api("/api/plans", {"name": "Shibboleth ALG08 A/B/A " + profile,
        "profile": profile, "targetKind": "IDP", "targetEntityId": TARGET_ENTITY,
        "metadataSourceKind": "URL", "metadataSourceLocation": TARGET_METADATA,
        "suiteMetadataDelivery": "HTTP_URL", "declaredFeatures": {},
        "parameters": {"clockSkewToleranceSeconds": 180, "metadataRefreshWaitSeconds": 300,
            "testUserHint": "samlscope-m0-user", "requestSigningMode": "REQUIRED"},
        "interaction": {"allowBrowserSteps": True, "allowAttestation": False, "preset": "quick"},
        "authorizedTarget": True})
    save(out / "plan.json", plan_value)
    plan = plan_value["plan"]["plan"]["id"]
    require(PLAN_RE.fullmatch(plan), "invalid Plan identity")
    created = api("/api/plans/" + plan + "/runs", {})
    save(out / "created.json", created)
    run = created["run"]["id"]
    require(RUN_RE.fullmatch(run), "invalid Run identity")
    preflight = api("/api/runs/" + run + "/preflight", {})
    save(out / "preflight.json", preflight)
    checks = {check.get("code"): check for check in preflight.get("checks", [])}
    require(checks.get("target_metadata", {}).get("status") == "PASS",
            "Suite target metadata preflight did not pass")
    return plan, run


def new_entries(run, before):
    entries = api("/api/runs/" + run + "/transcript")
    return entries, [entry for entry in entries if entry["id"] not in before]


def browser_flow(plan, run):
    sys.path.insert(0, str(REPO / "dev/keycloak"))
    from reference_flow import Client
    return Client().flow(BASE + "/p/" + plan + "/start/m0-roundtrip?run=" + run, None,
                         os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user"),
                         os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password"))


def phase_exchange(profile, plan, run, phase):
    before = {entry["id"] for entry in api("/api/runs/" + run + "/transcript")}
    if profile == "browser_sso_idp":
        require(browser_flow(plan, run) == "recorded", "browser SSO did not complete")
    else:
        value = api("/api/runs/" + run + "/ecp-probe/algorithm-prevention/" + phase,
                    {"username": os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user"),
                     "password": os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password")})
        require(value.get("outboxStatus") == "SENT", "ECP outbox action was not sent")
    entries, added = new_entries(run, before)
    by_id = {entry["id"]: entry for entry in entries}
    if profile == "browser_sso_idp":
        requests = [e for e in added if e.get("direction") == "OUTBOUND"
                    and e.get("samlSummary", {}).get("type") == "AuthnRequest"]
        responses = [e for e in added if e.get("direction") == "INBOUND"
                     and e.get("samlSummary", {}).get("type") == "Response"
                     and e.get("samlSummary", {}).get("normalFlowAccepted") is True]
        require(len(requests) == len(responses) == 1, "browser phase exchange is ambiguous")
        return requests[0]["id"], responses[0]["id"]
    responses = [e for e in added if e.get("direction") == "INBOUND"
                 and e.get("samlSummary", {}).get("type") == "EcpSoapResponse"]
    require(len(responses) == 1, "ECP phase response is ambiguous")
    request_id = responses[0].get("samlSummary", {}).get("request_transcript")
    require(request_id in by_id and by_id[request_id].get("samlSummary", {}).get("type") == "EcpSoapRequest",
            "ECP phase request is not correlated")
    return request_id, responses[0]["id"]


def capture_originals(out, run, transcript):
    decoded = out / "decoded"
    decoded.mkdir()
    manifest = []
    for entry in transcript:
        reference = entry.get("decodedSamlRef")
        if not reference:
            continue
        require(re.fullmatch(r"tx_[0-9A-HJKMNP-TV-Z]{26}", entry["id"])
                and not Path(reference).is_absolute() and ".." not in Path(reference).parts,
                "unsafe transcript reference")
        destination = decoded / (entry["id"] + ".xml")
        subprocess.run(["docker", "cp", SUITE + ":/data/" + reference, str(destination)],
                       check=True, timeout=60, stdout=subprocess.DEVNULL)
        manifest.append({"id": entry["id"], "file": str(destination.relative_to(out)),
                         "sha256": sha(destination.read_bytes())})
    save(out / "decoded-manifest.json", manifest)
    subprocess.run(["docker", "cp", SUITE + ":/data/target-metadata/" + run + ".xml",
                   str(out / "target-metadata.xml")], check=True, timeout=60, stdout=subprocess.DEVNULL)


def verify_wire_transition(out, phases):
    """Reject a campaign before receipt installation unless the actual wire is RSA15/OAEP/RSA15."""
    manifest = {item["id"]: item for item in json.loads((out / "decoded-manifest.json").read_text())}
    require(len(manifest) == len(json.loads((out / "decoded-manifest.json").read_text())),
            "decoded manifest identifiers are ambiguous")
    observed = []
    xenc = "{http://www.w3.org/2001/04/xmlenc#}"
    for phase in phases:
        reference = phase["responseReference"]
        require(reference in manifest, "phase response original is absent")
        item = manifest[reference]
        raw = (out / item["file"]).read_bytes()
        require(sha(raw) == item["sha256"], "phase response original hash differs")
        root = ET.fromstring(raw)
        data = root.findall(".//" + xenc + "EncryptedData/" + xenc + "EncryptionMethod")
        key = root.findall(".//" + xenc + "EncryptedKey/" + xenc + "EncryptionMethod")
        require(len(data) == len(key) == 1, "encrypted assertion algorithm cardinality differs")
        require(data[0].get("Algorithm") == AES128, "unexpected data-encryption wire algorithm")
        observed.append(key[0].get("Algorithm"))
    require(observed == [RSA15, OAEP, RSA15], "A/B/A key-transport wire transition differs")
    save(out / "wire-algorithms.json", {"phases": [item["name"] for item in phases],
        "dataEncryptionAlgorithm": AES128, "keyTransportAlgorithms": observed,
        "receiptInstalledOnlyAfterVerification": True})
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    # The generic ECP endpoint has fixed action IDs and cannot record three native phases
    # through this direct campaign. The ECP relay campaign uses distinct approved fixtures.
    parser.add_argument("--profile", choices=("browser_sso_idp",), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    readiness(out, "initial")
    initial_runtime = runtime_blob()
    save(out / "runtime-initial.json", initial_runtime)
    initial_suite_runtime = suite_runtime_blob()
    save(out / "suite-runtime-initial.json", initial_suite_runtime)
    original_global, original_relying, original_providers = read(GLOBAL), read(RELYING), read(PROVIDERS)
    for name, raw in (("global", original_global), ("relying", original_relying),
                      ("providers", original_providers)):
        (out / ("original-" + name)).write_bytes(raw)
    plan, run = create_run(out, args.profile)
    with urllib.request.urlopen(BASE + "/p/" + plan + "/metadata", timeout=30) as response:
        fixture = response.read()
    (out / "suite-metadata.xml").write_bytes(fixture)
    temporary = "/opt/reference-idp/metadata/algorithm-prevention-" + run + ".xml"
    configured_provider = configured_providers(original_providers, run)
    allowed_global = configured_global(original_global, False)
    blocked_global = configured_global(original_global, True)
    selected_relying = configured_relying(original_relying)
    expected_global, expected_relying, expected_providers = original_global, original_relying, original_providers
    changed = {"fixture": False, "providers": False, "global": False, "relying": False}
    phases = []
    failures = []
    final_runtime = None
    try:
        require(not path_exists(temporary), "temporary metadata path already exists")
        write(temporary, fixture); changed["fixture"] = True
        require(read(PROVIDERS) == expected_providers, "concurrent metadata provider change")
        write(PROVIDERS, configured_provider); changed["providers"] = True; expected_providers = configured_provider
        require(read(RELYING) == expected_relying, "concurrent relying-party.xml change")
        write(RELYING, selected_relying); changed["relying"] = True; expected_relying = selected_relying
        for index, (name, blocked) in enumerate(PHASES):
            folder = out / name; folder.mkdir()
            desired_global = blocked_global if blocked else allowed_global
            require(read(GLOBAL) == expected_global and read(RELYING) == expected_relying
                    and read(PROVIDERS) == expected_providers, "concurrent native configuration change")
            write(GLOBAL, desired_global); changed["global"] = True; expected_global = desired_global
            phase_runtime, _ = restart(out, name)
            global_readback, relying_readback = read(GLOBAL), read(RELYING)
            (folder / "global-readback.xml").write_bytes(global_readback)
            (folder / "relying-party-readback.xml").write_bytes(relying_readback)
            if args.profile == "ecp_idp" and index == 0:
                require(browser_flow(plan, run) == "recorded", "ECP Run baseline SSO did not complete")
            request, response = phase_exchange(args.profile, plan, run, name)
            phases.append({"name": name, "globalReadBack": blob(global_readback),
                           "relyingPartyReadBack": blob(relying_readback), "runtime": phase_runtime,
                           "requestReference": request, "responseReference": response})
            save(folder / "exchange.json", {"run": run, "profile": args.profile,
                                             "request": request, "response": response})
    finally:
        try:
            if changed["global"]:
                require(read(GLOBAL) == expected_global, "concurrent global.xml change; refusing overwrite")
                write(GLOBAL, original_global); expected_global = original_global
            if changed["relying"]:
                require(read(RELYING) == expected_relying, "concurrent relying-party.xml change; refusing overwrite")
                write(RELYING, original_relying); expected_relying = original_relying
            if changed["providers"]:
                require(read(PROVIDERS) == expected_providers, "concurrent metadata provider change; refusing overwrite")
                write(PROVIDERS, original_providers); expected_providers = original_providers
        except Exception as error:
            failures.append(type(error).__name__ + ":" + str(error))
        try:
            # Delete only after native read-back proves the provider no longer references it.
            if changed["fixture"] and read(PROVIDERS) == original_providers and path_exists(temporary):
                docker("exec", TARGET, "rm", "--", temporary)
        except Exception as error:
            failures.append(type(error).__name__ + ":" + str(error))
        try:
            if (any(changed[key] for key in ("global", "relying", "providers"))
                    and read(GLOBAL) == original_global and read(RELYING) == original_relying
                    and read(PROVIDERS) == original_providers):
                final_runtime, _ = restart(out, "restored")
        except Exception as error:
            failures.append(type(error).__name__ + ":" + str(error))
        removed = not path_exists(temporary)
        restored = (not failures and removed and read(GLOBAL) == original_global
                    and read(RELYING) == original_relying and read(PROVIDERS) == original_providers)
        restoration = {"run": run, "restored": restored, "failures": failures,
                       "temporary_metadata_removed": removed,
                       "global_sha256": sha(read(GLOBAL)), "relying_party_sha256": sha(read(RELYING)),
                       "providers_sha256": sha(read(PROVIDERS))}
        save(out / "restoration.json", restoration)
    require(restoration["restored"] and len(phases) == 3 and final_runtime is not None,
            "campaign or exact restoration incomplete")
    transcript = api("/api/runs/" + run + "/transcript")
    save(out / "transcript.json", transcript)
    capture_originals(out, run, transcript)
    verify_wire_transition(out, phases)
    target_metadata = (out / "target-metadata.xml").read_bytes()
    receipt = {"schema": "samlscope-shibboleth-algorithm-prevention-v2", "runId": run,
        "profile": args.profile, "targetEntityId": TARGET_ENTITY,
        "targetMetadataSha256": sha(target_metadata), "suiteMetadata": blob(fixture),
        "configuration": {"originalGlobal": blob(original_global),
            "originalRelyingParty": blob(original_relying), "originalProviders": blob(original_providers),
            "providerConfiguredReadBack": blob(configured_provider), "fixtureReadBack": blob(fixture),
            "restoredGlobal": blob(read(GLOBAL)), "restoredRelyingParty": blob(read(RELYING)),
            "restoredProviders": blob(read(PROVIDERS)), "temporaryMetadataRemoved": True, "restored": True},
        "runtime": {"initial": initial_runtime, "restored": final_runtime}, "phases": phases,
        "operationCounts": {"productConfigurationWrites": 9, "productRestarts": 4,
            "metadataReloads": 0, "protocolOperations": 3, "humanOperations": 0}}
    receipt_path = out / "algorithm-prevention-receipt.json"
    save(receipt_path, receipt)
    suite_directory = "/data/algorithm-prevention-evidence"
    docker("exec", SUITE, "mkdir", "-p", suite_directory)
    subprocess.run(["docker", "cp", str(receipt_path), SUITE + ":" + suite_directory + "/" + run + ".json"],
                   check=True, timeout=60)
    save(out / "tests-start.json", api("/api/runs/" + run + "/tests/start", {}))
    if args.profile == "ecp_idp":
        save(out / "standard-ecp-probes.json", api("/api/runs/" + run + "/ecp-probe", {
            "username": os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user"),
            "password": os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password")}))
    save(out / "evaluation.json", api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
    save(out / "result.json", api("/api/runs/" + run + "/result.json"))
    final_suite_runtime = suite_runtime_blob()
    require(same_suite_runtime(initial_suite_runtime, final_suite_runtime),
            "Suite runtime changed during campaign")
    save(out / "suite-runtime-final.json", final_suite_runtime)
    print("Run", run, args.profile, "restored; ALG08 receipt installed", flush=True)


if __name__ == "__main__":
    main()
