#!/usr/bin/env python3
"""Run the approved ALG08 A/B/A observation through the existing ECP outbox fixtures.

The relay changes native policy between sequential generic ECP fixtures. It never stores
Authorization or Cookie; only SOAP body originals and hashes are retained for review.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

import algorithm_prevention_campaign as c


SOAP_TARGET = "http://localhost:18280/idp/profile/SAML2/SOAP/ECP"
SOAP_PATH = "/idp/profile/SAML2/SOAP/ECP"
SOAP_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
PHASES = ("allowed-before", "blocked", "allowed-after")


class Relay:
    def __init__(self, out, port, originals):
        self.out = out
        self.originals = originals
        self.phase = 0
        self.phases = []
        self.exchanges = []
        self.error = None
        self.server = ThreadingHTTPServer(("0.0.0.0", port), self.handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def handler(self):
        relay = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_GET(self):
                if self.path != "/metadata":
                    self.send_error(404)
                    return
                try:
                    raw = urllib.request.urlopen(c.TARGET_ENTITY, timeout=20).read()
                    marker = b"</md:IDPSSODescriptor>"
                    c.require(raw.count(marker) == 1, "target metadata descriptor ambiguous")
                    soap = (b'<md:SingleSignOnService Binding="' + SOAP_BINDING.encode()
                            + b'" Location="http://host.docker.internal:'
                            + str(relay.server.server_port).encode() + SOAP_PATH.encode() + b'" />')
                    patched = raw.replace(marker, soap + b"\n" + marker)
                    (relay.out / "target-metadata-overlay.xml").write_bytes(patched)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/samlmetadata+xml")
                    self.send_header("Content-Length", str(len(patched)))
                    self.end_headers()
                    self.wfile.write(patched)
                except Exception as error:
                    relay.error = type(error).__name__ + ":" + str(error)
                    self.send_error(502)

            def do_POST(self):
                if self.path != SOAP_PATH:
                    self.send_error(404)
                    return
                try:
                    size = int(self.headers.get("Content-Length", "-1"))
                    c.require(0 < size <= 1_048_576, "SOAP request length invalid")
                    body = self.rfile.read(size)
                    index = len(relay.exchanges)
                    name = PHASES[index] if index < 3 else "allowed-control-" + str(index - 2)
                    if index < 3:
                        c.require(relay.phase == index, "native policy phase differs")
                        desired = c.configured_global(relay.originals["global"], index == 1)
                        c.require(c.read(c.GLOBAL) == desired, "native global policy changed before exchange")
                    headers = {"Content-Type": self.headers.get("Content-Type", "text/xml; charset=utf-8"),
                               "Accept": self.headers.get("Accept", "text/xml, application/soap+xml"),
                               "Host": "host.docker.internal:" + str(relay.server.server_port)}
                    authorization = self.headers.get("Authorization")
                    c.require(authorization is not None and authorization.startswith("Basic "),
                              "ECP Basic credential absent")
                    headers["Authorization"] = authorization
                    request = urllib.request.Request(SOAP_TARGET, data=body, headers=headers)
                    try:
                        with urllib.request.urlopen(request, timeout=45) as upstream:
                            status, response_body = upstream.status, upstream.read(1_048_577)
                            content_type = upstream.headers.get("Content-Type", "text/xml")
                    except urllib.error.HTTPError as upstream:
                        status, response_body = upstream.code, upstream.read(1_048_577)
                        content_type = upstream.headers.get("Content-Type", "text/xml")
                    c.require(len(response_body) <= 1_048_576, "SOAP response too large")
                    exchange = {"index": index, "phase": name, "status": status,
                                "requestSha256": c.sha(body), "responseSha256": c.sha(response_body),
                                "targetUrl": SOAP_TARGET, "credentialForwardedOnly": True,
                                "cookieForwarded": False}
                    (relay.out / ("relay-request-" + str(index) + ".xml")).write_bytes(body)
                    (relay.out / ("relay-response-" + str(index) + ".xml")).write_bytes(response_body)
                    relay.exchanges.append(exchange)
                    if index in (0, 1):
                        next_phase = index + 1
                        next_name = PHASES[next_phase]
                        desired = c.configured_global(relay.originals["global"], next_phase == 1)
                        c.write(c.GLOBAL, desired)
                        runtime, _ = c.restart(relay.out, next_name)
                        relay.phases.append({"name": next_name, "runtime": runtime,
                            "globalReadBack": c.blob(c.read(c.GLOBAL)),
                            "relyingPartyReadBack": c.blob(c.read(c.RELYING))})
                        phase_folder = relay.out / next_name
                        phase_folder.mkdir(exist_ok=True)
                        (phase_folder / "global-readback.xml").write_bytes(c.read(c.GLOBAL))
                        (phase_folder / "relying-party-readback.xml").write_bytes(c.read(c.RELYING))
                        relay.phase = next_phase
                    self.send_response(status)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(response_body)))
                    self.end_headers()
                    self.wfile.write(response_body)
                except Exception as error:
                    relay.error = type(error).__name__ + ":" + str(error)
                    try:
                        self.send_error(502)
                    except BrokenPipeError:
                        pass

        return Handler

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--port", default=18701, type=int)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    c.readiness(out, "initial")
    initial_runtime = c.runtime_blob()
    c.save(out / "runtime-initial.json", initial_runtime)
    initial_suite = c.suite_runtime_blob()
    c.save(out / "suite-runtime-initial.json", initial_suite)
    originals = {name: c.read(path) for name, path in
                 (("global", c.GLOBAL), ("relying", c.RELYING), ("providers", c.PROVIDERS))}
    for name, raw in originals.items():
        (out / ("original-" + name)).write_bytes(raw)
    relay = Relay(out, args.port, originals)
    relay.start()
    c.TARGET_METADATA = "http://host.docker.internal:" + str(args.port) + "/metadata"
    plan, run = c.create_run(out, "ecp_idp")
    with urllib.request.urlopen(c.BASE + "/p/" + plan + "/metadata", timeout=30) as response:
        published_fixture = response.read()
    (out / "suite-metadata-published.xml").write_bytes(published_fixture)
    root = ET.fromstring(published_fixture)
    ds = "{http://www.w3.org/2000/09/xmldsig#}Signature"
    for signature in list(root):
        if signature.tag == ds:
            root.remove(signature)
    md = "{urn:oasis:names:tc:SAML:2.0:metadata}"
    sp = root.find(md + "SPSSODescriptor")
    c.require(sp is not None, "Suite SP metadata descriptor absent")
    existing = {int(item.get("index")) for item in sp.findall(md + "AssertionConsumerService")}
    extra_index = max(existing, default=0) + 1
    ET.SubElement(sp, md + "AssertionConsumerService", {
        "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:PAOS",
        "Location": c.BASE + "/p/" + plan + "/sp/paos?run=" + run,
        "index": str(extra_index)})
    fixture = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    (out / "suite-metadata.xml").write_bytes(fixture)
    temporary = "/opt/reference-idp/metadata/algorithm-prevention-" + run + ".xml"
    configured_provider = c.configured_providers(originals["providers"], run)
    selected_relying = c.configured_relying(originals["relying"])
    expected = dict(originals)
    changed = {"fixture": False, "providers": False, "relying": False, "global": False}
    failures = []
    restored_runtime = None
    try:
        c.require(not c.path_exists(temporary), "temporary metadata path exists")
        c.write(temporary, fixture); changed["fixture"] = True
        c.require(c.read(c.PROVIDERS) == expected["providers"], "providers concurrently changed")
        c.write(c.PROVIDERS, configured_provider); changed["providers"] = True
        expected["providers"] = configured_provider
        c.require(c.read(c.RELYING) == expected["relying"], "relying concurrently changed")
        c.write(c.RELYING, selected_relying); changed["relying"] = True
        expected["relying"] = selected_relying
        c.require(c.read(c.GLOBAL) == expected["global"], "global concurrently changed")
        c.write(c.GLOBAL, c.configured_global(originals["global"], False)); changed["global"] = True
        expected["global"] = c.read(c.GLOBAL)
        runtime, _ = c.restart(out, PHASES[0])
        first = out / PHASES[0]; first.mkdir()
        (first / "global-readback.xml").write_bytes(c.read(c.GLOBAL))
        (first / "relying-party-readback.xml").write_bytes(c.read(c.RELYING))
        relay.phases.append({"name": PHASES[0], "runtime": runtime,
            "globalReadBack": c.blob(c.read(c.GLOBAL)),
            "relyingPartyReadBack": c.blob(c.read(c.RELYING))})
        c.require(c.browser_flow(plan, run) == "recorded", "ECP Plan browser baseline did not complete")
        probe = c.api("/api/runs/" + run + "/ecp-probe", {
            "username": "samlscope-m0-user", "password": "samlscope-m0-password"})
        c.save(out / "standard-ecp-probes.json", probe)
        c.require(relay.error is None, "relay error: " + str(relay.error))
        c.require(len(relay.exchanges) == 7 and all(item["status"] == 200 for item in relay.exchanges),
                  "generic ECP controls incomplete")
        c.require(len(relay.phases) == 3, "A/B/A phase runtime incomplete")
        c.require(c.read(c.GLOBAL) == c.configured_global(originals["global"], False),
                  "final allowed policy not active")
        expected["global"] = c.read(c.GLOBAL)
    finally:
        relay.stop()
        try:
            for name, path in (("global", c.GLOBAL), ("relying", c.RELYING), ("providers", c.PROVIDERS)):
                if changed[name]:
                    if name == "global" and relay.phase == 1:
                        expected[name] = c.configured_global(originals["global"], True)
                    c.require(c.read(path) == expected[name], "concurrent " + name + " change")
                    c.write(path, originals[name])
        except Exception as error:
            failures.append(type(error).__name__ + ":" + str(error))
        try:
            if changed["fixture"] and c.read(c.PROVIDERS) == originals["providers"] and c.path_exists(temporary):
                c.docker("exec", c.TARGET, "rm", "--", temporary)
        except Exception as error:
            failures.append(type(error).__name__ + ":" + str(error))
        try:
            if any(changed[name] for name in ("global", "relying", "providers")) and all(
                    c.read(path) == originals[name] for name, path in
                    (("global", c.GLOBAL), ("relying", c.RELYING), ("providers", c.PROVIDERS))):
                restored_runtime, _ = c.restart(out, "restored")
        except Exception as error:
            failures.append(type(error).__name__ + ":" + str(error))
        restored = not failures and all(c.read(path) == originals[name] for name, path in
                    (("global", c.GLOBAL), ("relying", c.RELYING), ("providers", c.PROVIDERS))) \
                   and not c.path_exists(temporary)
        c.save(out / "restoration.json", {"run": run, "restored": restored,
            "failures": failures, "temporary_metadata_removed": not c.path_exists(temporary),
            "global_sha256": c.sha(c.read(c.GLOBAL)), "relying_party_sha256": c.sha(c.read(c.RELYING)),
            "providers_sha256": c.sha(c.read(c.PROVIDERS))})
    c.require(restored and restored_runtime is not None and len(relay.phases) == 3,
              "campaign or exact restoration incomplete")
    c.save(out / "relay-exchanges.json", relay.exchanges)
    transcript = c.api("/api/runs/" + run + "/transcript")
    c.save(out / "transcript.json", transcript)
    c.capture_originals(out, run, transcript)
    manifest = {item["id"]: item for item in json.loads((out / "decoded-manifest.json").read_text())}
    for index, phase in enumerate(relay.phases):
        exchange = relay.exchanges[index]
        candidates = [item for item in transcript if item.get("direction") == "OUTBOUND"
            and item.get("samlSummary", {}).get("type") == "EcpSoapRequest"
            and item["id"] in manifest and manifest[item["id"]]["sha256"] == exchange["requestSha256"]]
        c.require(len(candidates) == 1, "ECP request original is ambiguous")
        request = candidates[0]
        responses = [item for item in transcript if item.get("direction") == "INBOUND"
            and item.get("samlSummary", {}).get("request_transcript") == request["id"]
            and item["id"] in manifest and manifest[item["id"]]["sha256"] == exchange["responseSha256"]]
        c.require(len(responses) == 1, "ECP response original is ambiguous")
        phase["requestReference"] = request["id"]
        phase["responseReference"] = responses[0]["id"]
        c.save(out / phase["name"] / "exchange.json", {"run": run, "profile": "ecp_idp",
            "request": request["id"], "response": responses[0]["id"]})
    c.verify_wire_transition(out, relay.phases)
    target_metadata = (out / "target-metadata.xml").read_bytes()
    c.require(target_metadata == (out / "target-metadata-overlay.xml").read_bytes(),
              "Suite target metadata differs from relay overlay")
    receipt = {"schema": "samlscope-shibboleth-algorithm-prevention-v2", "runId": run,
        "profile": "ecp_idp", "targetEntityId": c.TARGET_ENTITY,
        "targetMetadataSha256": c.sha(target_metadata), "suiteMetadata": c.blob(fixture),
        "configuration": {"originalGlobal": c.blob(originals["global"]),
            "originalRelyingParty": c.blob(originals["relying"]),
            "originalProviders": c.blob(originals["providers"]),
            "providerConfiguredReadBack": c.blob(configured_provider),
            "fixtureReadBack": c.blob(fixture),
            "restoredGlobal": c.blob(c.read(c.GLOBAL)),
            "restoredRelyingParty": c.blob(c.read(c.RELYING)),
            "restoredProviders": c.blob(c.read(c.PROVIDERS)),
            "temporaryMetadataRemoved": True, "restored": True},
        "runtime": {"initial": initial_runtime, "restored": restored_runtime},
        "phases": relay.phases,
        "operationCounts": {"productConfigurationWrites": 9, "productRestarts": 4,
            "metadataReloads": 0, "protocolOperations": 3, "humanOperations": 0}}
    c.save(out / "algorithm-prevention-receipt.json", receipt)
    c.docker("exec", c.SUITE, "mkdir", "-p", "/data/algorithm-prevention-evidence")
    import subprocess
    subprocess.run(["docker", "cp", str(out / "algorithm-prevention-receipt.json"),
        c.SUITE + ":/data/algorithm-prevention-evidence/" + run + ".json"], check=True)
    c.save(out / "tests-start.json", c.api("/api/runs/" + run + "/tests/start", {}))
    c.save(out / "evaluation.json", c.api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
    c.save(out / "result.json", c.api("/api/runs/" + run + "/result.json"))
    final_suite = c.suite_runtime_blob()
    c.require(c.same_suite_runtime(initial_suite, final_suite), "Suite runtime changed")
    c.save(out / "suite-runtime-final.json", final_suite)
    print("Run", run, "ECP ALG08 A/B/A restored", flush=True)


if __name__ == "__main__":
    main()
