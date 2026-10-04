#!/usr/bin/env python3
"""Finalize a restored generic-ECP ALG08 relay Run from immutable wire originals."""
import argparse
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

import algorithm_prevention_campaign as c


SELECTED = (0, 1, 6)
PHASES = ("allowed-before", "blocked", "allowed-after")
P = "{urn:oasis:names:tc:SAML:2.0:protocol}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    out = args.folder.resolve()
    restoration = json.loads((out / "restoration.json").read_text())
    run = restoration["run"]
    c.require(restoration["restored"] and restoration["temporary_metadata_removed"]
              and not restoration["failures"], "target restoration is incomplete")
    originals = {name: (out / ("original-" + name)).read_bytes()
                 for name in ("global", "relying", "providers")}
    for name, path in (("global", c.GLOBAL), ("relying", c.RELYING), ("providers", c.PROVIDERS)):
        c.require(c.read(path) == originals[name], "target changed after restoration: " + name)
    c.require((out / "algorithm-prevention-receipt.json").exists() is False,
              "receipt already exists")
    probes = json.loads((out / "standard-ecp-probes.json").read_text())
    c.require(len(probes) == 7 and len({item["actionId"] for item in probes}) == 7
              and all(item["outboxStatus"] == "SENT" and item["dispatchState"] == "SENT"
                      for item in probes), "generic ECP outbox actions incomplete")
    transcript = c.api("/api/runs/" + run + "/transcript")
    c.save(out / "transcript.json", transcript)
    c.capture_originals(out, run, transcript)
    manifest_list = json.loads((out / "decoded-manifest.json").read_text())
    manifest = {item["id"]: item for item in manifest_list}
    c.require(len(manifest) == len(manifest_list), "decoded original IDs ambiguous")
    exchanges = []
    phases = []
    for index in range(7):
        request_raw = (out / ("relay-request-" + str(index) + ".xml")).read_bytes()
        response_raw = (out / ("relay-response-" + str(index) + ".xml")).read_bytes()
        request_matches = [item for item in transcript if item.get("direction") == "OUTBOUND"
            and item.get("samlSummary", {}).get("type") == "EcpSoapRequest"
            and item["id"] in manifest and manifest[item["id"]]["sha256"] == c.sha(request_raw)]
        c.require(len(request_matches) == 1, "relay request does not match one Suite original")
        request = request_matches[0]
        response_matches = [item for item in transcript if item.get("direction") == "INBOUND"
            and item.get("samlSummary", {}).get("request_transcript") == request["id"]
            and item["id"] in manifest and manifest[item["id"]]["sha256"] == c.sha(response_raw)]
        c.require(len(response_matches) == 1, "relay response does not match one Suite original")
        response = response_matches[0]
        c.require(request["correlationId"] == response["correlationId"]
                  and request["correlationId"] == probes[index]["actionId"]
                  and probes[index]["responseTranscriptId"] == response["id"],
                  "outbox/relay/Suite correlation differs")
        root = ET.fromstring(response_raw)
        status = root.find(".//" + P + "StatusCode")
        success = status is not None and status.get("Value") == "urn:oasis:names:tc:SAML:2.0:status:Success"
        exchanges.append({"index": index, "actionId": probes[index]["actionId"],
                          "requestReference": request["id"], "responseReference": response["id"],
                          "requestSha256": c.sha(request_raw), "responseSha256": c.sha(response_raw),
                          "httpStatus": response.get("status"), "samlSuccess": success,
                          "targetUrl": "http://localhost:18280/idp/profile/SAML2/SOAP/ECP",
                          "credentialForwardedOnly": True, "cookieForwarded": False})
    c.require([item["samlSuccess"] and item["httpStatus"] == 200 for item in exchanges
               if item["index"] in SELECTED] == [True] * 3,
              "selected ECP responses are not three SOAP successes")
    for phase_index, index in enumerate(SELECTED):
        name = PHASES[phase_index]
        global_raw = (out / name / "global-readback.xml").read_bytes()
        relying_raw = (out / name / "relying-party-readback.xml").read_bytes()
        expected_global = c.configured_global(originals["global"], phase_index == 1)
        c.require(global_raw == expected_global and relying_raw == c.configured_relying(originals["relying"]),
                  "phase native read-back differs")
        runtime = json.loads((out / ("runtime-" + name + ".json")).read_text())
        phases.append({"name": name, "globalReadBack": c.blob(global_raw),
                       "relyingPartyReadBack": c.blob(relying_raw), "runtime": runtime,
                       "requestReference": exchanges[index]["requestReference"],
                       "responseReference": exchanges[index]["responseReference"]})
        c.save(out / name / "exchange.json", {"run": run, "profile": "ecp_idp",
            "request": phases[-1]["requestReference"], "response": phases[-1]["responseReference"]})
    c.save(out / "relay-exchanges.json", exchanges)
    c.save(out / "operation-ledger.json", {
        "schema": "samlscope-shibboleth-alg08-ecp-operations-v1",
        "runId": run, "humanOperations": 0, "browserBaselineOperations": 1,
        "genericEcpProtocolOperations": 7, "selectedAlg08Indices": list(SELECTED),
        "productConfigurationWrites": 9, "productRestarts": 4,
        "metadataReloads": 0, "targetConfigurationRestored": True})
    c.verify_wire_transition(out, phases)
    target_metadata = (out / "target-metadata.xml").read_bytes()
    c.require(target_metadata == (out / "target-metadata-overlay.xml").read_bytes(),
              "Suite target snapshot differs from relay overlay")
    fixture = (out / "suite-metadata.xml").read_bytes()
    initial_runtime = json.loads((out / "runtime-initial.json").read_text())
    restored_runtime = json.loads((out / "runtime-restored.json").read_text())
    initial_suite = json.loads((out / "suite-runtime-initial.json").read_text())
    receipt = {"schema": "samlscope-shibboleth-algorithm-prevention-v2", "runId": run,
        "profile": "ecp_idp", "targetEntityId": c.TARGET_ENTITY,
        "targetMetadataSha256": c.sha(target_metadata), "suiteMetadata": c.blob(fixture),
        "configuration": {"originalGlobal": c.blob(originals["global"]),
            "originalRelyingParty": c.blob(originals["relying"]),
            "originalProviders": c.blob(originals["providers"]),
            "providerConfiguredReadBack": c.blob(c.configured_providers(originals["providers"], run)),
            "fixtureReadBack": c.blob(fixture),
            "restoredGlobal": c.blob(originals["global"]),
            "restoredRelyingParty": c.blob(originals["relying"]),
            "restoredProviders": c.blob(originals["providers"]),
            "temporaryMetadataRemoved": True, "restored": True},
        "runtime": {"initial": initial_runtime, "restored": restored_runtime},
        "phases": phases,
        "operationCounts": {"productConfigurationWrites": 9, "productRestarts": 4,
            "metadataReloads": 0, "protocolOperations": 7, "humanOperations": 0}}
    receipt_path = out / "algorithm-prevention-receipt.json"
    c.save(receipt_path, receipt)
    c.docker("exec", c.SUITE, "mkdir", "-p", "/data/algorithm-prevention-evidence")
    subprocess.run(["docker", "cp", str(receipt_path),
        c.SUITE + ":/data/algorithm-prevention-evidence/" + run + ".json"], check=True)
    c.save(out / "tests-start.json", c.api("/api/runs/" + run + "/tests/start", {}))
    c.save(out / "evaluation.json", c.api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
    c.save(out / "result.json", c.api("/api/runs/" + run + "/result.json"))
    final_suite = c.suite_runtime_blob()
    c.require(c.same_suite_runtime(initial_suite, final_suite), "Suite runtime changed during campaign")
    c.save(out / "suite-runtime-final.json", final_suite)
    print(run, "ECP ALG08 formal result captured", flush=True)


if __name__ == "__main__":
    main()
