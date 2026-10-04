#!/usr/bin/env python3
"""Exercise native recurring HTTP metadata consumption with a changed signing key.

The product is configured once before A and B.  Only the Suite publication changes between
the phases; no target write, reload, or restart can account for B's successful signed request.
The native request-ID audit binds a deliberately invalid B signature to its rejection event.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
from import_metadata_batch import api, flow, save, BASE
sys.path.insert(0, str(Path(__file__).resolve().parent))
_spec = importlib.util.spec_from_file_location("shib_refresh_native_import", Path(__file__).with_name("import_metadata_batch.py"))
_native = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_native)
CONTAINER, CONFIG, docker = _native.CONTAINER, _native.CONFIG, _native.docker
from signature_audit_format import signature_audit, FORMAT
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
from capture_terminal_http_runtime import capture_target
from capture_run_originals import capture
from browser_probe_selection import prepare_and_skip

AUDIT = "/opt/reference-idp/conf/audit.xml"
NS = "urn:mace:shibboleth:2.0:metadata"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
VARIANTS = ("control", "no-valid-until")
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--refresh-wait-seconds", type=int, default=5)
    parser.add_argument("--supersession-probes", action="store_true",
                        help="Exercise simultaneous rollover followed by Suite outbox supersession controls")
    args = parser.parse_args()
    variants = ("control", "multiple-signing-keys-first", "multiple-signing-keys", "no-valid-until") if args.supersession_probes else VARIANTS
    wait = args.refresh_wait_seconds
    if not 2 <= wait <= 30:
        parser.error("refresh wait must be between 2 and 30 seconds")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    originals = {CONFIG: docker("cat", CONFIG), AUDIT: docker("cat", AUDIT)}
    (out / "original-providers.xml").write_bytes(originals[CONFIG])
    (out / "original-audit.xml").write_bytes(originals[AUDIT])
    plan_response = api("/api/plans", dict(name="Shibboleth native recurring HTTP metadata refresh",
        profile="metadata_idp", targetKind="IDP", targetEntityId="http://localhost:18280/idp/shibboleth",
        metadataSourceKind="URL", metadataSourceLocation="http://samlscope-reference-shibboleth:8080/idp/shibboleth",
        suiteMetadataDelivery="HTTP_URL", declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=wait, testUserHint="samlscope-m0-user", requestSigningMode="REQUIRED"),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset="quick"), authorizedTarget=True))
    save(out / "plan.json", plan_response)
    plan = plan_response["plan"]["plan"]["id"]
    created = api("/api/plans/" + plan + "/runs", {})
    save(out / "created.json", created)
    run = created["run"]["id"]
    save(out / "preflight.json", api("/api/runs/" + run + "/preflight", {}))
    save(out / "campaign.json", api("/api/runs/" + run + "/metadata-lab/automatic-polling",
                                    dict(variants=list(variants), pollingDelaySeconds=wait)))
    source = "http://samlscope-reference-suite:8080/p/" + plan + "/metadata/live?run=" + run
    backing = "/opt/reference-idp/metadata/refresh-" + run + ".xml"
    if docker("sh", "-c", "test -e " + backing + " && echo present || true").strip():
        raise RuntimeError("Temporary backing file already exists")
    ET.register_namespace("", NS)
    ET.register_namespace("xsi", XSI)
    providers = ET.fromstring(originals[CONFIG])
    provider = ET.Element("{" + NS + "}MetadataProvider", {
        "id": "Refresh" + run, "{" + XSI + "}type": "FileBackedHTTPMetadataProvider",
        "metadataURL": source, "backingFile": backing,
        "minRefreshDelay": "PT%dS" % wait, "maxRefreshDelay": "PT%dS" % (wait * 2),
        "refreshDelayFactor": "0.75"})
    providers.insert(0, provider)
    configured = {CONFIG: ET.tostring(providers), AUDIT: signature_audit(originals[AUDIT])}
    (out / "configured-providers.xml").write_bytes(configured[CONFIG])
    (out / "configured-audit.xml").write_bytes(configured[AUDIT])
    operations = []
    changed = set()
    phase_records = []
    failures = []
    probe_records = []
    skipped = []
    readbacks = []

    def capture_readbacks(phase):
        for path, kind in ((CONFIG, "providers"), (AUDIT, "audit")):
            raw = docker("cat", path)
            if raw != configured[path]:
                raise RuntimeError("Supersession configured state changed")
            filename = "supersession-%s-%s.xml" % (phase, kind)
            (out / filename).write_bytes(raw)
            readbacks.append(dict(kind=kind, phase=phase, file=filename, sha256=SHA(raw),
                recordedAt=datetime.now(timezone.utc).isoformat()))
        save(out / "supersession-readbacks.json", readbacks)

    def write(path, raw, label):
        item = dict(operation="product-config-write", label=label, path=path,
                    sha256=SHA(raw), recordedAt=time.time(), readBack=False)
        operations.append(item)
        save(out / "operations.json", operations)
        docker("sh", "-c", "cat > " + path, data=raw)
        if docker("cat", path) != raw:
            raise RuntimeError("Product configuration read-back differs")
        item["readBack"] = True
        save(out / "operations.json", operations)

    def restart(label):
        item = dict(operation="product-restart", label=label, recordedAt=time.time(), completed=False)
        operations.append(item)
        save(out / "operations.json", operations)
        subprocess.run(["docker", "restart", CONTAINER], check=True, timeout=60,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        docker("/usr/local/tomcat/bin/startup.sh")
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen("http://localhost:18280/idp/shibboleth", timeout=3) as response:
                    if response.status == 200:
                        item["completed"] = True
                        item["completedAt"] = time.time()
                        save(out / "operations.json", operations)
                        return
            except Exception:
                time.sleep(1)
        raise RuntimeError("Product did not become ready")

    def assert_unchanged():
        for path in configured:
            if docker("cat", path) != configured[path]:
                raise RuntimeError("Concurrent product configuration change")

    def await_native_fetch(variant, lower):
        deadline = time.monotonic() + wait * 8 + 30
        while time.monotonic() < deadline:
            transcript = api("/api/runs/" + run + "/transcript")
            fetches = [item for item in transcript if item.get("samlSummary", {})
                == {"type": "MetadataFetch", "variant": variant, "feed": "live"}
                and item.get("url") == source and float(item["timestamp"]) >= lower]
            prepared = [item for item in transcript if item.get("samlSummary", {}).get("type")
                == "MetadataPrepared" and item.get("samlSummary", {}).get("fetchTranscriptId")
                in {fetch["id"] for fetch in fetches}]
            if prepared:
                selected = prepared[0]
                fetch = next(item for item in fetches
                             if item["id"] == selected["samlSummary"]["fetchTranscriptId"])
                return fetch, selected
            assert_unchanged()
            time.sleep(1)
        raise RuntimeError("Native recurring fetch was not observed for " + variant)

    try:
        state = api("/api/runs/" + run + "/metadata-lab")
        with urllib.request.urlopen(state["automaticStartUrl"], timeout=30) as response:
            if response.status != 202:
                raise RuntimeError("Initial metadata gate did not wait for native retrieval")
            response.read()
        for path in configured:
            changed.add(path)
            write(path, configured[path], "apply-" + Path(path).name)
        restart("campaign-prepare")
        capture_target(out, "shibboleth", "start")
        after = 0
        for index, variant in enumerate(variants):
            state = api("/api/runs/" + run + "/metadata-lab")
            if state["selectedVariant"] != variant:
                raise RuntimeError("Unexpected publication variant")
            if index:
                remaining = after + wait + 0.25 - time.time()
                if remaining > 0:
                    time.sleep(remaining)
                with urllib.request.urlopen(state["automaticStartUrl"], timeout=30) as response:
                    response.read()
            fetch, prepared = await_native_fetch(variant, after + (wait if index else 0))
            assert_unchanged()
            flow_path = out / ("phase-%s.json" % variant)
            is_final = index == len(variants) - 1
            flow(run, flow_path, suite_signature_control=is_final)
            result = json.loads(flow_path.read_text())
            transcript = api("/api/runs/" + run + "/transcript")
            by_id = {item["id"]: item for item in transcript}
            exchange = [by_id[item] for item in result["positive_exchange"]["transcript_ids"]]
            request = next(item for item in exchange if item["direction"] == "OUTBOUND")
            response = next(item for item in exchange if item["direction"] == "INBOUND")
            record = dict(variant=variant, fetchReference=fetch["id"], preparedReference=prepared["id"],
                          requestReference=request["id"], responseReference=response["id"])
            if is_final:
                negative = [by_id[item] for item in result["negative_control"]["exchange"]["transcript_ids"]]
                requests = [item for item in negative if item["direction"] == "OUTBOUND"]
                if len(requests) != 1:
                    raise RuntimeError("Invalid-signature control is ambiguous")
                record["controlRequestReference"] = requests[0]["id"]
            phase_records.append(record)
            after = float(response["timestamp"])
            save(out / "phase-records.json", phase_records)
            if not index:
                save(out / "tests-start.json", api("/api/runs/" + run + "/tests/start", {}))
            print(variant, "native fetch and correlated Success recorded", flush=True)
        if args.supersession_probes:
            import reference_flow
            import os
            selected = "IIP-MD06-ab-idp-01"
            capture_readbacks("before")
            seen_selected = False
            for _ in range(700):
                status = api("/api/runs/" + run + "/active-probe")
                if seen_selected and status.get("caseId") != selected:
                    break
                if status["state"] != "READY":
                    raise RuntimeError("Supersession probe is not ready: " + repr(status))
                if status.get("caseId") != selected:
                    skipped.append(prepare_and_skip(BASE, run, status, api))
                    save(out / "supersession-skipped.json", skipped)
                    continue
                seen_selected = True
                previous = {entry["id"] for entry in api("/api/runs/" + run + "/transcript")}
                def terminal(url, page, code, reason, action=status["actionId"]):
                    api("/api/runs/" + run + "/active-probe/browser-response", dict(
                        actionId=action, status=code, url=url, body=page))
                receipt = reference_flow.Client().flow(status["startUrl"], None,
                    os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user"),
                    os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password"), terminal_observer=terminal)
                entries = api("/api/runs/" + run + "/transcript")
                issued = [entry for entry in entries if entry["id"] not in previous
                    and entry["direction"] == "OUTBOUND"
                    and entry.get("samlSummary", {}).get("action_id") == status["actionId"]]
                if len(issued) != 1:
                    raise RuntimeError("Exactly one Suite outbox request required")
                request = issued[0]
                probe_records.append(dict(fixture=request["samlSummary"]["fixture_id"],
                    requestReference=request["id"], actionId=status["actionId"], receipt=receipt,
                    completedAt=datetime.now(timezone.utc).isoformat()))
                save(out / "supersession-probes.json", probe_records)
                after_status = api("/api/runs/" + run + "/active-probe")
                if after_status.get("actionId") == status["actionId"]:
                    raise RuntimeError("Probe did not complete from actual SAML/browser evidence")
                assert_unchanged()
            if not seen_selected or len(probe_records) != 9:
                raise RuntimeError("Complete supersession outbox matrix not recorded")
            capture_readbacks("after")
        assert_unchanged()
        transcript = api("/api/runs/" + run + "/transcript")
        capture(out, run, transcript)
        decoded = {entry["id"]: entry for entry in json.loads((out / "decoded-manifest.json").read_text())}
        native_ids = {ET.fromstring((out / decoded[item["id"]]["file"]).read_bytes()).get("ID")
                      for item in transcript if item["id"] in decoded
                      and item.get("samlSummary", {}).get("type") == "AuthnRequest"}
        lines = []
        for line in docker("cat", "/opt/reference-idp/logs/idp-audit.log").decode().splitlines():
            if "SAMLscope-signature-v1|" not in line:
                continue
            fields = line.split("SAMLscope-signature-v1|", 1)[1].split("|")
            if len(fields) == 8 and fields[0] in native_ids:
                lines.append("SAMLscope-signature-v1|" + "|".join(fields))
        (out / "native-signature-audit.log").write_text("\n".join(lines) + "\n")
        process = docker("cat", "/opt/reference-idp/logs/idp-process.log").decode()
        logs = [line for line in process.splitlines() if "HTTPMetadataResolver Refresh" + run in line]
        (out / "native-refresh.log").write_text("\n".join(logs) + "\n")
        capture_target(out, "shibboleth", "end")
    finally:
        for path in reversed(list(configured)):
            if path in changed:
                try:
                    if docker("cat", path) != configured[path]:
                        raise RuntimeError("Concurrent change; refusing overwrite")
                    write(path, originals[path], "restore-" + Path(path).name)
                except Exception as error:
                    failures.append(str(error))
        if changed and not failures:
            try:
                restart("campaign-restore")
            except Exception as error:
                failures.append(str(error))
        docker("rm", "-f", backing)
        for path, name in ((CONFIG, "final-providers.xml"), (AUDIT, "final-audit.xml")):
            (out / name).write_bytes(docker("cat", path))
        restored = not failures and all(docker("cat", path) == originals[path] for path in originals)
        removed = not docker("sh", "-c", "test -e " + backing + " && echo present || true").strip()
        save(out / "restoration.json", dict(restored=restored and removed, failures=failures,
            backingFileRemoved=removed, original_sha256=SHA(originals[CONFIG]),
            final_sha256=SHA((out / "final-providers.xml").read_bytes())))
        save(out / "operation-counts.json", dict(operations=operations,
            product_configuration_writes=len([item for item in operations if item["operation"] == "product-config-write"]),
            restoration_writes=len([item for item in operations if item.get("label", "").startswith("restore-")]),
            product_restarts=len([item for item in operations if item["operation"] == "product-restart"]),
            product_reloads=0, human_operations=0, restored=restored and removed,
            protocol_operations=sum(1 + ("controlRequestReference" in phase) for phase in phase_records) + len(probe_records),
            prepared_unselected=len(skipped), skipped_unselected=len(skipped),
            sent_supersession_probes=len(probe_records)))
        for suffix in ("result.json", "transcript", "protocol-evidence"):
            save(out / (suffix if "." in suffix else suffix + ".json"), api("/api/runs/" + run + "/" + suffix))
        if not restored or not removed:
            raise RuntimeError("Native configuration restoration failed")
    print(run, "campaign complete; product configuration restored", flush=True)


if __name__ == "__main__":
    main()
