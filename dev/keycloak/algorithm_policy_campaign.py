#!/usr/bin/env python3
"""Record native Client Policy algorithm prevention, without assigning verdicts.

The policy and profile are scoped to a new temporary SAML client. All original
policy/profile states and their restored read-backs are compared in memory and
saved without credentials. Protocol outcomes are observations, not verdicts.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse as urls
import urllib.request as http
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "reference-acceptance"))
from attribute_policy_capability_absence import product_token, redact_client_credentials
from relying_party_attribute_campaign import client_recipe, ADMIN, api, save, BASE
from reference_flow import Client
from capture_run_originals import capture

RSA15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
AES128 = "http://www.w3.org/2009/xmlenc11#aes128-gcm"


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("browser_sso_idp", "ecp_idp"), default="browser_sso_idp")
    parser.add_argument("--port", type=int, default=18703)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    relay = None
    if args.profile == "ecp_idp":
        from algorithm_policy_ecp_relay import Relay
        relay = Relay(out, args.port)
    operations = []
    run = None
    plan = None

    def native_record(method, path, status, body, request_body=None):
        safe_body, _ = redact_client_credentials(body)
        safe_request, _ = redact_client_credentials(request_body)
        envelope = dict(schema="samlscope-keycloak-native-admin-original-v1", runId=run,
            campaignId="keycloak-algorithm-prevention", method=method, path=path,
            httpStatus=status, response=safe_body, request=safe_request)
        raw = canonical(envelope)
        before = {item["id"] for item in api("/api/runs/" + run + "/transcript")}
        request = http.Request(BASE + "/p/" + plan + "/sp/paos?run=" + run,
            data=raw, method="POST", headers={"Content-Type": "application/json"})
        with http.urlopen(request, timeout=30) as response:
            if response.status != 204:
                raise RuntimeError("native administration original not recorded")
        added = [item for item in api("/api/runs/" + run + "/transcript")
                 if item["id"] not in before and item.get("decodedSamlRef")
                 and item.get("method") == "POST" and item.get("status") == 204]
        if len(added) != 1:
            raise RuntimeError("native original Recorder reference ambiguous")
        reference = dict(reference=added[0]["id"], sha256=digest(raw))
        folder = out / "native-originals"
        folder.mkdir(exist_ok=True)
        (folder / (added[0]["id"] + ".json")).write_bytes(raw)
        return reference

    def admin(path, value=None, method="GET"):
        token = product_token()
        request = http.Request(ADMIN + path, data=None if value is None else canonical(value),
            method=method, headers={"Authorization": "Bearer " + token,
                                    "Content-Type": "application/json"})
        row = dict(method=method, path=path, status="attempted")
        operations.append(row)
        try:
            with http.urlopen(request, timeout=40) as response:
                row["status"] = response.status
                raw = response.read()
                result = json.loads(raw) if raw else None
                if run is not None:
                    row["original"] = native_record(method, path, row["status"], result, value)
                return result
        except urllib.error.HTTPError as error:
            row["status"] = error.code
            row["error"] = error.read().decode(errors="replace")[:1000]
            if run is not None:
                row["original"] = native_record(method, path, error.code, json.loads(row["error"]), value)
            return None

    profiles_path = "/client-policies/profiles"
    policies_path = "/client-policies/policies"
    original_profiles = admin(profiles_path)
    original_policies = admin(policies_path)
    if not isinstance(original_profiles, dict) or not isinstance(original_policies, dict):
        raise RuntimeError("native policy/profile read-back unavailable")
    save(out / "profiles-original.json", original_profiles)
    save(out / "policies-original.json", original_policies)
    plan_result = api("/api/plans", dict(name="Keycloak native algorithm policy A/B/A",
        profile=args.profile, targetKind="IDP",
        targetEntityId="http://localhost:18180/realms/samlscope", metadataSourceKind="URL",
        metadataSourceLocation=relay.metadata_url if relay is not None else
            "http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor",
        suiteMetadataDelivery="HTTP_URL", declaredFeatures={},
        parameters=dict(clockSkewToleranceSeconds=180, metadataRefreshWaitSeconds=300,
            testUserHint="samlscope-m0-user", requestSigningMode="REQUIRED"),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset="quick"),
        authorizedTarget=True))
    save(out / "plan.json", plan_result)
    plan = plan_result["plan"]["plan"]["id"]
    created = api("/api/plans/" + plan + "/runs", {})
    run = created["run"]["id"]
    save(out / "created.json", created)
    if not re.fullmatch(r"plan_[0-9A-HJKMNP-TV-Z]{26}", plan) or not re.fullmatch(
            r"run_[0-9A-HJKMNP-TV-Z]{26}", run):
        raise ValueError("invalid Suite identity")
    profiles_original_ref = native_record("GET", profiles_path, 200, original_profiles)
    policies_original_ref = native_record("GET", policies_path, 200, original_policies)
    save(out / "preflight.json", api("/api/runs/" + run + "/preflight", {}))
    entity = BASE + "/p/" + plan
    with http.urlopen(entity + "/metadata", timeout=30) as response:
        fixture = response.read()
    (out / "fixture.xml").write_bytes(fixture)
    recipe = client_recipe(ET.fromstring(fixture), "first")
    recipe["protocolMappers"] = []
    recipe["attributes"].update({"saml.encryption.algorithm": AES128,
        "saml.encryption.keyAlgorithm": RSA15, "samlscope-algorithm-policy-campaign": run})
    if relay is not None:
        paos = entity + "/sp/paos?run=" + run
        # Generic ECP controls include unsigned AuthnRequests. This campaign observes
        # encryption prevention, independently of the request-signature obligation.
        recipe["attributes"].update({"saml.allow.ecp.flow": "true", "saml_assertion_consumer_url_paos": paos,
                                    "saml.client.signature": "false"})
        recipe["redirectUris"].append(paos)
    lookup = "/clients?clientId=" + urls.quote(entity, safe="")
    if admin(lookup) != []:
        raise RuntimeError("refusing existing client overwrite")
    policy_name = "samlscope-algorithm-prevention-" + run
    profile_name = "samlscope-algorithm-prevention-profile-" + run
    identifier = None
    expected_profiles = original_profiles
    expected_policies = original_policies
    phases = []
    failures = []
    campaign_errors = []
    restored = False
    expected_client = None
    expected_client_record = None

    def assert_policy_current():
        if admin(profiles_path) != expected_profiles or admin(policies_path) != expected_policies:
            raise RuntimeError("concurrent native policy mutation")

    def set_policy(algorithm):
        nonlocal expected_policies
        assert_policy_current()
        changed = copy.deepcopy(original_policies)
        if algorithm is not None:
            pairs = [{"key": "samlscope-algorithm-policy-campaign", "value": run},
                     {"key": "saml.encryption.keyAlgorithm", "value": algorithm}]
            changed.setdefault("policies", []).append(dict(name=policy_name, enabled=True,
                description="Temporary native algorithm prevention evidence",
                conditions=[dict(condition="client-attributes", configuration={
                    "attributes": json.dumps(pairs, separators=(",", ":")),
                    "is-negative-logic": False})], profiles=[profile_name]))
        admin(policies_path, changed, "PUT")
        status = operations[-1]["status"]
        actual = admin(policies_path)
        save(out / ("policies-proposed-" + str(len(operations)) + ".json"), changed)
        save(out / ("policies-applied-" + str(len(operations)) + ".json"), actual)
        if status != 204 or actual != changed:
            raise RuntimeError("policy apply/read-back failed")
        expected_policies = changed

    def configure_client(algorithm):
        nonlocal expected_client, expected_client_record
        current = admin("/clients/" + identifier)
        if not isinstance(current, dict) or current.get("clientId") != entity:
            raise RuntimeError("temporary client read-back unavailable")
        current["attributes"]["saml.encryption.keyAlgorithm"] = algorithm
        admin("/clients/" + identifier, current, "PUT")
        if operations[-1]["status"] != 204:
            raise RuntimeError("client selection apply failed")
        expected_client = admin("/clients/" + identifier)
        expected_client_record = operations[-1]["original"]
        if not isinstance(expected_client, dict) or expected_client["attributes"]["saml.encryption.keyAlgorithm"] != algorithm:
            raise RuntimeError("client selection read-back failed")

    def flow(label, algorithm, blocked=False):
        assert_policy_current()
        folder = out / label
        folder.mkdir()
        current = admin("/clients/" + identifier)
        read_status = operations[-1]["status"]
        read_error = operations[-1].get("error")
        read_original = operations[-1]["original"]
        if blocked:
            if current is not None or read_status != 400 or json.loads(read_error).get("error_description") != "Request not allowed":
                raise RuntimeError("expected native policy read rejection missing")
        elif current != expected_client:
            raise RuntimeError("temporary client identity/configuration differs")
        admin("/clients/" + identifier, expected_client, "PUT")
        status = operations[-1]["status"]
        update_error = operations[-1].get("error")
        update_original = operations[-1]["original"]
        if blocked:
            if status != 400 or json.loads(update_error).get("error_description") != "Request not allowed":
                raise RuntimeError("expected native policy configuration rejection missing")
        elif status != 204:
            raise RuntimeError("non-prevented native configuration rejected")
        safe, removed = redact_client_credentials(expected_client)
        save(folder / "client-readback.json", safe)
        save(folder / "profiles-readback.json", admin(profiles_path))
        profiles_ref = operations[-1]["original"]
        save(folder / "policies-readback.json", admin(policies_path))
        policies_ref = operations[-1]["original"]
        if expected_client["attributes"]["saml.encryption.keyAlgorithm"] != algorithm:
            raise RuntimeError("configured selection differs")
        prior = {item["id"] for item in api("/api/runs/" + run + "/transcript")}
        terminal = []

        def observer(url, page, code, label):
            # Save only a terminal error page, never login forms, cookies or URL queries.
            index = len(terminal)
            path = folder / ("native-terminal-" + str(index) + ".html")
            path.write_bytes(page.encode())
            terminal.append(dict(path=path.name, sha256=digest(page.encode()),
                status=code, label=label, targetPath=urls.urlsplit(url).path))

        relay_exchange = None
        if relay is None:
            receipt = Client().flow(entity + "/start/m0-roundtrip?run=" + run, None,
                os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user"),
                os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password"), observer)
        else:
            if not phases:
                relay.start_probe(BASE, run, os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user"),
                    os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password"))
            receipt, relay_exchange = relay.exchange(label, folder)
        after = api("/api/runs/" + run + "/transcript")
        row = dict(phase=label, requestedAlgorithm=algorithm, clientUpdateStatus=status,
            clientReadStatus=read_status, clientReadError=read_error, clientUpdateError=update_error,
            clientConfigurationOriginal=expected_client_record,
            clientReadOriginal=read_original, clientUpdateOriginal=update_original,
            profilesOriginal=profiles_ref, policiesOriginal=policies_ref,
            flowStatus=receipt, terminal=terminal,
            addedTranscriptIds=[item["id"] for item in after if item["id"] not in prior],
            removedCredentialPaths=removed, verdictAdopted=False)
        if relay_exchange is not None:
            row["relayExchange"] = relay_exchange
        save(folder / "flow.json", row)
        phases.append(row)
        save(out / "phases.json", phases)
        print(label, receipt, flush=True)

    try:
        admin("/clients", recipe, "POST")
        if operations[-1]["status"] != 201:
            raise RuntimeError("temporary client creation failed")
        rows = admin(lookup)
        if len(rows) != 1:
            raise RuntimeError("temporary client ambiguous")
        identifier = rows[0]["id"]
        if not re.fullmatch(r"[0-9a-f-]{36}", identifier):
            raise RuntimeError("native client DB ID invalid")
        configure_client(RSA15)
        if relay is not None:
            baseline = Client().flow(entity + "/start/m0-roundtrip?run=" + run, None,
                os.environ.get("REFERENCE_USERNAME", "samlscope-m0-user"),
                os.environ.get("REFERENCE_PASSWORD", "samlscope-m0-password"))
            save(out / "browser-baseline.json", dict(status=baseline, protocolOperations=1))
            if baseline != "recorded":
                raise RuntimeError("ECP baseline SSO did not complete")
        flow("rsa15-before", RSA15)
        changed_profiles = copy.deepcopy(original_profiles)
        changed_profiles.setdefault("profiles", []).append(dict(name=profile_name,
            description="Temporary native algorithm prevention evidence",
            executors=[dict(executor="reject-request", configuration={})]))
        assert_policy_current()
        admin(profiles_path, changed_profiles, "PUT")
        if operations[-1]["status"] != 204 or admin(profiles_path) != changed_profiles:
            raise RuntimeError("profile apply/read-back failed")
        expected_profiles = changed_profiles
        set_policy(RSA15)
        flow("rsa15-prevented", RSA15, True)
        set_policy(None)
        configure_client(OAEP)
        set_policy(RSA15)
        flow("oaep-allowed-during-rsa15-prevention", OAEP)
        set_policy(None)
        configure_client(RSA15)
        flow("rsa15-after-remove", RSA15)
        set_policy(OAEP)
        flow("rsa15-allowed-during-oaep-prevention", RSA15)
        set_policy(None)
        configure_client(OAEP)
        set_policy(OAEP)
        flow("oaep-prevented", OAEP, True)
        set_policy(None)
        flow("oaep-after-remove", OAEP)
        if relay is not None:
            relay.finish()
            save(out / "standard-ecp-probes.json", relay.probe_result)
        save(out / "tests-start.json", api("/api/runs/" + run + "/tests/start", {}))
        save(out / "evaluation.json", api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
    except Exception as error:
        campaign_errors.append(type(error).__name__ + ":" + str(error))
    finally:
        if relay is not None:
            relay.stop()
        try:
            assert_policy_current()
            admin(policies_path, original_policies, "PUT")
            if operations[-1]["status"] != 204 or admin(policies_path) != original_policies:
                raise RuntimeError("policy restoration differs")
            expected_policies = original_policies
            admin(profiles_path, original_profiles, "PUT")
            if operations[-1]["status"] != 204 or admin(profiles_path) != original_profiles:
                raise RuntimeError("profile restoration differs")
            expected_profiles = original_profiles
            save(out / "policies-restored.json", admin(policies_path))
            policies_restored_ref = operations[-1]["original"]
            save(out / "profiles-restored.json", admin(profiles_path))
            profiles_restored_ref = operations[-1]["original"]
            if identifier is not None:
                if admin("/clients/" + identifier).get("clientId") != entity:
                    raise RuntimeError("cleanup client identity differs")
                admin("/clients/" + identifier, method="DELETE")
                if operations[-1]["status"] != 204:
                    raise RuntimeError("temporary client cleanup failed")
            restored = admin(lookup) == []
            save(out / "client-after.json", admin(lookup))
            client_after_ref = operations[-1]["original"]
        except Exception as error:
            failures.append(type(error).__name__ + ":" + str(error))
        save(out / "operations.json", dict(run=run, plan=plan, profile=args.profile,
            createdClientId=identifier, adminOperations=operations, phases=phases,
            restored=restored, failures=failures, humanOperations=0, productRestarts=0,
            campaignErrors=campaign_errors, verdictAdopted=False))
        save(out / "transcript.json", api("/api/runs/" + run + "/transcript"))
        if not campaign_errors:
            save(out / "result.json", api("/api/runs/" + run + "/result.json"))
        capture(out, run, json.loads((out / "transcript.json").read_text()))
        if relay is not None and not campaign_errors:
            transcript = json.loads((out / "transcript.json").read_text())
            manifest = {item["id"]: item for item in json.loads((out / "decoded-manifest.json").read_text())}
            for phase in phases:
                exchange = phase["relayExchange"]
                requests = [item for item in transcript if item["direction"] == "OUTBOUND"
                    and item.get("samlSummary", {}).get("type") == "EcpSoapRequest"
                    and item["id"] in manifest and manifest[item["id"]]["sha256"] == exchange["requestSha256"]]
                if len(requests) != 1:
                    raise RuntimeError("SOAP request original not unique")
                responses = [item for item in transcript if item["direction"] == "INBOUND"
                    and item.get("samlSummary", {}).get("request_transcript") == requests[0]["id"]
                    and item["id"] in manifest and manifest[item["id"]]["sha256"] == exchange["responseSha256"]]
                if len(responses) != 1:
                    raise RuntimeError("SOAP response original not unique")
                phase["addedTranscriptIds"] = [requests[0]["id"], responses[0]["id"]]
                save(out / phase["phase"] / "flow.json", phase)
            save(out / "phases.json", phases)
        if not restored or failures:
            raise RuntimeError("product restoration incomplete")
        if not campaign_errors:
            target = (out / "target-metadata.xml").read_bytes()
            (out / "target-metadata.xml").write_bytes(target)
            def blob(raw):
                return dict(base64=base64.b64encode(raw).decode(), sha256=digest(raw))
            receipt = dict(schema="samlscope-keycloak-algorithm-prevention-v1", runId=run,
                profile=args.profile, targetEntityId="http://localhost:18180/realms/samlscope",
                targetMetadataSha256=digest(target), suiteMetadata=blob(fixture),
                clientDatabaseId=identifier, profileName=profile_name, policyName=policy_name,
                configuration=dict(originalProfiles=profiles_original_ref, originalPolicies=policies_original_ref,
                    restoredProfiles=profiles_restored_ref, restoredPolicies=policies_restored_ref,
                    deletedClient=client_after_ref), phases=phases,
                operationCounts=dict(productConfigurationWrites=sum(1 for row in operations if row['method'] in {'POST','PUT','DELETE'}),
                    protocolOperations=len(phases), productRestarts=0, humanOperations=0))
            save(out / "algorithm-prevention-receipt.json", receipt)
    if campaign_errors:
        raise RuntimeError(";".join(campaign_errors))
    print(run, "native client and policy/profile originals restored; diagnostic only")


if __name__ == "__main__":
    main()
