"""Gate adoption of the Keycloak IDP05.a browser probe on correlated originals."""

import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


CASE_ID = 'IIP-IDP05-a-idp-01'
FOLDER = 'keycloak-idp05a-v127-retry1'
IMAGE = 'sha256:072e161c0e2ac06fe6db1a8a1769193500fdc3b19e59d83aa33053de6c32a580'
P = '{urn:oasis:names:tc:SAML:2.0:protocol}'
A = '{urn:oasis:names:tc:SAML:2.0:assertion}'


def read(folder, name):
    return json.loads((folder / name).read_text())


def verify(root):
    folder = Path(root).parent.parent / 'reference-20260930' / FOLDER
    result_path = folder / 'result.json'
    raw = result_path.read_bytes()
    result = json.loads(raw)
    run = result['run']['id']
    plan = read(folder, 'created.json')['run']['planId']
    assert run == read(folder, 'created.json')['run']['id']
    assert plan == read(folder, 'plan.json')['plan']['plan']['id']
    assert result['suite']['image_digest'] == IMAGE
    assert result['profile']['id'] == 'browser-sso-idp'
    assert read(folder, 'plan.json')['plan']['plan']['target']['entityId'] == 'http://localhost:18180/realms/samlscope'
    assert result['target']['role'] == 'IDP'
    case = next(c for r in result['requirements'] for c in r['cases'] if c['id'] == CASE_ID)
    assert case['outcome'] == 'VIOLATED' and case['verdict'] == 'FAIL'
    assert case['reason_code'] == 'idp.error-response.violated'
    assert case['evidence_class'] == 'PROTOCOL_OBSERVED' and not case['attested']
    assert case['diagnostics']['violating_fixtures'] == ['unsatisfiable-authn-context']

    imported = read(folder, 'import.json')
    entity = 'http://localhost:18080/p/' + plan
    assert imported['status'] == 'success'
    assert imported['import']['ui_status'] == 'client-settings-page'
    assert imported['import']['read_back']['client_id'] == entity
    assert imported['fixture']['entity_id'] == entity
    assert imported['fixture']['sha256'] == hashlib.sha256((folder / 'suite-sp-metadata.xml').read_bytes()).hexdigest()
    assert read(folder, 'initial-login.json')['receipt'] == 'recorded'
    restoration = read(folder, 'restoration.json')
    assert restoration['restored'] and restoration['import_ok']
    assert restoration['cleanup']['delete_status'] == 204
    assert restoration['cleanup']['read_back_absent']

    audit = read(folder, 'decryption-audit.json')
    assert audit['run'] == run and audit['plan'] == plan
    assert audit['result'] == 'different-class'
    assert audit['keyLocation'] == 'suite-plan-key-in-container'
    assert audit['privateKeyExported'] is False
    source = Path(__file__).with_name('VerifyIdpErrorResponse.java')
    assert audit['verifierSourceSha256'] == hashlib.sha256(source.read_bytes()).hexdigest()

    entries = read(folder, 'transcript.json')
    by_id = {e['id']: e for e in entries}
    assert len(by_id) == len(entries)
    originals = {m['id']: m for m in read(folder, 'decoded-manifest.json')}

    def original(entry):
        manifest = originals[entry['id']]
        assert manifest['file'] == 'decoded/' + entry['id'] + '.xml'
        data = (folder / manifest['file']).read_bytes()
        assert manifest['sha256'] == hashlib.sha256(data).hexdigest()
        assert entry['decodedSamlBytes'] == len(data)
        assert entry['runId'] == run
        return ET.fromstring(data), data

    request_entry = by_id[audit['requestTranscriptId']]
    response_entry = by_id[audit['responseTranscriptId']]
    assert request_entry['direction'] == 'OUTBOUND'
    assert request_entry['samlSummary']['scenario_case_id'] == CASE_ID
    assert request_entry['samlSummary']['fixture_id'] == 'unsatisfiable-authn-context'
    assert response_entry['direction'] == 'INBOUND'
    assert response_entry['samlSummary']['activeProbeAccepted'] is True
    assert request_entry['timestamp'] < response_entry['timestamp']
    request, request_bytes = original(request_entry)
    response, response_bytes = original(response_entry)
    assert request.tag == P + 'AuthnRequest' and response.tag == P + 'Response'
    assert request.get('ID') == audit['requestId'] == response.get('InResponseTo')
    assert response_entry['correlationId'] == audit['requestId']
    assert response_entry['samlSummary']['inResponseTo'] == audit['requestId']
    assert request_entry['samlSummary']['action_id'] == audit['requestId'].removeprefix('_')
    requested = request.find(P + 'RequestedAuthnContext')
    assert requested is not None and requested.get('Comparison') == 'exact'
    classes = requested.findall(A + 'AuthnContextClassRef')
    assert len(classes) == 1 and classes[0].text == audit['requestedClass']
    assert audit['requestedClass'] == 'urn:samlscope:probe:unavailable-authn-context:' + audit['requestId'][1:]
    assert response.find(P + 'Status/' + P + 'StatusCode').get('Value').endswith(':Success')
    assert len(response.findall(A + 'EncryptedAssertion')) == 1
    assert audit['actualClass'] == 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified'
    assert audit['actualClass'] != audit['requestedClass']
    assert audit['requestSha256'] == hashlib.sha256(request_bytes).hexdigest()
    assert audit['responseSha256'] == hashlib.sha256(response_bytes).hexdigest()
    assert {'kind': 'transcript', 'reference': response_entry['id']} in case['evidence']

    # The same Run must contain a correlated, accepted Success baseline before the negative probe.
    baseline = [e for e in entries if (e.get('samlSummary') or {}).get('fixture_id') == 'baseline-success']
    assert len(baseline) == 1
    baseline_request, _ = original(baseline[0])
    baseline_responses = [e for e in entries if e['direction'] == 'INBOUND'
                          and e.get('correlationId') == baseline_request.get('ID')]
    assert len(baseline_responses) == 1
    baseline_response, _ = original(baseline_responses[0])
    assert baseline_response.find(P + 'Status/' + P + 'StatusCode').get('Value').endswith(':Success')
    assert baseline_responses[0]['samlSummary']['activeProbeAccepted'] is True
    assert baseline_responses[0]['timestamp'] < request_entry['timestamp']

    steps = read(folder, 'steps.json')
    assert any(s.get('actionId') == audit['requestId'][1:] and s.get('result') == 'recorded' for s in steps)
    assert any(s.get('caseId') == CASE_ID for s in steps)
    return result_path, {CASE_ID: case}


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--root', type=Path, required=True)
    args = p.parse_args()
    path, cases = verify(args.root)
    print(path, cases[CASE_ID]['verdict'])
