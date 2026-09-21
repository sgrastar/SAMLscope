"""Adopt the ForceAuthn fresh-authentication observation when the fixed Suite decrypted the assertion.

The Suite v72 ForceAuthn oracle decrypts an EncryptedAssertion with the Run key before reading the
AuthnStatement, so an encrypted success is not mistaken for a missing control. This verifier requires
the four-stage sequence (omitted / omitted / false / true), correlated Success responses, assertion
material in every response, the deployed revision and a clean native restore.
"""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

CASE = 'IIP-IDP06-a-idp-01'
FOLDERS = {'shibboleth': 'shibboleth-browser-chain-v73', 'keycloak': 'keycloak-browser-chain-v73'}
PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol'
ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion'
SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'
EXPECTED_FORCE_AUTHN = [None, None, 'false', 'true']


def verify(root, product='shibboleth'):
    root = Path(root)
    folder = root / FOLDERS[product]
    read = lambda name: json.loads((folder / name).read_text())
    deployment = json.loads((root / 'metadata-keys-runtime-v72' / 'deployment.json').read_text())
    run = read('created.json')['run']['id']
    transcript = read('transcript.json')
    by = {}
    for entry in transcript:
        assert entry['runId'] == run and by.setdefault(entry['id'], entry) is entry
    result = read('result.json')
    assert result['run']['id'] == run
    assert result['suite']['image_digest'] == deployment['digest'], 'Run did not use the ForceAuthn decryption revision'
    restoration = read('restoration.json')
    assert restoration['restored']
    if 'original_sha256' in restoration:
        assert restoration['original_sha256'] == restoration['final_sha256']
    if 'cleanup' in restoration:
        assert restoration['import_ok'] is True and restoration['cleanup'].get('read_back_absent') is True
    manifest = {row['id']: row for row in read('decoded-manifest.json')}

    def decoded(entry_id):
        row = manifest[entry_id]
        path = (folder / row['file']).resolve()
        assert path.parent == (folder / 'decoded').resolve()
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == row['sha256']
        return ET.fromstring(raw)

    cases = {c['id']: c for r in result['requirements'] for c in r['cases']}
    case = cases[CASE]
    assert (case['outcome'], case['verdict'], case['reason_code'], case['attested']) == (
        'SATISFIED', 'PASS', 'force_authn_fresh_authentication_observed', False), CASE
    assert case['evidence_class'] == 'PROTOCOL_OBSERVED'
    evidence = [by[ref['reference']] for ref in case['evidence'] if ref['kind'] == 'transcript']
    assert len(evidence) == 4
    requests = [e for e in transcript if e['direction'] == 'OUTBOUND'
                and e['samlSummary'].get('type') == 'AuthnRequest'
                and e['samlSummary'].get('scenario_case_id') == CASE]
    responses = [e for e in evidence if e['direction'] == 'INBOUND' and e['samlSummary'].get('type') == 'Response']
    assert len(requests) == 4 and len(responses) == 4
    requests.sort(key=lambda e: e['timestamp'])
    responses.sort(key=lambda e: e['timestamp'])
    for index, (request, response) in enumerate(zip(requests, responses)):
        request_xml = decoded(request['id'])
        assert request_xml.tag == '{' + PROTOCOL + '}AuthnRequest'
        assert request_xml.get('ID') == response['samlSummary'].get('inResponseTo')
        force_authn = request_xml.get('ForceAuthn')
        assert force_authn == EXPECTED_FORCE_AUTHN[index], (index, force_authn)
        assert response['samlSummary'].get('statusCode') == SUCCESS
        response_xml = decoded(response['id'])
        assert response_xml.tag == '{' + PROTOCOL + '}Response'
        assertions = [child for child in response_xml
                      if child.tag in ('{' + ASSERTION + '}Assertion', '{' + ASSERTION + '}EncryptedAssertion')]
        assert len(assertions) == 1, 'each stage response must carry assertion material'
        if index == len(requests) - 1:
            # The final stage must be judged from assertion material; an encrypted assertion is
            # acceptable only because the fixed oracle decrypts it before reading AuthnInstant.
            assert assertions[0].tag in ('{' + ASSERTION + '}Assertion', '{' + ASSERTION + '}EncryptedAssertion')
    return folder / 'result.json', cases


if __name__ == '__main__':
    import sys
    product = sys.argv[2] if len(sys.argv) > 2 else 'shibboleth'
    path, cases = verify(sys.argv[1], product)
    print({case: cases[case]['verdict'] for case in [CASE]})
