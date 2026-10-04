"""Adopt the Keycloak exact-RequestedAuthnContext violation observed after the decryption fix.

The Suite v73 RequestedAuthnContext oracle decrypts the EncryptedAssertion with the Run key before
reading the context. Keycloak returns a successful assertion for an exact request naming a per-request
unavailable AuthnContextClassRef, which the approved IIP-IDP08.a control treats as a violation. This
verifier requires the four-fixture matrix, the baseline control, the violating response material, the
deployed revision and a clean native restore.
"""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

CASE = 'IIP-IDP08-a-idp-01'
PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol'
ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion'
SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'
FIXTURES = ['baseline', 'satisfiable-class', 'satisfiable-declaration', 'unsatisfiable-class']


def verify(root):
    root = Path(root)
    folder = root / 'keycloak-browser-chain-v75'
    read = lambda name: json.loads((folder / name).read_text())
    deployment = json.loads((root / 'metadata-keys-runtime-v73' / 'deployment.json').read_text())
    run = read('created.json')['run']['id']
    transcript = read('transcript.json')
    by = {}
    for entry in transcript:
        assert entry['runId'] == run and by.setdefault(entry['id'], entry) is entry
    result = read('result.json')
    assert result['run']['id'] == run
    assert result['suite']['image_digest'] == deployment['digest'], 'Run did not use the decryption revision'
    restoration = read('restoration.json')
    assert restoration['restored'] and restoration['import_ok'] is True
    assert restoration['cleanup'].get('read_back_absent') is True
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
        'VIOLATED', 'FAIL', 'requested_authn_context_exact_violated', False), CASE
    assert case['evidence_class'] == 'PROTOCOL_OBSERVED'
    responses = {}
    for entry in transcript:
        summary = entry['samlSummary']
        if entry['direction'] == 'OUTBOUND' and summary.get('scenario_case_id') == CASE:
            request_id = '_' + summary['action_id']
            matches = [e for e in transcript if e['direction'] == 'INBOUND'
                       and e['samlSummary'].get('inResponseTo') == request_id
                       and e['samlSummary'].get('type') == 'Response']
            assert len(matches) == 1, summary.get('fixture_id')
            responses[summary.get('fixture_id')] = matches[0]
    assert sorted(responses) == sorted(FIXTURES), responses
    for fixture, response in responses.items():
        assert response['samlSummary'].get('statusCode') == SUCCESS, fixture
        xml = decoded(response['id'])
        material = [child for child in xml
                    if child.tag in ('{' + ASSERTION + '}Assertion', '{' + ASSERTION + '}EncryptedAssertion')]
        assert len(material) == 1, fixture
    assert 'unsatisfiable-class' in responses and responses['unsatisfiable-class']['samlSummary'].get('statusCode') == SUCCESS
    evidence = {ref['reference'] for ref in case['evidence'] if ref['kind'] == 'transcript'}
    assert evidence and evidence <= {response['id'] for response in responses.values()}
    return folder / 'result.json', cases


if __name__ == '__main__':
    import sys
    path, cases = verify(sys.argv[1])
    print({CASE: cases[CASE]['verdict']})
