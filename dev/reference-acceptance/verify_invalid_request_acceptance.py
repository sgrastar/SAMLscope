"""Adopt invalid-request browser evidence only when the malformed fixtures are present and unconcluded.

The Suite persists an AuthnRequest without @ID unchanged (it cannot carry a reference signature) for the
approved invalid-request scenarios. This verifier requires that shape, the baseline control response, the
absence of a fabricated SAML Response for the malformed fixtures, and the deployed Suite revision.
"""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

CASES = {'IIP-SSO01-an-idp-01': ['baseline', 'missing-id', 'unsupported-version'],
         'IIP-SSO01-gi-idp-01': ['baseline', 'missing-id']}
FOLDERS = {'simplesamlphp': 'simplesamlphp-browser-chain-v68', 'keycloak': 'keycloak-browser-chain-v71'}
PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol'
DS = 'http://www.w3.org/2000/09/xmldsig#'


def verify(root, product='simplesamlphp', folder=None):
    root = Path(root)
    folder = root / (folder or FOLDERS.get(product, product + '-browser-chain-v68'))
    read = lambda name: json.loads((folder / name).read_text())
    deployment = json.loads((root / 'metadata-keys-runtime-v68' / 'deployment.json').read_text())
    created = read('created.json')
    run = created['run']['id']
    transcript = read('transcript.json')
    by = {}
    for entry in transcript:
        assert entry['runId'] == run and by.setdefault(entry['id'], entry) is entry
    result = read('result.json')
    assert result['run']['id'] == run
    assert result['suite']['image_digest'] == deployment['digest'], 'Run did not use the deployed invalid-request revision'
    restoration = read('restoration.json')
    assert restoration['restored']
    if 'original_sha256' in restoration:
        assert restoration['original_sha256'] == restoration['final_sha256']
    if 'cleanup' in restoration:
        assert restoration['import_ok'] is True and restoration['cleanup'].get('read_back_absent') is True
    counts_path = folder / 'operation-counts.json'
    if counts_path.exists():
        counts = json.loads(counts_path.read_text())
        assert counts['restored'] and counts['human_operations'] == 0 and counts['verdict_adopted'] is False
    manifest = {row['id']: row for row in read('decoded-manifest.json')}

    def decoded(entry_id):
        row = manifest[entry_id]
        path = (folder / row['file']).resolve()
        assert path.parent == (folder / 'decoded').resolve()
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == row['sha256']
        assert by[entry_id]['decodedSamlBytes'] == len(raw)
        return ET.fromstring(raw)

    cases = {c['id']: c for r in result['requirements'] for c in r['cases']}
    for case_id, fixtures in CASES.items():
        case = cases[case_id]
        assert (case['outcome'], case['verdict'], case['reason_code'], case['attested']) == (
            'SATISFIED', 'PASS', 'idp.invalid-request.satisfied', False), case_id
        assert case['evidence_class'] == 'PROTOCOL_OBSERVED'
        observed = {}
        for entry in transcript:
            summary = entry['samlSummary']
            if (entry['direction'] == 'OUTBOUND' and summary.get('type') == 'AuthnRequest'
                    and summary.get('scenario_case_id') == case_id):
                observed.setdefault(summary.get('fixture_id'), []).append(entry)
        for fixture in fixtures:
            assert len(observed.get(fixture, [])) == 1, (case_id, fixture)
        baseline = observed['baseline'][0]
        action_id = baseline['samlSummary']['action_id']
        request_id = '_' + action_id
        request = decoded(baseline['id'])
        assert request.tag == '{' + PROTOCOL + '}AuthnRequest' and request.get('ID') == request_id
        assert request.findall('{' + DS + '}Signature'), 'the valid control must be signed'
        responses = [e for e in transcript if e['direction'] == 'INBOUND'
                     and e['samlSummary'].get('type') == 'Response'
                     and e['samlSummary'].get('inResponseTo') == request_id]
        assert len(responses) == 1
        assert responses[0]['samlSummary']['statusCode'] == 'urn:oasis:names:tc:SAML:2.0:status:Success'
        for fixture in fixtures:
            if fixture == 'baseline':
                continue
            entry = observed[fixture][0]
            malformed = decoded(entry['id'])
            malformed_action = entry['samlSummary']['action_id']
            if fixture == 'missing-id':
                assert not malformed.get('ID') and not malformed.findall('{' + DS + '}Signature')
            if fixture == 'unsupported-version':
                assert malformed.get('Version') == '1.1' and malformed.get('ID')
            # Both incorporated Core rules are conditional on a SAML Response; no response was returned.
            assert not [e for e in transcript if e['direction'] == 'INBOUND'
                        and e['samlSummary'].get('inResponseTo') == '_' + malformed_action], (case_id, fixture)
        for ref in case['evidence']:
            assert ref['kind'] == 'transcript' and by[ref['reference']]['runId'] == run
    return folder / 'result.json', cases


if __name__ == '__main__':
    import sys
    path, cases = verify(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'simplesamlphp')
    print({case: cases[case]['verdict'] for case in CASES})
