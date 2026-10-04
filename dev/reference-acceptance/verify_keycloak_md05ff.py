"""Verify the Keycloak UI-import evidence for the DiscoHints IPHint batch before adoption.

The native UI import must read back the imported client with signature validation on, each fixture
must be used in a correlated SSO, and the Suite signature control must be exercised: a mutated
request (metadataSignatureControl=invalid) rejected by the IdP and a valid request accepted. A
correlated SSO alone is not proof when the product did not keep signature validation enabled.
"""
import hashlib
import json
from pathlib import Path

ADOPTED = {
    'IIP-MD05-ff-idp-01': ['disco-hints-ipv6-cidr', 'disco-hints-ipv4-cidr'],
}


def verify(root, folder='keycloak-md05ff-v99', adopted=None):
    adopted = ADOPTED if adopted is None else adopted
    final = Path(root) / folder
    result_path = final / 'result.json'
    result = json.loads(result_path.read_text())
    run = result['run']['id']
    entries = {e['id']: e for e in json.loads((final / 'transcript.json').read_text())}
    cases = {c['id']: c for req in result['requirements'] for c in req['cases']}
    imports = {}
    for path in final.glob('*/import.json'):
        data = json.loads(path.read_text())
        if data['status'] != 'success':
            continue
        flow = json.loads((path.parent / 'flow.json').read_text())
        if flow['run'] != run or not flow['correlated_success']:
            continue
        negative = flow.get('negative_control') or {}
        assert negative.get('correlated_success') is False
        assert negative.get('receipt') == 'no-response:Invalid requester'
        control_ids = negative.get('exchange', {}).get('transcript_ids', [])
        assert control_ids, (flow['variant'], 'no control exchange recorded')
        for ref in control_ids:
            entry = entries[ref]
            assert entry['samlSummary'].get('metadataSignatureControl') == 'invalid'
        positive_ids = flow['positive_exchange']['transcript_ids']
        assert any(entries[ref]['samlSummary'].get('metadataSignatureControl') == 'valid'
                   for ref in positive_ids), (flow['variant'], 'no valid-signature request recorded')
        imports.setdefault(flow['variant'], []).append((path, data))
    for case_id, variants in adopted.items():
        case = cases[case_id]
        assert (case['verdict'], case['reason_code']) == ('PASS', 'metadata.fixture-probe.satisfied')
        used = set(case['diagnostics']['used_variants'])
        assert set(variants).issubset(used)
        assert 'control' in used
        # A fixture variant the console could not import (recorded as a failure) is not adopted;
        # only the variants actually used in the correlated flow need a successful import.
        for variant in ['control', *variants]:
            if variant not in used:
                continue
            assert variant in imports, (case_id, variant, 'no successful native import')
            for path, data in imports[variant]:
                assert data['cleanup']['read_back_absent']
                assert data['import']['ui_status'] == 'client-settings-page'
                assert data['import']['read_back']['client_id'] == data['fixture']['entity_id']
                assert data['import']['read_back']['saml_attributes'].get('saml.client.signature') == 'true'
                assert hashlib.sha256((path.parent / 'fixture.xml').read_bytes()).hexdigest() \
                    == data['fixture']['sha256']
        assert case['evidence']
        for ref in case['evidence']:
            assert ref['kind'] == 'transcript'
            entry = entries[ref['reference'].removeprefix('transcript:')]
            assert entry['runId'] == run
    return result_path, cases


if __name__ == '__main__':
    import sys
    verify(sys.argv[1])
    print('Verified Keycloak UI import, signature control and transcript references for',
          len(ADOPTED), 'cases')
