"""Adopt IIP-MD05.e7 only when multiple advertised methods were consulted in preference order.

The Run's own correlation proves the target used the first advertised DigestMethod/SigningMethod
for each entity- and role-level ordering fixture. Each member's Suite-issued invalid control must
be rejected, and the native provider configuration must be restored.
"""
import hashlib
import json
from pathlib import Path

CASE = 'IIP-MD05-e7-idp-01'
FIXTURES = ['algorithm-entity-order-256-384', 'algorithm-entity-order-384-256',
            'algorithm-role-order-256-384', 'algorithm-role-order-384-256']
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def verify(root, product='shibboleth'):
    assert product == 'shibboleth'
    folder = Path(root) / 'shibboleth-md05e7-order-v90'
    load = lambda name: json.loads((folder / name).read_text())
    result = load('result.json')
    case = {c['id']: c for r in result['requirements'] for c in r['cases']}[CASE]
    assert (case['outcome'], case['verdict'], case['reason_code'], case['attested']) == (
        'SATISFIED', 'PASS', 'metadata.algorithms.preference-order-observed', False)
    restoration = load('restoration.json')
    assert restoration['restored'] and restoration['original_sha256'] == restoration['final_sha256']
    assert restoration['temporary_file_removed']
    for variant in ['control', *FIXTURES]:
        imported = load(Path(variant) / 'import.json')
        assert imported['status'] == 'success', variant
        assert imported['fixture_sha256'] == SHA((folder / variant / 'fixture.xml').read_bytes())
        assert imported.get('configuration_read_back') and imported.get('provider_reloaded')
        flow = load(Path(variant) / 'flow.json')
        assert flow['negative_control']['correlated_success'] is False, variant
        assert flow['positive_exchange']['success'] is True, variant
    return folder / 'result.json', {CASE: case}


if __name__ == '__main__':
    import sys
    _, cases = verify(sys.argv[1], 'shibboleth')
    for name, row in cases.items():
        print(name, row['verdict'])
