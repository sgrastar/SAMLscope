"""Adopt IIP-MD05.c only when every MDIOP representation was consumed in a correlated flow.

MD05.c evaluates acceptance of MDIOP representations; runtime key interpretation is evaluated in
the MD06.a group. The fixtures must therefore be used (a correlated success) while each member's
Suite-issued invalid-signature control is rejected.
"""
import hashlib
import json
from pathlib import Path

CASE = 'IIP-MD05-c-idp-01'
FIXTURES = ['entity-root', 'entities-root-one', 'keyvalue-only', 'certificate-expired',
            'certificate-not-yet-valid', 'multiple-signing-keys-first', 'multiple-signing-keys']
SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def verify(root, product='shibboleth'):
    assert product == 'shibboleth'
    folder = Path(root) / 'shibboleth-md05c-mdiop-v86'
    load = lambda name: json.loads((folder / name).read_text())
    result = load('result.json')
    cases = {c['id']: c for r in result['requirements'] for c in r['cases']}
    case = cases[CASE]
    assert (case['outcome'], case['verdict'], case['reason_code'], case['attested']) == (
        'SATISFIED', 'PASS', 'metadata.fixture-probe.satisfied', False)
    restoration = load('restoration.json')
    assert restoration['restored'] and restoration['original_sha256'] == restoration['final_sha256']
    assert restoration['temporary_file_removed']
    manifest = {row['id']: row for row in load('decoded-manifest.json')}
    for row in manifest.values():
        path = (folder / row['file']).resolve()
        assert path.parent == (folder / 'decoded').resolve() and SHA(path.read_bytes()) == row['sha256']
    transcript = load('transcript.json')
    prepared = {}
    for variant in ['control', *FIXTURES]:
        deliveries = [e for e in transcript if e['direction'] == 'OUTBOUND'
                      and e['samlSummary'].get('type') == 'MetadataPrepared'
                      and e['samlSummary'].get('variant') == variant]
        assert len(deliveries) == 1, variant
        used = [e for e in transcript if e['direction'] == 'INBOUND'
                and e['samlSummary'].get('metadataProbeAccepted') is True
                and e['samlSummary'].get('statusCode') == SUCCESS
                and ('mdv=' + variant + '&') in (e.get('url') or '')]
        assert len(used) == 1, (variant, len(used))
        prepared[variant] = deliveries[0]['id']
    for variant in FIXTURES:
        assert SHA((folder / variant / 'fixture.xml').read_bytes()) == manifest[prepared[variant]]['sha256']
        flow = load(Path(variant) / 'flow.json')
        assert flow['negative_control']['correlated_success'] is False, variant
        assert flow['positive_exchange']['success'] is True, variant
    return folder / 'result.json', {CASE: case}


if __name__ == '__main__':
    import sys
    _, cases = verify(sys.argv[1], 'shibboleth')
    for name, row in cases.items():
        print(name, row['verdict'])
