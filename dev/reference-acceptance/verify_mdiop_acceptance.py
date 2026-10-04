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
REQUIRED_FIXTURES = {
    'entity-root', 'entities-root-one', 'keyvalue-only', 'keyvalue-and-x509',
    'certificate-expired', 'certificate-not-yet-valid', 'certificate-empty-subject',
    'certificate-unknown-ca', 'certificate-critical-extension', 'certificate-noncritical-extension',
    'certificate-no-digital-signature', 'certificate-unrelated-eku', 'key-use-omitted',
    'multiple-signing-keys-first', 'multiple-signing-keys', 'multiple-omitted-keys-first',
    'multiple-omitted-keys-second', 'multiple-encryption-keys',
}
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
    observed = {e['samlSummary'].get('variant') for e in transcript
                if e['direction'] == 'OUTBOUND' and e['samlSummary'].get('type') == 'MetadataPrepared'}
    # This historical campaign proves its seven original members, but the signed case is an
    # all-of over wider representation families. Keep the original PASS as historical data;
    # never adopt the incomplete campaign as proof of the whole obligation.
    missing = sorted(REQUIRED_FIXTURES - observed)
    (folder / 'admission-withdrawal-v171.json').write_text(json.dumps(dict(
        case=CASE, adoptable=False, historicalResultUnchanged=True,
        reason='required-mdiop-representation-variants-unobserved',
        verifiedPartialFixtures=FIXTURES, missingFixtures=missing), indent=2) + '\n')
    return None


if __name__ == '__main__':
    import sys
    verified = verify(sys.argv[1], 'shibboleth')
    print(CASE, 'NOT_VERIFIED: historical campaign does not cover all approved representation variants')
