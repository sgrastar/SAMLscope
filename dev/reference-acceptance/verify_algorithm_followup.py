"""Audit published singleton/absent groups and observed supported-order/skip decisions."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from verify_metadata_algorithm_outcomes import verify as verify_previous
from native_algorithm_preparation import verify as verify_preparation

SOURCES = {
    'keycloak': 'keycloak-algorithm-metadata',
    'simplesamlphp': 'simplesamlphp-algorithm-recorded-metadata',
    'shibboleth': 'shibboleth-algorithm-metadata',
}
PUBLISHER = 'IIP-MD05-e5-idp-01'
SEQUENTIAL = 'IIP-MD05-e9-idp-01'
MD = '{urn:oasis:names:tc:SAML:2.0:metadata}'


def load(folder, name):
    return json.loads((folder / name).read_text())


def verify(root, product):
    root = Path(root)
    verify_previous(root, product)
    source = root / SOURCES[product]
    folder = root / 'algorithm-followup' / product
    path = folder / 'result.json'
    result = load(folder, 'result.json')
    previous = load(source, 'result.json')
    assert result['run']['id'] == previous['run']['id']
    raw = (source / 'target-metadata.xml').read_bytes()
    digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    assert result['target']['metadata_digest'] == digest == previous['target']['metadata_digest']
    metadata = ET.fromstring(raw)
    assert metadata.tag == MD + 'EntityDescriptor'
    roles = metadata.findall(MD + 'IDPSSODescriptor')
    assert roles
    for role in roles:
        assert 'urn:oasis:names:tc:SAML:2.0:protocol' in role.get('protocolSupportEnumeration', '').split()
        for key in role.findall(MD + 'KeyDescriptor'):
            assert key.get('use') in (None, 'signing', 'encryption')
            if key.get('use') != 'signing':
                # These accepted reference snapshots contain no encryption declarations.
                assert not key.findall(MD + 'EncryptionMethod')
    cases = {c['id']: c for req in result['requirements'] for c in req['cases']}
    publisher = cases[PUBLISHER]
    assert (publisher['outcome'], publisher['verdict'], publisher['reason_code']) == (
        'SATISFIED', 'PASS', 'metadata.publisher.encryption-preference-antecedent-false')
    assert not publisher['attested']
    assert publisher['evidence'] == [{'kind': 'target-metadata', 'reference': digest}]
    receipt = load(folder, SEQUENTIAL + '-configure.json')['outcome']
    details = receipt['details']
    assert details['configuration_confirmed'] and not details['missing_variants'] and not details['evidence_issues']
    assert len(details['campaigns']) == 1
    assert 'algorithm-unsupported-first' in details['required_variants']
    assert {'algorithm-entity-sha256', 'algorithm-entity-sha384',
            'algorithm-entity-order-256-384', 'algorithm-entity-order-384-256'} <= set(details['required_variants'])
    signed = {o['variant']: o for o in load(source, 'verified-algorithm-signatures.json')['observations']}
    prepared = {o['variant']: o for o in load(source, 'prepared-metadata-verification.json')['receipts']}
    evidence = {e['reference'] for e in cases[SEQUENTIAL]['evidence'] if e['kind'] == 'transcript'}
    for variant in details['required_variants']:
        verify_preparation(source, variant)
        assert signed[variant]['signed_response_verified']
        assert {signed[variant]['request'], signed[variant]['response']} <= evidence
        assert any(p in evidence for p in prepared[variant]['prepared_entries'])
    if product == 'shibboleth':
        assert cases[SEQUENTIAL]['verdict'] == 'PASS' and not details['selection_mismatches']
        assert cases[SEQUENTIAL]['reason_code'] == 'metadata.algorithms.supported-order-and-skip-observed'
        for signature in signed['algorithm-unsupported-first']['verified_signatures']:
            assert signature['signatureAlgorithm'] == 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
            assert signature['digestAlgorithm'] == 'http://www.w3.org/2001/04/xmlenc#sha256'
    else:
        assert cases[SEQUENTIAL]['verdict'] == 'NOT_VERIFIED'
        assert cases[SEQUENTIAL]['reason_code'] == 'metadata.algorithms.local-policy-unverified'
        assert details['local_policy_verified'] is False
    assert not cases[SEQUENTIAL]['attested']
    return path, cases


if __name__ == '__main__':
    import sys
    for product in SOURCES:
        path, cases = verify(sys.argv[1], product)
        print(product, {case: cases[case]['verdict'] for case in [PUBLISHER, SEQUENTIAL]})
