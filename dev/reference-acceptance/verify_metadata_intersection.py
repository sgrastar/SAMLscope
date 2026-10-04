"""Bind the complete native Shibboleth intersection campaign to its runtime outcome."""
import hashlib
import json
from pathlib import Path
from native_algorithm_preparation import verify as verify_preparation

CASE = 'IIP-MD05-e8-idp-01'
REQUIRED = {'control', 'algorithm-entity-sha256', 'algorithm-entity-sha384',
    'algorithm-encryption-aes128-gcm', 'algorithm-encryption-aes256-gcm',
    'algorithm-encryption-keysize-128', 'algorithm-encryption-keysize-256',
    'algorithm-oaep-10-sha1', 'algorithm-oaep-10-sha256',
    'algorithm-oaep-11-sha1', 'algorithm-oaep-11-sha256',
    'algorithm-signing-256-keysize-excluded', 'algorithm-signing-384-keysize-excluded'}


def load(folder, name):
    return json.loads((folder / name).read_text())


def verify(root):
    source = Path(root) / 'shibboleth-intersection-metadata'
    folder = Path(root) / 'shibboleth-intersection-evaluation'
    path = folder / 'result.json'
    result = load(folder, 'result.json')
    before = load(source, 'result.json')
    assert result['run']['id'] == before['run']['id']
    assert result['target']['metadata_digest'] == before['target']['metadata_digest']
    assert result['target']['metadata_digest'] == 'sha256:' + hashlib.sha256((source / 'target-metadata.xml').read_bytes()).hexdigest()
    basis = load(folder, 'preparation-confirmation-basis.json')
    assert basis['run_id'] == result['run']['id']
    for name, digest in basis['sha256'].items():
        assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest
    cases = {c['id']: c for req in result['requirements'] for c in req['cases']}
    case = cases[CASE]
    assert (case['verdict'], case['outcome'], case['reason_code']) == ('PASS', 'SATISFIED', 'metadata.algorithms.intersection-observed')
    assert not case['attested']
    receipt = load(folder, CASE + '-configure.json')['outcome']
    details = receipt['details']
    assert details['configuration_confirmed'] and details['signature_capability_controls_verified']
    assert not details['missing_variants'] and not details['evidence_issues'] and not details['selection_mismatches']
    assert set(details['required_variants']) == set(details['observed_variants']) == REQUIRED
    assert len(details['campaigns']) == 1
    signed = {o['variant']: o for o in load(source, 'verified-algorithm-signatures.json')['observations']}
    decrypted = {o['variant']: o for o in load(source, 'verified-encryption-decryption.json')['observations']}
    prepared = {o['variant']: o for o in load(source, 'prepared-metadata-verification.json')['receipts']}
    evidence = {e['reference'] for e in case['evidence'] if e['kind'] == 'transcript'}
    assert set(signed) == set(decrypted) == set(prepared) == REQUIRED
    assert load(source, 'verified-encryption-decryption.json')['signed_evidence_sha256'] == hashlib.sha256((source / 'verified-algorithm-signatures.json').read_bytes()).hexdigest()
    for entry in load(source, 'decoded-manifest.json'):
        assert hashlib.sha256((source / entry['file']).read_bytes()).hexdigest() == entry['sha256']
    for variant in REQUIRED:
        verify_preparation(source, variant)
        assert signed[variant]['signed_response_verified']
        assert decrypted[variant]['advertised_key_matched'] and decrypted[variant]['wrong_key_rejected']
        assert decrypted[variant]['decrypted_assertions'] > 0
        assert not decrypted[variant]['private_key_exported'] and not decrypted[variant]['plaintext_persisted']
        assert decrypted[variant]['response'] == signed[variant]['response']
        assert {signed[variant]['request'], signed[variant]['response']} <= evidence
        assert any(p in evidence for p in prepared[variant]['prepared_entries'])
    return path, cases


if __name__ == '__main__':
    import sys
    print(verify(sys.argv[1])[1][CASE]['verdict'])
