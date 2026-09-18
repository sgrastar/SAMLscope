"""Verify complete observations while keeping missing capability controls NOT_VERIFIED."""
import hashlib
import json
from pathlib import Path
from native_algorithm_preparation import verify as verify_preparation
from verify_metadata_intersection import REQUIRED

CASE = 'IIP-MD05-e8-idp-01'


def load(folder, name):
    return json.loads((folder / name).read_text())


def verify(root):
    source = Path(root) / 'simplesamlphp-intersection-metadata'
    folder = Path(root) / 'simplesamlphp-intersection-evaluation'
    path = folder / 'result.json'
    result = load(folder, 'result.json')
    original = load(source, 'result.json')
    assert result['run']['id'] == original['run']['id']
    assert load(source, 'plan.json')['plan']['plan']['profile'] == 'metadata_idp'
    assert result['target']['metadata_digest'] == 'sha256:' + hashlib.sha256((source / 'target-metadata.xml').read_bytes()).hexdigest()
    basis = load(folder, 'preparation-confirmation-basis.json')
    assert basis['run_id'] == result['run']['id']
    for name, digest in basis['sha256'].items():
        assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest
    cases = {c['id']: c for req in result['requirements'] for c in req['cases']}
    case = cases[CASE]
    assert (case['verdict'], case['reason_code'], case['attested']) == ('NOT_VERIFIED', 'metadata.algorithms.intersection-evidence-incomplete', False)
    outcome = load(folder, CASE + '-configure.json')['outcome']
    details = outcome['details']
    assert details['configuration_confirmed'] and not details['signature_capability_controls_verified']
    assert set(details['required_variants']) == set(details['observed_variants']) == REQUIRED
    assert not details['missing_variants'] and not details['evidence_issues']
    assert len(details['campaigns']) == 1 and details['selection_mismatches']
    signed = {o['variant']: o for o in load(source, 'verified-algorithm-signatures.json')['observations']}
    proof = load(source, 'verified-encryption-decryption.json')
    assert proof['signed_evidence_sha256'] == hashlib.sha256((source / 'verified-algorithm-signatures.json').read_bytes()).hexdigest()
    decrypted = {o['variant']: o for o in proof['observations']}
    prepared = {o['variant']: o for o in load(source, 'prepared-metadata-verification.json')['receipts']}
    assert set(signed) == set(decrypted) == set(prepared) == REQUIRED
    evidence = {e['reference'] for e in case['evidence'] if e['kind'] == 'transcript'}
    algorithms = set()
    for item in load(source, 'decoded-manifest.json'):
        assert hashlib.sha256((source / item['file']).read_bytes()).hexdigest() == item['sha256']
    for variant in REQUIRED:
        verify_preparation(source, variant)
        imported = load(source / variant, 'import.json')
        assert imported['assertion_encryption_override'] and imported['assertion_encryption']
        assert signed[variant]['signed_response_verified']
        assert decrypted[variant]['decrypted_assertions'] > 0 and decrypted[variant]['wrong_key_rejected']
        assert decrypted[variant]['advertised_key_matched'] and decrypted[variant]['response'] == signed[variant]['response']
        assert {signed[variant]['request'], signed[variant]['response']} <= evidence
        assert any(p in evidence for p in prepared[variant]['prepared_entries'])
        for signature in signed[variant]['verified_signatures']:
            algorithms.add(signature['signatureAlgorithm'])
    assert algorithms == {'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'}
    restoration = load(source, 'restoration.json')
    assert restoration['restored'] and restoration['original_sha256'] == restoration['final_sha256']
    return path, cases


def verify_restoration_batch(root):
    folder = Path(root) / 'simplesamlphp-batched-restoration'
    operations = load(folder, 'operations.json')
    restoration = load(folder, 'restoration.json')
    assert restoration['restored'] and restoration['original_sha256'] == restoration['final_sha256']
    assert restoration['applied_conditions'] == len(operations) == 3
    assert restoration['configuration_write_attempts'] == len(operations) + 1
    assert restoration['restoration_write_attempts'] == 1
    for record in operations:
        assert record['restoration_scope'] == 'batch-finally' and not record['restoration_pending']
        assert record['configuration_written'] and record['configuration_read_back']
        verify_preparation(folder, record['variant'])
    return restoration


if __name__ == '__main__':
    import sys
    print(verify(sys.argv[1])[1][CASE]['verdict'])
    print(verify_restoration_batch(sys.argv[1]))
