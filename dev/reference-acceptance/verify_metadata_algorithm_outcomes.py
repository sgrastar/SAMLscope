"""Audit the selected native-import algorithm outcomes before ledger adoption."""
import hashlib
import json
from pathlib import Path
from native_algorithm_preparation import verify as verify_preparation

CASES = {'IIP-MD05-ea-idp-01', 'IIP-MD05-eb-idp-01'}


def load(folder, name):
    return json.loads((folder / name).read_text())


def verify(root, product='simplesamlphp'):
    root = Path(root)
    assert product in {'simplesamlphp', 'keycloak', 'shibboleth'}
    folder = root / ('algorithm-oracle-evaluation' if product == 'simplesamlphp' else product + '-algorithm-evaluation')
    source = root / ('simplesamlphp-algorithm-recorded-metadata' if product == 'simplesamlphp' else product + '-algorithm-metadata')
    result = load(folder, 'result.json')
    original = load(source, 'result.json')
    run = result['run']['id']
    assert run == original['run']['id']
    assert result['target']['metadata_digest'] == original['target']['metadata_digest']
    basis = load(folder, 'preparation-confirmation-basis.json')
    assert basis['run_id'] == run
    for name, digest in basis['sha256'].items():
        assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest
    if product == 'simplesamlphp':
        native = load(folder, 'native-import-path-audit.json')
        assert native['driver_matches_native_static_conversion']
        assert hashlib.sha256((folder / 'native-admin-Federation.php').read_bytes()).hexdigest() == native['sha256']
        assert native['native_static_output_removals'] == ['entityDescriptor', 'expire']
    operations = {o['variant']: o for o in load(source, 'operations.json')}
    prepared = {o['variant']: o for o in load(source, 'prepared-metadata-verification.json')['receipts']}
    signatures = {o['variant']: o for o in load(source, 'verified-algorithm-signatures.json')['observations']}
    manifest = {o['id']: o for o in load(source, 'decoded-manifest.json')}
    for entry in manifest.values():
        assert hashlib.sha256((source / entry['file']).read_bytes()).hexdigest() == entry['sha256']
    entries = {e['id']: e for e in load(source, 'transcript.json')}
    cases = {c['id']: c for req in result['requirements'] for c in req['cases']}
    before = {c['caseId']: c for c in load(folder, 'protocol-evidence-before.json')['cases']}
    expected = {
        'IIP-MD05-ea-idp-01': ('NOT_VERIFIED', 'metadata.algorithms.local-policy-unverified'),
        'IIP-MD05-eb-idp-01': ('FAIL', 'metadata.algorithms.role-precedence-violated'),
    }
    if product == 'shibboleth':
        expected = {
            'IIP-MD05-ea-idp-01': ('PASS', 'metadata.algorithms.first-supported-observed'),
            'IIP-MD05-eb-idp-01': ('PASS', 'metadata.algorithms.role-precedence-observed'),
        }
    for case_id in CASES:
        case = cases[case_id]
        assert (case['verdict'], case['reason_code']) == expected[case_id]
        assert not case['attested']
        receipt = load(folder, case_id + '-configure.json')
        details = receipt['outcome']['details']
        assert details['configuration_confirmed']
        assert not details['evidence_issues'] and not details['missing_variants']
        assert len(details['campaigns']) == 1
        assert before[case_id]['ready'] is False
        assert before[case_id]['details']['configuration_confirmation_required']
        evidence = {e['reference'] for e in case['evidence'] if e['kind'] == 'transcript'}
        for variant in details['required_variants']:
            operation = operations[variant]
            assert operation['fixture_sha256'] == verify_preparation(source, variant)
            if product == 'keycloak':
                assert operation['driver_exit'] == 0
            signed = signatures[variant]
            assert signed['signed_response_verified']
            assert {signed['request'], signed['response']} <= evidence
            assert any(p in evidence for p in prepared[variant]['prepared_entries'])
        assert all(entries[e]['runId'] == run for e in evidence)
    mismatches = load(folder, 'IIP-MD05-eb-idp-01-configure.json')['outcome']['details']['selection_mismatches']
    if product == 'shibboleth':
        assert not mismatches
        assert not load(folder, 'IIP-MD05-ea-idp-01-configure.json')['outcome']['details']['selection_mismatches']
    else:
        assert 'algorithm-role-signing-384:outside-effective-list' in mismatches
        assert 'algorithm-role-digest-384:outside-effective-list' in mismatches
    return folder / 'result.json', cases


if __name__ == '__main__':
    import sys
    path, cases = verify(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'simplesamlphp')
    print({case: cases[case]['verdict'] for case in sorted(CASES)})
