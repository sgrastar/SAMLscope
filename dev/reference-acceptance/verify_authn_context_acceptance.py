"""Require native configuration, signed originals, controls and formal evaluation before ledger adoption."""
import hashlib
import json
from pathlib import Path
from export_authn_context_preparation import export

CASES = {'IIP-SSO01-' + suffix + '-idp-01' for suffix in ['ga', 'gb', 'gc', 'gj']}


def verify(root):
    root = Path(root)
    source = root / 'shibboleth-authn-context-acceptance'
    evaluation = root / 'shibboleth-authn-context-evaluation'
    read = lambda folder, name: json.loads((folder / name).read_text())
    run = read(source, 'created.json')['run']['id']
    assert read(source, 'plan.json')['plan']['plan']['profile'] == 'browser_sso_idp'
    installed = read(evaluation, 'receipt-installation.json')
    assert installed['run'] == run
    installations = {row['file']: row for row in installed['receipts']}
    comparison = read(source, 'production-comparison.json')
    assert comparison['run'] == run and not comparison['issues']
    assert comparison['transcript_sha256'] == hashlib.sha256((source / 'transcript.json').read_bytes()).hexdigest()
    baseline = read(evaluation / 'baseline', 'operations.json')
    assert baseline['run'] == run and baseline['restored'] and not baseline['failures'] and baseline['temporary_removed']
    assert baseline['original_sha256'] == baseline['final_sha256']
    assert read(evaluation / 'baseline', 'flow.json') == 'recorded'
    result = read(evaluation, 'result.json')
    assert result['run']['id'] == run
    cases = {c['id']: c for req in result['requirements'] for c in req['cases']}
    previous = {row['id']: row for row in read(source, 'transcript.json')}
    current = {row['id']: row for row in read(evaluation, 'transcript.json')}
    for suffix in ['ga', 'gb', 'gc', 'gj']:
        case_id = 'IIP-SSO01-' + suffix + '-idp-01'
        receipt_path = source / 'preparation-receipts' / (run + '-' + case_id + '.json')
        receipt = export(source.resolve(), receipt_path.resolve(), suffix, source / 'detection-controls.json')
        installation = installations[receipt_path.name]
        assert installation['read_back'] and installation['sha256'] == hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        assert result['target']['metadata_digest'] == 'sha256:' + receipt['targetMetadataSha256']
        oracle = comparison['comparisons'][case_id]
        assert set(oracle['negative_controls_rejected']) == {'missing', 'duplicate', 'wrong-response', 'unverified-controls'}
        assert not oracle['details']['evidence_issues']
        expected = ('VIOLATED', 'FAIL', 'configuration.authn-context.selection-mismatch') if suffix == 'gc' \
            else ('SATISFIED', 'PASS', 'configuration.authn-context.comparison-observed')
        case = cases[case_id]
        assert (case['outcome'], case['verdict'], case['reason_code']) == expected and case['attested'] is False
        assert oracle['outcome'] == expected[0] and oracle['reason_code'] == expected[2]
        assert oracle['details']['mismatched_conditions'] == (['declaration-selection'] if suffix == 'gc' else [])
        evidence = {(e['kind'], e['reference']) for e in oracle['evidence']}
        assert len(evidence) == (18 if suffix == 'gc' else 10)
        assert evidence == {(e['kind'], e['reference']) for e in case['evidence']}
        for kind, reference in evidence:
            assert kind == 'transcript' and previous[reference] == current[reference]
    return evaluation / 'result.json', cases


if __name__ == '__main__':
    import sys
    _, cases = verify(sys.argv[1])
    print({case: cases[case]['verdict'] for case in sorted(CASES)})
