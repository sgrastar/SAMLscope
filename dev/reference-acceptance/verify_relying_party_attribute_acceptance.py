"""Adopt only the RP-specific native experiment and its formally evaluated case."""
import hashlib
import json
from pathlib import Path
from verify_relying_party_attribute_experiment import verify as verify_experiment
from export_relying_party_attribute_preparation import export

CASE = 'IIP-IDP02-a-idp-01'


def verify(root):
    root = Path(root)
    evidence = root / 'shibboleth-relying-party-attributes'
    evaluation = root / 'shibboleth-relying-party-attribute-evaluation'
    audited = verify_experiment(evidence)
    def read(folder, name): return json.loads((folder / name).read_text())
    receipt_path = evidence / 'preparation-receipts' / (audited['run'] + '.json')
    receipt = export(evidence, receipt_path)
    installation = read(evaluation, 'receipt-installation.json')
    assert installation['read_back'] and installation['run'] == audited['run']
    assert installation['sha256'] == hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    assert read(evidence, 'plan.json')['plan']['plan']['profile'] == 'browser_sso_idp'
    comparison = read(evidence, 'production-comparison.json')['comparison']
    assert comparison['outcome'] == 'SATISFIED'
    assert set(comparison['negative_controls_rejected']) == {
        'missing', 'duplicate', 'wrong-response', 'mixed-policy', 'mixed-login', 'mixed-input'}
    baseline = read(evaluation / 'baseline', 'operations.json')
    assert baseline['restored'] and baseline['run'] == audited['run']
    assert not baseline['failures'] and baseline['temporary_removed']
    assert baseline['original_sha256'] == baseline['final_sha256']
    assert read(evaluation / 'baseline', 'flow.json') == 'recorded'
    result = read(evaluation, 'result.json')
    assert result['run']['id'] == audited['run'] == receipt['runId']
    assert result['target']['metadata_digest'] == 'sha256:' + receipt['targetMetadataSha256']
    cases = {case['id']: case for req in result['requirements'] for case in req['cases']}
    case = cases[CASE]
    assert (case['outcome'], case['verdict'], case['reason_code'], case['attested']) == (
        'SATISFIED', 'PASS', 'configuration.relying-party-attributes.difference-observed', False)
    expected = {(ref['kind'], ref['reference']) for ref in comparison['evidence']}
    assert len(expected) == 8 and {(ref['kind'], ref['reference']) for ref in case['evidence']} == expected
    current = {row['id']: row for row in read(evaluation, 'transcript.json')}
    previous = {row['id']: row for row in read(evidence, 'transcript.json')}
    for _, reference in expected:
        # Reevaluation must not replace or rewrite the measured original exchanges.
        assert current[reference] == previous[reference]
    return evaluation / 'result.json', cases


if __name__ == '__main__':
    import sys
    path, cases = verify(sys.argv[1])
    print(CASE, cases[CASE]['verdict'])
