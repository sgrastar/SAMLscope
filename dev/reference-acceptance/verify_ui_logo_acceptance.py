"""Adopt only the native UI comparison with retained originals and a formal Run outcome."""
import hashlib
import json
from pathlib import Path
from export_ui_logo_receipt import export

CASE = 'IIP-MD05-f9-idp-01'


def verify(root):
    root = Path(root)
    evidence = root / 'shibboleth-ui-consumer-language-control'
    evaluation = root / 'shibboleth-ui-logo-evaluation'
    def load(folder, name): return json.loads((folder / name).read_text())
    receipt_path = evidence / 'qualified-ui-logo-receipt.json'
    receipt = load(evidence, receipt_path.name)
    assert receipt == export(evidence, evidence / 'target-metadata.xml')
    installed = load(evaluation, 'receipt-installation.json')
    digest = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    assert installed['read_back'] and installed['sha256'] == digest and installed['run'] == receipt['runId']
    replay = load(evidence, 'production-logo-comparison.json')
    assert replay['receipt_sha256'] == digest and replay['run'] == receipt['runId']
    assert replay['production_comparison']['outcome'] == 'SATISFIED'
    assert set(replay['negative_controls']) == {'always-default', 'always-localized', 'hidden', 'wrong-target', 'wrong-request', 'duplicate', 'missing'}
    assert set(replay['negative_controls'].values()) == {'NOT_VERIFIED'}
    baseline = load(evaluation / 'baseline', 'operations.json')
    assert baseline['run'] == receipt['runId'] and baseline['restored'] and baseline['temporary_removed'] and not baseline['failures']
    assert baseline['original_sha256'] == baseline['final_sha256']
    assert load(evaluation / 'baseline', 'flow.json') == 'recorded'
    assert load(evidence, 'plan.json')['plan']['plan']['profile'] == 'metadata_idp'
    result = load(evaluation, 'result.json')
    assert result['run']['id'] == receipt['runId']
    assert result['target']['metadata_digest'] == 'sha256:' + receipt['targetMetadataSha256']
    cases = {case['id']: case for requirement in result['requirements'] for case in requirement['cases']}
    case = cases[CASE]
    assert (case['outcome'], case['verdict'], case['reason_code'], case['attested']) == (
        'SATISFIED', 'PASS', 'browser.ui-logo.language-fallback-observed', False)
    expected = {(ref['kind'], ref['reference']) for ref in replay['production_comparison']['evidence']}
    assert {(ref['kind'], ref['reference']) for ref in case['evidence']} == expected
    assert len(expected) == 8
    return evaluation / 'result.json', cases


if __name__ == '__main__':
    import sys
    _, cases = verify(sys.argv[1])
    print(CASE, cases[CASE]['verdict'])
