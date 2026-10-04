"""Adopt only native-prepared, cryptographically observed and formally evaluated policy cases."""
import hashlib
import json
from pathlib import Path
from verify_attribute_policy_experiment import verify as verify_experiment
from export_attribute_policy_preparation import export

CASE_LABELS = {
    'IIP-IDP03-a-idp-01': ['baseline', 'entity-present', 'entity-absent'],
    'IIP-IDP04-a-idp-01': ['baseline', 'requested-required', 'requested-optional', 'requested-absent'],
    'IIP-IDP04-b-idp-01': ['baseline', 'index-zero', 'index-one', 'index-zero-repeat'],
}


def verify(root):
    root = Path(root)
    evidence = root / 'shibboleth-attribute-policy-preparation'
    evaluation = root / 'shibboleth-attribute-policy-evaluation'
    audited = verify_experiment(evidence)
    assert audited['native_preparation_recorded'] and audited['production_collector_observed']
    def load(folder, name):
        return json.loads((folder / name).read_text())
    assert (evidence / 'qualified-preparation-corrected.json').is_file()
    receipt = export(evidence, evidence / 'qualified-preparation-corrected.json')
    correction = load(evaluation, 'preparation-correction.json')
    assert correction['run'] == audited['run'] and correction['read_back']
    assert correction['accepted_input_sha256'] == hashlib.sha256((evidence / 'qualified-preparation-corrected.json').read_bytes()).hexdigest()
    assert correction['rejected_sha256'] == hashlib.sha256((evidence / 'qualified-preparation.json').read_bytes()).hexdigest()
    assert load(evidence, 'plan.json')['plan']['plan']['profile'] == 'browser_sso_idp'
    result = load(evaluation, 'result.json')
    assert result['run']['id'] == receipt['runId'] == audited['run']
    assert result['target']['metadata_digest'] == 'sha256:' + receipt['targetMetadataSha256']
    cases = {c['id']: c for r in result['requirements'] for c in r['cases']}
    production = load(evidence, 'production-observation.json')['observations']
    observations = load(evidence, 'observations.json')
    by_label = dict(zip([o['label'] for o in observations], production))
    for case_id, labels in CASE_LABELS.items():
        case = cases[case_id]
        assert (case['outcome'], case['verdict'], case['reason_code'], case['attested']) == (
            'SATISFIED', 'PASS', 'configuration.attribute-policy.comparison-observed', False)
        confirmation = load(evaluation, case_id + '-configure.json')['outcome']
        assert confirmation['outcome'] == 'SATISFIED'
        details = confirmation['details']
        assert details['configuration_confirmed'] and details['preparation_source'] == 'local-native-adapter'
        assert not details['missing_conditions'] and not details['evidence_issues'] and not details['unobserved_policy_differences']
        expected = {e['reference'] for label in labels for e in by_label[label]['evidence']}
        assert {e['reference'] for e in case['evidence'] if e['kind'] == 'transcript'} == expected
    return evaluation / 'result.json', cases


if __name__ == '__main__':
    import sys
    path, cases = verify(sys.argv[1])
    print({case: cases[case]['verdict'] for case in CASE_LABELS})
