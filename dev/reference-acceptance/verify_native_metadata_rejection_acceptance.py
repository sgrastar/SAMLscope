"""Require a Run-bound product rejection, mutation controls and a formal Suite outcome before adoption."""
import hashlib
import json
from pathlib import Path
from export_native_metadata_rejection_receipt import export

SHA = lambda raw: hashlib.sha256(raw).hexdigest()

_SHIBBOLETH_EXPIRED = dict(
    folder='shibboleth-md05as-rejection-v77', variant='expired', adapter='shibboleth-resolver',
    proof='verified-metadata-rejection-v77.json',
    log_path='/opt/reference-idp/logs/idp-warn.log', marker='expired at time of loading',
    expected=('SATISFIED', 'PASS', 'metadata.fixture-probe.satisfied'))

_SHIBBOLETH_XPATH = dict(
    folder='shibboleth-md05-consumer-sig-v81',
    variants=['xpath-identity', 'xpath-exclude-role-descriptors', 'xpath-exclude-endpoints',
              'xpath-exclude-key-descriptors'],
    adapter='shibboleth-resolver', proof='verified-metadata-rejection-v81.json',
    log_file='resolver-rejections.log', level='ERROR',
    log_path='/opt/reference-idp/logs/idp-warn.log', marker='failed signature pre-validation')

CASES = {
    'shibboleth': {
        # MD04.b rejects the expired root; MD05.as (MUST_NOT) cannot use its endpoints or keys.
        # One resolver rejection binds both. MD03.a rejects unsigned, tampered and untrusted-key
        # documents; one signature-validation campaign binds all three reject fixtures.
        'IIP-MD04-b-idp-01': _SHIBBOLETH_EXPIRED,
        'IIP-MD05-as-idp-01': _SHIBBOLETH_EXPIRED,
        # MD04.a (capability to reject a root without validUntil) is exercised with the product's
        # RequiredValidUntil metadata filter enabled; a missing attribute is then refused.
        'IIP-MD04-a-idp-01': dict(
            folder='shibboleth-md04a-required-validuntil-v84', variant='no-valid-until',
            adapter='shibboleth-resolver', proof='verified-metadata-rejection-v84.json', level='ERROR',
            log_path='/opt/reference-idp/logs/idp-warn.log',
            marker='Metadata did not include a validUntil attribute',
            expected=('SATISFIED', 'PASS', 'metadata.fixture-probe.satisfied')),
        # MD04.c: the Run's tested threshold is T=20 days (RequiredValidUntil maxValidityInterval),
        # so now+T-delta is accepted and now+T+delta is refused.
        'IIP-MD04-c-idp-01': dict(
            folder='shibboleth-md04c-boundary-v84', variant='valid-until-far',
            adapter='shibboleth-resolver', proof='verified-metadata-rejection-v84.json', level='ERROR',
            log_path='/opt/reference-idp/logs/idp-warn.log', marker='is larger than is allowed',
            expected=('SATISFIED', 'PASS', 'metadata.fixture-probe.satisfied')),
        'IIP-MD03-a-idp-01': dict(
            folder='shibboleth-md03-signature-v78', variants=['unsigned', 'bad-signature', 'signed-other-key'],
            adapter='shibboleth-resolver', proof='verified-metadata-rejection-v78.json',
            log_file='resolver-rejections.log', level='ERROR',
            log_path='/opt/reference-idp/logs/idp-warn.log', marker='Error filtering metadata from',
            expected=('SATISFIED', 'PASS', 'metadata.fixture-probe.satisfied')),
        # MD05.an (excluded signed content): refusing every excluding document proves non-use.
        # MD05.am (identity transform choice): refusing the identity document records the rejected
        # choice. One receipt covers all four xpath fixtures; each case reads its own evaluation.
        'IIP-MD05-an-idp-01': {**_SHIBBOLETH_XPATH,
            'expected': ('SATISFIED', 'PASS', 'metadata.excluded-content.rejected')},
        'IIP-MD05-am-idp-01': {**_SHIBBOLETH_XPATH, 'evaluation': 'evaluation-am',
            'expected': ('SATISFIED_WITH_NOTE', 'WARNING', 'metadata.unauthorized-transform.rejected')},
    },
}


def _args(folder, spec):
    class Args:
        pass
    args = Args()
    args.campaign_dir = folder
    args.run = json.loads((folder / 'created.json').read_text())['run']['id']
    args.variant = spec.get('variant')
    args.variants = ','.join(spec['variants']) if spec.get('variants') else None
    args.rejected_order = ','.join(spec['rejected_order']) if spec.get('rejected_order') else None
    args.adapter = spec['adapter']
    args.marker = spec['marker']
    args.level = spec.get('level')
    args.container = None
    args.log_path = None
    args.log_file = folder / spec.get('log_file', (spec.get('variant') or '') + '/resolver-rejection.log')
    args.log_ref = spec['log_path']
    return args


def verify(root, product='shibboleth', case=None):
    spec = CASES[product][case or next(iter(CASES[product]))]
    folder = Path(root) / spec['folder']
    evaluation = folder / spec.get('evaluation', 'evaluation')
    campaign_read = lambda name: json.loads((folder / name).read_text())
    eval_read = lambda name: json.loads((evaluation / name).read_text())
    expected_variants = spec.get('variants') or [spec['variant']]
    raw = (folder / 'qualified-metadata-rejection-receipt.json').read_bytes()
    receipt = json.loads(raw)
    assert receipt['schema'] == 'samlscope-native-metadata-rejection-receipt-v1'
    assert receipt['evidenceAdapter'] == spec['adapter']
    assert [row['variant'] for row in receipt['rejections']] == expected_variants
    assert export(_args(folder, spec)) == receipt, 'Receipt is not reproducible from the campaign evidence'
    proof = json.loads((folder / spec['proof']).read_text())
    installation = eval_read('receipt-installation.json')
    result = eval_read('result.json')
    run = receipt['runId']
    assert proof['run'] == installation['run'] == result['run']['id'] == run
    assert installation['read_back'] and installation['sha256'] == proof['receipt_sha256'] == SHA(raw)
    assert proof['transcript_sha256'] == SHA((folder / 'transcript.json').read_bytes())
    assert proof['verdict_adopted'] is False and proof['adapter'] == spec['adapter']
    assert proof['target_metadata_sha256'] == receipt['targetMetadataSha256']
    assert proof['proven_variants'] == {variant: spec['adapter'] for variant in expected_variants}
    assert set(proof['negative_controls'].values()) == {'NOT_VERIFIED'}
    assert len(proof['negative_controls']) >= 16
    manifest = campaign_read('decoded-manifest.json')
    assert len({row['id'] for row in manifest}) == len(manifest)
    for row in manifest:
        path = (folder / row['file']).resolve()
        assert path.parent == (folder / 'decoded').resolve() and SHA(path.read_bytes()) == row['sha256']
    restoration = campaign_read('restoration.json')
    assert restoration['restored'] and restoration['original_sha256'] == restoration['final_sha256']
    assert restoration['temporary_file_removed']
    assert result['target']['metadata_digest'] == 'sha256:' + receipt['targetMetadataSha256']
    assert {e['id']: e for e in campaign_read('transcript.json')} == \
           {e['id']: e for e in eval_read('transcript.json')}
    assert {e['id']: e for e in eval_read('transcript-before.json')} == \
           {e['id']: e for e in eval_read('transcript.json')}
    completed = {row['caseId']: row['outcome'] for row in eval_read('evaluation.json')['completed']}
    assert completed.get(case) == spec['expected'][0]
    cases = {c['id']: c for req in result['requirements'] for c in req['cases']}
    case_row = cases[case]
    assert (case_row['outcome'], case_row['verdict'], case_row['reason_code']) == spec['expected']
    assert case_row['attested'] is False
    return evaluation / 'result.json', {case: case_row}


if __name__ == '__main__':
    import sys
    _, cases = verify(sys.argv[1], 'shibboleth', sys.argv[2])
    for name, row in cases.items():
        print(name, row['verdict'])
