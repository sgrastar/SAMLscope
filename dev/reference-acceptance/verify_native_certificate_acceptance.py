"""Require original-bound native certificate controls and formal Run outcomes before adoption."""
import hashlib
import json
from pathlib import Path
from export_native_certificate_receipt import export

CASES = {'IIP-MD12-b-idp-01', 'IIP-MD12-d-idp-01'}
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def verify(root, runtime=False):
    folder = Path(root)/'keycloak-native-certificate-signature/observations/metadata_idp'
    read = lambda name: json.loads((folder/name).read_text())
    receipt = export(folder.resolve())
    raw = (folder/'qualified-native-certificate-receipt.json').read_bytes()
    assert receipt == json.loads(raw)
    installed = read('evaluation/receipt-installation.json')
    proof = read('verified-native-certificate-v64.json' if runtime else 'verified-native-certificate-v60.json')
    evaluation = 'evaluation-v64' if runtime else 'evaluation'
    result = read(evaluation+'/result.json')
    run = receipt['runId']
    assert installed['run'] == proof['run'] == result['run']['id'] == run
    assert installed['read_back'] and installed['sha256'] == proof['receipt_sha256'] == SHA(raw)
    assert proof['transcript_sha256'] == SHA((folder/'transcript.json').read_bytes())
    assert proof['verdict_adopted'] is False
    assert result['target']['metadata_digest'] == 'sha256:' + receipt['targetMetadataSha256']
    assert set(proof['negative_controls']) == {'wrong-target','wrong-run','not-restored','missing','duplicate',
        'wrong-original','signature-disabled','wrong-certificate','changed-policy','wrong-event-id',
        'wrong-event-time','wrong-event-issuer','generic-http-error','missing-event','wrong-response'}
    assert set(proof['negative_controls'].values()) == {'REJECTED'}
    before = {e['id']: e for e in read('transcript.json')}
    after = {e['id']: e for e in read(evaluation+'/transcript.json')}
    assert before == after  # Reevaluation neither sends requests nor substitutes originals.
    baseline = read('baseline/operations.json')
    assert baseline['restored']
    cases = {c['id']: c for req in result['requirements'] for c in req['cases']}
    selected = {}
    for case_id in ({'IIP-MD06-a9-idp-01'} if runtime else CASES):
        case = cases[case_id]
        observed = proof['production_comparison'][case_id]
        assert (case['outcome'], case['verdict'], case['reason_code']) == (
            'VIOLATED', 'FAIL', 'metadata.certificate.native-valid-request-rejected')
        assert case['attested'] is False
        assert observed['outcome'] == case['outcome'] and observed['reasonCode'] == case['reason_code']
        assert {(e['kind'],e['reference']) for e in observed['evidence']} == {
            (e['kind'],e['reference']) for e in case['evidence']}
        if runtime:
            assert set(observed['details']['required_variants']) == {'control', 'certificate-expired',
                'certificate-not-yet-valid', 'certificate-empty-subject', 'certificate-unknown-ca',
                'certificate-critical-extension', 'certificate-noncritical-extension',
                'certificate-no-digital-signature', 'certificate-unrelated-eku'}
        selected[case_id] = case
    return folder/evaluation/'result.json', selected


if __name__ == '__main__':
    import sys
    _, cases = verify(sys.argv[1])
    for case_id, case in sorted(cases.items()): print(case_id, case['verdict'])
