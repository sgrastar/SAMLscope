"""Adopt native EC support only after original evidence, negative controls and formal evaluation agree."""
import hashlib
import json
from pathlib import Path
from export_native_ec_signature import export

CASE = 'IIP-ALG03-a-idp-01'
PROFILES = {'browser_sso_idp': 'shibboleth-ecdsa-native-audit',
            'metadata_idp': 'shibboleth-ecdsa-native-audit-metadata',
            'ecp_idp': 'shibboleth-ecdsa-native-audit-additional',
            'single_logout_idp': 'shibboleth-ecdsa-native-audit-additional'}
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def verify(root, profile, product='shibboleth'):
    assert profile in PROFILES and product in {'shibboleth','keycloak','simplesamlphp'}
    source = Path(root) / PROFILES[profile] / profile
    if product=='simplesamlphp':
        strengthened=Path(root).parent/'reference-20260930'/'ssp-native-ec-v133'/profile
        previous=Path(root).parent/'reference-20260930'/'ssp-native-ec-v132b'/profile
        source=strengthened if strengthened.is_dir() else previous if previous.is_dir() else Path(root)/'simplesamlphp-native-ec-signature'/profile
    if product=='keycloak':source=Path(root)/('keycloak-native-ec-signature-v2' if profile=='browser_sso_idp' else 'keycloak-native-ec-signature-v3')/'observations'/profile
    read = lambda name: json.loads((source / name).read_text())
    run = read('created.json')['run']['id']
    assert read('plan.json')['plan']['plan']['profile'] == profile
    receipt_path = source / 'preparation-receipts' / (run + '.json')
    if product=='shibboleth':receipt = export(source.resolve(), receipt_path.resolve())
    else:
        from export_native_ec_product import export as export_product
        receipt=export_product(source.resolve(),receipt_path.resolve(),product)
    installation = read('receipt-installation.json')
    proof = read('native-ec-verification-v2.json' if (source/'native-ec-verification-v2.json').is_file() else 'native-ec-verification.json')
    assert installation['run'] == proof['run'] == run and installation['read_back']
    assert installation['sha256'] == proof['receipt_sha256'] == SHA(receipt_path.read_bytes())
    assert proof['transcript_sha256'] == SHA((source / 'transcript.json').read_bytes())
    assert proof['product_verdict_assigned'] is False
    controls={'wrong-run', 'wrong-request', 'wrong-event', 'wrong-metadata', 'missing-condition'}
    if product!='shibboleth':controls.update({'wrong-http-status','wrong-http-hash','wrong-http-endpoint','wrong-request-original','wrong-control-response'})
    if product=='keycloak':controls.update({'wrong-native-hash','wrong-native-issuer','wrong-native-time','indirect-http-response'})
    if product=='simplesamlphp' and receipt.get('nativeVerifierSource'):
        controls.update({'wrong-source-hash','wrong-source-path','wrong-source-algorithm','wrong-image-id',
                         'wrong-container-id','wrong-native-observations-hash','wrong-call-path',
                         'wrong-runtime-inspect-hash','wrong-runtime-source-mount','wrong-runtime-route'})
    assert set(proof['negative_controls_rejected'])==controls
    if product=='shibboleth':
        baseline = read('baseline/operations.json')
        assert baseline['run'] == run and baseline['restored'] and baseline['temporary_removed'] and not baseline['failures']
        assert baseline['original_sha256'] == baseline['final_sha256']
        assert read('baseline/flow.json') == 'recorded'
    evaluation = 'evaluation-v133' if (source/'evaluation-v133').is_dir() else 'evaluation-v132' if (source/'evaluation-v132').is_dir() else 'evaluation'
    result = read(evaluation+'/result.json')
    assert result['run']['id'] == run
    assert result['target']['metadata_digest'] == 'sha256:' + receipt['targetMetadataSha256']
    cases = {c['id']: c for req in result['requirements'] for c in req['cases']}
    case = cases[CASE]
    valid_rejected=proof['outcome']['details'].get('valid_ec_request_rejected',False)
    assert isinstance(valid_rejected,bool)
    rsa_only=proof['outcome']['details'].get('rsa_only_verifier_proven',False)
    assert isinstance(rsa_only,bool)
    expected = (('VIOLATED','WARNING','ec-signature.native-unsupported-verifier') if rsa_only else
                ('NOT_VERIFIED','NOT_VERIFIED','ec-signature.native-valid-request-rejected')) if valid_rejected else \
               ('SATISFIED', 'PASS', 'ec-signature.native-support-observed')
    assert (case['outcome'], case['verdict'], case['reason_code']) == expected and case['attested'] is False
    observed = proof['outcome']
    assert (observed['outcome'], observed['reasonCode']) == (expected[0], expected[2])
    assert observed['details']['original_signatures_verified'] is True
    assert observed['details']['native_receipt_sha256'] == SHA(receipt_path.read_bytes())
    references = {(e['kind'], e['reference']) for e in observed['evidence']}
    assert references == {(e['kind'], e['reference']) for e in case['evidence']}
    before = {e['id']: e for e in read('transcript.json')}
    after = {e['id']: e for e in read(evaluation+'/transcript.json')}
    assert len(references) == (10 if valid_rejected else 11)
    for kind, reference in references:
        assert kind == 'transcript' and before[reference] == after[reference]
    return source / evaluation / 'result.json', {CASE: case}


if __name__ == '__main__':
    import sys
    for profile in PROFILES:
        _, cases = verify(sys.argv[1], profile,sys.argv[2] if len(sys.argv)>2 else 'shibboleth')
        print(profile, cases[CASE]['verdict'])
