"""Adopt native algorithm evidence only after restored configuration, controls and formal outcomes agree."""
import hashlib
import json
from pathlib import Path
from export_native_signed_request import export, CASES

PROFILES={'browser_sso_idp','metadata_idp','ecp_idp','single_logout_idp'}
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def verify(root,profile,product='shibboleth'):
    assert profile in PROFILES
    assert product in {'shibboleth','simplesamlphp','keycloak'}
    exporter=export
    if product=='simplesamlphp':
        from export_simplesamlphp_native_signed import export as exporter
    if product=='keycloak':
        from export_keycloak_native_signed import export as exporter
    folder=Path(root)/{'shibboleth':'shibboleth-native-signed-request-v2',
        'simplesamlphp':'simplesamlphp-native-signature-observation-v2','keycloak':'keycloak-native-signature-audit'}[product]/profile
    read=lambda name:json.loads((folder/name).read_text())
    run=read('created.json')['run']['id']
    assert read('plan.json')['plan']['plan']['profile']==profile
    proof=read('verification/protocol-verification.json')
    assert proof['run']==run and proof['product_verdict_assigned'] is False
    assert proof['transcript_sha256']==SHA((folder/'transcript.json').read_bytes())
    installed=read('receipt-installation.json');assert installed['run']==run
    installation={r['case']:r for r in installed['receipts']}
    result=read('evaluation/result.json');assert result['run']['id']==run
    cases={c['id']:c for q in result['requirements'] for c in q['cases']}
    before={e['id']:e for e in read('transcript.json')}
    after={e['id']:e for e in read('evaluation/transcript.json')}
    previous={c['id']:c for q in read('result.json')['requirements'] for c in q['cases']}
    for case in CASES:
        receipt_path=folder/'preparation-receipts'/(run+'-'+case+'.json')
        receipt=exporter(folder.resolve(),receipt_path.resolve(),case)
        assert result['target']['metadata_digest']=='sha256:'+receipt['targetMetadataSha256']
        replay=proof['cases'][case];entry=cases[case]
        assert installation[case]['read_back'] and installation[case]['sha256']==replay['receipt_sha256']==SHA(receipt_path.read_bytes())
        assert previous[case]['verdict']=='NOT_VERIFIED' and previous[case]['reason_code']=='idp.signed-request.inconclusive'
        assert (entry['outcome'],entry['verdict'],entry['reason_code'])==('SATISFIED','PASS','algorithm.native-verification-observed')
        assert entry['attested'] is False
        assert replay['outcome']['outcome']=='SATISFIED' and replay['outcome']['reasonCode']==entry['reason_code']
        controls={'wrong-run','wrong-case','wrong-request','wrong-event','wrong-metadata','missing-condition','duplicate-fixture','wrong-request-original','wrong-response'}
        if product in {'simplesamlphp','keycloak'}:controls.update({'wrong-http-status','wrong-http-request-hash','wrong-http-endpoint'})
        if product=='keycloak':controls.update({'wrong-native-hash','wrong-native-issuer','wrong-native-time','wrong-native-type','indirect-http-response'})
        assert set(replay['negative_controls_rejected'])==controls
        details=replay['outcome']['details']
        assert details['native_receipt_sha256']==SHA(receipt_path.read_bytes())
        assert details['producer_signature_verified'] is True and details['original_fixture_replay_verified'] is True
        if product=='simplesamlphp':assert details['evidence_adapter']=='simplesamlphp-native-http'
        if product=='keycloak':assert details['evidence_adapter']=='keycloak-native-event'
        assert set(details['completed_observations'])=={'VALID','TAMPERED_ACS','BAD_REFERENCE','BAD_SIGNATURE_VALUE'}
        refs={(e['kind'],e['reference']) for e in entry['evidence']}
        assert len(refs)==5 and refs=={(e['kind'],e['reference']) for e in replay['outcome']['evidence']}
        for kind,ref in refs:assert kind=='transcript' and before[ref]==after[ref]
    return folder/'evaluation/result.json',{case:cases[case] for case in CASES}


if __name__=='__main__':
    import sys
    for profile in sorted(PROFILES):
        _,cases=verify(sys.argv[1],profile,sys.argv[2] if len(sys.argv)>2 else 'shibboleth')
        print(profile,{case:cases[case]['verdict'] for case in sorted(CASES)})
