"""Require native originals, mutation controls and formal Suite outcomes for key evidence adoption."""
import hashlib
import json
from pathlib import Path
from export_metadata_key_receipt import export
from export_ssp_metadata_key_receipt import export as export_simplesamlphp
from export_shibboleth_metadata_key_receipt import export as export_shibboleth
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CONTROLS={'wrong-target','wrong-run','not-restored','missing','duplicate','wrong-import-hash',
          'wrong-import-entity','import-not-verified','wrong-original','signature-disabled','wrong-certificate',
          'changed-policy','wrong-event-id','wrong-event-time','wrong-event-issuer','generic-http-error',
          'missing-event','wrong-response'}
PRODUCTS={
    'keycloak': dict(
        folder='keycloak-native-key-selection-v65/observations/metadata_idp',
        adapter='keycloak-native-event', proof='verified-key-evidence-v65.json', export=export,
        expected={'IIP-MD06-a8-idp-01': ('SATISFIED','PASS','metadata.keys.selection-observed'),
                  'IIP-MD07-a-idp-01': ('VIOLATED','FAIL','metadata.keys.selection-violated')}),
    'simplesamlphp': dict(
        folder='simplesamlphp-native-key-selection-v65/metadata_idp',
        adapter='simplesamlphp-native-http', proof='verified-key-evidence-v66.json',
        export=export_simplesamlphp,
        expected={'IIP-MD06-a8-idp-01': ('SATISFIED','PASS','metadata.keys.selection-observed'),
                  'IIP-MD07-b-idp-01': ('SATISFIED','PASS','metadata.keys.selection-observed')},
        not_adopted={'IIP-MD06-a7-idp-01'}),
    'shibboleth': dict(
        folder='shibboleth-native-key-selection-v67/metadata_idp',
        adapter='shibboleth-audit', proof='verified-key-evidence-v67.json',
        export=export_shibboleth,
        expected={'IIP-MD06-a8-idp-01': ('SATISFIED','PASS','metadata.keys.selection-observed'),
                  'IIP-MD07-b-idp-01': ('SATISFIED','PASS','metadata.keys.selection-observed')},
        not_adopted=set()),
}


def verify(root, product='keycloak'):
    spec=PRODUCTS[product]
    folder=Path(root)/spec['folder']
    read=lambda name:json.loads((folder/name).read_text())
    raw=(folder/'qualified-metadata-key-receipt.json').read_bytes()
    receipt=json.loads(raw)
    assert receipt.get('evidenceAdapter','keycloak-native-event')==spec['adapter']
    assert spec['export'](folder.resolve())==receipt
    proof=read(spec['proof']);installed=read('evaluation/receipt-installation.json')
    result=read('evaluation/result.json');run=receipt['runId']
    assert proof['run']==installed['run']==result['run']['id']==run
    assert installed['read_back'] and installed['sha256']==proof['receipt_sha256']==SHA(raw)
    assert proof['transcript_sha256']==SHA((folder/'transcript.json').read_bytes())
    assert proof['verdict_adopted'] is False
    assert result['target']['metadata_digest']=='sha256:'+receipt['targetMetadataSha256']
    assert {e['id']:e for e in read('transcript.json')}=={e['id']:e for e in read('evaluation/transcript.json')}
    if (folder/'evaluation/transcript-before.json').exists():
        assert {e['id']:e for e in read('evaluation/transcript-before.json')}=={e['id']:e for e in read('evaluation/transcript.json')}
    manifest=read('decoded-manifest.json')
    assert len({row['id'] for row in manifest})==len(manifest)
    for row in manifest:
        path=(folder/row['file']).resolve()
        assert path.parent==(folder/'decoded').resolve() and SHA(path.read_bytes())==row['sha256']
    expected=spec['expected']
    assert set(expected)<=set(proof['qualified_cases'])
    assert set(proof['qualified_cases']).isdisjoint(spec.get('not_adopted',set()))
    cases={c['id']:c for req in result['requirements'] for c in req['cases']}
    for case_id in spec.get('not_adopted',set()):
        assert cases[case_id]['verdict']=='NOT_VERIFIED'
        assert proof['production_comparison'][case_id]['outcome']=='NOT_VERIFIED'
    selected={}
    for case_id,want in expected.items():
        case=cases[case_id];observed=proof['production_comparison'][case_id]
        assert (case['outcome'],case['verdict'],case['reason_code'])==want
        assert case['attested'] is False
        assert (observed['outcome'],observed['reasonCode'])==(want[0],want[2])
        assert observed['details']['evidence_issues']==observed['details']['missing_variants']==[]
        assert {(e['kind'],e['reference']) for e in observed['evidence']}=={(e['kind'],e['reference']) for e in case['evidence']}
        controls={k.removeprefix(case_id+':'):v for k,v in proof['negative_controls'].items() if k.startswith(case_id+':')}
        assert set(controls)==CONTROLS and set(controls.values())=={'NOT_VERIFIED'}
        selected[case_id]=case
    if product=='keycloak':
        assert read('baseline/operations.json')['restored']
    elif product=='shibboleth':
        restoration=json.loads((folder/'restoration.json').read_text())
        assert restoration['restored'] and restoration['original_sha256']==restoration['final_sha256']
        assert restoration['temporary_file_removed']
        campaign=json.loads((folder.parent/'restoration.json').read_text())
        assert campaign['restored'] and campaign['original_sha256']==campaign['final_sha256'] and not campaign['failures']
        counts=json.loads((folder.parent/'operation-counts.json').read_text())
        assert counts['restored'] and counts['human_operations']==0 and counts['verdict_adopted'] is False
        matrix=json.loads((folder.parent/'matrix.json').read_text())
        assert matrix['matrix']=='keys' and matrix['verdict_adopted'] is False
    else:
        restoration=json.loads((folder.parent/'restoration.json').read_text())
        assert restoration['restored'] and restoration['original_sha256']==restoration['final_sha256']
        assert restoration['configuration_write_attempts']==15
        assert restoration['applied_conditions']==14 and restoration['restoration_write_attempts']==1
        counts=json.loads((folder.parent/'operation-counts.json').read_text())
        assert counts['restored'] and counts['product_restarts']==0 and counts['human_operations']==0
        captured=json.loads((folder.parent/'original-capture.json').read_text())
        assert captured['restored'] and captured['verdict_adopted'] is False
        assert [p for p in captured['profiles'] if p['run']==run] and all(p['run']==run for p in captured['profiles'])
        matrix=json.loads((folder.parent/'matrix.json').read_text())
        assert matrix['matrix']=='keys' and matrix['verdict_adopted'] is False
    return folder/'evaluation/result.json',selected


if __name__=='__main__':
    import sys
    product=sys.argv[2] if len(sys.argv)>2 else 'keycloak'
    _,cases=verify(sys.argv[1],product)
    for name,case in cases.items():print(name,case['verdict'])
