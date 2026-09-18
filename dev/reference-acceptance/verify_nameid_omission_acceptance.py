"""Adopt only native NameID omission with original protocol evidence and formal CONFIG evaluation."""
import hashlib
import json
from pathlib import Path
from export_nameid_omission_preparation import export

CASE='IIP-IDP11-a-idp-01'


def verify(root):
    root=Path(root);evidence=root/'shibboleth-nameid-omission';evaluation=root/'shibboleth-nameid-omission-evaluation'
    def read(folder,name):return json.loads((folder/name).read_text())
    run=read(evidence,'created.json')['run']['id']
    receipt_path=evidence/'preparation-receipts'/(run+'.json');receipt=export(evidence,receipt_path)
    installation=read(evaluation,'receipt-installation.json')
    assert installation['read_back'] and installation['run']==run
    assert installation['sha256']==hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    assert read(evidence,'plan.json')['plan']['plan']['profile']=='browser_sso_idp'
    comparison=read(evidence,'production-comparison.json')['comparison']
    assert comparison['outcome']=='SATISFIED'
    assert set(comparison['negative_controls_rejected'])=={'missing','duplicate','wrong-response','mixed-login','mixed-input'}
    baseline=read(evaluation/'baseline','operations.json')
    assert baseline['run']==run and baseline['restored'] and not baseline['failures'] and baseline['temporary_removed']
    assert baseline['original_sha256']==baseline['final_sha256']
    assert read(evaluation/'baseline','flow.json')=='recorded'
    result=read(evaluation,'result.json');assert result['run']['id']==run
    assert result['target']['metadata_digest']=='sha256:'+receipt['targetMetadataSha256']
    cases={case['id']:case for req in result['requirements'] for case in req['cases']};case=cases[CASE]
    assert (case['outcome'],case['verdict'],case['reason_code'],case['attested'])==(
        'SATISFIED','PASS','configuration.nameid-omission.observed',False)
    expected={(ref['kind'],ref['reference']) for ref in comparison['evidence']}
    assert len(expected)==6 and {(ref['kind'],ref['reference']) for ref in case['evidence']}==expected
    current={row['id']:row for row in read(evaluation,'transcript.json')}
    previous={row['id']:row for row in read(evidence,'transcript.json')}
    for _,reference in expected:assert current[reference]==previous[reference]
    return evaluation/'result.json',cases


if __name__=='__main__':
    import sys
    _,cases=verify(sys.argv[1]);print(CASE,cases[CASE]['verdict'])
