"""Verify the local product-import evidence selected for the September metadata batch.

A correlated SSO alone does not prove key interpretation when the product disabled signature
validation. KeyValue-only results from this batch are deliberately not in the adoption list.
"""
import hashlib
import json
from pathlib import Path

ADOPTED = {
    'IIP-MD02-c-idp-01': ['entity-root', 'entities-root-one'],
    'IIP-MD05-a4-idp-01': ['entity-root', 'entities-root-one'],
    'IIP-MD05-a5-idp-01': ['entity-root', 'entity-cache-duration', 'entities-cache-duration', 'entities-valid-until'],
    'IIP-MD05-g-idp-01': ['unknown-extension', 'mdrpi-registration-info'],
    'IIP-MD12-a-idp-01': ['entity-root', 'three-signing-keys', 'certificate-long-validity'],
    'IIP-MD12-c-idp-01': ['certificate-sha1', 'certificate-sha512'],
}

def verify(root):
    root=Path(root)
    final=root/'keycloak-signature-control-3'
    result_path=final/'result.json'
    result=json.loads(result_path.read_text())
    run=result['run']['id']
    entries=json.loads((final/'transcript.json').read_text())
    by_id={e['id']:e for e in entries}
    assert len(by_id)==len(entries)
    cases={c['id']:c for req in result['requirements'] for c in req['cases']}
    imports={}
    for batch in ['keycloak-signature-control-3']:
        for path in (root/batch).glob('*/import.json'):
            data=json.loads(path.read_text())
            if data['status']!='success':continue
            flow=json.loads((path.parent/'flow.json').read_text())
            if flow['run']!=run or not flow['correlated_success']:continue
            negative=flow.get('negative_control') or {}
            assert negative.get('correlated_success') is False
            assert negative.get('receipt') == 'no-response:Invalid requester'
            mutations=negative.get('mutations',[])
            assert len(mutations)==1 and mutations[0]['binding']=='post'
            assert mutations[0]['original_request_sha256']!=mutations[0]['mutated_request_sha256']
            assert flow['after_index']==flow['before_index']+1
            imports.setdefault(flow['variant'],[]).append((path,data))
    for case_id,variants in ADOPTED.items():
        case=cases[case_id]
        assert (case['verdict'],case['reason_code'])==('PASS','metadata.fixture-probe.satisfied')
        assert set(variants).issubset(case['diagnostics']['used_variants'])
        assert 'control' in case['diagnostics']['used_variants']
        for variant in ['control',*variants]:
            assert variant in imports,(case_id,variant,'no successful native import')
            for path,data in imports[variant]:
                assert data['cleanup']['read_back_absent']
                assert data['import']['ui_status']=='client-settings-page'
                assert data['import']['read_back']['client_id']==data['fixture']['entity_id']
                assert data['import']['read_back']['saml_attributes'].get('saml.client.signature')=='true'
                assert hashlib.sha256((path.parent/'fixture.xml').read_bytes()).hexdigest()==data['fixture']['sha256']
        assert case['evidence']
        for ref in case['evidence']:
            assert ref['kind']=='transcript'
            entry=by_id[ref['reference'].removeprefix('transcript:')]
            assert entry['runId']==run and entry['direction']=='INBOUND'
    return result_path, cases

if __name__=='__main__':
    import sys
    path,cases=verify(sys.argv[1])
    print('Verified native import, signed SSO, cleanup and transcript references for',len(ADOPTED),'cases')
