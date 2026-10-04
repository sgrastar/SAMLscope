#!/usr/bin/env python3
"""Export specific native signature errors bound to the exact dispatched request, never generic HTTP failure."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
from export_native_signed_request import collect, CASES

SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def export(folder,output,case_id):
    assert case_id in CASES
    read=lambda name:json.loads((folder/name).read_text())
    run=read('created.json')['run']['id']
    restored=json.loads((folder.parent/'restoration.json').read_text())
    assert restored['restored'] and restored['original_sha256']==restored['final_sha256']
    imported=read('import.json');parsed=read('parser-output.json')
    assert imported['run']==run and imported['read_back'] and imported['validate_authnrequest'] is True
    assert imported['import_path']=='native-parser-cli' and imported['entity_id']==parsed['entity_id']
    assert parsed['validate_authnrequest'] is True and imported['fixture_sha256']==SHA((folder/'fixture.xml').read_bytes())
    assert read('baseline.json')['receipt']=='recorded'
    observations=read('native-http-observations.json')
    assert observations['run']==run and observations['product_verdict_assigned'] is False
    entries={e['id']:e for e in read('transcript.json')}
    originals={}
    for item in read('decoded-manifest.json'):
        file=(folder/item['file']).resolve();assert file.parent==(folder/'decoded').resolve()
        raw=file.read_bytes();assert len(raw)==entries[item['id']]['decodedSamlBytes'] and SHA(raw)==item['sha256']
        assert item['id'] not in originals;originals[item['id']]=raw
    exchanges=[]
    for fixture in ['VALID','TAMPERED_ACS','BAD_REFERENCE','BAD_SIGNATURE_VALUE']:
        sent=[e for e in entries.values() if e['direction']=='OUTBOUND' and e['samlSummary'].get('scenario_case_id')==case_id
              and e['samlSummary'].get('fixture_id')==fixture.lower().replace('_','-')]
        assert len(sent)==1;sent=sent[0];request_id='_'+sent['samlSummary']['action_id']
        http=[r for r in observations['records'] if r['request_id']==request_id];assert len(http)==1;http=http[0]
        assert http['request_sha256']==SHA(originals[sent['id']]) and http['request_url']==sent['url']
        responses=[e for e in entries.values() if e['direction']=='INBOUND' and e['samlSummary'].get('inResponseTo')==request_id]
        if fixture=='VALID':assert len(responses)==1 and not http['native_signature_rejection']
        else:
            assert not responses and http['response_status']==500 and http['response_url']==http['request_url']
            assert not http['saml_response_form_present']
            assert http['native_signature_rejection']==('signature-value-invalid' if fixture=='BAD_SIGNATURE_VALUE' else 'signature-not-established')
        exchanges.append(dict(fixture=fixture,requestReference=sent['id'],responseReference=responses[0]['id'] if responses else None,nativeHttp=http))
    receipt=dict(schema='samlscope-native-signed-request-v1',evidenceAdapter='simplesamlphp-native-http',runId=run,caseId=case_id,
        targetMetadataSha256=SHA((folder/'target-metadata.xml').read_bytes()),nativeConfigurationSha256=imported['configuration_sha256'],
        nativeHttpObservationsSha256=SHA((folder/'native-http-observations.json').read_bytes()),
        collectedAt=datetime.datetime.fromtimestamp((folder/'native-http-observations.json').stat().st_mtime,datetime.timezone.utc).isoformat(),
        exchanges=exchanges,rawEvidence=[dict(reference=item['id'],sha256=item['sha256']) for item in read('decoded-manifest.json')])
    raw=(json.dumps(receipt,indent=2)+'\n').encode();output.parent.mkdir(parents=True,exist_ok=True)
    if output.exists():assert not output.is_symlink() and output.read_bytes()==raw
    else:
        with output.open('xb') as stream:stream.write(raw)
    return receipt


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence',type=Path,required=True);p.add_argument('--collect-originals',action='store_true')
    a=p.parse_args();folder=a.evidence.resolve()
    if a.collect_originals:collect(folder)
    run=json.loads((folder/'created.json').read_text())['run']['id']
    for case in sorted(CASES):export(folder,folder/'preparation-receipts'/(run+'-'+case+'.json'),case)
    print('Specific native signature failures bound',run)
