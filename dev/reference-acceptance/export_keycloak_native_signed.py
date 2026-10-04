#!/usr/bin/env python3
"""Bind synchronous native signature error events to immutable outbox originals."""
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
    observer=json.loads((folder.parent/'native-observer.json').read_text())
    assert observer['previously_absent'] and observer['readback_verified'] and observer['provider_removed']
    assert observer['realm_configuration_restored'] and observer['product_restart_verified']
    assert observer['source_sha256']==SHA((folder.parent/'native-observer-source.java').read_bytes())
    assert len(observer['jar_sha256'])==64
    assert read('restoration.json')['restored'] and read('baseline.json')['receipt']=='recorded'
    prepared=read('preparation.json');native=prepared['native']
    assert prepared['run']==run and prepared['fixture_sha256']==SHA((folder/'fixture.xml').read_bytes())
    assert prepared['metadata_interpretation_claimed'] is False
    assert native['attributes']['saml.client.signature']=='true' and native['protocol']=='saml' and native['enabled']
    observations=read('native-http-observations.json');audits=read('native-signature-audit.json')
    assert observations['run']==audits['run']==run and observations['product_verdict_assigned'] is False
    assert audits['listener']=='samlscope-signature-observation'
    entries={entry['id']:entry for entry in read('transcript.json')}
    originals={}
    for item in read('decoded-manifest.json'):
        path=(folder/item['file']).resolve();assert path.parent==(folder/'decoded').resolve()
        raw=path.read_bytes();assert len(raw)==entries[item['id']]['decodedSamlBytes'] and SHA(raw)==item['sha256']
        assert item['id'] not in originals;originals[item['id']]=raw
    exchanges=[]
    for fixture in ['VALID','TAMPERED_ACS','BAD_REFERENCE','BAD_SIGNATURE_VALUE']:
        sent=[entry for entry in entries.values() if entry['direction']=='OUTBOUND'
              and entry['samlSummary'].get('scenario_case_id')==case_id
              and entry['samlSummary'].get('fixture_id')==fixture.lower().replace('_','-')]
        assert len(sent)==1;sent=sent[0];request_id='_'+sent['samlSummary']['action_id']
        observed=[row for row in observations['records'] if row['request_id']==request_id]
        assert len(observed)==1;http=observed[0]
        assert http['request_sha256']==SHA(originals[sent['id']]) and http['request_url']==sent['url']
        events=[row for row in audits['rows'] if row['request_id']==request_id]
        received=[entry for entry in entries.values() if entry['direction']=='INBOUND'
                  and entry['samlSummary'].get('inResponseTo')==request_id]
        event=None
        if fixture=='VALID':assert len(received)==1 and not events
        else:
            assert not received and len(events)==1;event=events[0]
            assert event['request_sha256']==http['request_sha256'] and event['issuer']==native['clientId']
            assert (event['event_type'],event['error'])==('LOGIN_ERROR','invalid_signature')
            assert http['response_status']==400 and http['response_url_exact_match']
            assert http['response_url']==http['request_url'] and not http['saml_response_form_present']
        exchanges.append(dict(fixture=fixture,requestReference=sent['id'],responseReference=received[0]['id'] if received else None,
            nativeHttp=http,nativeEvent=event))
    receipt=dict(schema='samlscope-native-signed-request-v1',evidenceAdapter='keycloak-native-event',runId=run,caseId=case_id,
        targetMetadataSha256=SHA((folder/'target-metadata.xml').read_bytes()),
        nativeConfigurationSha256=SHA((folder/'preparation.json').read_bytes()),
        nativeAuditSha256=SHA((folder/'native-signature-audit.json').read_bytes()),nativeObserverSha256=observer['jar_sha256'],
        nativeHttpObservationsSha256=SHA((folder/'native-http-observations.json').read_bytes()),
        collectedAt=datetime.datetime.fromtimestamp((folder/'native-signature-audit.json').stat().st_mtime,datetime.timezone.utc).isoformat(),
        exchanges=exchanges,rawEvidence=[dict(reference=item['id'],sha256=item['sha256']) for item in read('decoded-manifest.json')])
    raw=(json.dumps(receipt,indent=2)+'\n').encode();output.parent.mkdir(parents=True,exist_ok=True)
    if output.exists():assert not output.is_symlink() and output.read_bytes()==raw
    else:
        with output.open('xb') as stream:stream.write(raw)
    return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--collect-originals',action='store_true');args=parser.parse_args();folder=args.evidence.resolve()
    if args.collect_originals:collect(folder)
    run=json.loads((folder/'created.json').read_text())['run']['id']
    for case in sorted(CASES):export(folder,folder/'preparation-receipts'/(run+'-'+case+'.json'),case)
    print('Request-bound native Keycloak signature events exported',run)
