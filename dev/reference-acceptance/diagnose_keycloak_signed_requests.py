#!/usr/bin/env python3
"""Inventory native signed-request evidence gaps without promoting HTTP failures to verdicts."""
import argparse
import hashlib
import json
from pathlib import Path

CASES=('IIP-ALG01-a-idp-01','IIP-ALG02-a-idp-01')
FIXTURES=('valid','tampered-acs','bad-reference','bad-signature-value')


def diagnose(folder):
    read=lambda name:json.loads((folder/name).read_text())
    run=read('created.json')['run']['id']
    observations=read('native-http-observations.json')
    if observations['run']!=run or observations['product_verdict_assigned'] is not False:
        raise ValueError('Unexpected observation scope')
    transcript=read('transcript.json')
    if any(entry['runId']!=run for entry in transcript):raise ValueError('Mixed Run transcript')
    originals={}
    manifest=folder/'decoded-manifest.json'
    if manifest.exists():
        for item in read('decoded-manifest.json'):
            file=(folder/item['file']).resolve()
            if file.parent!=(folder/'decoded').resolve() or item['id'] in originals:
                raise ValueError('Invalid original manifest')
            raw=file.read_bytes()
            if hashlib.sha256(raw).hexdigest()!=item['sha256']:raise ValueError('Original hash mismatch')
            originals[item['id']]=raw
    rows=[]
    for case in CASES:
        for fixture in FIXTURES:
            sent=[entry for entry in transcript if entry['direction']=='OUTBOUND'
                  and entry['samlSummary'].get('scenario_case_id')==case
                  and entry['samlSummary'].get('fixture_id')==fixture]
            row=dict(case_id=case,fixture=fixture,run=run,diagnostic_only=True)
            rows.append(row)
            if len(sent)!=1:
                row['gap']='outbox-request-missing-or-ambiguous';continue
            request=sent[0];request_id='_'+request['samlSummary']['action_id']
            observed=[item for item in observations['records'] if item['request_id']==request_id]
            row.update(request_reference=request['id'],request_id=request_id)
            if len(observed)!=1:
                row['gap']='native-http-observation-missing-or-ambiguous';continue
            item=observed[0]
            if item['request_url']!=request['url']:
                row['gap']='request-endpoint-mismatch';continue
            raw=originals.get(request['id'])
            row['request_original_hash_verified']=raw is not None and len(raw)==request['decodedSamlBytes'] and hashlib.sha256(raw).hexdigest()==item['request_sha256']
            if raw is not None and not row['request_original_hash_verified']:
                row['gap']='request-original-mismatch';continue
            received=[entry for entry in transcript if entry['direction']=='INBOUND'
                      and entry.get('samlSummary',{}).get('inResponseTo')==request_id]
            events=item['native_events']
            row.update(http_status=item['response_status'],native_errors=[event['error'] for event in events],
                native_event_request_ids=[event.get('details',{}).get('request_id') or event.get('details',{}).get('saml_request_id') for event in events],
                response_references=[entry['id'] for entry in received],
                original_request_sha256=item['request_sha256'],
                native_request_correlation_proven=False)
            if fixture=='valid':
                row['gap']='response-cryptographic-verification-required' if len(received)==1 else 'correlated-response-missing-or-ambiguous'
            elif received:
                row['gap']='unexpected-correlated-response-requires-inspection'
            elif any(event.get('error')=='invalid_signature' for event in events):
                # Even a single native event between two reads is not a request ID binding.
                row['gap']='native-event-request-correlation-unavailable'
            else:row['gap']='specific-native-signature-event-unavailable'
    return dict(schema='samlscope-keycloak-signature-diagnosis-v1',run=run,rows=rows,
        native_observations_sha256=hashlib.sha256((folder/'native-http-observations.json').read_bytes()).hexdigest(),
        transcript_sha256=hashlib.sha256((folder/'transcript.json').read_bytes()).hexdigest(),
        product_verdict_assigned=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('evidence',type=Path)
    args=parser.parse_args();folder=args.evidence.resolve()
    result=diagnose(folder)
    (folder/'signature-diagnosis.json').write_text(json.dumps(result,indent=2)+'\n')
    print(folder.name, len(result['rows']), 'fixture observations; no verdict promotion')
