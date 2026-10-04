"""Bind public certificate/request proofs to native, request-scoped rejection events. No verdict."""
import argparse
import base64
import datetime
import hashlib
import json
from pathlib import Path

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
TIME=lambda value:datetime.datetime.fromisoformat(value.replace('Z','+00:00'))


def diagnose(folder):
    read=lambda name:json.loads((folder/name).read_text())
    proof=read('verified-certificate-requests.json');run=proof['run']
    for field,name in [('transcript_sha256','transcript.json'),('manifest_sha256','decoded-manifest.json'),('operations_sha256','operations.json'),('target_metadata_sha256','target-metadata.xml')]:
        if proof[field]!=SHA((folder/name).read_bytes()):raise ValueError('Public proof source changed')
    campaign=folder.parent.parent
    restoration=json.loads((campaign/'observer/restoration.json').read_text())
    if not all(restoration.get(k) for k in ['previously_absent','readback_verified','provider_removed','realm_configuration_restored','product_restart_verified']) or restoration['failures']:
        raise ValueError('Observer restoration unproven')
    if SHA((campaign/'observer/SignatureEventListenerFactory.java').read_bytes())!=restoration['source_sha256']:
        raise ValueError('Observer source mismatch')
    audit=read('native-signature-audit.json');http=read('native-http-observations.json')
    if audit['run']!=run or http['run']!=run or audit['listener']!='samlscope-signature-observation':
        raise ValueError('Mixed native observation')
    if len({r['request_id'] for r in http['records']})!=len(http['records']):raise ValueError('Ambiguous HTTP requests')
    rows=[]
    for observation in proof['observations']:
        variant=observation['variant'];imported=read(variant+'/import.json')
        if not imported.get('cleanup',{}).get('read_back_absent') or imported['import']['ui_status']!='client-settings-page':
            raise ValueError('Native import/cleanup unproven')
        if imported['fixture']['sha256']!=observation['fixture_sha256']:
            raise ValueError('Native fixture identity mismatch')
        attrs=imported['import']['read_back']['saml_attributes']
        if attrs.get('saml.client.signature')!='true':raise ValueError('Native signature checking disabled')
        certificate=base64.b64decode(''.join(attrs['saml.signing.certificate'].split()),validate=True)
        if SHA(certificate)!=observation['certificate_sha256']:raise ValueError('Native certificate differs from fixture')
        for request in observation['requests']:
            samples=[s for s in http['records'] if s['request_id']==request['request_id']]
            events=[e for e in audit['rows'] if e['request_id']==request['request_id']]
            if len(samples)!=1:raise ValueError('HTTP request binding missing')
            sample=samples[0]
            if sample['request_sha256']!=request['request_sha256']:raise ValueError('HTTP original mismatch')
            successes=request['signed_success_responses']
            rejection=False
            if events:
                if len(events)!=1 or successes:raise ValueError('Conflicting native evidence')
                event=events[0]
                if event['request_sha256']!=request['request_sha256'] or event['issuer']!=request['issuer']:
                    raise ValueError('Native event original mismatch')
                if (event['event_type'],event['error'])!=('LOGIN_ERROR','invalid_signature'):raise ValueError('Unexpected native event')
                if not TIME(sample['started_at'])<=TIME(event['observed_at'])<=TIME(sample['finished_at']):
                    raise ValueError('Native event outside request window')
                if sample['response_status']!=400 or not sample['response_url_exact_match'] or sample['request_url']!=sample['response_url'] or sample['saml_response_form_present']:
                    raise ValueError('Indirect or ambiguous rejection')
                rejection=True
            if request['negative_control']:
                if request['signature_valid'] or not rejection:raise ValueError('Negative signature control unavailable')
                state='invalid-signature-native-rejection'
            elif not request['signature_valid']:raise ValueError('Suite positive signature invalid')
            elif successes:state='valid-signature-signed-success'
            elif rejection:state='valid-signature-native-rejection'
            else:state='unobserved'
            stamp=TIME(sample['started_at']);validity=('not-yet-valid' if stamp<TIME(observation['not_before']) else
                'expired' if stamp>TIME(observation['not_after']) else 'within-validity')
            rows.append(dict(variant=variant,request=request['request'],request_id=request['request_id'],
                request_sha256=request['request_sha256'],certificate_validity_at_request=validity,
                observation=state,signed_success_responses=successes,affects_verdict=False))
    return dict(run=run,observations=rows,verdict_adopted=False,
        source_sha256={name:SHA((folder/name).read_bytes()) for name in
            ['verified-certificate-requests.json','native-signature-audit.json','native-http-observations.json','operations.json']},
        limitation='Request-bound diagnostic only; approved case evaluation and negative controls for the native adapter remain required.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args();report=diagnose(args.evidence.resolve())
    with (args.evidence/'certificate-native-diagnosis.json').open('x') as out:json.dump(report,out,indent=2);out.write('\n')
    for row in report['observations']:
        if row['observation']!='invalid-signature-native-rejection':print(row['variant'],row['observation'],row['certificate_validity_at_request'])
