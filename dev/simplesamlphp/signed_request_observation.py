#!/usr/bin/env python3
"""Collect request-bound native error codes without treating HTTP errors as signature rejection."""
import argparse
import base64
import hashlib
import datetime
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from attribute_name_capability import native,api,save,BASE,Client,ConfigurationBatch,REPO

CASES={'IIP-ALG01-a-idp-01','IIP-ALG02-a-idp-01'}
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def signature_rejection(page,status):
    """Recognize explicit product signature errors, never a generic HTTP failure."""
    if status!=500 or len(page)>1048576:return None
    class Text(HTMLParser):
        def __init__(self):super().__init__(convert_charrefs=True);self.parts=[];self.hidden=0
        def handle_starttag(self,tag,attrs):
            if tag in {'script','style'}:self.hidden+=1
        def handle_endtag(self,tag):
            if tag in {'script','style'}:self.hidden=max(0,self.hidden-1)
        def handle_data(self,data):
            if not self.hidden:self.parts.append(data)
    parser=Text();parser.feed(page);text='\n'.join(parser.parts)
    if re.search(r'SimpleSAML\\+Error\\+Exception:\s*Validation of received messages enabled, but no signature found on message\.',text):
        return 'signature-not-established'
    for line in text.splitlines():
        found=re.search(r'SimpleSAML\\+Error\\+Error:\s*(\{.*\})',line)
        if not found:continue
        try:detail=json.loads(found.group(1))
        except ValueError:continue
        if detail.get('errorCode')=='NOTVALIDCERTSIGNATURE' and re.fullmatch(r'SAML2\\+(?:XML\\+samlp\\+)?AuthnRequest',str(detail.get('%ELEMENT%',''))):
            return 'signature-value-invalid'
    return None


class SignatureClient(Client):
    def __init__(self,records):
        super().__init__();self.records=records

    def request(self,url,fields=None):
        request=None
        if urllib.parse.urlparse(url).port==18380 and fields and 'SAMLRequest' in fields:
            raw=base64.b64decode(fields['SAMLRequest'],validate=True)
            root=ET.fromstring(raw)
            request=dict(request_id=root.get('ID'),request_sha256=SHA(raw),request_url=url,
                         request_type=root.tag)
        final,page,status=super().request(url,fields)
        if request:
            # Preserve no cookies, credentials, session identifiers, form fields or full error pages.
            safe_url=urllib.parse.urlunsplit(urllib.parse.urlsplit(final)._replace(query='',fragment=''))
            request.update(response_url=safe_url,response_url_exact_match=final==url,
                response_status=status,response_body_sha256=SHA(page.encode()),
                observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                native_signature_rejection=signature_rejection(page,status),
                recognized_native_error_codes=[code for code in ['NOTVALIDCERTSIGNATURE','UNHANDLEDEXCEPTION','NOSIGNATURE']
                    if re.search(r'(?<![A-Z])'+code+r'(?![A-Z])',page)],
                saml_response_form_present='name="SAMLResponse"' in page)
            self.records.append(request)
        return final,page,status


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--profiles',default='browser_sso_idp,metadata_idp,ecp_idp,single_logout_idp')
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    profiles=args.profiles.split(',')
    assert len(profiles)==len(set(profiles)) and set(profiles)<={'browser_sso_idp','metadata_idp','ecp_idp','single_logout_idp'}
    configuration=ConfigurationBatch(REPO/'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php')
    assert b'?>' not in configuration.original
    user=os.environ.get('REFERENCE_USERNAME','samlscope-m0-user');password=os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password')
    plans=[]
    try:
        for profile in profiles:
            p=out/profile;p.mkdir();records=[];attempts=[]
            plan=api('/api/plans',dict(name='SimpleSAMLphp native signature observations',profile=profile,targetKind='IDP',
                targetEntityId='http://localhost:18380/idp',metadataSourceKind='URL',
                metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
                suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,
                metadataRefreshWaitSeconds=300,testUserHint=user,requestSigningMode='REQUIRED'),
                interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
            save(p/'plan.json',plan);plan_id=plan['plan']['plan']['id'];entity=BASE+'/p/'+plan_id
            assert entity.encode() not in configuration.original
            created=api('/api/plans/'+plan_id+'/runs',{});save(p/'created.json',created);run=created['run']['id']
            plans.append(dict(profile=profile,run=run))
            save(p/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
            with urllib.request.urlopen(entity+'/metadata',timeout=30) as response:fixture=response.read()
            (p/'fixture.xml').write_bytes(fixture)
            parsed=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',native.PHP,entity,'default'],
                input=fixture,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
            if parsed.returncode:raise RuntimeError('Native metadata parser failed')
            data=json.loads(parsed.stdout);assert data['entity_id']==entity and data['validate_authnrequest'] is True
            (p/'parser-output.json').write_bytes(parsed.stdout)
            digest=configuration.apply(data['php'].encode());time.sleep(3)
            save(p/'import.json',dict(run=run,entity_id=entity,fixture_sha256=SHA(fixture),configuration_sha256=digest,
                import_path='native-parser-cli',read_back=True,validate_authnrequest=True))
            try:
                baseline=SignatureClient(records).flow(entity+'/start/m0-roundtrip?run='+run,None,user,password)
                save(p/'baseline.json',dict(receipt=baseline));assert baseline=='recorded'
                save(p/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
                finished=set()
                for index in range(32):
                    result=api('/api/runs/'+run+'/result.json')
                    selected={c['id']:c for q in result['requirements'] for c in q['cases'] if c['id'] in CASES}
                    finished={id for id,c in selected.items() if c['reason_code'] in {
                        'idp.signed-request.inconclusive','idp.signed-request.satisfied','algorithm.native-verification-observed'}}
                    if finished==CASES:break
                    state=api('/api/runs/'+run+'/active-probe')
                    if state['state']!='READY' or state['caseId'] not in CASES|{'IIP-IDP05-a-idp-01'}:
                        raise RuntimeError('Unexpected active scenario state')
                    row=dict(case=state['caseId'],action=state['actionId'],fresh_client=True);attempts.append(row)
                    row['flow_result']=SignatureClient(records).flow(state['startUrl'],dict(freshSessionConfirmed='true'),user,password)
                    current=api('/api/runs/'+run+'/active-probe')
                    if current['state']=='AWAITING_RESPONSE' and current['actionId']==state['actionId']:
                        api('/api/runs/'+run+'/active-probe/abort',{});row['unavailable_reported']=True
                    save(p/'attempts.json',attempts)
                if finished!=CASES:raise RuntimeError('Incomplete algorithm matrix')
            finally:
                save(p/'native-http-observations.json',dict(run=run,records=records,product_verdict_assigned=False))
                save(p/'attempts.json',attempts)
                for name in ['result.json','transcript','protocol-evidence']:
                    save(p/(name if '.' in name else name+'.json'),api('/api/runs/'+run+'/'+name))
            print(profile,'collected',run,flush=True)
    finally:
        restored=configuration.restore();save(out/'restoration.json',restored)
        save(out/'operations.json',dict(plans=plans,configuration_write_attempts=configuration.write_count,
            applied_conditions=configuration.applied_count,human_interactions=0,restarts=0,**{'restored':restored['restored']}))


if __name__=='__main__':main()
