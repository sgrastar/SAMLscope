#!/usr/bin/env python3
"""Run the existing outbox signature matrix through native metadata import; preserve every attempt."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.request
import xml.etree.ElementTree as ET
from attribute_name_capability import docker, api, save, BASE, Client, XSI

CASES={'IIP-ALG01-a-idp-01','IIP-ALG02-a-idp-01'}
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--profile',choices=['browser_sso_idp','metadata_idp','ecp_idp','single_logout_idp'],required=True)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    config='/opt/reference-idp/conf/metadata-providers.xml';original=docker('cat',config)
    (out/'original-providers.xml').write_bytes(original)
    plan=api('/api/plans',dict(name='Shibboleth request-bound algorithm verification',profile=a.profile,targetKind='IDP',
        targetEntityId='http://localhost:18280/idp/shibboleth',metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},
        parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(out/'plan.json',plan);plan_id=plan['plan']['plan']['id']
    created=api('/api/plans/'+plan_id+'/runs',{});save(out/'created.json',created);run=created['run']['id']
    assert re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run)
    save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
    temporary='/opt/reference-idp/metadata/signed-request-'+run+'.xml'
    if docker('sh','-c','if test -e '+temporary+'; then echo exists; fi').strip():raise ValueError('Temporary file exists')
    with urllib.request.urlopen(BASE+'/p/'+plan_id+'/metadata',timeout=30) as response:fixture=response.read()
    (out/'fixture.xml').write_bytes(fixture)
    ns='urn:mace:shibboleth:2.0:metadata';ET.register_namespace('',ns);ET.register_namespace('xsi',XSI)
    providers=ET.fromstring(original)
    providers.insert(0,ET.Element('{'+ns+'}MetadataProvider',{'id':'SignedRequest'+run,'{'+XSI+'}type':'FilesystemMetadataProvider','metadataFile':temporary}))
    configured=ET.tostring(providers);(out/'configured-providers.xml').write_bytes(configured)
    operations=[];attempts=[];written=changed=False
    def write(path,raw,label):
        operation=dict(operation='write',label=label,read_back=False);operations.append(operation)
        save(out/'operations.json',operations);docker('sh','-c','cat > '+path,data=raw)
        assert docker('cat',path)==raw;operation.update(read_back=True,sha256=SHA(raw));save(out/'operations.json',operations)
    def reload(label):
        operation=dict(operation='reload',label=label,completed=False);operations.append(operation);save(out/'operations.json',operations)
        (out/(label+'-reload.log')).write_bytes(docker('/opt/reference-idp/bin/reload-service.sh','-id','shibboleth.MetadataResolverService','-u','http://localhost:8080/idp'))
        operation['completed']=True;save(out/'operations.json',operations)
    user=os.environ.get('REFERENCE_USERNAME','samlscope-m0-user');password=os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password')
    try:
        written=True;write(temporary,fixture,'native-metadata');changed=True;write(config,configured,'provider');reload('provider')
        baseline=Client().flow(BASE+'/p/'+plan_id+'/start/m0-roundtrip?run='+run,None,user,password)
        save(out/'baseline.json',dict(receipt=baseline));assert baseline=='recorded'
        save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
        finished=set()
        for index in range(32):
            result=api('/api/runs/'+run+'/result.json')
            observed={c['id']:c for q in result['requirements'] for c in q['cases'] if c['id'] in CASES}
            finished={id for id,c in observed.items() if c['reason_code'] in {
                'idp.signed-request.inconclusive','idp.signed-request.satisfied','algorithm.native-verification-observed'}}
            if finished==CASES:break
            status=api('/api/runs/'+run+'/active-probe')
            if status['caseId'] not in CASES|{'IIP-IDP05-a-idp-01'}:raise RuntimeError('Unexpected scenario before algorithm completion')
            if status['state']!='READY':raise RuntimeError('Scenario is not ready')
            attempt=dict(case=status['caseId'],action=status['actionId'],fresh_client=True)
            attempts.append(attempt);save(out/'attempts.json',attempts)
            receipt=Client().flow(status['startUrl'],dict(freshSessionConfirmed='true'),user,password)
            attempt['flow_result']=receipt
            after=api('/api/runs/'+run+'/active-probe')
            if after['state']=='AWAITING_RESPONSE' and after['actionId']==status['actionId']:
                # This advances the scenario only. Native audit + original requests must prove rejection later.
                api('/api/runs/'+run+'/active-probe/abort',{});attempt['unavailable_reported']=True
            save(out/'attempts.json',attempts)
        if finished!=CASES:raise RuntimeError('Algorithm matrices did not finish')
    finally:
        failures=[]
        if changed:
            try:
                if docker('cat',config)!=configured:raise RuntimeError('Concurrent provider change')
                write(config,original,'restore-provider');reload('restore-provider')
            except Exception as error:failures.append(type(error).__name__)
        if written and not failures:docker('rm','--',temporary);operations.append(dict(operation='delete',label='temporary-metadata'))
        removed=not docker('sh','-c','if test -e '+temporary+'; then echo exists; fi').strip()
        final=docker('cat',config);restored=not failures and removed and original==final
        save(out/'operations.json',operations)
        save(out/'restoration.json',dict(restored=restored,temporary_file_removed=removed,failures=failures,original_sha256=SHA(original),final_sha256=SHA(final)))
        for name in ['result.json','transcript','protocol-evidence']:
            save(out/(name if '.' in name else name+'.json'),api('/api/runs/'+run+'/'+name))
        if not restored:raise RuntimeError('Native provider restoration failed')
    print('Signature matrices collected',run,flush=True)


if __name__=='__main__':main()
