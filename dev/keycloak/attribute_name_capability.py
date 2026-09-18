#!/usr/bin/env python3
"""Native attribute-name/format capability experiment; explicit client settings, exact deletion."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import hashlib
import urllib.request as http
import urllib.parse as urls
import xml.etree.ElementTree as ET
from relying_party_attribute_campaign import client_recipe, projection, ADMIN, api, save, BASE, Client


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    created=api('/api/plans',dict(name='Keycloak native attribute names and formats',profile='browser_sso_idp',targetKind='IDP',
        targetEntityId='http://localhost:18180/realms/samlscope',metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',
        suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,
        testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(out/'plan.json',created);plan=created['plan']['plan']['id']
    run_created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',run_created);args.run=run_created['run']['id']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',args.run) or not re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',plan):raise ValueError('Invalid Run or Plan')
    save(out/'preflight.json',api('/api/runs/'+args.run+'/preflight',{}))
    entity=BASE+'/p/'+plan
    with http.urlopen(entity+'/metadata',timeout=30) as response:fixture=response.read()
    (out/'fixture.xml').write_bytes(fixture)
    recipe=client_recipe(ET.fromstring(fixture),'first')
    recipe['protocolMappers']=[]
    if recipe['clientId']!=entity:raise ValueError('Unexpected baseline identity')
    request=http.Request('http://localhost:18180/realms/master/protocol/openid-connect/token',data=urls.urlencode(dict(
        client_id='admin-cli',username=os.environ.get('KEYCLOAK_ADMIN_USERNAME','admin'),
        password=os.environ.get('KEYCLOAK_ADMIN_PASSWORD','admin'),grant_type='password')).encode())
    with http.urlopen(request,timeout=30) as response:token=json.load(response)['access_token']
    operations=[]
    def admin(path,body=None,method='GET'):
        request=http.Request(ADMIN+path,data=None if body is None else json.dumps(body).encode(),method=method,
            headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        row=dict(method=method,path=path.split('?')[0],status='attempted');operations.append(row)
        with http.urlopen(request,timeout=30) as response:
            row['status']=response.status;raw=response.read()
            return json.loads(raw) if raw else None
    lookup='/clients?clientId='+urls.quote(entity,safe='')
    if admin(lookup):raise ValueError('Refusing existing client overwrite')
    identifier=None;restored=False;failures=[]
    try:
        admin('/clients',recipe,'POST')
        clients=admin(lookup)
        if len(clients)!=1:raise ValueError('Created client ambiguous')
        identifier=clients[0]['id']
        if not re.fullmatch(r'[a-f0-9-]{36}',identifier):raise ValueError('Invalid client ID')
        records=[]
        for condition in ['baseline','custom']:
            if condition=='custom':
                recipe['protocolMappers']=[dict(name='samlscope-capability-'+str(index),protocol='saml',protocolMapper='saml-user-property-mapper',
                    consentRequired=False,config={'user.attribute':'firstName','attribute.name':name,
                        'attribute.nameformat':'urn:samlscope:test:attribute-name-format'})
                    for index,name in enumerate(['urn:samlscope:test:attribute-name','SAMLscope arbitrary attribute'])]
                admin('/clients/'+identifier,recipe,'PUT')
            record=dict(condition=condition,before=projection(admin('/clients/'+identifier),recipe))
            records.append(record)
            before={row['id'] for row in api('/api/runs/'+args.run+'/transcript')}
            flow=Client().flow(entity+'/start/m0-roundtrip?run='+args.run,None,
                os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
            record.update(flow=flow,after=projection(admin('/clients/'+identifier),recipe),
                new_transcript_ids=[row['id'] for row in api('/api/runs/'+args.run+'/transcript') if row['id'] not in before])
            save(out/'observations.json',records)
            if flow!='recorded':raise RuntimeError('Normal login not recorded')
            if condition=='baseline':
                save(out/'tests-start.json',api('/api/runs/'+args.run+'/tests/start',{}))
                save(out/'control-protocol-evidence.json',api('/api/runs/'+args.run+'/protocol-evidence'))
        save(out/'configure.json',api('/api/runs/'+args.run+'/cases/IIP-IDP01-a-idp-01/configure',dict(value='CONFIRMED')))
    finally:
        try:
            clients=admin(lookup)
            if len(clients)>1:raise ValueError('Cleanup identity ambiguous')
            if clients:
                current=clients[0]
                if current['clientId']!=entity or (identifier is not None and current['id']!=identifier):
                    raise ValueError('Cleanup identity changed')
                identifier=current['id']
                if not re.fullmatch(r'[a-f0-9-]{36}',identifier):raise ValueError('Invalid cleanup ID')
                admin('/clients/'+identifier,method='DELETE')
            restored=not admin(lookup)
        except Exception as error:failures.append(type(error).__name__)
        save(out/'operations.json',dict(run=args.run,admin_operations=operations,restored=restored,
            failures=failures,created_client_id=identifier,existing_clients_overwritten=False,human_operations=0))
        save(out/'run-after.json',api('/api/runs/'+args.run))
        if not restored or failures:raise RuntimeError('Native baseline cleanup incomplete')
    save(out/'result.json',api('/api/runs/'+args.run+'/result.json'))
    entries=api('/api/runs/'+args.run+'/transcript');save(out/'transcript.json',entries);manifest=[]
    for entry in entries:
        ref=entry.get('decodedSamlRef')
        if not ref:continue
        if not re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}',entry['id']) or Path(ref).is_absolute() or '..' in Path(ref).parts:raise ValueError('Invalid original reference')
        path=out/'decoded'/(entry['id']+'.xml');path.parent.mkdir(exist_ok=True)
        subprocess.run(['docker','cp','samlscope-reference-suite:/data/'+ref,str(path)],check=True,stdout=subprocess.DEVNULL)
        manifest.append(dict(id=entry['id'],file=str(path.relative_to(out)),sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    save(out/'decoded-manifest.json',manifest)
    subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+args.run+'.xml',str(out/'target-metadata.xml')],check=True,stdout=subprocess.DEVNULL)
    print('Recorded native capability attempt;',args.run,'; temporary client deleted')


if __name__=='__main__':main()
