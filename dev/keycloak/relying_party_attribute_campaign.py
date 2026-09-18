#!/usr/bin/env python3
"""Per-client native Keycloak user-property mappers; explicit configuration, not metadata interpretation."""
import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import urllib.request as http
import urllib.parse as urls
import urllib.error
import xml.etree.ElementTree as ET
from import_metadata_batch import api, save, BASE
from reference_flow import Client
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shibboleth'))
_shared_spec=importlib.util.spec_from_file_location('shibboleth_rp_campaign',Path(__file__).resolve().parents[1]/'shibboleth/relying_party_attribute_campaign.py')
_shared=importlib.util.module_from_spec(_shared_spec);_shared_spec.loader.exec_module(_shared)
StopAtAcs,AcsSubmitted,VARIANTS=_shared.StopAtAcs,_shared.AcsSubmitted,_shared.VARIANTS

ADMIN='http://localhost:18180/admin/realms/samlscope'
MD='{urn:oasis:names:tc:SAML:2.0:metadata}'
DS='{http://www.w3.org/2000/09/xmldsig#}'
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def client_recipe(entity, side):
    role=entity.findall(MD+'SPSSODescriptor')
    if len(role)!=1:raise ValueError('Expected one SP role')
    certificates={''.join(cert.itertext()).strip() for cert in role[0].findall('.//'+DS+'X509Certificate')}
    if len(certificates)!=1:raise ValueError('Expected one fixed role key')
    certificate=certificates.pop()
    acs=[node.get('Location') for node in role[0].findall(MD+'AssertionConsumerService')
        if node.get('Binding')=='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']
    if not acs:raise ValueError('Missing POST ACS')
    return dict(clientId=entity.get('entityID'),protocol='saml',enabled=True,redirectUris=acs,
        fullScopeAllowed=False,defaultClientScopes=[],optionalClientScopes=[],
        attributes={'saml.client.signature':'true','saml.signing.certificate':certificate,
            'saml.server.signature':'true','saml.assertion.signature':'true','saml.encrypt':'true',
            'saml.encryption.certificate':certificate,'saml.force.post.binding':'true',
            'saml_assertion_consumer_url_post':acs[0]},
        protocolMappers=[dict(name='samlscope-rp-'+marker,protocol='saml',protocolMapper='saml-user-property-mapper',
            consentRequired=False,config={'user.attribute':'firstName','attribute.name':'urn:samlscope:test:relying-party:'+marker,
                'attribute.nameformat':'URI Reference'}) for marker in ['anchor',side]])


def projection(client, expected):
    value={key:client.get(key) for key in ['id','clientId','protocol','enabled','redirectUris','fullScopeAllowed','defaultClientScopes','optionalClientScopes']}
    value['attributes']={key:client.get('attributes',{}).get(key) for key in expected['attributes']}
    # Retain only mapper semantics, never tokens or unrelated client credentials.
    value['protocolMappers']=[{key:mapper.get(key) for key in ['name','protocol','protocolMapper','consentRequired','config']}
                              for mapper in client.get('protocolMappers',[])]
    comparison={key:value[key] for key in expected}
    comparison['protocolMappers']=sorted(comparison['protocolMappers'],key=lambda mapper:mapper['name'])
    wanted=dict(expected);wanted['protocolMappers']=sorted(wanted['protocolMappers'],key=lambda mapper:mapper['name'])
    if comparison!=wanted:raise ValueError('Native client configuration differs from recipe')
    return value


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    out=parser.parse_args().output.resolve();out.mkdir(parents=True,exist_ok=False)
    token_request=http.Request('http://localhost:18180/realms/master/protocol/openid-connect/token',data=urls.urlencode(dict(
        client_id='admin-cli',username=os.environ.get('KEYCLOAK_ADMIN_USERNAME','admin'),
        password=os.environ.get('KEYCLOAK_ADMIN_PASSWORD','admin'),grant_type='password')).encode())
    with http.urlopen(token_request,timeout=30) as response:token=json.load(response)['access_token']
    operations=[]
    def admin(path,body=None,method='GET'):
        request=http.Request(ADMIN+path,data=None if body is None else json.dumps(body).encode(),method=method,
            headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        record=dict(method=method,path=path.split('?')[0],status='attempted');operations.append(record)
        try:
            with http.urlopen(request,timeout=30) as response:
                raw=response.read();record['status']=response.status
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            record['status']=error.code
            raise RuntimeError('Native administration request failed: '+str(error.code)) from None
    credentials=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
    login_binding=secrets.token_hex(32)
    plan_result=api('/api/plans',dict(name='Keycloak relying-party attributes',profile='browser_sso_idp',targetKind='IDP',
        targetEntityId='http://localhost:18180/realms/samlscope',metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',
        suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(out/'plan.json',plan_result);plan=plan_result['plan']['plan']['id']
    created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id']
    if not re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',plan) or not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run):raise ValueError('Invalid identity')
    save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
    campaign=api('/api/runs/'+run+'/metadata-lab/preloaded',dict(variants=list(VARIANTS.values())));save(out/'campaign.json',campaign)
    with http.urlopen(campaign['preloadedMetadataUrl'],timeout=60) as response:raw=response.read()
    (out/'fixture.xml').write_bytes(raw)
    root=ET.fromstring(raw);recipes={}
    for side,variant in VARIANTS.items():
        entity_id=BASE+'/p/'+plan+'/metadata-peer/'+variant
        entities=[entity for entity in root.findall(MD+'EntityDescriptor') if entity.get('entityID')==entity_id]
        if len(entities)!=1:raise ValueError('Ambiguous peer')
        recipes[side]=client_recipe(entities[0],side)
    save(out/'client-recipes.json',recipes)
    owned={};attempted={};observations=[]
    try:
        for side,recipe in recipes.items():
            path='/clients?clientId='+urls.quote(recipe['clientId'],safe='')
            if admin(path):raise ValueError('Refusing existing client overwrite')
            attempted[side]=recipe['clientId']
            admin('/clients',recipe,'POST')
            found=admin(path)
            if len(found)!=1:raise RuntimeError('Created client lookup ambiguous')
            owned[side]=found[0]['id']
            if not re.fullmatch(r'[a-f0-9-]{36}',owned[side]):raise ValueError('Invalid native client identifier')
        def readback():
            return {side:projection(admin('/clients/'+identifier),recipes[side]) for side,identifier in owned.items()}
        native=readback()
        save(out/'preparation.json',dict(run=run,entity_ids={side:recipe['clientId'] for side,recipe in recipes.items()},native=native,
            login_input_binding=login_binding,login_provenance='fixed-in-memory-driver-input',authenticated_principal_verified=False,
            source='native-admin-client-user-property-mapper',source_attribute='firstName',metadata_interpretation_claimed=False))
        start=urls.urlsplit(campaign['preloadedStartUrl'])
        for condition,side in [('first','first'),('second','second'),('first-repeat','first')]:
            variant=VARIANTS[side];index=campaign['preloadedVariants'].index(variant)
            url=urls.urlunsplit(start._replace(path='/p/'+plan+'/start/metadata-preloaded/'+str(index)))
            before={e['id'] for e in api('/api/runs/'+run+'/transcript')}
            record=dict(condition=condition,variant=variant,entity_id=recipes[side]['clientId'],before=readback(),login_input_binding=login_binding)
            observations.append(record)
            client=Client();client.op=http.build_opener(http.HTTPCookieProcessor(client.jar),StopAtAcs())
            try:record['flow_status']=client.flow(url,None,*credentials)
            except AcsSubmitted as submitted:record.update(flow_status='acs-submitted',http_status=submitted.status)
            finally:
                record['after']=readback()
                record['new_transcript_ids']=[e['id'] for e in api('/api/runs/'+run+'/transcript') if e['id'] not in before]
                save(out/'observations.json',observations)
    finally:
        failures=[]
        # Recover a successful create even if the first lookup/response was interrupted.
        for side,entity_id in attempted.items():
            if side in owned:continue
            try:
                found=admin('/clients?clientId='+urls.quote(entity_id,safe=''))
                if len(found)>1:raise ValueError('Ambiguous cleanup identity')
                if found:
                    identifier=found[0]['id']
                    if not re.fullmatch(r'[a-f0-9-]{36}',identifier):raise ValueError('Invalid cleanup identifier')
                    owned[side]=identifier
            except Exception as error:failures.append(side+':lookup:'+type(error).__name__)
        for side,identifier in owned.items():
            try:
                current=admin('/clients/'+identifier)
                if current['clientId']!=recipes[side]['clientId']:raise ValueError('Client identity changed')
                admin('/clients/'+identifier,method='DELETE')
                if admin('/clients?clientId='+urls.quote(recipes[side]['clientId'],safe='')):raise ValueError('Client deletion unproven')
            except Exception as error:failures.append(side+':'+type(error).__name__)
        save(out/'restoration.json',dict(restored=not failures and len(owned)==2,failures=failures,
            deleted_client_ids=owned,existing_clients_overwritten=False))
        save(out/'operations.json',dict(run=run,admin_operations=operations,protocol_starts=len(observations),verdict_adopted=False,human_operations=0))
        entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);manifest=[]
        for entry in entries:
            ref=entry.get('decodedSamlRef')
            if not ref:continue
            if not re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}',entry['id']) or Path(ref).is_absolute() or '..' in Path(ref).parts:raise ValueError('Invalid evidence reference')
            path=out/'decoded'/(entry['id']+'.xml');path.parent.mkdir(exist_ok=True)
            subprocess.run(['docker','cp','samlscope-reference-suite:/data/'+ref,str(path)],check=True,stdout=subprocess.DEVNULL)
            manifest.append(dict(id=entry['id'],file=str(path.relative_to(out)),sha256=SHA(path.read_bytes())))
        save(out/'decoded-manifest.json',manifest)
        subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,stdout=subprocess.DEVNULL)
        if failures:raise RuntimeError('Native client cleanup incomplete')
    print('Recorded',len(observations),'conditions;',run,'; no verdict assigned')


if __name__=='__main__':main()
