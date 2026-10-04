#!/usr/bin/env python3
"""Observe native algorithm generation under explicit temporary client settings, not metadata interpretation."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import subprocess
import urllib.request as http
import urllib.parse as urls
import xml.etree.ElementTree as ET
from relying_party_attribute_campaign import client_recipe, projection, ADMIN, api, save, BASE, Client

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'reference-acceptance'))
from capture_run_originals import capture

X='http://www.w3.org/2001/04/xmlenc#'
X11='http://www.w3.org/2009/xmlenc11#'
SHA1='http://www.w3.org/2000/09/xmldsig#sha1'
SHA256=X+'sha256'
PHASES=[('oaep11-sha256-aes256',X11+'rsa-oaep',SHA256,X11+'aes256-gcm'),
        ('oaep11-sha256-aes128',X11+'rsa-oaep',SHA256,X11+'aes128-gcm'),
        ('oaep10-sha256',X+'rsa-oaep-mgf1p',SHA256,X11+'aes128-gcm'),
        ('oaep10-sha1',X+'rsa-oaep-mgf1p',SHA1,X11+'aes128-gcm'),
        ('oaep11-sha1',X11+'rsa-oaep',SHA1,X11+'aes128-gcm')]

class CountingClient(Client):
    """Count requests and login submissions without persisting credentials or cookies."""
    def __init__(self):
        super().__init__();self.request_count=0;self.login_submissions=0
    def request(self,url,fields=None):
        self.request_count+=1
        if fields and ('password' in fields or 'j_password' in fields):self.login_submissions+=1
        return super().request(url,fields)

def runtime():
    values={}
    for name in ['samlscope-reference-suite','samlscope-reference-keycloak']:
        # Select only immutable/runtime fields; never export container environment.
        value=json.loads(subprocess.check_output(['docker','inspect','--format',
            '{"id":{{json .Id}},"image":{{json .Image}},"startedAt":{{json .State.StartedAt}},"running":{{json .State.Running}}}',name],timeout=30))
        if not value['running']:raise ValueError('Reference runtime is not running')
        values[name]=value
    return values


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',choices=['browser_sso_idp','ecp_idp'],default='ecp_idp')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--matrix', choices=['encryption', 'signature'], default='encryption')
    parser.add_argument('--default-mgf-sha1', action='store_true',
                        help='Select native MGF1-SHA1 for the final OAEP1.1/SHA1 phase; inspect output omission separately')
    parser.add_argument('--ecp-corroboration', action='store_true',
                        help='Also collect the existing outbox SOAP probe group in an ECP Run; never relabel it as browser evidence')
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    if args.default_mgf_sha1 and args.matrix != 'encryption': raise ValueError('Default MGF requires the encryption matrix')
    if args.ecp_corroboration and args.profile != 'ecp_idp': raise ValueError('SOAP corroboration requires an ECP profile')
    operations=[];token_requests=[]
    if args.default_mgf_sha1:save(out/'runtime-before.json',runtime())
    def admin(path,body=None,method='GET'):
        # Fresh token for each administration operation; never retain it in evidence.
        request=http.Request('http://localhost:18180/realms/master/protocol/openid-connect/token',data=urls.urlencode(dict(
            client_id='admin-cli',username=os.environ.get('KEYCLOAK_ADMIN_USERNAME','admin'),
            password=os.environ.get('KEYCLOAK_ADMIN_PASSWORD','admin'),grant_type='password')).encode())
        with http.urlopen(request,timeout=30) as response:
            token=json.load(response)['access_token'];token_requests.append(dict(status=response.status))
        request=http.Request(ADMIN+path,data=None if body is None else json.dumps(body).encode(),method=method,
            headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        row=dict(method=method,path=path.split('?')[0],status='attempted');operations.append(row)
        with http.urlopen(request,timeout=30) as response:
            row['status']=response.status;raw=response.read()
            return json.loads(raw) if raw else None
    created=api('/api/plans',dict(name='Keycloak native producer '+args.matrix+' matrix',profile=args.profile,
        targetKind='IDP',targetEntityId='http://localhost:18180/realms/samlscope',metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',
        suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,
            metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(out/'plan.json',created);plan=created['plan']['plan']['id']
    created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id']
    if not re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',plan) or not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run):
        raise ValueError('Invalid Suite identity')
    save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
    entity=BASE+'/p/'+plan
    metadata_url = entity+'/metadata' + ('?variant=signature-modes-optional&run='+run if args.matrix == 'signature' else '')
    with http.urlopen(metadata_url,timeout=30) as response:fixture=response.read()
    (out/'fixture.xml').write_bytes(fixture)
    if args.matrix == 'signature':
        role = ET.fromstring(fixture).find('{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor')
        if role is None or role.get('WantAssertionsSigned') != 'false':
            raise ValueError('Signature matrix requires optional Assertion signing metadata')
    recipe=client_recipe(ET.fromstring(fixture),'first')
    recipe['protocolMappers']=[]
    if args.ecp_corroboration:
        recipe['redirectUris'].append(entity+'/sp/paos?run='+run)
    if recipe['clientId']!=entity:raise ValueError('Unexpected client identity')
    lookup='/clients?clientId='+urls.quote(entity,safe='')
    original=admin(lookup)
    if original:raise ValueError('Refusing existing client overwrite')
    if args.default_mgf_sha1:save(out/'client-original-state.json',dict(clientId=entity,clients=original))
    identifier=None;restored=False;failures=[];phases=[];expected=copy.deepcopy(recipe)
    shared_client=CountingClient() if args.default_mgf_sha1 else None
    try:
        admin('/clients',recipe,'POST');clients=admin(lookup)
        if len(clients)!=1:raise ValueError('Created client ambiguous')
        identifier=clients[0]['id']
        if not re.fullmatch(r'[a-f0-9-]{36}',identifier):raise ValueError('Invalid native client identity')
        initial_native=projection(admin('/clients/'+identifier),expected)
        if args.default_mgf_sha1:save(out/'client-created-native.json',initial_native)
        selected_phases = PHASES if args.matrix == 'encryption' else [
            ('both', True, True, None), ('assertion-only', False, True, None), ('response-only', True, False, None)]
        for phase,transport,digest,data_algorithm in selected_phases:
            folder=out/phase;folder.mkdir()
            current=admin('/clients/'+identifier);projection(current,expected)
            wanted=copy.deepcopy(recipe)
            if args.matrix == 'encryption':
                wanted['attributes'].update({'saml.encryption.algorithm':data_algorithm,
                    'saml.encryption.keyAlgorithm':transport,'saml.encryption.digestMethod':digest})
                requested = dict(transport=transport,digest=digest,data=data_algorithm)
                if args.default_mgf_sha1 and phase == 'oaep11-sha1':
                    wanted['attributes']['saml.encryption.maskGenerationFunction']=X11+'mgf1sha1'
                    requested['mgf']=X11+'mgf1sha1'
            else:
                wanted['attributes'].update({'saml.server.signature':str(transport).lower(),
                    'saml.assertion.signature':str(digest).lower(),'saml.encrypt':'false'})
                requested = dict(response_signed=transport,assertion_signed=digest,encrypted=False)
            admin('/clients/'+identifier,wanted,'PUT');expected=wanted
            readback=projection(admin('/clients/'+identifier),expected);save(folder/'native-readback.json',readback)
            before=api('/api/runs/'+run+'/transcript');before_ids={entry['id'] for entry in before}
            receipt=(shared_client or Client()).flow(entity+'/start/m0-roundtrip?run='+run,None,
                os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
            after=api('/api/runs/'+run+'/transcript')
            row=dict(phase=phase,run=run,client_database_id=identifier,receipt=receipt,
                added_transcripts=[entry['id'] for entry in after if entry['id'] not in before_ids],
                readback_sha256=hashlib.sha256((folder/'native-readback.json').read_bytes()).hexdigest(),
                requested=requested,
                evidence_scope='explicit-client-settings-and-browser-sso',verdict_adopted=False)
            phases.append(row);save(folder/'flow.json',row)
            if receipt!='recorded':raise RuntimeError('Producer flow did not complete')
            if args.default_mgf_sha1 and len(phases)==1:
                # A result exists after baseline completion. Preflight the real stored
                # producer slots before collecting the default-MGF condition.
                save(out/'tests-start-before-default.json',api('/api/runs/'+run+'/tests/start',{}))
                initial=api('/api/runs/'+run+'/result.json');save(out/'result-before.json',initial)
                selected={case['id']:case for requirement in initial['requirements'] for case in requirement['cases']}
                if initial['profile']['id']!=args.profile.replace('_','-') or not all(
                    selected.get('IIP-ALG06-'+letter+'-idp-01',{}).get('mode')=='BROWSER' for letter in 'bcd'):
                    raise ValueError('Actual Run must contain the approved producer slots')
            print(phase,'recorded',flush=True)
        if args.ecp_corroboration:
            before_ids={entry['id'] for entry in api('/api/runs/'+run+'/transcript')}
            probe=api('/api/runs/'+run+'/ecp-probe',dict(
                username=os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),
                password=os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password')))
            save(out/'ecp-probe.json',probe)
            save(out/'ecp-corroboration.json',dict(run=run,
                added_transcripts=[entry['id'] for entry in api('/api/runs/'+run+'/transcript') if entry['id'] not in before_ids],
                scope='original-outbox-soap-only; browser-slot conclusion remains separately bound',
                credentials_persisted=False))
        save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
        save(out/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}))
    finally:
        try:
            clients=admin(lookup)
            if len(clients)>1:raise ValueError('Cleanup identity ambiguous')
            if clients:
                current=clients[0]
                if current['clientId']!=entity or (identifier is not None and current['id']!=identifier):
                    raise ValueError('Cleanup identity changed')
                identifier=current['id']
                if not re.fullmatch(r'[a-f0-9-]{36}',identifier):raise ValueError('Invalid cleanup identity')
                projection(admin('/clients/'+identifier),expected)
                admin('/clients/'+identifier,method='DELETE')
            final_clients=admin(lookup);restored=not final_clients
            if args.default_mgf_sha1:save(out/'client-final-state.json',dict(clientId=entity,clients=final_clients))
        except Exception as error:failures.append(type(error).__name__)
        save(out/'operations.json',dict(run=run,profile=args.profile,matrix=args.matrix,admin_operations=operations,
            token_requests=token_requests,phases=phases,restored=restored,failures=failures,
            created_client_id=identifier,existing_clients_overwritten=False,human_operations=0,
            default_mgf_sha1_requested=args.default_mgf_sha1,shared_browser_session=shared_client is not None,
            ecp_corroboration_requested=args.ecp_corroboration,
            browser_request_attempts=shared_client.request_count if shared_client else None,
            browser_login_submissions=shared_client.login_submissions if shared_client else None))
        for name,endpoint in [('result.json','result.json'),('transcript.json','transcript'),('run-after.json','')]:
            save(out/name,api('/api/runs/'+run+('/'+endpoint if endpoint else '')))
        capture(out, run, json.loads((out/'transcript.json').read_text()))
        if args.default_mgf_sha1:save(out/'runtime-after.json',runtime())
        if not restored or failures:raise RuntimeError('Native producer cleanup incomplete')
    print('Run',run,'native client deleted; formal results still require evidence audit')


if __name__=='__main__':main()
