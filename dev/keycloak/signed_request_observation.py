#!/usr/bin/env python3
"""Collect native Keycloak signed-request observations; never assign a verdict.

Admin client attributes prepare a signature capability test, not a metadata import test.
Native events are diagnostic unless they actually identify the request. A time window
or the generic Invalid requester page does not establish that association.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.parse as urls
import urllib.request as http
import xml.etree.ElementTree as ET
from relying_party_attribute_campaign import client_recipe, projection, ADMIN, api, save, BASE, Client

CASES={'IIP-ALG01-a-idp-01','IIP-ALG02-a-idp-01'}
SHA=lambda value:hashlib.sha256(value).hexdigest()
LISTENER='samlscope-signature-observation'


def signature_events(since,request_ids):
    result=subprocess.run(['docker','logs','--since',since,'samlscope-reference-keycloak'],
        capture_output=True,text=True,check=True,timeout=30)
    rows=[]
    for line in (result.stdout+'\n'+result.stderr).splitlines():
        if not line.startswith('SAMLscope-native-signature-v1|'):continue
        fields=line.split('|')
        if len(fields)!=8 or fields[3] not in request_ids:continue
        if not re.fullmatch(r'[0-9a-f]{64}',fields[4]) or fields[6:]!=['LOGIN_ERROR','invalid_signature']:
            raise ValueError('Malformed native signature audit')
        datetime.datetime.fromisoformat(fields[1])
        rows.append(dict(observed_at=fields[1],event_time=int(fields[2]),request_id=fields[3],
            request_sha256=fields[4],issuer=fields[5],event_type=fields[6],error=fields[7]))
    return rows


def event_configuration(value):
    return {key:sorted(item) if key in {'enabledEventTypes','eventsListeners'} else item for key,item in value.items()}


def native_projection(client,recipe):
    # Redirect URI order is not significant in the product's set-valued field.
    return projection({**client,'redirectUris':sorted(client.get('redirectUris',[]))},
                      {**recipe,'redirectUris':sorted(recipe['redirectUris'])})


class ObservedClient(Client):
    def __init__(self,records,admin):
        super().__init__();self.records=records;self.admin=admin

    def request(self,url,fields=None):
        observation=None
        if url=='http://localhost:18180/realms/samlscope/protocol/saml' and fields and 'SAMLRequest' in fields:
            raw=base64.b64decode(fields['SAMLRequest'],validate=True);root=ET.fromstring(raw)
            observation=dict(request_id=root.get('ID'),request_sha256=SHA(raw),request_url=url,
                request_type=root.tag,started_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
            before=self.admin('/events?type=LOGIN_ERROR&max=100') if self.admin else []
        final,page,status=super().request(url,fields)
        if observation is not None:
            after=self.admin('/events?type=LOGIN_ERROR&max=100') if self.admin else []
            # Event IDs are native event identities, not SAML request correlations.
            previous={event.get('id') for event in before}
            events=[]
            for event in after:
                if event.get('id') in previous:continue
                details=event.get('details') or {}
                events.append({**{key:event.get(key) for key in ['id','time','type','clientId','error']},
                    'details':{key:details[key] for key in ['reason','request_id','saml_request_id'] if key in details}})
            safe_url=urls.urlunsplit(urls.urlsplit(final)._replace(query='',fragment=''))
            observation.update(response_url=safe_url,response_url_exact_match=final==url,
                response_status=status,response_body_sha256=SHA(page.encode()),
                finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                invalid_requester_text_present='Invalid requester' in page,
                saml_response_form_present='name="SAMLResponse"' in page,
                native_events=events,event_request_correlation_proven=False)
            self.records.append(observation)
        return final,page,status


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--profiles',default='browser_sso_idp,metadata_idp,ecp_idp,single_logout_idp')
    parser.add_argument('--native-signature-listener',action='store_true')
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    save(out/'collector-source.json',dict(source=Path(__file__).name,
        sha256=SHA(Path(__file__).read_bytes()),diagnostic_only=True))
    profiles=args.profiles.split(',')
    if len(profiles)!=len(set(profiles)) or not set(profiles)<={'browser_sso_idp','metadata_idp','ecp_idp','single_logout_idp'}:
        raise ValueError('Invalid profiles')
    token_request=http.Request('http://localhost:18180/realms/master/protocol/openid-connect/token',data=urls.urlencode(dict(
        client_id='admin-cli',username=os.environ.get('KEYCLOAK_ADMIN_USERNAME','admin'),
        password=os.environ.get('KEYCLOAK_ADMIN_PASSWORD','admin'),grant_type='password')).encode())
    with http.urlopen(token_request,timeout=30) as response:token=json.load(response)['access_token']
    operations=[]
    def admin(path,body=None,method='GET'):
        request=http.Request(ADMIN+path,data=None if body is None else json.dumps(body).encode(),method=method,
            headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        row=dict(method=method,path=path.split('?')[0],status='attempted');operations.append(row)
        with http.urlopen(request,timeout=30) as response:
            row['status']=response.status;raw=response.read()
            return json.loads(raw) if raw else None
    original=admin('/events/config')
    # Store only error events; no successful login data, admin payloads or credentials.
    configured={**original,'eventsEnabled':True,'enabledEventTypes':sorted(set(original.get('enabledEventTypes',[]))|{'LOGIN_ERROR'})
        if original.get('eventsEnabled') else ['LOGIN_ERROR']}
    if args.native_signature_listener:
        configured['eventsListeners']=sorted(set(original.get('eventsListeners',[]))|{LISTENER})
    save(out/'event-configuration-before.json',original)
    plans=[];event_write_attempted=False;event_restored=False
    user=os.environ.get('REFERENCE_USERNAME','samlscope-m0-user');password=os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password')
    try:
        event_write_attempted=True;admin('/events/config',configured,'PUT')
        if event_configuration(admin('/events/config'))!=event_configuration(configured):raise RuntimeError('Native event configuration readback differs')
        for profile in profiles:
            folder=out/profile;folder.mkdir();records=[];attempts=[]
            began=datetime.datetime.now(datetime.timezone.utc).isoformat()
            plan=api('/api/plans',dict(name='Keycloak native signed-request observations',profile=profile,targetKind='IDP',
                targetEntityId='http://localhost:18180/realms/samlscope',metadataSourceKind='URL',
                metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',
                suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,
                metadataRefreshWaitSeconds=300,testUserHint=user,requestSigningMode='REQUIRED'),
                interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
            save(folder/'plan.json',plan);plan_id=plan['plan']['plan']['id'];entity=BASE+'/p/'+plan_id
            created=api('/api/plans/'+plan_id+'/runs',{});save(folder/'created.json',created);run=created['run']['id']
            plans.append(dict(profile=profile,run=run))
            save(folder/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
            with http.urlopen(entity+'/metadata',timeout=30) as response:fixture=response.read()
            (folder/'fixture.xml').write_bytes(fixture)
            recipe=client_recipe(ET.fromstring(fixture),'first')
            if recipe['clientId']!=entity:raise ValueError('Unexpected client identity')
            lookup='/clients?clientId='+urls.quote(entity,safe='')
            if admin(lookup):raise ValueError('Refusing existing client overwrite')
            identifier=None;restored=False;created_attempted=False
            try:
                created_attempted=True;admin('/clients',recipe,'POST')
                clients=admin(lookup)
                if len(clients)!=1:raise ValueError('Ambiguous created client')
                identifier=clients[0]['id']
                if not re.fullmatch(r'[a-f0-9-]{36}',identifier):raise ValueError('Invalid native client ID')
                save(folder/'preparation.json',dict(run=run,fixture_sha256=SHA(fixture),
                    native=native_projection(admin('/clients/'+identifier),recipe),metadata_interpretation_claimed=False))
                baseline=ObservedClient(records,admin).flow(entity+'/start/m0-roundtrip?run='+run,None,user,password)
                save(folder/'baseline.json',dict(receipt=baseline))
                if baseline!='recorded':raise RuntimeError('Normal login not recorded')
                save(folder/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
                finished=set()
                for index in range(32):
                    result=api('/api/runs/'+run+'/result.json')
                    selected={case['id']:case for requirement in result['requirements'] for case in requirement['cases'] if case['id'] in CASES}
                    finished={key for key,case in selected.items() if case['reason_code'] in {
                        'idp.signed-request.inconclusive','algorithm.native-verification-observed'}}
                    if finished==CASES:break
                    state=api('/api/runs/'+run+'/active-probe')
                    if state['state']!='READY' or state['caseId'] not in CASES|{'IIP-IDP05-a-idp-01'}:
                        raise RuntimeError('Unexpected active scenario state')
                    row=dict(case=state['caseId'],action=state['actionId'],fresh_client=True);attempts.append(row)
                    row['flow_result']=ObservedClient(records,admin).flow(state['startUrl'],dict(freshSessionConfirmed='true'),user,password)
                    current=api('/api/runs/'+run+'/active-probe')
                    if current['state']=='AWAITING_RESPONSE' and current['actionId']==state['actionId']:
                        api('/api/runs/'+run+'/active-probe/abort',{});row['unavailable_reported']=True
                    save(folder/'attempts.json',attempts)
                if finished!=CASES:raise RuntimeError('Incomplete signature matrix')
            finally:
                save(folder/'native-http-observations.json',dict(run=run,records=records,product_verdict_assigned=False))
                save(folder/'attempts.json',attempts)
                try:
                    if created_attempted:
                        clients=admin(lookup)
                        if len(clients)>1:raise ValueError('Cleanup identity ambiguous')
                        if clients:
                            current=clients[0]
                            if current['clientId']!=entity or identifier is not None and current['id']!=identifier:
                                raise ValueError('Cleanup identity changed')
                            if not re.fullmatch(r'[a-f0-9-]{36}',current['id']):raise ValueError('Invalid cleanup ID')
                            # Refuse to erase a concurrent operator edit to the temporary client.
                            native_projection(admin('/clients/'+current['id']),recipe)
                            admin('/clients/'+current['id'],method='DELETE')
                        restored=not admin(lookup)
                finally:
                    save(folder/'restoration.json',dict(restored=restored,created_client_id=identifier,existing_clients_overwritten=False))
                for name in ['result.json','transcript','protocol-evidence']:
                    save(folder/(name if '.' in name else name+'.json'),api('/api/runs/'+run+'/'+name))
                if args.native_signature_listener:
                    save(folder/'native-signature-audit.json',dict(run=run,listener=LISTENER,
                        rows=signature_events(began,{record['request_id'] for record in records})))
                if not restored:raise RuntimeError('Temporary client cleanup incomplete')
            print(profile,'collected',run,flush=True)
    finally:
        try:
            if event_write_attempted:
                current=admin('/events/config')
                if event_configuration(current) not in [event_configuration(configured),event_configuration(original)]:
                    raise RuntimeError('Event configuration changed concurrently; refusing overwrite')
                if event_configuration(current)!=event_configuration(original):admin('/events/config',original,'PUT')
                event_restored=event_configuration(admin('/events/config'))==event_configuration(original)
        finally:
            save(out/'operations.json',dict(plans=plans,admin_operations=operations,event_configuration_restored=event_restored,
                product_verdict_assigned=False,human_operations=0,product_restarts=0))
        if not event_restored:raise RuntimeError('Event configuration restoration incomplete')


if __name__=='__main__':main()
