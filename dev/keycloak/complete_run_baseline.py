#!/usr/bin/env python3
"""Complete normal login using a temporary native client; delete only the created identity."""
import argparse
import json
import os
from pathlib import Path
import re
import urllib.request as http
import urllib.parse as urls
import xml.etree.ElementTree as ET
from relying_party_attribute_campaign import client_recipe, projection, ADMIN, api, save, BASE, Client


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',args.run):raise ValueError('Invalid Run')
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    run=api('/api/runs/'+args.run);plan=run['planId']
    if not re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',plan):raise ValueError('Invalid Plan')
    entity=BASE+'/p/'+plan
    with http.urlopen(entity+'/metadata',timeout=30) as response:fixture=response.read()
    (out/'fixture.xml').write_bytes(fixture)
    recipe=client_recipe(ET.fromstring(fixture),'first')
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
        save(out/'native-readback.json',projection(admin('/clients/'+identifier),recipe))
        flow=Client().flow(entity+'/start/m0-roundtrip?run='+args.run,None,
            os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
        save(out/'flow.json',flow)
        if flow!='recorded':raise RuntimeError('Normal login not recorded')
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
    print('Ordinary login recorded; native client deleted')


if __name__=='__main__':main()
