#!/usr/bin/env python3
"""Import original signature metadata through the product console and collect synchronous native events."""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse as urls
import urllib.request as http
from signed_request_observation import event_configuration,signature_events,LISTENER,ADMIN,api,save


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--profiles',default='browser_sso_idp,metadata_idp,ecp_idp,single_logout_idp')
    parser.add_argument('--playwright-modules',type=Path,required=True)
    parser.add_argument('--matrix',choices=['ec','certificate','keys'],default='ec')
    parser.add_argument('--verify-request-signatures',action='store_true')
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    variants=(['control','ecdsa-sha256','ecdsa-sha256-invalid-signature'] if args.matrix=='ec' else
        ['control','certificate-expired','certificate-not-yet-valid','certificate-critical-extension',
         'certificate-noncritical-extension','certificate-no-digital-signature','certificate-unrelated-eku',
         'certificate-empty-subject','certificate-unknown-ca'])
    if args.matrix=='keys':
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'reference-acceptance'))
        from metadata_key_matrix import KEY_CAMPAIGN
        variants=list(KEY_CAMPAIGN)
    save(out/'matrix.json',dict(matrix=args.matrix,variants=variants,verdict_adopted=False))
    profiles=args.profiles.split(',')
    if len(profiles)!=len(set(profiles)) or not set(profiles)<={'browser_sso_idp','metadata_idp','ecp_idp','single_logout_idp'}:
        raise ValueError('Invalid profiles')
    operations=[]
    def admin(path,body=None,method='GET'):
        # A console batch can outlive an admin token. Obtain a fresh in-memory token for configuration operations.
        request=http.Request('http://localhost:18180/realms/master/protocol/openid-connect/token',data=urls.urlencode(dict(
            client_id='admin-cli',username=os.environ.get('KEYCLOAK_ADMIN_USERNAME','admin'),
            password=os.environ.get('KEYCLOAK_ADMIN_PASSWORD','admin'),grant_type='password')).encode())
        with http.urlopen(request,timeout=30) as response:token=json.load(response)['access_token']
        row=dict(method=method,path=path,status='attempted');operations.append(row)
        request=http.Request(ADMIN+path,data=None if body is None else json.dumps(body).encode(),method=method,
            headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        with http.urlopen(request,timeout=30) as response:
            row['status']=response.status;raw=response.read();return json.loads(raw) if raw else None
    original=admin('/events/config');save(out/'event-configuration-before.json',original)
    configured={**original,'eventsEnabled':True,
        'eventsListeners':sorted(set(original.get('eventsListeners',[]))|{LISTENER}),
        'enabledEventTypes':sorted(set(original.get('enabledEventTypes',[]))|{'LOGIN_ERROR'}) if original.get('eventsEnabled') else ['LOGIN_ERROR']}
    plans=[];changed=False;restored=False
    try:
        changed=True;admin('/events/config',configured,'PUT')
        if event_configuration(admin('/events/config'))!=event_configuration(configured):raise RuntimeError('Observer configuration differs')
        for profile in profiles:
            folder=out/profile;began=datetime.datetime.now(datetime.timezone.utc).isoformat()
            arguments=[sys.executable,str(Path(__file__).with_name('import_metadata_batch.py')),
                '--output',str(folder),'--profile',profile,'--playwright-modules',str(args.playwright_modules.resolve()),
                '--variants',','.join(variants),
                '--suite-signature-control','--native-signature-observations']
            if args.verify_request_signatures:arguments.append('--verify-request-signatures')
            child=subprocess.run(arguments,check=False,timeout=900)
            if not (folder/'created.json').exists():raise RuntimeError('Metadata campaign did not create a Run')
            run=json.loads((folder/'created.json').read_text())['run']['id'];plans.append(dict(profile=profile,run=run,exit_code=child.returncode))
            try:
                if child.returncode:raise RuntimeError('Native metadata import campaign failed')
                subprocess.run([sys.executable,str(Path(__file__).with_name('complete_run_baseline.py')),
                    '--run',run,'--output',str(folder/'baseline')],check=True,timeout=120)
            finally:
                records=[]
                for variant in variants:
                    path=folder/variant/'native-http-observations.json'
                    if path.exists():
                        data=json.loads(path.read_text())
                        if data['run']!=run:raise RuntimeError('Observation belongs to another Run')
                        records.extend(data['records'])
                save(folder/'native-http-observations.json',dict(run=run,records=records,product_verdict_assigned=False))
                save(folder/'native-signature-audit.json',dict(run=run,listener=LISTENER,
                    rows=signature_events(began,{record['request_id'] for record in records})))
                for name in ['result.json','transcript','protocol-evidence']:
                    try:save(folder/(name if '.' in name else name+'.json'),api('/api/runs/'+run+'/'+name))
                    except Exception as error:save(folder/(name.replace('.','-')+'-unavailable.json'),dict(reason=str(error)))
            print(profile,'native',args.matrix,'campaign collected',run,flush=True)
    finally:
        try:
            if changed:
                current=admin('/events/config')
                if event_configuration(current) not in [event_configuration(configured),event_configuration(original)]:
                    raise RuntimeError('Concurrent event configuration change; refusing overwrite')
                if event_configuration(current)!=event_configuration(original):admin('/events/config',original,'PUT')
                restored=event_configuration(admin('/events/config'))==event_configuration(original)
        finally:
            save(out/'operations.json',dict(plans=plans,admin_operations=operations,event_configuration_restored=restored,human_operations=0))
        if not restored:raise RuntimeError('Native event configuration restoration incomplete')


if __name__=='__main__':main()
