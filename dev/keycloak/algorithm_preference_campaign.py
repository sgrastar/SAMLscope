#!/usr/bin/env python3
"""Collect native, same-policy SHA256/SHA512 ordering without deciding conformance."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
import zipfile

REPO=Path(__file__).resolve().parents[2]
from import_metadata_batch import api,save,flow,BASE
from attribute_policy_capability_absence import product_token
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture
ADMIN='http://localhost:18180/admin/realms/samlscope'
REQUIRED=['control','algorithm-entity-sha256','algorithm-entity-sha512',
    'algorithm-entity-order-256-512','algorithm-entity-order-512-256',
    'algorithm-role-order-256-512','algorithm-role-order-512-256','algorithm-unsupported-first',
    'algorithm-entity-digest-order-256-512','algorithm-entity-digest-order-512-256',
    'algorithm-entity-signing-order-256-512','algorithm-entity-signing-order-512-256']
CLASSES={
    'org/keycloak/protocol/saml/SamlClient.class':'keycloak-services',
    'org/keycloak/models/ClientConfigResolver.class':'keycloak-server-spi-private',
    'org/keycloak/models/jpa/ClientAdapter.class':'keycloak-model-jpa'}

def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def load(path):return json.loads(path.read_bytes())
def admin(path,method='GET'):
    q=urllib.request.Request(ADMIN+path,method=method,headers={'Authorization':'Bearer '+product_token()})
    with urllib.request.urlopen(q,timeout=40) as r:
        if r.status!=(204 if method=='DELETE' else 200):raise ValueError('Native public read-back failed')
        return None if method=='DELETE' else json.load(r)

def recorded(out,created,value,label):
    run,plan=created['run']['id'],created['run']['planId']
    raw=canonical(value);before={e['id'] for e in api('/api/runs/'+run+'/transcript')}
    q=urllib.request.Request(BASE+'/p/'+plan+'/sp/paos?run='+run,data=raw,method='POST',headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(q,timeout=40) as r:
        if r.status!=204:raise ValueError('Native original Recorder write failed')
    added=[e for e in api('/api/runs/'+run+'/transcript') if e['id'] not in before and e.get('decodedSamlRef')]
    if len(added)!=1:raise ValueError('Native original reference ambiguous')
    ref={'reference':added[0]['id'],'sha256':sha(raw)}
    originals=out/'native-originals';originals.mkdir(exist_ok=True)
    (originals/(label+'.json')).write_bytes(raw)
    return ref

def policy(out,created):
    native={}
    for path,jar in CLASSES.items():
        with zipfile.ZipFile(out/'native-runtime'/(jar+'.jar')) as z:native[path]=base64.b64encode(z.read(path)).decode()
    value={'schema':'samlscope-keycloak-preference-native-policy-v1','runId':created['run']['id'],
        'campaignId':'metadata-fixture-refresh','targetMetadataSha256':sha((out/'target-metadata.xml').read_bytes()),
        'clientPolicies':admin('/client-policies/policies'),'clientProfiles':admin('/client-policies/profiles'),
        'nativeClasses':native}
    if value['clientPolicies']!={'policies':[]} or value['clientProfiles']!={'profiles':[]}:
        raise ValueError('Additional native constraints present; keep NOT_VERIFIED')
    return value

def collect_member(out,folder):
    created=load(out/'created.json');run=created['run']['id'];entity=BASE+'/p/'+created['run']['planId']
    ids=admin('/clients?clientId='+urllib.parse.quote(entity,safe=''))
    if len(ids)!=1:raise ValueError('Native temporary client ambiguous')
    native=admin('/clients/'+ids[0]['id'])
    attributes={k:v for k,v in native.get('attributes',{}).items() if k.startswith('saml')}
    if any(re.search('private|secret|token|credential|password',k,re.I) for k in attributes):
        raise ValueError('Unexpected credential-bearing native attribute; never persist')
    original={'schema':'samlscope-keycloak-preference-native-client-v1','runId':run,
        'targetMetadataSha256':sha((out/'target-metadata.xml').read_bytes()),
        'targetEntityId':'http://localhost:18180/realms/samlscope','method':'GET','httpStatus':200,
        'path':'/clients/'+native['id'],'fixtureSha256':sha((folder/'fixture.xml').read_bytes()),
        'client':{'id':native['id'],'clientId':native['clientId'],'protocol':native['protocol'],'samlAttributes':attributes}}
    save(folder/'native-configuration-reference.json',recorded(out,created,original,folder.name+'-configuration'))
    save(folder/'native-configuration.json',original)
    flow(run,folder/'flow.json',suite_signature_control=True)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--playwright-modules',type=Path);p.add_argument('--flow-member',type=Path)
    args=p.parse_args();out=args.output.resolve()
    if args.flow_member:collect_member(out,args.flow_member.resolve());return
    if args.playwright_modules is None:p.error('--playwright-modules required')
    out.mkdir(exist_ok=False,parents=True);runtime=out/'native-runtime';runtime.mkdir()
    jar_pins={}
    for jar in set(CLASSES.values()):
        path=runtime/(jar+'.jar')
        subprocess.run(['docker','cp','samlscope-reference-keycloak:/opt/keycloak/lib/lib/main/org.keycloak.'+jar+'-26.7.2.jar',str(path)],check=True,capture_output=True)
        jar_pins[jar]=sha(path.read_bytes())
    save(runtime/'pins.json',jar_pins)
    stage=out/'driver';stage.mkdir();shutil.copy2(Path(__file__).with_name('console_import.mjs'),stage/'console_import.mjs')
    (stage/'node_modules').symlink_to(args.playwright_modules.resolve(),target_is_directory=True)
    plan=api('/api/plans',dict(name='Keycloak native independent algorithm orders',profile='metadata_idp',targetKind='IDP',
        targetEntityId='http://localhost:18180/realms/samlscope',metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',
        suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,
        testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];created=api('/api/plans/'+pid+'/runs',{})
    save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
    subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,capture_output=True)
    entity=BASE+'/p/'+pid;original_clients=admin('/clients?clientId='+urllib.parse.quote(entity,safe=''))
    if original_clients:raise ValueError('Refusing native existing client')
    before=policy(out,created);before_ref=recorded(out,created,before,'policy-before')
    matrix=[];caps=[];operations=[];restored=False
    def member(label,variant,capability=None):
        folder=out/label;folder.mkdir();state=api('/api/runs/'+run+'/metadata-lab')
        if state['selectedVariant']!=variant:raise ValueError('Selected native fixture differs')
        with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as r:
            if r.status!=202:raise ValueError('Native fixture fetch gate missing')
        with urllib.request.urlopen(state['metadataUrl'],timeout=30) as r:(folder/'fixture.xml').write_bytes(r.read())
        follow=shlex.join([sys.executable,str(Path(__file__).resolve()),'--output',str(out),'--flow-member',str(folder)])
        command=['node',str(stage/'console_import.mjs'),'--fixture',str(folder/'fixture.xml'),'--record',str(folder/'import.json'),
            '--entity-id',entity,'--verify-command',follow,'--delete']
        command+=['--signing-capability',capability] if capability else ['--native-default-signature-selector']
        row={'label':label,'variant':variant,'native_import_attempted':True,'capability':capability,'restored':False,'driver_exit':None}
        operations.append(row);save(out/'operations.json',operations)
        result=subprocess.run(command,capture_output=True,text=True,timeout=420);(folder/'driver.log').write_text(result.stdout+result.stderr)
        imported=load(folder/'import.json');row.update(driver_exit=result.returncode,restored=imported.get('cleanup',{}).get('read_back_absent') is True)
        row['native_write_attempts']=imported['import'].get('native_default_signature_selector',imported['import'].get('signing_capability_policy',{})).get('write_attempts',0)
        save(out/'operations.json',operations)
        if result.returncode or not row['restored']:raise ValueError('Native matrix/control incomplete; no verdict adopted')
        exchange=load(folder/'flow.json')['positive_exchange'];configuration=load(folder/'native-configuration-reference.json')
        evidence={'variant':variant,'configuration':configuration,'responseReference':exchange['transcript_ids'][-1]}
        if capability:evidence['algorithm']=capability;caps.append(evidence)
        else:matrix.append(evidence)
        print(label+' native original recorded/restored',flush=True)
    try:
        save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=REQUIRED,pollingDelaySeconds=0)))
        for variant in REQUIRED:
            member(variant,variant)
            if variant=='control':save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
        for label,algo in [('sha256','RSA_SHA256'),('sha512','RSA_SHA512')]:
            save(out/('capability-'+label+'-campaign.json'),api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=['control'],pollingDelaySeconds=0)))
            member('capability-'+label,'control',algo)
        after=policy(out,created)
        if after!=before:raise ValueError('Native global policy changed')
        after_ref=recorded(out,created,after,'policy-after')
        remaining=admin('/clients?clientId='+urllib.parse.quote(entity,safe=''));restored=remaining==original_clients==[] and all(r['restored'] for r in operations)
        restoration={'schema':'samlscope-keycloak-preference-restoration-v1','runId':run,'targetEntityId':'http://localhost:18180/realms/samlscope',
            'originalClients':original_clients,'remainingClients':remaining}
        restore_ref=recorded(out,created,restoration,'restoration')
        receipt={'schema':'samlscope-keycloak-algorithm-preference-v1','adapter':'keycloak-native-default-selector-v1',
            'runId':run,'campaignId':'metadata-fixture-refresh','targetEntityId':'http://localhost:18180/realms/samlscope',
            'targetMetadataSha256':sha((out/'target-metadata.xml').read_bytes()),'policyBefore':before_ref,'policyAfter':after_ref,
            'matrix':matrix,'capabilities':caps,'restoration':restore_ref}
        if not restored:raise ValueError('Native restoration not proven')
        save(out/'qualified-receipt.json',receipt)
    finally:
        remaining=admin('/clients?clientId='+urllib.parse.quote(entity,safe=''))
        recovery_deletes=0
        # The unique Run entity had no original client. Clean up only matching
        # owned clients after an interrupted driver, before doing any next work.
        for owned in remaining:
            if owned.get('clientId')!=entity or owned.get('protocol')!='saml':raise ValueError('Native failure cleanup ownership unproven')
            admin('/clients/'+owned['id'],method='DELETE');recovery_deletes+=1
        remaining=admin('/clients?clientId='+urllib.parse.quote(entity,safe=''))
        public_remaining=[{k:r.get(k) for k in ['id','clientId','protocol']} for r in remaining]
        save(out/'restoration.json',dict(restored=remaining==original_clients==[],remaining_clients=public_remaining,
            recovery_client_removals=recovery_deletes))
        save(out/'operation-counts.json',dict(native_import_attempts=len(operations),temporary_clients_removed=sum(r['restored'] for r in operations),
            native_selector_write_attempts=sum(r.get('native_write_attempts',0) for r in operations),protocol_operation_pairs_attempted=len(operations),
            recovery_client_removals=recovery_deletes,product_restarts=0,human_operations=0,restored=remaining==[],verdict_adopted=False))
        entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
    print('Full native preference originals restored; no verdict assigned',run,flush=True)

if __name__=='__main__':main()
