#!/usr/bin/env python3
"""One native UI safety campaign, with executable detector controls and a shared authenticated session."""
import argparse,base64,datetime,hashlib,json,os,pathlib,select,subprocess,sys,urllib.parse,urllib.request,urllib.error,xml.etree.ElementTree as ET
from metadata_supersession_campaign import api,public,sha,now,BASE,ADMIN
from attribute_policy_capability_absence import product_token

from algorithm_preference_campaign import recorded
REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture
from import_metadata_batch import recorded_exchange
from preflight_observation_adoption import scope_preflight,approved_case
VARIANTS=['control','ui-safety-logo-data','ui-safety-information-javascript','ui-safety-privacy-javascript']
UI='{urn:oasis:names:tc:SAML:metadata:ui}'
def runtime():
 raw=subprocess.check_output(['docker','inspect','--format','{"containerId":{{json .Id}},"image":{{json .Image}},"startedAt":{{json .State.StartedAt}},"running":{{json .State.Running}},"mounts":{{json .Mounts}}}', 'samlscope-reference-keycloak'],timeout=30)
 row=json.loads(raw);row['version']=subprocess.check_output(['docker','exec','samlscope-reference-keycloak','/opt/keycloak/bin/kc.sh','--version'],text=True,timeout=30).strip()
 if len(row['mounts'])!=1 or row['mounts'][0]['Destination']!='/opt/keycloak/data/import/realm-samlscope.json' or row['mounts'][0]['RW'] is not False or row['mounts'][0]['Type']!='bind':raise ValueError('Native custom renderer mounts unsupported by fixed renderer proof')
 return row

def worker_result(worker):
 if not select.select([worker.stdout],[],[],90)[0]:raise ValueError('Bounded native browser worker timeout')
 line=worker.stdout.readline()
 if not line:raise ValueError('Native browser worker stopped')
 return json.loads(line)

def restore_clients(read_fn,native_fn,lookup,entity,before,record):
 for client in read_fn(lookup):
  if client.get('clientId')!=entity or client.get('protocol')!='saml':raise ValueError('Restoration ownership differs')
  row=record('native-recovery-delete',clientId=client['id']);status,_,_=native_fn('/clients/'+client['id'],method='DELETE');row.update(status=status,finishedAt=now())
  if status!=204:raise ValueError('Native recovery failed')
 after=read_fn(lookup)
 if after!=before:raise ValueError('Original client inventory not restored')
 return after

NATIVE_OPERATIONS=[]
TOKEN=None
AUTH_GRANTS=0
def native(path,body=None,method='GET',content_type='application/json'):
 global TOKEN,AUTH_GRANTS
 if TOKEN is None:TOKEN=product_token();AUTH_GRANTS+=1
 raw=None if body is None else body if isinstance(body,bytes) else json.dumps(body,separators=(',',':')).encode()
 started=now();request=urllib.request.Request(ADMIN+path,data=raw,method=method,headers={'Authorization':'Bearer '+TOKEN,'Content-Type':content_type})
 try:
  with urllib.request.urlopen(request,timeout=40) as response:status,data=response.status,response.read()
 except urllib.error.HTTPError as response:status,data=response.code,response.read()
 finished=now();NATIVE_OPERATIONS.append(dict(method=method,path=path,status=status,startedAt=started,finishedAt=finished))
 return status,data,dict(method=method,url=ADMIN+path,status=status,startedAt=started,finishedAt=finished,requestSha256=sha(raw) if raw is not None else None,responseBase64=base64.b64encode(data).decode(),responseSha256=sha(data))
def read(path):
 status,raw,_=native(path)
 if status!=200:raise ValueError('Native public readback unavailable '+str(status))
 return json.loads(raw)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--playwright-module',type=pathlib.Path,required=True);p.add_argument('--variants',help='Diagnostic subset only; complete adoption requires all four including control');p.add_argument('--reuse-unstarted-run',action='store_true',help='Reuse only an immutable preflight-only Run with no native campaign operations');a=p.parse_args()
 variants=a.variants.split(',') if a.variants else VARIANTS
 if not variants or variants[0]!='control' or not set(variants)<=set(VARIANTS):raise ValueError('Control first, known Suite originals only')
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=a.reuse_unstarted_run);
 if a.reuse_unstarted_run and any((out/p).exists() for p in ['operations.json','members.json','campaign.json','native-source','scope-before.json']):raise ValueError('Only unstarted, never-mutated Run may be reused')
 operations=[];members=[];created=run=entity=None;worker=None;restored=False;lookup=None;credential_attempts=0
 def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
 def op(kind,**fields):value=dict(kind=kind,startedAt=now(),**fields);operations.append(value);save(out/'operations.json',operations);return value
 if a.reuse_unstarted_run:
  plan=json.loads((out/'plan.json').read_bytes());created=json.loads((out/'created.json').read_bytes());pid=plan['plan']['plan']['id'];run=created['run']['id']
  if created['run']['planId']!=pid or plan['plan']['plan']['profile']!='metadata_idp':raise ValueError('Preflight-only scope differs')
  current=api('/api/runs/'+run)
  if current['status'] not in ['READY','RUNNING'] or api('/api/runs/'+run+'/transcript'):raise ValueError('Cannot reuse Run with prior protocol/original operations')
  save(out/'preflight-only-reuse.json',dict(runId=run,originalFiles={p:sha((out/p).read_bytes()) for p in ['plan.json','created.json','preflight.json','target-metadata.xml']},priorNativeWrites=0,priorSaml=0,priorCredentialSubmissions=0,reason='result-artifact-not-generated-before-M0'))
 else:
  plan=api('/api/plans',dict(name='Keycloak native metadata UI safety',profile='metadata_idp',targetKind='IDP',targetEntityId='http://localhost:18180/realms/samlscope',metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
  save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=created['run']['id']
  save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
  subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,capture_output=True,timeout=45)
 entity=BASE+'/p/'+pid;lookup='/clients?clientId='+urllib.parse.quote(entity,safe='')
 target=sha((out/'target-metadata.xml').read_bytes())
 def original(label,value):
  value=dict(schema='samlscope-keycloak-ui-safety-original-v1',runId=run,targetMetadataSha256=target,peerEntityId=entity,recordedAt=now(),**value);save(out/(label+'.json'),value);return recorded(out,created,value,label)
 def scope(phase):
  folder=out/'native-source';folder.mkdir(exist_ok=True);jars={}
  for key in ['services','themes']:
   path=folder/(phase+'-'+key+'.jar');subprocess.run(['docker','cp','samlscope-reference-keycloak:/opt/keycloak/lib/lib/main/org.keycloak.keycloak-'+key+'-26.7.2.jar',str(path)],check=True,capture_output=True,timeout=45);jars[key]=sha(path.read_bytes())
   if jars[key]!={'services':'213c45bb357e0881ead8284f12308e3c9fd8e09e7f0b6ec816f95f8b0921bea9','themes':'a89cbd82fa30951224262aaf5326f6239e1217224678d69cfac3d3fd1b493407'}[key]:raise ValueError('Native source differs before fixed renderer proof')
  files=subprocess.check_output(['docker','exec','samlscope-reference-keycloak','find','/opt/keycloak/providers','/opt/keycloak/themes','-type','f'],timeout=30).decode().splitlines()
  if sorted(files)!=['/opt/keycloak/providers/README.md','/opt/keycloak/themes/README.md']:raise ValueError('Native custom renderer/provider requires separate source qualification')
  realm=read('');realm={key:realm.get(key) for key in ['id','realm','loginTheme','internationalizationEnabled','defaultLocale','enabled']}
  return dict(kind='native-scope',runtime=runtime(),realm=realm,clientPolicies={key:read('/client-policies/'+key) for key in ['policies','profiles']},sourceJarSha256=jars,customNativeFiles=files)
 before=read(lookup)
 if before:raise ValueError('Refuse preexisting native client')
 case,spec=approved_case('IIP-MD05-fg-idp-01',REPO);profile=json.loads((REPO/'profiles/metadata_idp.json').read_bytes());planned=[r for r in profile['cases'] if r['id']==case['id']]
 if len(planned)!=1 or case['role']!='idp' or case['mode']!='BROWSER' or case['obligation']!='IIP-MD05.fg' or profile['profile']!=plan['plan']['plan']['profile'] or any(profile['source_digests'][p]!='sha256:'+sha((REPO/p).read_bytes()) for p in profile['source_digests']):raise ValueError('Current approved planned profile excludes native safety case')
 save(out/'planned-scope-preflight.json',dict(scope_only=True,formal_case_slot_verified=False,runId=run,caseId=case['id'],profile='metadata_idp',membership=planned[0],profileSha256=sha((REPO/'profiles/metadata_idp.json').read_bytes()),catalogDigests=spec,targetMetadataSha256=target,readiness='planned-only-M0-required'))
 before_scope=scope('before');before_ref=original('before',dict(kind='client-inventory',clients=before));scope_before_ref=original('scope-before',before_scope)
 lab=api('/api/runs/'+run+'/metadata-lab')
 if not set(VARIANTS)<=set(lab['availableVariants']):raise ValueError('Whole Suite fixture matrix unavailable before native writes')
 env=dict(os.environ,SAMLSCOPE_PLAYWRIGHT_MODULE=str(a.playwright_module.resolve()))
 worker=subprocess.Popen(['node',str(REPO/'dev/keycloak/ui_safety_worker.mjs')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
 worker.stdin.write('{"detectorOnly":true}\n');worker.stdin.flush();detector=worker_result(worker);save(out/'detector-preflight.json',detector)
 if detector.get('ok') is not True:
  worker.kill();worker.communicate(timeout=10);raise ValueError('Browser execution detector unavailable before native writes')
 try:
  save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=variants,pollingDelaySeconds=0)))
  for variant in variants:
   folder=out/variant;folder.mkdir();state=api('/api/runs/'+run+'/metadata-lab')
   if state['selectedVariant']!=variant:raise ValueError('Prepared fixture differs')
   with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as response:
    if response.status!=202:raise ValueError('Expected preparation gate')
   with urllib.request.urlopen(state['metadataUrl'],timeout=30) as response:fixture=response.read()
   (folder/'fixture.xml').write_bytes(fixture);root=ET.fromstring(fixture);candidates=[e.text for name in ['Logo','InformationURL','PrivacyStatementURL'] for e in root.findall('.//'+UI+name)]
   status,raw,converter=native('/client-description-converter',fixture,'POST','application/xml');conv_ref=original(variant+'-converter',dict(kind='converter',variant=variant,fixtureSha256=sha(fixture),native=converter))
   if status!=200:raise ValueError('Native converter did not admit the fixture')
   recipe=json.loads(raw)
   if public(recipe)!=recipe or recipe.get('clientId')!=entity or recipe.get('protocol')!='saml':raise ValueError('Native converter identity differs')
   configured=dict(recipe,consentRequired=True);mutation=op('native-client-create-attempt',variant=variant)
   status,raw,created_native=native('/clients',configured,'POST');mutation.update(status=status,finishedAt=now());save(out/'operations.json',operations)
   applied_ref=original(variant+'-application',dict(kind='ui-prerequisite-application',variant=variant,fixtureSha256=sha(fixture),converterSha256=sha(json.dumps(recipe,separators=(',',':')).encode()),consentRequired=True,native=created_native))
   member=dict(variant=variant,fixtureSha256=sha(fixture),converter=conv_ref,application=applied_ref)
   if status==400:
    # This is an explicit native client-validation refusal. It is never a SAML rejection.
    if read(lookup):raise ValueError('Failed native import left a client')
    member['nativeAdmission']='rejected';member['rejection']=json.loads(raw)
   elif status==201:
    ids=read(lookup)
    if len(ids)!=1:raise ValueError('Native UI client ambiguous')
    client=public(read('/clients/'+ids[0]['id']));client_id=client['id'];save(folder/'client-readback.json',client)
    member['persisted']=original(variant+'-persisted',dict(kind='operative-client',variant=variant,fixtureSha256=sha(fixture),client=client));member['nativeAdmission']='accepted'
    before_ids={e['id'] for e in api('/api/runs/'+run+'/transcript')};payload=dict(runId=run,variant=variant,startUrl=state['automaticStartUrl'],candidates=candidates,publicHtmlFile=str(folder/'native-consent-public.html'),startedAt=now())
    row=op('native-browser-saml-flow',variant=variant);worker.stdin.write(json.dumps(payload)+'\n');worker.stdin.flush();browser=worker_result(worker);save(folder/'browser.json',browser);credential_attempts+=browser.get('observation',browser).get('credentialSubmissions',0);row.update(finishedAt=now(),browserStatus=browser.get('ok'));save(out/'operations.json',operations)
    if not browser.get('ok'):raise ValueError('Native browser incomplete '+browser.get('stage','unknown'))
    exchange=recorded_exchange(run,variant,before_ids);save(folder/'exchange.json',exchange)
    if not exchange['success']:raise ValueError('Native correlated Success absent')
    observation=browser['observation'];html=(folder/'native-consent-public.html').read_bytes() if (folder/'native-consent-public.html').exists() else None
    member['browser']=original(variant+'-browser',dict(kind='native-browser-ui',variant=variant,fixtureSha256=sha(fixture),observation=observation,publicHtmlBase64=None if html is None else base64.b64encode(html).decode(),exchange=exchange))
    row=op('native-client-delete',variant=variant);deleted,_,_=native('/clients/'+client_id,method='DELETE');row.update(status=deleted,finishedAt=now());save(out/'operations.json',operations)
    if deleted!=204 or read(lookup)!=before:raise ValueError('Native UI client restoration incomplete')
   else:raise ValueError('Native client application unexpected status '+str(status))
   member['restoration']=original(variant+'-restored',dict(kind='client-inventory',variant=variant,clients=read(lookup)));members.append(member);save(out/'members.json',members)
   pending=api('/api/runs/'+run+'/metadata-lab')
   if pending['campaignIndex']==state['campaignIndex']:
    with urllib.request.urlopen(urllib.request.Request(pending['automaticContinueUrl'],data=b''),timeout=30) as response:response.read()
    member['orchestrationOnlyContinue']=True;save(out/'members.json',members)
   if variant=='control':
    save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));scope_result=api('/api/runs/'+run+'/result.json');save(out/'scope-result-before.json',scope_result);ready=scope_preflight('IIP-MD05-fg-idp-01',out/'scope-result-before.json');save(out/'case-slot-preflight.json',ready)
    if ready['scope_ready'] is not True:raise ValueError('Actual case slot absent after baseline; do not send payloads')
   print(variant+' '+member['nativeAdmission']+' recorded',flush=True)
 finally:
  if worker:
   try:worker.stdin.write('{"stop":true}\n');worker.stdin.flush();worker.communicate(timeout=30)
   except Exception:worker.kill();worker.communicate()
  after=restore_clients(read,native,lookup,entity,before,op);save(out/'operations.json',operations);after_scope=scope('after');after_ref=original('after',dict(kind='client-inventory',clients=after));scope_after_ref=original('scope-after',after_scope)
  restored=before==after and before_scope==after_scope;save(out/'restoration.json',dict(restored=restored,before=before_ref,after=after_ref,scopeBefore=scope_before_ref,scopeAfter=scope_after_ref))
  entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
  for name in ['result.json','protocol-evidence']:
   try:save(out/(name if '.' in name else name+'.json'),api('/api/runs/'+run+'/'+name))
   except Exception:pass
  counts=dict(configurationWriteAttempts=sum(r['kind'].startswith('native-client-') or r['kind']=='native-recovery-delete' for r in operations),successfulConfigurationWrites=sum(r['kind'].startswith('native-client-') and r.get('status') in [201,204] or r['kind']=='native-recovery-delete' and r.get('status')==204 for r in operations),productRestarts=0,humanOperations=0,browserAttempts=sum(r['kind']=='native-browser-saml-flow' for r in operations),actualSamlSubmissions=sum(e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='AuthnRequest' for e in entries),metadataFixtureCount=len(members),credentialSubmissions=credential_attempts,browserContexts=1,isolatedDetectorContexts=1,restored=restored);save(out/'operation-counts.json',counts);save(out/'native-http-operation-counts.json',dict(adminTokenGrants=AUTH_GRANTS,nativeHttpAttempts=len(NATIVE_OPERATIONS),operations=NATIVE_OPERATIONS,credentialsPersisted=False))
  if not restored:raise ValueError('Native restoration mismatch; stop product mutations')
 save(out/'qualified-receipt.json',dict(schema='samlscope-keycloak-ui-safety-v1',runId=run,campaignId='native-ui-safety',targetEntityId='http://localhost:18180/realms/samlscope',targetMetadataSha256=target,peerEntityId=entity,members=members,operations=counts,counterfactualCalibrationOnly=False,restoration=json.loads((out/'restoration.json').read_bytes())))
 print('Restored native UI safety campaign; no verdict assigned '+run,flush=True)
if __name__=='__main__':main()
