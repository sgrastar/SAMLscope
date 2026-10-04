#!/usr/bin/env python3
"""Consume unchanged dual-role XML with one shared login and eleven Suite outbox controls."""
import argparse,datetime,hashlib,json,os,pathlib,re,subprocess,sys,time,urllib.request,importlib.util,zipfile,xml.etree.ElementTree as E
REPO=pathlib.Path(__file__).resolve().parents[2];sys.path[:0]=[str(REPO/'dev/shibboleth'),str(REPO/'dev/keycloak'),str(REPO/'dev/reference-acceptance')]
_spec=importlib.util.spec_from_file_location("role_key_suite_api",REPO/"dev/keycloak/import_metadata_batch.py");_suite=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_suite)
api,save,BASE=_suite.api,_suite.save,_suite.BASE
from metadata_native_observation import MetadataNativeClient
from metadata_validity_baseline_recovery import complete as baseline
from signature_audit_format import signature_audit
from public_runtime_capture import capture_target
from capture_run_originals import capture
from browser_probe_selection import prepare_and_skip
import metadata_certificate_trust_scope as trust_scope
from registered_signer_campaign import audit_configuration
CONTAINER='samlscope-reference-shibboleth';PROVIDERS='/opt/reference-idp/conf/metadata-providers.xml';AUDIT='/opt/reference-idp/conf/audit.xml';NS='urn:mace:shibboleth:2.0:metadata';XSI='http://www.w3.org/2001/XMLSchema-instance'
CASE='IIP-MD06-a2-idp-01';VARIANTS=['role-keys-sp-first-explicit-a','role-keys-idp-first-explicit-b','role-keys-sp-first-omitted-a','role-keys-idp-first-omitted-b'];FIXTURES=['explicit-a-normal','explicit-a-peer-key','explicit-a-encryption-key','explicit-a-invalid-signature','explicit-b-normal','explicit-b-peer-key','explicit-b-encryption-key','omitted-a-normal','omitted-a-peer-key','omitted-b-normal','omitted-b-peer-key']
SHA=lambda b:hashlib.sha256(b).hexdigest();NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def docker(*args,data=None):return subprocess.run(['docker','exec','-i',CONTAINER,*args],input=data,capture_output=True,check=True,timeout=90).stdout
def variant(fixture):return VARIANTS[0] if fixture.startswith('explicit-a-') else VARIANTS[1] if fixture.startswith('explicit-b-') else VARIANTS[2] if fixture.startswith('omitted-a-') else VARIANTS[3]

def preflight_slots(result,run):
 assert result['run']['id']==run and result['profile']['id']=='metadata-idp','Actual metadata profile required before product mutation'
 slots={c['id']:c for r in result['requirements'] for c in r['cases']}
 assert CASE in slots and 'IIP-MD06-c-idp-01' in slots,'Role and trust cases must both exist in this Run'
 assert result['target']['entity_id'] in {'http://localhost:18280/idp/shibboleth','redacted:internal-target'} and result['target']['metadata_digest'].startswith('sha256:'),'Actual target binding required'
 return slots

def preflight_fixture(raw,entity,v):
 root=E.fromstring(raw);md='urn:oasis:names:tc:SAML:2.0:metadata';ds='http://www.w3.org/2000/09/xmldsig#'
 assert root.tag=='{'+md+'}EntityDescriptor' and root.get('entityID')==entity
 assert len(root.findall('./{'+ds+'}Signature'))==1
 sp=root.findall('./{'+md+'}SPSSODescriptor');idp=root.findall('./{'+md+'}IDPSSODescriptor');assert len(sp)==len(idp)==1
 assert (list(root).index(idp[0])<list(root).index(sp[0]))==('idp-first' in v)
 for role in sp+idp:
  keys=role.findall('./{'+md+'}KeyDescriptor');assert len(keys)==(2 if 'explicit' in v else 1)
  assert [k.get('use','') for k in keys]==(['signing','encryption'] if 'explicit' in v else [''])
  assert all(len(k.findall('.//{'+ds+'}X509Certificate'))==1 for k in keys)
 acs=sp[0].findall('./{'+md+'}AssertionConsumerService[@index="0"]');assert len(acs)==1 and acs[0].get('Binding')=='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' and acs[0].get('Location','').startswith(entity+'/sp/acs/0')

def trust_runtime():
 fmt='{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}},"mounts":{{json .Mounts}}}'
 return json.loads(subprocess.run(['docker','inspect','--format',fmt,CONTAINER],capture_output=True,check=True,timeout=30).stdout)

def collect(output,capture_trust=False,reuse_prepared=None):
 out=pathlib.Path(output).resolve();out.mkdir(parents=True,exist_ok=False);receipt=out/'receipt';receipt.mkdir();original={PROVIDERS:docker('cat',PROVIDERS),AUDIT:docker('cat',AUDIT)};configured={AUDIT:audit_configuration(original[AUDIT]) if capture_trust else signature_audit(original[AUDIT])};audit_changed=configured[AUDIT]!=original[AUDIT];ops=[];changed=[];errors=[];http=[];steps=[];observations=[];credential_posts=0;session_closed=False;run=None;source=None;entity=None;plan=None;selected=0;baseline_completed=False;native_get_attempts=0;native_post_attempts=0;client=MetadataNativeClient(http,receipt);request=client.request
 for path,kind in [(PROVIDERS,'providers'),(AUDIT,'audit')]: (receipt/('original-'+kind+'.xml')).write_bytes(original[path])
 (receipt/'configured-audit.xml').write_bytes(configured[AUDIT])
 def observed(url,fields=None):
  nonlocal credential_posts,native_get_attempts,native_post_attempts
  if fields and ('password' in fields or 'j_password' in fields):
   if session_closed or credential_posts:raise RuntimeError('Shared authentication unavailable; no additional test-user login submitted')
   credential_posts+=1
  if url.startswith('http://localhost:18280/'):
   if fields and 'SAMLRequest' in fields:native_post_attempts+=1
   elif 'SAMLRequest=' in url:native_get_attempts+=1
  return request(url,fields)
 client.request=observed
 def write(path,raw,label):
  item=dict(operation='write',path=path,label=label,recordedAt=NOW(),sha256=SHA(raw),readBack=False);ops.append(item);save(out/'operations.json',ops);docker('sh','-c','cat > '+path,data=raw);assert docker('cat',path)==raw;item['readBack']=True;save(out/'operations.json',ops)
 def reload(label):
  item=dict(operation='reload',label=label,recordedAt=NOW(),completed=False);ops.append(item);save(out/'operations.json',ops);(receipt/(label+'-reload.txt')).write_bytes(docker('/opt/reference-idp/bin/reload-service.sh','-id','shibboleth.MetadataResolverService','-u','http://localhost:8080/idp'));item['completed']=True;save(out/'operations.json',ops)
 def restart(label):
  item=dict(operation='restart',label=label,recordedAt=NOW(),completed=False);ops.append(item);save(out/'operations.json',ops);subprocess.run(['docker','restart',CONTAINER],check=True,capture_output=True,timeout=60);docker('/usr/local/tomcat/bin/catalina.sh','start');limit=time.monotonic()+90
  while time.monotonic()<limit:
   try:
    with urllib.request.urlopen('http://localhost:18280/idp/shibboleth',timeout=3) as r:
     if r.status==200:item['completed']=True;save(out/'operations.json',ops);return
   except Exception:pass
   time.sleep(1)
  raise RuntimeError('Native readiness unavailable')
 def clock(label):
  start=NOW();raw=docker('date','-u','+%Y-%m-%dT%H:%M:%S.%NZ');end=NOW();file=label+'-clock.txt';(receipt/file).write_bytes(raw);record=dict(command=['date','-u','+%Y-%m-%dT%H:%M:%S.%NZ'],clockDomain='native-product-os-UTC',nativeClockFile=file,nativeClockSha256=SHA(raw),nativeInstant=raw.decode().strip(),hostStartedAt=start,hostCompletedAt=end);save(receipt/(label+'-clock.json'),record);return raw.decode().strip(),label+'-clock.json'
 def query(v):
  command=['/opt/reference-idp/bin/mdquery.sh','-u','http://localhost:8080/idp','-e',entity];r=subprocess.run(['docker','exec',CONTAINER,*command],capture_output=True,timeout=40);(receipt/(v+'-metadata-stdout.txt')).write_bytes(r.stdout);(receipt/(v+'-metadata-stderr.txt')).write_bytes(r.stderr);save(receipt/(v+'-metadata-query.json'),dict(command=command,entityId=entity,exitCode=r.returncode,recordedAt=NOW(),stdoutSha256=SHA(r.stdout),stderrSha256=SHA(r.stderr)));assert r.returncode==0,'Native import not accepted; stop before target protocol controls'
 def snapshot(v,phase):
  for path,kind in [(PROVIDERS,'providers'),(AUDIT,'audit')]:raw=docker('cat',path);assert raw==configured[path];(receipt/(v+'-'+phase+'-'+kind+'.xml')).write_bytes(raw)
  raw=docker('cat',source);assert raw==(receipt/(v+'-fixture.xml')).read_bytes();(receipt/(v+'-'+phase+'-source.xml')).write_bytes(raw)
 def export_audit():
  ids={r['requestId'] for r in http};lines=[]
  for line in docker('cat','/opt/reference-idp/logs/idp-audit.log').decode().splitlines():
   if 'SAMLscope-signature-v1|' not in line:continue
   fields=line.split('SAMLscope-signature-v1|',1)[1].split('|')
   if len(fields)==8 and fields[0] in ids:lines.append('SAMLscope-signature-v1|'+'|'.join(fields))
  (receipt/'native-request-bound-audit.log').write_text('\n'.join(lines)+'\n')
 try:
  if reuse_prepared:
   previous=pathlib.Path(reuse_prepared).resolve();cost=json.loads((previous/'operation-counts.json').read_bytes());assert cost['restored'] and all(cost[k]==0 for k in ['productWrites','protocolSubmissions','credentialPosts','productRestarts'])
   for name in ['plan.json','created.json','preflight.json','target-metadata.xml']:(out/name).write_bytes((previous/name).read_bytes())
   plan=json.loads((out/'created.json').read_bytes())['run']['planId'];run=json.loads((out/'created.json').read_bytes())['run']['id'];entity=BASE+'/p/'+plan
   assert api('/api/runs/'+run)['planId']==plan
   for v in VARIANTS:(receipt/(v+'-fixture.xml')).write_bytes((previous/'receipt'/(v+'-fixture.xml')).read_bytes())
   save(out/'suite-only-attempt-reuse.json',dict(previousAttempt=str(previous),runId=run,planId=plan,previousCountsSha256=SHA((previous/'operation-counts.json').read_bytes()),previousRestorationSha256=SHA((previous/'restoration.json').read_bytes()),previousTargetOperations=0,metadataPreparedResubmitted=False,originalsChanged=False))
  else:
   response=api('/api/plans',dict(name='Shibboleth shared-session role and purpose key consumption',profile='metadata_idp',targetKind='IDP',targetEntityId='http://localhost:18280/idp/shibboleth',metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=30,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',response);plan=response['plan']['plan']['id'];entity=BASE+'/p/'+plan;created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
   for v in VARIANTS:
    save(out/(v+'-campaign.json'),api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=[v],pollingDelaySeconds=0)));state=api('/api/runs/'+run+'/metadata-lab')
    with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as r:assert r.status==202
    with urllib.request.urlopen(state['metadataUrl'],timeout=30) as r:raw=r.read()
    (receipt/(v+'-fixture.xml')).write_bytes(raw)
  source='/opt/reference-idp/metadata/role-keys-'+run+'.xml';assert not docker('sh','-c','test -e '+source+' && echo exists || true').strip()
  if capture_trust:
   assert json.loads((out/'plan.json').read_bytes())['plan']['plan'].get('profile')=='metadata_idp' and api('/api/runs/'+run)['planId']==plan
   apiJar=REPO/'api/build/install/samlscope/lib/api-0.1.0.jar';nativeSha=subprocess.run(['docker','exec','samlscope-reference-suite','sha256sum','/opt/samlscope/lib/api-0.1.0.jar'],check=True,capture_output=True,timeout=30).stdout.decode().split()[0];assert SHA(apiJar.read_bytes())==nativeSha
   with zipfile.ZipFile(apiJar) as z:profileRaw=z.read('profiles/metadata_idp.json')
   assert profileRaw==(REPO/'profiles/metadata_idp.json').read_bytes();profile=json.loads(profileRaw);assert profile['profile']=='metadata_idp' and {CASE,'IIP-MD06-c-idp-01'}<={c['id'] for c in profile['cases']}
   save(out/'planned-case-scope.json',dict(runId=run,planId=plan,profile='metadata_idp',runtimeApiJarSha256=nativeSha,profileArtifactSha256=SHA(profileRaw),plannedCaseIds=[CASE,'IIP-MD06-c-idp-01'],actualExecutionSlotsCreated=False));(out/'approved-profile.json').write_bytes(profileRaw)
   subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],capture_output=True,check=True,timeout=30)
   assert E.fromstring((out/'target-metadata.xml').read_bytes()).get('entityID')=='http://localhost:18280/idp/shibboleth'
   for v in VARIANTS:preflight_fixture((receipt/(v+'-fixture.xml')).read_bytes(),entity,v)
  if audit_changed:
   changed.append(AUDIT);write(AUDIT,configured[AUDIT],'prepare-audit');restart('prepare-native-audit')
  baseline(run,out/'initial-baseline',client=client);baseline_completed=True;assert credential_posts==1;session_closed=True
  (receipt/'baseline-fixture.xml').write_bytes((out/'initial-baseline/fixture.xml').read_bytes());b=json.loads((out/'initial-baseline/baseline-proof.json').read_bytes());save(receipt/'baseline.json',dict(runId=run,protocolSubmissions=1,credentialPosts=credential_posts,outboundReferences=[b['requestReference']],responseReference=b['responseReference']))
  if capture_trust:save(receipt/'trust-runtime-protocol-start.json',trust_runtime())
  E.register_namespace('',NS);E.register_namespace('xsi',XSI);root=E.fromstring(original[PROVIDERS]);root.insert(0,E.Element('{'+NS+'}MetadataProvider',dict(id='RoleKeys'+run,**{'{'+XSI+'}type':'FilesystemMetadataProvider','metadataFile':source})));configured[PROVIDERS]=E.tostring(root);(receipt/'configured-providers.xml').write_bytes(configured[PROVIDERS]);capture_target(receipt,'shibboleth','start');inventory=[]
  for i,n in enumerate(E.fromstring(original[PROVIDERS]).iter('{'+NS+'}MetadataProvider')):
   if n.get('metadataFile') is None:continue
   path=n.get('metadataFile').replace('%{idp.home}','/opt/reference-idp');raw=docker('cat',path);file='other-provider-'+str(i)+'.xml';(receipt/file).write_bytes(raw);inventory.append(dict(path=path,file=file,sha256=SHA(raw)))
  save(receipt/'other-provider-inventory.json',inventory);save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));current=None;epoch=None
  if capture_trust:
   preflight=api('/api/runs/'+run+'/result.json');preflight_slots(preflight,run);save(out/'case-slot-preflight.json',preflight);assert preflight['target']['metadata_digest']=='sha256:'+SHA((out/'target-metadata.xml').read_bytes())
  for _ in range(400):
   status=api('/api/runs/'+run+'/active-probe')
   if selected==len(FIXTURES):break
   if status['state']=='AWAITING_RESPONSE':
    api('/api/runs/'+run+'/active-probe/abort',{});steps.append(dict(caseId=status.get('caseId'),actionId=status.get('actionId'),action='abort-before-new-operation'));save(out/'steps.json',steps);continue
   if status['state']!='READY':raise RuntimeError('Role-key outbox not ready: '+status['state'])
   if status.get('caseId')!=CASE:steps.append(prepare_and_skip(BASE,run,status,api));save(out/'steps.json',steps);continue
   fixture=FIXTURES[selected];v=variant(fixture)
   if v!=current:
    if epoch is not None:
     snapshot(current,'after')
     if capture_trust:trust_scope.capture(receipt,current+'-after',entity)
     epoch['completedAt']=NOW();observations.append(epoch);save(out/'observations.json',observations)
    epoch=dict(variant=v,startedAt=NOW(),exchanges=[]);write(source,(receipt/(v+'-fixture.xml')).read_bytes(),'fixture-'+v)
    if current is None:changed.append(PROVIDERS);write(PROVIDERS,configured[PROVIDERS],'prepare-provider')
    reload(v);snapshot(v,'before');query(v)
    if capture_trust:trust_scope.capture(receipt,v+'-before',entity)
    entries=api('/api/runs/'+run+'/transcript');prepared=[e for e in entries if e['samlSummary'].get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==v];assert len(prepared)==1;epoch['preparedReference']=prepared[0]['id'];epoch['fetchReference']=prepared[0]['samlSummary']['fetchTranscriptId'];current=v
   begin,clock_before=clock(fixture+'-before');old={e['id'] for e in api('/api/runs/'+run+'/transcript')};index=len(http);result=client.flow(status['startUrl'],None,os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'));end,clock_after=clock(fixture+'-after');entries=api('/api/runs/'+run+'/transcript');issued=[e for e in entries if e['id'] not in old and e['direction']=='OUTBOUND' and e['samlSummary'].get('scenario_case_id')==CASE and e['samlSummary'].get('fixture_id')==fixture];assert len(issued)==1 and len(http)-index==1,'One prepared outbox request must produce one actual target submission';rid=http[index]['requestId'];matches=[e for e in entries if e['direction']=='INBOUND' and e['samlSummary'].get('inResponseTo')==rid];assert len(matches)<=1;exchange=dict(fixtureId=fixture,requestReference=issued[0]['id'],responseReference=matches[0]['id'] if matches else None,nativeHttp=http[index:],nativeBegin=begin,nativeEnd=end,clockBeforeFile=clock_before,clockAfterFile=clock_after);epoch['exchanges'].append(exchange);save(receipt/(fixture+'-exchange.json'),exchange);steps.append(dict(caseId=CASE,fixtureId=fixture,actionId=status['actionId'],requestReference=issued[0]['id'],receipt=result,prepared=True,sentToTarget=True,reusedAuthenticatedClient=True,freshSessionRequired=False));save(out/'steps.json',steps);selected+=1
   if fixture.endswith('normal'):assert len(matches)==1,'Normal control failed; do not request extra logins'
   after=api('/api/runs/'+run+'/active-probe')
   if after['state']=='AWAITING_RESPONSE' and after.get('actionId')==status['actionId']:api('/api/runs/'+run+'/active-probe/abort',{})
  assert selected==len(FIXTURES);snapshot(current,'after')
  if capture_trust:trust_scope.capture(receipt,current+'-after',entity);save(receipt/'trust-runtime-protocol-end.json',trust_runtime())
  epoch['completedAt']=NOW();observations.append(epoch);save(out/'observations.json',observations);export_audit();capture_target(receipt,'shibboleth','end')
  for item in inventory:assert SHA(docker('cat',item['path']))==item['sha256']
  save(receipt/'other-provider-final-readback.json',inventory)
 finally:
  for path in reversed(changed):
   try:assert docker('cat',path)==configured[path];write(path,original[path],'restore-'+path.rsplit('/',1)[-1])
   except Exception as error:errors.append(type(error).__name__)
  if not errors and changed:
   try:
    if audit_changed:restart('restore-native-settings')
    else:reload('restore-native-settings')
   except Exception as error:errors.append(type(error).__name__)
  if source and not errors:docker('rm','-f','--',source)
  for path,kind in [(PROVIDERS,'providers'),(AUDIT,'audit')]: (receipt/('final-'+kind+'.xml')).write_bytes(docker('cat',path))
  restored=not errors and all(docker('cat',path)==raw for path,raw in original.items());save(out/'restoration.json',dict(restored=restored,errors=errors,original={p:SHA(v) for p,v in original.items()},final={p:SHA(docker('cat',p)) for p in original}));save(out/'operation-counts.json',dict(restored=restored,personOperations=0,credentialPosts=credential_posts,productWrites=sum(o['operation']=='write' for o in ops),restorationWrites=sum(o['operation']=='write' and o['label'].startswith('restore-') for o in ops),productRestarts=sum(o['operation']=='restart' for o in ops),metadataReloads=sum(o['operation']=='reload' for o in ops),roleKeyTargetSubmissions=len(http),ordinaryBaselineSubmissions=int(baseline_completed),protocolSubmissions=native_get_attempts+native_post_attempts,recorderQualifiedProtocolSubmissions=native_post_attempts+max(native_get_attempts,int(baseline_completed)),protocolCounterSource='explicit-native-wrapper-attempts',nativeGetAttempts=native_get_attempts,nativePostAttempts=native_post_attempts,completedRoleResponses=len(http),auditChanged=audit_changed,preparedSuiteActions=sum(s.get('prepared') is True for s in steps),skippedBeforeTargetSubmission=sum(s.get('sentToTarget') is False for s in steps),sameAuthenticatedClient=True,additionalLoginBlocked=True))
  if capture_trust:save(receipt/'trust-runtime-final.json',trust_runtime())
  baseline_cost=json.loads((out/'initial-baseline/operation-counts.json').read_bytes()) if (out/'initial-baseline/operation-counts.json').exists() else dict(productConfigurationWrites=0,metadataReloads=0,productRestarts=0)
  totals=json.loads((out/'operation-counts.json').read_bytes());save(out/'cumulative-operation-counts.json',dict(protocolSubmissions=totals.get('recorderQualifiedProtocolSubmissions',totals['protocolSubmissions']),credentialPosts=credential_posts,nativeConfigurationWrites=totals['productWrites']+baseline_cost['productConfigurationWrites'],restorationWrites=totals['restorationWrites']+int(any(x.get('label')=='restore-provider' for x in json.loads((out/'initial-baseline/operations.json').read_bytes()))) if (out/'initial-baseline/operations.json').exists() else totals['restorationWrites'],metadataReloads=totals['metadataReloads']+baseline_cost['metadataReloads'],productRestarts=totals['productRestarts']+baseline_cost['productRestarts'],personOperations=0,baselineAndRoleCredentialCounterShared=True,failedAttemptsIncluded=True))
  if run:
   entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
   try:save(out/'result.json',api('/api/runs/'+run+'/result.json'))
   except Exception as error:save(out/'result-pending.json',dict(errorType=type(error).__name__))
  if not restored:raise RuntimeError('Native restoration incomplete')
 if errors:raise RuntimeError('Native collection failed')
 if capture_trust:
  for name,source_file in [('trust-product-operations.json','operations.json'),('trust-product-counts.json','operation-counts.json'),('trust-cumulative-counts.json','cumulative-operation-counts.json'),('trust-product-restoration.json','restoration.json')]: (receipt/name).write_bytes((out/source_file).read_bytes())
 originals={p.name:SHA(p.read_bytes()) for p in receipt.iterdir() if p.is_file() and p.name!='manifest.json'};manifest=dict(schema='samlscope-metadata-role-key-consumption-v1',adapter='shibboleth-native-filesystem-role-keys-v1',runId=run,entityId=entity,targetMetadataSha256=SHA((out/'target-metadata.xml').read_bytes()),sourcePath=source,observations=observations,originals=originals);save(receipt/'manifest.json',manifest);print(run,'all role-key outbox controls collected; native configuration exactly restored',flush=True)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--capture-trust',action='store_true');a=p.parse_args();collect(a.output,a.capture_trust)
if __name__=='__main__':main()
