#!/usr/bin/env python3
"""Consume five certificate fixtures with one shared login and six Suite outbox controls."""
import argparse,datetime,hashlib,json,os,pathlib,re,subprocess,sys,time,urllib.request,importlib.util,shutil,xml.etree.ElementTree as E
REPO=pathlib.Path(__file__).resolve().parents[2];sys.path[:0]=[str(REPO/'dev/shibboleth'),str(REPO/'dev/keycloak'),str(REPO/'dev/reference-acceptance')]
_spec=importlib.util.spec_from_file_location("certificate_runtime_suite_api",REPO/"dev/keycloak/import_metadata_batch.py");_suite=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_suite)
api,save,BASE=_suite.api,_suite.save,_suite.BASE
from metadata_native_observation import MetadataNativeClient
from metadata_validity_baseline_recovery import complete as baseline
from signature_audit_format import signature_audit
from public_runtime_capture import capture_target
from metadata_certificate_trust_scope import capture as capture_trust
from capture_run_originals import capture
from browser_probe_selection import prepare_and_skip
CONTAINER='samlscope-reference-shibboleth';PROVIDERS='/opt/reference-idp/conf/metadata-providers.xml';AUDIT='/opt/reference-idp/conf/audit.xml';NS='urn:mace:shibboleth:2.0:metadata';XSI='http://www.w3.org/2001/XMLSchema-instance'
CASE='IIP-MD06-a6-idp-01';VARIANTS=['control','certificate-critical-extension','certificate-unknown-ca','certificate-revoked','certificate-revocation-unreachable'];FIXTURES=['control-normal','control-invalid-signature','certificate-critical-extension-normal','certificate-unknown-ca-normal','certificate-revoked-normal','certificate-revocation-unreachable-normal']
SHA=lambda b:hashlib.sha256(b).hexdigest();NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def docker(*args,data=None):return subprocess.run(['docker','exec','-i',CONTAINER,*args],input=data,capture_output=True,check=True,timeout=90).stdout
def variant(fixture):return 'control' if fixture=='control-invalid-signature' else fixture.removesuffix('-normal')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);receipt=out/'receipt';receipt.mkdir();original={PROVIDERS:docker('cat',PROVIDERS),AUDIT:docker('cat',AUDIT)};configured={AUDIT:signature_audit(original[AUDIT])};ops=[];changed=[];errors=[];http=[];steps=[];observations=[];credential_posts=0;session_closed=False;run=None;source=None;entity=None;plan=None;selected=0;native_queries=0;native_clocks=0;native_network_probes=0;native_profile_reads=0;client=MetadataNativeClient(http,receipt);request=client.request
 for path,kind in [(PROVIDERS,'providers'),(AUDIT,'audit')]: (receipt/('original-'+kind+'.xml')).write_bytes(original[path])
 (receipt/'configured-audit.xml').write_bytes(configured[AUDIT])
 def observed(url,fields=None):
  nonlocal credential_posts
  if fields and ('password' in fields or 'j_password' in fields):
   if session_closed:raise RuntimeError('Shared authentication unavailable; no additional test-user login submitted')
   credential_posts+=1
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
  nonlocal native_clocks
  native_clocks+=1
  start=NOW();raw=docker('date','-u','+%Y-%m-%dT%H:%M:%S.%NZ');end=NOW();file=label+'-clock.txt';(receipt/file).write_bytes(raw);record=dict(command=['date','-u','+%Y-%m-%dT%H:%M:%S.%NZ'],clockDomain='native-product-os-UTC',nativeClockFile=file,nativeClockSha256=SHA(raw),nativeInstant=raw.decode().strip(),hostStartedAt=start,hostCompletedAt=end);save(receipt/(label+'-clock.json'),record);return raw.decode().strip(),label+'-clock.json'
 def query(v):
  nonlocal native_queries
  native_queries+=1
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
  changed.append(AUDIT);write(AUDIT,configured[AUDIT],'prepare-audit');restart('prepare-native-audit')
  response=api('/api/plans',dict(name='Shibboleth shared-session metadata certificate runtime use',profile='metadata_idp',targetKind='IDP',targetEntityId='http://localhost:18280/idp/shibboleth',metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=30,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',response);plan=response['plan']['plan']['id'];entity=BASE+'/p/'+plan;created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));source='/opt/reference-idp/metadata/certificate-runtime-'+run+'.xml';assert not docker('sh','-c','test -e '+source+' && echo exists || true').strip()
  baseline(run,out/'initial-baseline',client=client);assert credential_posts==1;session_closed=True
  for v in VARIANTS:
   save(out/(v+'-campaign.json'),api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=[v],pollingDelaySeconds=0)));state=api('/api/runs/'+run+'/metadata-lab')
   with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as r:assert r.status==202
   with urllib.request.urlopen(state['metadataUrl'],timeout=30) as r:raw=r.read()
   (receipt/(v+'-fixture.xml')).write_bytes(raw)
  E.register_namespace('',NS);E.register_namespace('xsi',XSI);root=E.fromstring(original[PROVIDERS]);root.insert(0,E.Element('{'+NS+'}MetadataProvider',dict(id='CertificateRuntime'+run,**{'{'+XSI+'}type':'FilesystemMetadataProvider','metadataFile':source})));configured[PROVIDERS]=E.tostring(root);(receipt/'configured-providers.xml').write_bytes(configured[PROVIDERS]);capture_target(receipt,'shibboleth','start');inventory=[]
  for i,n in enumerate(E.fromstring(original[PROVIDERS]).iter('{'+NS+'}MetadataProvider')):
   if n.get('metadataFile') is None:continue
   path=n.get('metadataFile').replace('%{idp.home}','/opt/reference-idp');raw=docker('cat',path);file='other-provider-'+str(i)+'.xml';(receipt/file).write_bytes(raw);inventory.append(dict(path=path,file=file,sha256=SHA(raw)))
  save(receipt/'other-provider-inventory.json',inventory);save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));current=None;epoch=None
  for _ in range(400):
   status=api('/api/runs/'+run+'/active-probe')
   if selected==len(FIXTURES):break
   if status['state']=='AWAITING_RESPONSE':
    api('/api/runs/'+run+'/active-probe/abort',{});steps.append(dict(caseId=status.get('caseId'),actionId=status.get('actionId'),action='abort-before-new-operation'));save(out/'steps.json',steps);continue
   if status['state']!='READY':raise RuntimeError('Certificate outbox not ready: '+status['state'])
   if status.get('caseId')!=CASE:steps.append(prepare_and_skip(BASE,run,status,api));save(out/'steps.json',steps);continue
   fixture=FIXTURES[selected];v=variant(fixture)
   if v!=current:
    if epoch is not None:snapshot(current,'after');epoch['completedAt']=NOW();observations.append(epoch);save(out/'observations.json',observations)
    epoch=dict(variant=v,startedAt=NOW(),exchanges=[]);write(source,(receipt/(v+'-fixture.xml')).read_bytes(),'fixture-'+v)
    if current is None:changed.append(PROVIDERS);write(PROVIDERS,configured[PROVIDERS],'prepare-provider')
    reload(v);snapshot(v,'before');query(v);entries=api('/api/runs/'+run+'/transcript');prepared=[e for e in entries if e['samlSummary'].get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==v];assert len(prepared)==1;epoch['preparedReference']=prepared[0]['id'];epoch['fetchReference']=prepared[0]['samlSummary']['fetchTranscriptId'];current=v
    if v=='control':capture_trust(receipt,'before',entity);native_profile_reads+=1
    if v=='certificate-revocation-unreachable':
     serial=E.fromstring((receipt/(v+'-fixture.xml')).read_bytes()).find('.//{urn:samlscope:test:certificate-revocation}RevocationOriginals');raw=(receipt/(v+'-fixture.xml')).read_bytes();urls=sorted(set(re.findall(rb'http://samlscope-reference-suite:18481/[^<\s]+',raw)))
     # URLs are DER extension values, not XML text. Decode the public certificate locally.
     from cryptography import x509
     import base64
     certnode=E.fromstring(raw).find('.//{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor').find('.//{http://www.w3.org/2000/09/xmldsig#}X509Certificate');cert=x509.load_der_x509_certificate(base64.b64decode(certnode.text));prefix='http://samlscope-reference-suite:18481/samlscope-revocation/'+format(cert.serial_number,'x');network=[]
     for suffix in ['.crl','.ocsp']:
      native_network_probes+=1;url=prefix+'/unavailable'+suffix;command=['curl','--noproxy','*','--connect-timeout','1','--max-time','2','--silent',url];started=NOW();r=subprocess.run(['docker','exec',CONTAINER,*command],capture_output=True,timeout=10);finished=NOW();stdout='unreachable'+suffix+'-stdout.txt';stderr='unreachable'+suffix+'-stderr.txt';(receipt/stdout).write_bytes(r.stdout);(receipt/stderr).write_bytes(r.stderr);network.append(dict(url=url,command=command,source='native-target-network',exitCode=r.returncode,startedAt=started,completedAt=finished,stdoutFile=stdout,stdoutSha256=SHA(r.stdout),stderrFile=stderr,stderrSha256=SHA(r.stderr)));assert r.returncode==7,'Revocation endpoint must be explicitly refused from target network'
     save(receipt/'certificate-revocation-unreachable-network.json',network)
   begin,clock_before=clock(fixture+'-before');old={e['id'] for e in api('/api/runs/'+run+'/transcript')};index=len(http);result=client.flow(status['startUrl'],None,os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'));end,clock_after=clock(fixture+'-after');entries=api('/api/runs/'+run+'/transcript');issued=[e for e in entries if e['id'] not in old and e['direction']=='OUTBOUND' and e['samlSummary'].get('scenario_case_id')==CASE and e['samlSummary'].get('fixture_id')==fixture];assert len(issued)==1 and len(http)-index==1,'One prepared outbox request must produce one actual target submission';rid=http[index]['requestId'];matches=[e for e in entries if e['direction']=='INBOUND' and e['samlSummary'].get('inResponseTo')==rid];assert len(matches)<=1;exchange=dict(fixtureId=fixture,requestReference=issued[0]['id'],responseReference=matches[0]['id'] if matches else None,nativeHttp=http[index:],nativeBegin=begin,nativeEnd=end,clockBeforeFile=clock_before,clockAfterFile=clock_after);epoch['exchanges'].append(exchange);save(receipt/(fixture+'-exchange.json'),exchange);steps.append(dict(caseId=CASE,fixtureId=fixture,actionId=status['actionId'],requestReference=issued[0]['id'],receipt=result,prepared=True,sentToTarget=True,reusedAuthenticatedClient=True,freshSessionRequired=False));save(out/'steps.json',steps);selected+=1
   if fixture.endswith('normal'):assert len(matches)==1,'Normal control failed; do not request extra logins'
   after=api('/api/runs/'+run+'/active-probe')
   if after['state']=='AWAITING_RESPONSE' and after.get('actionId')==status['actionId']:api('/api/runs/'+run+'/active-probe/abort',{})
  assert selected==len(FIXTURES);snapshot(current,'after');epoch['completedAt']=NOW();observations.append(epoch);save(out/'observations.json',observations);export_audit();capture_trust(receipt,'after',entity);native_profile_reads+=1;capture_target(receipt,'shibboleth','end')
  for item in inventory:assert SHA(docker('cat',item['path']))==item['sha256']
  save(receipt/'other-provider-final-readback.json',inventory)
 finally:
  for path in reversed(changed):
   try:assert docker('cat',path)==configured[path];write(path,original[path],'restore-'+path.rsplit('/',1)[-1])
   except Exception as error:errors.append(type(error).__name__)
  if not errors and changed:
   try:restart('restore-native-settings')
   except Exception as error:errors.append(type(error).__name__)
  if source and not errors:docker('rm','-f','--',source)
  for path,kind in [(PROVIDERS,'providers'),(AUDIT,'audit')]: (receipt/('final-'+kind+'.xml')).write_bytes(docker('cat',path))
  restored=not errors and all(docker('cat',path)==raw for path,raw in original.items());save(out/'restoration.json',dict(restored=restored,errors=errors,original={p:SHA(v) for p,v in original.items()},final={p:SHA(docker('cat',p)) for p in original}));save(out/'operation-counts.json',dict(restored=restored,personOperations=0,credentialPosts=credential_posts,productWrites=sum(o['operation']=='write' for o in ops),restorationWrites=sum(o['operation']=='write' and o['label'].startswith('restore-') for o in ops),productRestarts=sum(o['operation']=='restart' for o in ops),metadataReloads=sum(o['operation']=='reload' for o in ops),certificateTargetSubmissions=len(http),ordinaryBaselineSubmissions=1,protocolSubmissions=len(http)+1,preparedSuiteActions=sum(s.get('prepared') is True for s in steps),skippedBeforeTargetSubmission=sum(s.get('sentToTarget') is False for s in steps),sameAuthenticatedClient=True,additionalLoginBlocked=True))
  if run:
   entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
   try:save(out/'result.json',api('/api/runs/'+run+'/result.json'))
   except Exception as error:save(out/'result-pending.json',dict(errorType=type(error).__name__))
  if not restored:raise RuntimeError('Native restoration incomplete')
  with urllib.request.urlopen('http://localhost:18280/idp/shibboleth',timeout=5) as readiness:save(receipt/'restored-native-readiness.json',dict(status=readiness.status,url='http://localhost:18280/idp/shibboleth',recordedAt=NOW(),credentialsPersisted=False))
 if errors:raise RuntimeError('Native collection failed')
 save(out/'native-readonly-operation-counts.json',dict(nativeMetadataQueries=native_queries,nativeClockQueries=native_clocks,nativeNetworkProbes=native_network_probes,nativeEffectiveProfileReads=native_profile_reads,includesReadOnlyDiagnostics=True,notProductSettingWrites=True,notProtocolSubmissions=True))
 main_counts=json.loads((out/'operation-counts.json').read_bytes());baseline_counts=json.loads((out/'initial-baseline/operation-counts-reconciled.json').read_bytes());baseline_ops=json.loads((out/'initial-baseline/operations.json').read_bytes());sources=['operation-counts.json','operations.json','initial-baseline/operation-counts-reconciled.json','initial-baseline/operations.json'];save(out/'cumulative-operation-audit.json',dict(schema='samlscope-certificate-runtime-cumulative-operations-v1',credentialCountsAreSharedObservationNotAdditive=True,cumulative=dict(productConfigurationWrites=main_counts['productWrites']+baseline_counts['productConfigurationWrites'],metadataReloads=main_counts['metadataReloads']+baseline_counts['metadataReloads'],productRestarts=main_counts['productRestarts']+baseline_counts['productRestarts'],credentialPosts=credential_posts,protocolSubmissions=main_counts['protocolSubmissions'],restorationWrites=main_counts['restorationWrites']+sum(o['operation']=='write' and o['label'].startswith('restore-') for o in baseline_ops),personOperations=0,restored=main_counts['restored']),sources={name:SHA((out/name).read_bytes()) for name in sources}))
 command=['docker','inspect','--format','{"Id":{{json .Id}},"Image":{{json .Image}},"Mounts":{{json .Mounts}}}',CONTAINER];started=NOW();raw=subprocess.run(command,capture_output=True,check=True,timeout=30).stdout;completed=NOW();native=json.loads(raw);assert native['Mounts']==[] and native['Id']==json.loads((receipt/'target-container-inspect-start.json').read_bytes())[0]['Id'];file='target-container-mounts-native-original.json';(receipt/file).write_bytes(raw);save(receipt/'target-container-mounts-capture.json',dict(schema='samlscope-immutable-container-mounts-capture-v1',source='native-docker-inspect-readback',command=command,hostStartedAt=started,hostCompletedAt=completed,originalFile=file,originalSha256=SHA(raw),capturedAfterNativeSettingsRestoration=True,productConfigurationWrites=0,protocolSubmissions=0,credentialPosts=0))
 for name in ['created.json','restoration.json','operation-counts.json','operations.json']:shutil.copy2(out/name,receipt/name)
 for old,new in [('baseline-proof.json','baseline-proof.json'),('fixture.xml','baseline-fixture.xml'),('restoration.json','baseline-restoration.json'),('operation-counts-reconciled.json','baseline-operation-counts.json'),('original-providers.xml','baseline-original-providers.xml'),('final-providers.xml','baseline-final-providers.xml')]:shutil.copy2(out/'initial-baseline'/old,receipt/new)
 originals={p.name:SHA(p.read_bytes()) for p in receipt.iterdir() if p.is_file() and p.name!='manifest.json'};manifest=dict(schema='samlscope-metadata-certificate-runtime-v1',adapter='shibboleth-native-filesystem-certificate-runtime-v1',runId=run,entityId=entity,targetMetadataSha256=SHA((out/'target-metadata.xml').read_bytes()),sourcePath=source,observations=observations,originals=originals);save(receipt/'manifest.json',manifest);print(run,'all certificate outbox controls collected; native configuration exactly restored',flush=True)
if __name__=='__main__':main()
