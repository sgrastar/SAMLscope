#!/usr/bin/env python3
"""Stock default ALG08.c native consumer campaign; one initial login, then six recorded outboxes.

No algorithm configuration is changed. Public registration and audit instrumentation are restored
byte-for-byte in finally. A missing native preparation/case slot stops before any credential.
"""
import argparse,base64,datetime,hashlib,importlib.util,json,os,pathlib,re,shutil,subprocess,sys,tempfile,time,urllib.parse,urllib.request,xml.etree.ElementTree as ET
REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'dev/shibboleth'),str(REPO/'dev/keycloak'),str(REPO/'dev/reference-acceptance')]
_spec=importlib.util.spec_from_file_location('default_algorithm_api',REPO/'dev/keycloak/import_metadata_batch.py');_api=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_api)
api,save,BASE=_api.api,_api.save,_api.BASE
from reference_flow import Client,parse_forms
from metadata_validity_baseline_recovery import complete as complete_baseline
from default_algorithm_policy_scope import Capture
from capture_run_originals import capture
from browser_probe_selection import prepare_and_skip
from default_algorithm_transcript import correlate_exchange
from default_algorithm_terminal_guard import require_unfinished
from default_algorithm_audit_capture import capture as capture_audit
from capture_stock_unmarshaller import SOURCE as STOCK_DECODER_SOURCE,SOURCE_SHA as STOCK_DECODER_SOURCE_SHA
from capture_default_algorithm_calibration import SOURCE as CALIBRATION_SOURCE,SOURCE_SHA as CALIBRATION_SOURCE_SHA
from default_algorithm_logout_continuation import continuation as logout_continuation
from default_algorithm_logout_continuation import public_response_identity
from default_algorithm_response_payload import redirect_response
CONTAINER='samlscope-reference-shibboleth';SUITE='samlscope-reference-suite'
PROVIDERS='/opt/reference-idp/conf/metadata-providers.xml';AUDIT='/opt/reference-idp/conf/audit.xml';LOGBACK='/opt/reference-idp/conf/logback.xml'
P='urn:oasis:names:tc:SAML:2.0:protocol';MD='urn:oasis:names:tc:SAML:2.0:metadata';N='urn:mace:shibboleth:2.0:metadata';XSI='http://www.w3.org/2001/XMLSchema-instance'
CASE='IIP-ALG08-c-idp-01';CAMPAIGN='default-algorithm-prevention';SCHEMA='samlscope-default-algorithm-prevention-v1';ADAPTER='shibboleth-native-default-algorithm-consumers-v1'
FORMAT='SAMLscope-default-algorithm-v1|%I|%SP|%e|%S|%XX|%b|%P|%T|%n|%f|%SPQ|%x'
FIXTURES=['sha256-control','invalid-sha256-signature','md5-digest','rsa-md5','rsa15-encrypted-id','oaep-encrypted-id-control']
SHA=lambda b:hashlib.sha256(b).hexdigest();NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')

def require(value,reason):
 if not value:raise ValueError(reason)

def docker(*args,data=None,timeout=90):return subprocess.run(['docker','exec','-i',CONTAINER,*args],input=data,capture_output=True,check=True,timeout=timeout).stdout

def public_terminal(page):return len(page.encode())<=262144 and re.search(r'<\s*input\b|SAMLResponse|SAMLRequest|Authorization\s*:|Cookie\s*:|csrf',page,re.I) is None

def install_public_preparation(folder,prep_file,run):
 """Stage readable byte copies; never chmod/hardlink immutable collection originals."""
 destination='/data/default-algorithm-evidence/'+run+'.preparation'
 with tempfile.TemporaryDirectory(prefix='default-public-preparation-') as temporary:
  staged=pathlib.Path(temporary)/'public';staged.mkdir(mode=0o755)
  for source in folder.iterdir():
   require(source.is_file() and not source.is_symlink(),'Preparation must be flat public originals')
   copied=staged/source.name;copied.write_bytes(source.read_bytes());copied.chmod(0o644)
  sidecar=pathlib.Path(temporary)/prep_file.name;sidecar.write_bytes(prep_file.read_bytes());sidecar.chmod(0o644)
  subprocess.run(['docker','exec',SUITE,'mkdir','-p',destination],capture_output=True,check=True,timeout=30)
  subprocess.run(['docker','cp',str(staged)+'/.',SUITE+':'+destination],capture_output=True,check=True,timeout=60)
  subprocess.run(['docker','cp',str(sidecar),SUITE+':/data/default-algorithm-evidence/'+sidecar.name],capture_output=True,check=True,timeout=30)
  for name,digest in {**{p.name:SHA(p.read_bytes()) for p in staged.iterdir()},'../'+sidecar.name:SHA(sidecar.read_bytes())}.items():
   got=subprocess.run(['docker','exec',SUITE,'sha256sum',destination+'/'+name],capture_output=True,check=True,timeout=20).stdout.decode().split()[0]
   require(got==digest,'Suite user cannot read identical public preparation')

def audit_configuration(raw):
 root=ET.fromstring(raw);entries=[e for e in root.iter('{http://www.springframework.org/schema/beans}entry') if e.get('key')=='Shibboleth-Audit'];require(len(entries)==1,'Native audit map ambiguous');entries[0].set('value',FORMAT);return ET.tostring(root)

def logback_configuration(raw):
 text=raw.decode();old='%date{ISO8601} - %mdc{idp.remote_addr} - %level [%logger:%line] - %msg%n'
 audit_patterns=[tag for tag in ['pattern','Pattern'] if '<'+tag+'>%msg%n</'+tag+'>' in text]
 require(old in text and len(audit_patterns)==1,'Unsupported stock logging instrumentation')
 tag=audit_patterns[0]
 return text.replace(old,'%date{ISO8601,UTC} - %mdc{idp.remote_addr} - %level [%thread] [%logger:%line] - %msg%n').replace('<'+tag+'>%msg%n</'+tag+'>','<'+tag+'>%msg|%thread%n</'+tag+'>').replace('%ex{short}','%ex{full}').encode()

def planned_slot(run,output,diagnostics):
 """Resolve the real Plan release read-only; the public result does not exist before M0."""
 source=REPO/'dev/reference-acceptance/ReadDefaultAlgorithmPlannedSlot.java';remote='/tmp/default-algorithm-planned-slot-'+run
 require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run),'Unsafe planned-slot Run')
 started=NOW()
 with tempfile.TemporaryDirectory(prefix='default-planned-slot-') as temporary:
  classes=pathlib.Path(temporary)/'classes';classes.mkdir();classpath=str(REPO/'api/build/install/samlscope/lib/*')
  subprocess.run([str(pathlib.Path(os.environ.get('JAVA_HOME','/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home'))/'bin/javac'),'-cp',classpath,'-d',str(classes),str(source)],capture_output=True,check=True,timeout=30)
  subprocess.run(['docker','exec','-u','0',SUITE,'mkdir',remote],capture_output=True,check=True,timeout=20)
  try:
   subprocess.run(['docker','cp',str(classes),SUITE+':'+remote+'/classes'],capture_output=True,check=True,timeout=20)
   command=['docker','exec',SUITE,'java','-cp',remote+'/classes:/opt/samlscope/lib/*','com.samlscope.api.ReadDefaultAlgorithmPlannedSlot','/data',run]
   result=subprocess.run(command,capture_output=True,check=True,timeout=30);value=json.loads(result.stdout)
   require(value['runId']==run and value['caseId']==CASE and value['profile']=='browser_sso_idp' and value['mode']=='ATTESTED'
           and value['role']=='IDP' and value['scopeOnly'] is True and value['caseStarted'] is False,'Actual approved planned slot mismatch')
   (output/'planned-slot-before-login.json').write_bytes(result.stdout)
  finally:subprocess.run(['docker','exec','-u','0',SUITE,'rm','-rf','--',remote],capture_output=True,check=True,timeout=20)
 diagnostics.append(dict(operation='suite-planned-slot-read-only',startedAt=started,completedAt=NOW(),sourceSha256=SHA(source.read_bytes()),suiteJavaCalls=1,hostCompilerCalls=1,productSettings=0,protocolSubmissions=0,credentialPosts=0))
 return value

def native_preparation_preflight(run,output,diagnostics):
 """Call the installed production reader before the one allowed initial login."""
 source=REPO/'dev/reference-acceptance/ReadDefaultAlgorithmPreparation.java';remote='/tmp/default-native-preparation-'+run;started=NOW()
 with tempfile.TemporaryDirectory(prefix='default-native-preparation-') as temporary:
  classes=pathlib.Path(temporary)/'classes';classes.mkdir();classpath=str(REPO/'api/build/install/samlscope/lib/*')
  subprocess.run([str(pathlib.Path(os.environ.get('JAVA_HOME','/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home'))/'bin/javac'),'-cp',classpath,'-d',str(classes),str(source)],capture_output=True,check=True,timeout=30)
  subprocess.run(['docker','exec','-u','0',SUITE,'mkdir',remote],capture_output=True,check=True,timeout=20)
  try:
   subprocess.run(['docker','cp',str(classes),SUITE+':'+remote+'/classes'],capture_output=True,check=True,timeout=20)
   result=subprocess.run(['docker','exec',SUITE,'java','-cp',remote+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.ReadDefaultAlgorithmPreparation',run],capture_output=True,timeout=30)
   (output/'native-preparation-before-login.stdout').write_bytes(result.stdout);(output/'native-preparation-before-login.stderr').write_bytes(result.stderr)
   require(result.returncode==0,'Installed native preparation predicate failed before login');value=json.loads(result.stdout)
   require(value['runId']==run and value['caseId']==CASE and value['nativePreparationReady'] is True and value['keyTransportConsumerAvailable'] is True,'Installed native preparation not complete')
  finally:subprocess.run(['docker','exec','-u','0',SUITE,'rm','-rf','--',remote],capture_output=True,check=True,timeout=20)
 diagnostics.append(dict(operation='suite-native-preparation-read-only',startedAt=started,completedAt=NOW(),sourceSha256=SHA(source.read_bytes()),suiteJavaCalls=1,hostCompilerCalls=1,productSettings=0,protocolSubmissions=0,credentialPosts=0))

class SharedClient(Client):
 def __init__(self,folder):super().__init__();self.folder=folder;self.http=[];self.credential_posts=0;self.blocked_credentials=0;self.protocol_gets=0;self.logout_continuations=[]
 def request(self,url,fields=None):
  native=urllib.parse.urlsplit(url).netloc=='localhost:18280';observation=None
  if native and fields and ('password' in fields or 'j_password' in fields):
   if self.credential_posts>=1:self.blocked_credentials+=1;raise ValueError('No additional test-user login is submitted')
   self.credential_posts+=1
  if native and 'SAMLRequest=' in url:self.protocol_gets+=1
  if native and fields and 'SAMLRequest' in fields:
   raw=base64.b64decode(fields['SAMLRequest'],validate=True);root=ET.fromstring(raw)
   require(root.tag in {'{'+P+'}AuthnRequest','{'+P+'}LogoutRequest'},'Unexpected native input')
   require(root.get('ForceAuthn') not in {'true','1'} and root.get('IsPassive') not in {'true','1'},'Shared session input violates authentication boundary')
   observation=dict(requestId=root.get('ID'),requestSha256=SHA(raw),requestUrl=url,requestMethod='POST',startedAt=NOW());self.http.append(observation)
  final,page,status=super().request(url,fields)
  # Stock SLO renders an iframe to complete this very operation. Following its actual
  # same-flow URL keeps the execution value in memory; no new SAML input is created.
  for hop in range(2):
   following=logout_continuation(final,page,status)
   if following is None:break
   require(observation is not None and root.tag=='{'+P+'}LogoutRequest','Unexpected native logout navigation')
   navigation=dict(operation='native-logout-flow-completion',requestId=observation['requestId'],requestSha256=observation['requestSha256'],method='GET',urlSha256=SHA(following.encode()),path=urllib.parse.urlsplit(following).path,issuedPageSha256=SHA(page.encode()),startedAt=NOW(),executionValueExported=False)
   self.logout_continuations.append(navigation);final,page,status=super().request(following)
   navigation.update(completedAt=NOW(),responseStatus=status,responseBodySha256=SHA(page.encode()))
  else:raise ValueError('Native logout completion hop limit')
  if observation is not None:
   forms=[f for f in parse_forms(page) if 'SAMLResponse' in f.fields]
   require(len(forms)<=1,'Ambiguous native response forms');redirected=redirect_response(final)
   require(not (forms and redirected),'Two native response payloads observed')
   if forms:observation.update(responseSamlSha256=SHA(base64.b64decode(forms[0].fields['SAMLResponse'],validate=True)),responseBinding='HTTP-POST')
   elif redirected:observation.update(redirected)
   observation.update(public_response_identity(final));observation.update(responseStatus=status,responseBodySha256=SHA(page.encode()),completedAt=NOW())
   if status>=400 and public_terminal(page):
    name='public-error-'+observation['requestId']+'.html';require(re.fullmatch(r'[A-Za-z0-9_-]+',observation['requestId']),'Unsafe input identity');(self.folder/name).write_bytes(page.encode());observation['publicErrorFile']=name
  return final,page,status

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);folder=out/'receipt';folder.mkdir();client=SharedClient(folder)
 ops=[];diagnostics=[];errors=[];changed=[];created=None;run=plan=entity=source=None;observations=[];steps=[];original={};configured={};baseline_done=False;baseline_http_count=0;capture_scope=Capture(folder,diagnostics);installed_prep=False
 def save_ops():save(out/'operations.json',ops)
 save_ops()
 def write(path,raw,label):
  row=dict(operation='write',path=path,label=label,sha256=SHA(raw),startedAt=NOW(),readBack=False);ops.append(row);save_ops();docker('sh','-c','cat > '+path,data=raw);require(docker('cat',path)==raw,'Native write readback mismatch');row.update(completedAt=NOW(),readBack=True);save_ops()
 def reload(label):
  row=dict(operation='reload',label=label,startedAt=NOW(),completed=False);ops.append(row);save_ops();raw=docker('/opt/reference-idp/bin/reload-service.sh','-id','shibboleth.MetadataResolverService','-u','http://localhost:8080/idp');(folder/(label+'-reload.txt')).write_bytes(raw);row.update(completedAt=NOW(),completed=True);save_ops()
 def restart(label):
  row=dict(operation='restart',label=label,startedAt=NOW(),completed=False);ops.append(row);save_ops();subprocess.run(['docker','restart',CONTAINER],capture_output=True,check=True,timeout=60);docker('/usr/local/tomcat/bin/catalina.sh','start');limit=time.monotonic()+90
  while time.monotonic()<limit:
   try:
    with urllib.request.urlopen('http://localhost:18280/idp/shibboleth',timeout=3) as r:
     if r.status==200:row.update(completedAt=NOW(),completed=True);save_ops();return
   except Exception:pass
   time.sleep(1)
  raise ValueError('Native readiness unavailable')
 def clock(label):
  started=NOW();raw=docker('date','-u','+%Y-%m-%dT%H:%M:%S.%NZ');completed=NOW();name=label+'-clock.txt';(folder/name).write_bytes(raw);file=label+'-clock.json';save(folder/file,dict(nativeInstant=raw.decode().strip(),nativeClockFile=name,nativeClockSha256=SHA(raw),hostStartedAt=started,hostCompletedAt=completed));diagnostics.append(dict(operation='native-clock',startedAt=started,completedAt=completed));return file
 def snapshot(label):
  names={}
  for path,kind in [(PROVIDERS,'providers'),(AUDIT,'audit'),(LOGBACK,'logback')]:
   raw=docker('cat',path);require(raw==configured[path],'Native configuration changed');file=label+'-'+kind+'.xml';(folder/file).write_bytes(raw);names[kind]=file
  raw=docker('cat',source);require(raw==(folder/'registered-suite-metadata.xml').read_bytes(),'Native source metadata changed');file=label+'-source.xml';(folder/file).write_bytes(raw);names['source']=file;return names
 def record(value,label):
  raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode();before={e['id'] for e in api('/api/runs/'+run+'/transcript')};req=urllib.request.Request(BASE+'/p/'+plan+'/sp/paos?run='+run,data=raw,method='POST',headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(req,timeout=30) as r:require(r.status==204,'Public original Recorder failed')
  rows=[e for e in api('/api/runs/'+run+'/transcript') if e['id'] not in before and e.get('decodedSamlRef')];require(len(rows)==1 and rows[0]['runId']==run and rows[0]['decodedSamlBytes']==len(raw),'Original Recorder binding ambiguous');file=label+'.json';(folder/file).write_bytes(raw);return dict(reference=rows[0]['id'],sha256=SHA(raw))
 def query(label='native-metadata-query'):
  command=['/opt/reference-idp/bin/mdquery.sh','-u','http://localhost:8080/idp','-e',entity];started=NOW();r=subprocess.run(['docker','exec',CONTAINER,*command],capture_output=True,timeout=45);completed=NOW();require(r.returncode==0,'Native metadata registration failed; no login');stdout=label+'.xml';stderr=label+'.stderr';(folder/stdout).write_bytes(r.stdout);(folder/stderr).write_bytes(r.stderr);q=dict(command=command,entityId=entity,exitCode=r.returncode,startedAt=started,completedAt=completed,stdoutFile=stdout,stdoutSha256=SHA(r.stdout),stderrFile=stderr,stderrSha256=SHA(r.stderr));save(folder/(label+'.json'),q);diagnostics.append(dict(operation='native-metadata-query',startedAt=started,completedAt=completed));return q
 def logfile_position(path='/opt/reference-idp/logs/idp-process.log'):
  require(path in {'/opt/reference-idp/logs/idp-process.log','/opt/reference-idp/logs/idp-audit.log'},'Native log path outside collection');command=['stat','-c','%i %s',path];inode,size=map(int,docker(*command).decode().split());return dict(inode=inode,size=size,capturedAt=NOW())
 def public_log_delta(first,last,path='/opt/reference-idp/logs/idp-process.log'):
  require(path in {'/opt/reference-idp/logs/idp-process.log','/opt/reference-idp/logs/idp-audit.log'},'Native log path outside collection');require(first['inode']==last['inode'] and last['size']>=first['size'],'Native log rotated; preserve uncertain finding');count=last['size']-first['size'];raw=docker('dd','if='+path,'bs=1','skip='+str(first['size']),'count='+str(count),'status=none')
  require(len(raw)==count and not re.search(rb'(?i)authorization\s*:|cookie\s*:|(?:j_)?password\s*[:=]',raw),'Private or incomplete native log delta refused');return raw
 def read_original(entry):
  reference=entry['id'];require(re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}',reference),'Unsafe original reference')
  require(entry.get('runId')==run and entry.get('decodedSamlRef')=='transcripts/'+run+'/'+reference+'.saml.xml','Original Run/path mismatch')
  destination=folder/(reference+'-protocol-original.xml')
  subprocess.run(['docker','cp',SUITE+':/data/'+entry['decodedSamlRef'],str(destination)],capture_output=True,check=True,timeout=30)
  raw=destination.read_bytes();require(len(raw)==entry['decodedSamlBytes'],'Original length mismatch');return raw
 try:
  require(SHA(STOCK_DECODER_SOURCE.read_bytes())==STOCK_DECODER_SOURCE_SHA and SHA(CALIBRATION_SOURCE.read_bytes())==CALIBRATION_SOURCE_SHA,'Frozen native producer contract changed before any login')
  # Create a real case/Run before any product write or test-user interaction.
  made=api('/api/plans',dict(name='Shibboleth unchanged default algorithm prevention',profile='browser_sso_idp',targetKind='IDP',targetEntityId='http://localhost:18280/idp/shibboleth',metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=30,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',made);plan=made['plan']['plan']['id'];entity=BASE+'/p/'+plan;created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
  planned_slot(run,out,diagnostics)
  save(out/'control-campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=['control'],pollingDelaySeconds=0)));lab=api('/api/runs/'+run+'/metadata-lab')
  with urllib.request.urlopen(lab['automaticStartUrl'],timeout=30) as r:require(r.status==202,'Fixture campaign did not prepare')
  with urllib.request.urlopen(lab['metadataUrl'],timeout=30) as r:suite=r.read()
  (folder/'registered-suite-metadata.xml').write_bytes(suite);entries=api('/api/runs/'+run+'/transcript');prepared=[e for e in entries if e['samlSummary'].get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')=='control' and e['samlSummary'].get('feed')=='live'];require(len(prepared)==1,'Control metadata original absent or ambiguous')
  subprocess.run(['docker','cp',SUITE+':/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],capture_output=True,check=True,timeout=30);target=(out/'target-metadata.xml').read_bytes();target_entity=ET.fromstring(target).get('entityID');source='/opt/reference-idp/metadata/default-algorithm-'+run+'.xml'
  require(not docker('sh','-c','test -e '+source+' && echo exists || true').strip(),'Fresh metadata path already exists')
  for path,kind in [(PROVIDERS,'providers'),(AUDIT,'audit'),(LOGBACK,'logback')]:original[path]=docker('cat',path);(folder/('original-'+kind+'.xml')).write_bytes(original[path])
  configured[AUDIT]=audit_configuration(original[AUDIT]);configured[LOGBACK]=logback_configuration(original[LOGBACK]);ET.register_namespace('',N);ET.register_namespace('xsi',XSI);root=ET.fromstring(original[PROVIDERS]);root.insert(0,ET.Element('{'+N+'}MetadataProvider',dict(id='DefaultAlgorithm'+run,**{'{'+XSI+'}type':'FilesystemMetadataProvider','metadataFile':source})));configured[PROVIDERS]=ET.tostring(root)
  for path,kind in [(PROVIDERS,'providers'),(AUDIT,'audit'),(LOGBACK,'logback')]:(folder/('configured-'+kind+'.xml')).write_bytes(configured[path])
  for path in [AUDIT,LOGBACK]:changed.append(path);write(path,configured[path],'prepare-'+path.rsplit('/',1)[-1])
  restart('prepare-audit-instrumentation');write(source,suite,'native-suite-metadata');changed.append(PROVIDERS);write(PROVIDERS,configured[PROVIDERS],'prepare-provider');reload('prepare-metadata');q=query();snap=snapshot('prepared')
  name,_=capture_scope.capture('before',entity,run);before_ref=record(json.loads((folder/name).read_bytes()),'before-scope-original');registered=record(dict(schema='samlscope-shibboleth-default-metadata-registration-v1',runId=run,entityId=entity,suiteMetadataSha256=SHA(suite),targetMetadataSha256=SHA(target),query=q),'registration-original')
  common=dict(runId=run,caseId=CASE,campaignId=CAMPAIGN,adapter=ADAPTER,profile='browser_sso_idp',counterfactualCalibrationOnly=False,targetEntityId=target_entity,targetMetadataSha256=SHA(target),suiteMetadataReference=prepared[0]['id'],suiteMetadataSha256=SHA(suite),registeredSuiteMetadataFile='registered-suite-metadata.xml',beforeScopeReference=before_ref['reference'],beforeScopeSha256=before_ref['sha256'],registrationReference=registered['reference'],registrationSha256=registered['sha256'],nativeOriginals=[before_ref,registered])
  for kind in ['providers','audit','logback']:common['prepared'+kind+'ReadBackFile']=snap[kind]
  prep=dict(common,schema=SCHEMA+'-preparation',files={f.name:SHA(f.read_bytes()) for f in folder.iterdir() if f.is_file() and f.stat().st_size>0})
  prep_file=out/(run+'.preparation.json');save(prep_file,prep);install_public_preparation(folder,prep_file,run);installed_prep=True;native_preparation_preflight(run,out,diagnostics)
  complete_baseline(run,out/'initial-baseline',client=client);baseline_done=True;baseline_http_count=len(client.http);require(client.credential_posts==1,'One shared initial credential required');query('post-baseline-metadata-query');snapshot('post-baseline');save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
  # The first activation reads preparation before any outbox. Other reserved cases are prepared
  # and aborted only at the Suite, so they never consume a target login or protocol submission.
  for _ in range(300):
   require_unfinished(api('/api/runs/'+run+'/campaigns'),run,CASE)
   pending=api('/api/runs/'+run+'/interactions')
   if any(row['caseId']==CASE and row['kind']=='CONFIGURATION' for row in pending):break
   status=api('/api/runs/'+run+'/active-probe')
   pending=api('/api/runs/'+run+'/interactions')
   if any(row['caseId']==CASE and row['kind']=='CONFIGURATION' for row in pending):break
   require(status['state']=='READY' and status.get('caseId')!=CASE,'Qualified native preparation did not reach the expected configuration wait')
   steps.append(prepare_and_skip(BASE,run,status,api));save(out/'steps.json',steps)
  else:raise ValueError('Native case activation incomplete; no weak target inputs submitted')
  report=api('/api/runs/'+run+'/result.json');save(out/'formal-case-slot-after-baseline.json',report);slots=[c for req in report['requirements'] for c in req.get('cases',[]) if c['id']==CASE]
  require(report['run']['id']==run and len(slots)==1 and slots[0]['mode']=='ATTESTED','Formal execution slot mismatch')
  answer=api('/api/runs/'+run+'/cases/'+CASE+'/configure',dict(value='CONFIRMED',note=''));save(out/'native-preparation-confirmed.json',answer)
  selected=0
  for _ in range(400):
   if selected==6:break
   classification=api('/api/runs/'+run+'/campaigns');save(out/'last-selected-campaign-state.json',classification);require_unfinished(classification,run,CASE)
   status=api('/api/runs/'+run+'/active-probe')
   if status['state']=='AWAITING_RESPONSE':raise ValueError('Selected input still awaits recorded response; do not issue another')
   require(status['state']=='READY','Selected native outbox is not ready')
   if status.get('caseId')!=CASE:
    require_unfinished(api('/api/runs/'+run+'/campaigns'),run,CASE)
    steps.append(prepare_and_skip(BASE,run,status,api));save(out/'steps.json',steps);continue
   require(status.get('requiresFreshSession') is False,'Native shared-session prerequisite unknown; no login repeated');fixture=FIXTURES[selected];before_files=snapshot(fixture+'-before');clock_before=clock(fixture+'-before');position_before=logfile_position();audit_before=logfile_position('/opt/reference-idp/logs/idp-audit.log');old={e['id'] for e in api('/api/runs/'+run+'/transcript')};http_before=len(client.http)
   terminals=[]
   def terminal_observer(url,page,code,label):
    require(urllib.parse.urlsplit(url).netloc=='localhost:18280' and not terminals,'Native terminal feedback is ambiguous')
    require(not any(key=='execution' for key,value in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)),'Native terminal Webflow value must not be recorded')
    # The actual HTTP status/URL confirm this dispatch. Secret-bearing HTML is omitted,
    # while its real hash remains in native-http; native cause/audit decide the outcome.
    body=page if public_terminal(page) else '';terminals.append(dict(url=url,status=code,label=label,originalBodySha256=SHA(page.encode()),bodyOmittedForPrivacy=body==''))
    api('/api/runs/'+run+'/active-probe/browser-response',dict(actionId=status['actionId'],status=code,url=url,body=body))
   selected_step=dict(caseId=CASE,fixtureId=fixture,prepared=True,sentToTarget=False,targetSubmissionAttempted=False,observationCompleted=False,reusedAuthenticatedClient=True,actionId=status['actionId']);steps.append(selected_step);save(out/'steps.json',steps)
   try:result=client.flow(status['startUrl'],None,os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'),terminal_observer=terminal_observer)
   finally:
    selected_step['targetSubmissionAttempted']=len(client.http)>http_before;selected_step['sentToTarget']=len(client.http)-http_before==1 and 'completedAt' in client.http[-1];save(out/'steps.json',steps)
   save(out/'native-http.json',client.http);save(folder/(fixture+'-terminal-feedback.json'),terminals)
   audit_after=logfile_position('/opt/reference-idp/logs/idp-audit.log');position_after=logfile_position();clock_after=clock(fixture+'-after');after_files=snapshot(fixture+'-after');rows=api('/api/runs/'+run+'/transcript')
   require(len(client.http)-http_before==1,'One outbox must make one native submission');http=client.http[-1]
   request,response=correlate_exchange(rows,old,run,fixture,status['actionId'],http,read_original)
   log=public_log_delta(position_before,position_after);process_file=fixture+'-process.log';(folder/process_file).write_bytes(log);http_file=fixture+'-http.json';save(folder/http_file,http)
   audit_delta=public_log_delta(audit_before,audit_after,'/opt/reference-idp/logs/idp-audit.log');audit_capture,audit_line=capture_audit(run,http['requestId'],http['requestSha256'],fixture,audit_before,audit_after,audit_delta)
   audit_capture_file=fixture+'-audit-capture.json';save(folder/audit_capture_file,audit_capture)
   use=dict(schema='samlscope-shibboleth-default-algorithm-use-v1',runId=run,entityId=entity,fixtureId=fixture,suiteMetadataSha256=SHA(suite),targetMetadataSha256=SHA(target),requestId=http['requestId'],requestSha256=http['requestSha256'],httpFile=http_file,clockBeforeFile=clock_before,clockAfterFile=clock_after,processLogFile=process_file,auditCaptureFile=audit_capture_file,metadataSourceFile=before_files['source'],processLogRange=dict(path='/opt/reference-idp/logs/idp-process.log',inode=position_before['inode'],beforeOffset=position_before['size'],afterOffset=position_after['size']))
   if audit_line is None:use['auditMode']='pre-audit-decoder-rejection'
   else:
    audit_file=fixture+'-audit.log';(folder/audit_file).write_bytes(audit_line);use.update(auditFile=audit_file,auditMode='request-bound-audit')
   for kind in ['providers','audit','logback']:use[kind+'beforeFile']=before_files[kind];use[kind+'afterFile']=after_files[kind]
   # Cipher input math is captured inside the product JVM after all native operations, below.
   row=dict(fixtureId=fixture,requestReference=request['id'],requestSha256=http['requestSha256'],responseReference=response['id'] if response else None,responseSha256=http.get('responseSamlSha256') if response else None,nativeUsePending=use)
   observations.append(row);save(out/'observations-pending.json',observations);selected_step.update(receipt=result,observationCompleted=True);save(out/'steps.json',steps);selected+=1
   waiting=api('/api/runs/'+run+'/active-probe')
   if waiting['state']=='AWAITING_RESPONSE' and waiting.get('actionId')==status['actionId']:
    require(not terminals,'Recorded terminal feedback did not advance the same action')
    api('/api/runs/'+run+'/active-probe/abort',{})
  require(selected==6,'Native consumer input collection incomplete');name,_=capture_scope.capture('after',entity,run);after_ref=record(json.loads((folder/name).read_bytes()),'after-scope-original');common.update(afterScopeReference=after_ref['reference'],afterScopeSha256=after_ref['sha256']);common['nativeOriginals'].append(after_ref)
  # Input validation and production-reader replay are finalized independently after restore.
  save(out/'manifest-pending.json',dict(common,observations=observations));save(out/'native-http.json',client.http)
 finally:
  save(out/'native-http.json',client.http)
  save(out/'native-logout-flow-completions.json',client.logout_continuations)
  for path in reversed(changed):
   try:require(docker('cat',path)==configured[path],'Native state changed during lease');write(path,original[path],'restore-'+path.rsplit('/',1)[-1])
   except Exception as e:errors.append(type(e).__name__)
  if changed and not errors:
   try:restart('restore-native-settings')
   except Exception as e:errors.append(type(e).__name__)
  if source and not errors:
   try:docker('rm','-f','--',source)
   except Exception as e:errors.append(type(e).__name__)
  for path,kind in [(PROVIDERS,'providers'),(AUDIT,'audit'),(LOGBACK,'logback')]:
   if path in original:(folder/('final-'+kind+'.xml')).write_bytes(docker('cat',path))
  restored=not errors and all(docker('cat',p)==v for p,v in original.items());save(out/'restoration.json',dict(restored=restored,errors=errors,original={p:SHA(v) for p,v in original.items()},final={p:SHA(docker('cat',p)) for p in original}));counts=dict(restored=restored,personOperations=0,credentialPosts=client.credential_posts,additionalCredentialAttemptsBlocked=client.blocked_credentials,productWrites=sum(o['operation']=='write' for o in ops),restorationWrites=sum(o['operation']=='write' and o['label'].startswith('restore-') for o in ops),productRestarts=sum(o['operation']=='restart' for o in ops),metadataReloads=sum(o['operation']=='reload' for o in ops),selectedTargetSubmissions=len(client.http)-baseline_http_count,ordinaryBaselineSubmissions=1 if baseline_done else 0,protocolSubmissions=len(client.http)-baseline_http_count+(1 if baseline_done else 0),preparedSuiteActions=sum(s.get('prepared') is True for s in steps),skippedBeforeTargetSubmission=sum(s.get('sentToTarget') is False for s in steps),sameAuthenticatedClient=True,nativeLogoutFlowCompletionGets=len(client.logout_continuations))
  save(out/'operation-counts.json',counts);save(out/'native-readonly-diagnostics.json',diagnostics)
  baseline_file=out/'initial-baseline/operation-counts-reconciled.json'
  baseline_counts=json.loads(baseline_file.read_bytes()) if baseline_file.is_file() else {}
  cumulative=dict(schema='samlscope-default-algorithm-cumulative-operations-v1',runId=run,mainCountsSha256=SHA((out/'operation-counts.json').read_bytes()),baselineCountsSha256=SHA(baseline_file.read_bytes()) if baseline_file.is_file() else None,
    productWrites=counts['productWrites']+baseline_counts.get('productConfigurationWrites',0),metadataReloads=counts['metadataReloads']+baseline_counts.get('metadataReloads',0),productRestarts=counts['productRestarts']+baseline_counts.get('productRestarts',0),
    credentialPosts=client.credential_posts,personOperations=0,protocolSubmissions=counts['protocolSubmissions'],selectedTargetSubmissions=counts['selectedTargetSubmissions'],ordinaryBaselineSubmissions=counts['ordinaryBaselineSubmissions'],
    baselineProtocolAlreadyIncluded=True,baselineCredentialAlreadyIncluded=True,suiteOnlySkipsNotTargetOperations=True,additionalCredentialAttemptsBlocked=client.blocked_credentials,restored=restored)
  save(out/'cumulative-operation-counts.json',cumulative)
  if run:
   rows=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',rows);capture(out,run,rows)
   try:save(out/'result.json',api('/api/runs/'+run+'/result.json'))
   except Exception as e:save(out/'result-unavailable.json',dict(errorType=type(e).__name__))
  for name in ['restoration.json','operation-counts.json','operations.json','cumulative-operation-counts.json']:shutil.copy2(out/name,folder/name)
  require(restored,'Native restoration incomplete')
  with urllib.request.urlopen('http://localhost:18280/idp/shibboleth',timeout=5) as r:save(folder/'restored-native-readiness.json',dict(status=r.status,url='http://localhost:18280/idp/shibboleth',recordedAt=NOW()))
 if errors:raise ValueError('Native collection failed')
 print(run,'native controls captured; policy unchanged; exact restoration completed',flush=True)
if __name__=='__main__':main()
