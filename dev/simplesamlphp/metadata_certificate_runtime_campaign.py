#!/usr/bin/env python3
"""Five native certificate imports, six deterministic outbox probes, one memory-only login."""
import argparse,base64,datetime,hashlib,json,os,pathlib,re,shutil,subprocess,sys,time,urllib.request,xml.etree.ElementTree as ET
REPO=pathlib.Path(__file__).resolve().parents[2];sys.path[:0]=[str(REPO/'dev/simplesamlphp'),str(REPO/'dev/keycloak'),str(REPO/'dev/reference-acceptance')]
from registered_signer_campaign import SharedClient,canonical,public_terminal,PARSER,READBACK,SOURCES as BASE_SOURCES,CONTAINER,SUITE,REMOTE,CONFIG
from configuration_batch import ConfigurationBatch
from metadata_validity_epoch_campaign import reject_sensitive
from import_metadata_batch import api,save,BASE
from capture_run_originals import capture
from browser_probe_selection import prepare_and_skip
from algorithm_preference_campaign import recorded
CASE='IIP-MD06-a6-idp-01';CAMPAIGN='native-metadata-certificate-runtime';TARGET='http://localhost:18380/idp';VARIANTS=('control','certificate-critical-extension','certificate-unknown-ca','certificate-revoked','certificate-revocation-unreachable');FIXTURES=('control-normal','control-invalid-signature','certificate-critical-extension-normal','certificate-unknown-ca-normal','certificate-revoked-normal','certificate-revocation-unreachable-normal')
SOURCES=BASE_SOURCES|{'native-utils.php':'/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/Utils.php','native-xml-security-key.php':'/var/simplesamlphp/vendor/robrichards/xmlseclibs/src/XMLSecurityKey.php','native-xml-security-dsig.php':'/var/simplesamlphp/vendor/robrichards/xmlseclibs/src/XMLSecurityDSig.php'}
READBACK=READBACK.replace('$sourceHashes=[];',r'''$operativeClasses=[];foreach(['SAML2\\Utils','SAML2\\SignedElementHelper','RobRichards\\XMLSecLibs\\XMLSecurityDSig','RobRichards\\XMLSecLibs\\XMLSecurityKey'] as $class){$r=new \ReflectionClass($class);$p=$r->getFileName();$operativeClasses[$class]=['path'=>$p,'sha256'=>hash_file('sha256',$p)];}$sourceHashes=[];''').replace("'sourceHashes'=>$sourceHashes", "'sourceHashes'=>$sourceHashes,'operativeClasses'=>$operativeClasses")
SHA=lambda b:hashlib.sha256(b).hexdigest();NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def public_certificate_urls(xml):
 node=ET.fromstring(xml).find('.//{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor').find('.//{http://www.w3.org/2000/09/xmldsig#}X509Certificate')
 der=base64.b64decode(node.text,validate=True)
 result=subprocess.run(['openssl','x509','-inform','DER','-noout','-serial'],input=der,capture_output=True,check=True,timeout=20)
 serial=result.stdout.decode().strip();assert re.fullmatch(r'serial=[0-9A-Fa-f]+',serial)
 prefix='http://samlscope-reference-suite:18481/samlscope-revocation/'+format(int(serial.split('=',1)[1],16),'x')
 return [prefix+'/unavailable'+suffix for suffix in ('.crl','.ocsp')]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--min-free-mib',type=int,default=96);a=p.parse_args();space=os.statvfs(REPO)
 if a.min_free_mib<32 or space.f_bavail*space.f_frsize<a.min_free_mib*1024*1024:p.error('Insufficient disk; product configuration/login/protocol operations0')
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);receipt=out/'receipt';receipt.mkdir();(out/'collector-source.py').write_bytes(pathlib.Path(__file__).read_bytes());(receipt/'native-parser-command.php').write_text(PARSER);(receipt/'native-readback-command.php').write_text(READBACK)
 batch=ConfigurationBatch(CONFIG);batch.container,batch.container_path=CONTAINER,REMOTE;client=SharedClient();user=os.environ.get('REFERENCE_USERNAME','samlscope-m0-user');password=os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password');refs={};commands=[];epochs=[];skips=[];created=None;run=plan=entity=None;baseline_attempts=0;selected_attempts=0;restoration={'restored':False};baseline_safe=False
 def docker(*args,data=None,container=CONTAINER):
  start=NOW();r=subprocess.run(['docker','exec','-i',container,*args],input=data,capture_output=True,timeout=40);commands.append(dict(container=container,executable=args[0],startedAt=start,finishedAt=NOW(),exitCode=r.returncode));save(out/'native-command-counts.json',commands)
  if r.returncode:raise ValueError('Bounded native command failed; stderr not persisted')
  return r.stdout
 def runtime():
  fmt='{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}}}';r=subprocess.run(['docker','inspect','--format',fmt,CONTAINER],capture_output=True,check=True,timeout=20);n=json.loads(r.stdout);assert n['running'] is True;return n
 def record(label,kind,**value):
  n=dict(schema='samlscope-simplesamlphp-certificate-runtime-original-v1',runId=run,campaignId=CAMPAIGN,targetMetadataSha256=SHA((receipt/'target-metadata.xml').read_bytes()),recordedAt=NOW(),kind=kind,**value);reject_sensitive(n);refs[label]=recorded(receipt,created,n,label);return n
 def state(label,phase,variant=None,**extra):
  start=NOW();raw=docker('php','-r',READBACK,data=canonical(dict(entities=[entity],sourcePaths=SOURCES)));end=NOW();n=json.loads(raw);reject_sensitive(n);actual=docker('cat',REMOTE);assert actual==batch.expected and n['configurationSha256']==SHA(actual);d=receipt/'native-readbacks';d.mkdir(exist_ok=True);(d/(label+'.json')).write_bytes(raw);return record(label,'native-certificate-state',phase=phase,variant=variant,runtime=runtime(),nativeReadbackSha256=SHA(raw),nativeStartedAt=start,nativeFinishedAt=end,**n,**extra)
 try:
  assert b'?>' not in batch.original and docker('cat',REMOTE)==batch.original
  if re.search(rb'(?i)private[._-]?key|password|passwd|authorization|cookie|client[._-]?secret',batch.original):raise ValueError('Credential-bearing metadata baseline; never persist it')
  baseline_safe=True;(receipt/'original-configuration.php').write_bytes(batch.original);d=receipt/'native-source';d.mkdir()
  reuse=REPO/'build/acceptance/reference-20261002/simplesamlphp-registered-signer-r3/receipt/native-source';extra=REPO/'build/acceptance/reference-20261002/cross-cluster-audit/ssp-certificate-runtime-source'
  for name,path in SOURCES.items():
   prior=(reuse if name in BASE_SOURCES else extra)/name
   if prior.exists():os.link(prior,d/name)
   else:(d/name).write_bytes(docker('cat',path))
  response=api('/api/plans',dict(name='SimpleSAMLphp shared-session certificate runtime',profile='metadata_idp',targetKind='IDP',targetEntityId=TARGET,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=30,testUserHint=user,requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',response);plan=response['plan']['plan']['id'];entity=BASE+'/p/'+plan;created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);save(receipt/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));assert entity.encode() not in batch.original
  subprocess.run(['docker','cp',SUITE+':/data/target-metadata/'+run+'.xml',str(receipt/'target-metadata.xml')],capture_output=True,check=True,timeout=40);(out/'target-metadata.xml').write_bytes((receipt/'target-metadata.xml').read_bytes());state('initial','initial')
  with urllib.request.urlopen(entity+'/metadata',timeout=30) as r:baseline_xml=r.read()
  (receipt/'baseline-fixture.xml').write_bytes(baseline_xml);start=NOW();baseline_parser_raw=docker('php','-r',PARSER,entity,data=baseline_xml);end=NOW();baseline_parser=json.loads(baseline_parser_raw);reject_sensitive(baseline_parser);assert baseline_parser['entityId']==entity and baseline_parser['validateAuthnRequest'] is True;(receipt/'baseline-parser-output.json').write_bytes(baseline_parser_raw);record('baseline-conversion','native-metadata-conversion',entityId=entity,fixtureSha256=SHA(baseline_xml),parserOutput=baseline_parser,parserOutputSha256=SHA(baseline_parser_raw),nativeStartedAt=start,nativeFinishedAt=end)
  parsed={};prepared={}
  for v in VARIANTS:
   save(out/(v+'-campaign.json'),api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=[v],pollingDelaySeconds=0)));lab=api('/api/runs/'+run+'/metadata-lab')
   with urllib.request.urlopen(lab['automaticStartUrl'],timeout=30) as r:assert r.status==202
   with urllib.request.urlopen(lab['metadataUrl'],timeout=30) as r:xml=r.read()
   (receipt/(v+'-fixture.xml')).write_bytes(xml);start=NOW();raw=docker('php','-r',PARSER,entity,data=xml);end=NOW();n=json.loads(raw);reject_sensitive(n);assert n['entityId']==entity and n['validateAuthnRequest'] is True;parsed[v]=n;(receipt/(v+'-parser-output.json')).write_bytes(raw);record(v+'-conversion','native-metadata-conversion',entityId=entity,fixtureSha256=SHA(xml),parserOutput=n,parserOutputSha256=SHA(raw),nativeStartedAt=start,nativeFinishedAt=end)
   rows=[e for e in api('/api/runs/'+run+'/transcript') if e.get('samlSummary',{}).get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==v and e['samlSummary'].get('feed')=='live'];assert len(rows)==1;prepared[v]=rows[0]['id']
  for variant in VARIANTS:public_certificate_urls((receipt/(variant+'-fixture.xml')).read_bytes())
  batch.apply(baseline_parser['php'].encode());assert docker('cat',REMOTE)==batch.expected;(receipt/'baseline-configuration.php').write_bytes(batch.expected);time.sleep(3);state('baseline-before','configured','baseline')
  before_ids={e['id'] for e in api('/api/runs/'+run+'/transcript')};before_attempts=client.native_post_attempts+client.native_redirect_attempts;result=client.flow(entity+'/start/m0-roundtrip?run='+run,None,user,password);rows=api('/api/runs/'+run+'/transcript');wire=[e for e in rows if e['id'] not in before_ids and e['direction']=='OUTBOUND' and e.get('samlSummary',{}).get('type')=='AuthnRequest'];baseline_attempts=client.native_post_attempts+client.native_redirect_attempts-before_attempts;assert result=='recorded' and len(wire)==1 and baseline_attempts==1 and client.credential_posts==1;save(receipt/'baseline.json',dict(receipt=result,outboundReferences=[e['id'] for e in wire],credentialPosts=client.credential_posts,protocolSubmissions=baseline_attempts,credentialValuesPersisted=False))
  state('baseline-after','configured','baseline');batch.apply(parsed['control']['php'].encode());assert docker('cat',REMOTE)==batch.expected;(receipt/'control-configuration.php').write_bytes(batch.expected);time.sleep(3)
  save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));selected=0;current=None;epoch=None
  for _ in range(400):
   if selected==6:break
   status=api('/api/runs/'+run+'/active-probe');
   if status.get('state')!='READY' and any(x.get('caseId')==CASE and x.get('kind')=='CONFIGURATION' for x in api('/api/runs/'+run+'/interactions')):save(out/'native-config-confirmed.json',api('/api/runs/'+run+'/cases/'+CASE+'/configure',dict(value='confirmed')));continue
   assert status.get('state')=='READY','Selected outbox not ready'
   if status.get('caseId')!=CASE:skips.append(prepare_and_skip(BASE,run,status,api));save(out/'suite-only-skips.json',skips);continue
   assert status.get('requiresFreshSession') is False,'No extra/fresh login allowed';fixture=FIXTURES[selected];v='control' if fixture=='control-invalid-signature' else fixture.removesuffix('-normal')
   if v!=current:
    if epoch is not None:state(current+'-after','configured',current);epochs.append(epoch);save(out/'epochs.json',epochs)
    if v!='control':batch.apply(parsed[v]['php'].encode());assert docker('cat',REMOTE)==batch.expected;(receipt/(v+'-configuration.php')).write_bytes(batch.expected);time.sleep(3)
    state(v+'-before','configured',v);epoch=dict(variant=v,preparedReference=prepared[v],probes=[]);current=v
    if v=='certificate-revocation-unreachable':
     network=[]
     for url in public_certificate_urls((receipt/(v+'-fixture.xml')).read_bytes()):
      suffix='.crl' if url.endswith('.crl') else '.ocsp';cmd=['curl','--noproxy','*','--connect-timeout','1','--max-time','2','--silent',url];start=NOW();r=subprocess.run(['docker','exec',CONTAINER,*cmd],capture_output=True,timeout=10);end=NOW();assert r.returncode==7;stdout='unreachable'+suffix+'-stdout.txt';stderr='unreachable'+suffix+'-stderr.txt';(receipt/stdout).write_bytes(r.stdout);(receipt/stderr).write_bytes(r.stderr);network.append(dict(url=url,command=cmd,source='native-target-network',exitCode=r.returncode,startedAt=start,completedAt=end,stdoutFile=stdout,stdoutSha256=SHA(r.stdout),stderrFile=stderr,stderrSha256=SHA(r.stderr)))
     save(receipt/'certificate-revocation-unreachable-network.json',network)
   action=status['actionId'];old={e['id'] for e in api('/api/runs/'+run+'/transcript')};first=len(client.protocol_posts);selected_attempts+=1
   def terminal(url,page,code,reason):
    if not public_terminal(page):raise ValueError('Unsafe terminal page; never record forms or credentials')
    api('/api/runs/'+run+'/active-probe/browser-response',dict(actionId=action,status=code,url=url,body=page))
   flow=client.flow(status['startUrl'],None,user,password,terminal_observer=terminal);entries=api('/api/runs/'+run+'/transcript');requests=[e for e in entries if e['id'] not in old and e['direction']=='OUTBOUND' and e.get('correlationId')==action and e.get('samlSummary',{}).get('type')=='AuthnRequest'];assert len(requests)==1 and len(client.protocol_posts[first:])==1;request=requests[0];rid=client.protocol_posts[first]['requestId'];assert rid=='_'+action
   responses=[e for e in entries if e['direction']=='INBOUND' and (e.get('samlSummary',{}).get('inResponseTo')==rid or e.get('correlationId')==action and e.get('samlSummary',{}).get('type')=='BrowserResponseObservation')];assert len(responses)==1;response=responses[0];row=dict(fixture=fixture,actionId=action,requestReference=request['id'],responseReference=response['id'],receipt=flow)
   label=fixture+'-http';record(label,'native-http-response',requestReference=request['id'],responseReference=response['id'],actionId=action,native=client.protocol_posts[first]);row['nativeHttpOriginal']=label
   if response.get('method')!='BROWSER' and fixture.endswith('invalid-signature'):raise ValueError('Invalid signature control accepted; no product failure inferred')
   if response.get('method')=='BROWSER' and not fixture.endswith('invalid-signature'):raise ValueError('Normal key refused without causal proof; stop additional user/protocol actions')
   epoch['probes'].append(row);save(out/'current-epoch.json',epoch);selected+=1
  assert selected==6;state(current+'-after','configured',current);epochs.append(epoch);save(out/'epochs.json',epochs)
 finally:
  try:
   restoration=batch.restore();final=docker('cat',REMOTE);restoration['restored']=restoration.get('restored') is True and final==batch.original
   if baseline_safe and final==batch.original:(receipt/'final-configuration.php').write_bytes(final)
   if run:state('restoration','restored',restored=restoration['restored'])
  except Exception as error:restoration=dict(restored=False,failureType=type(error).__name__)
  attempts=client.native_post_attempts+client.native_redirect_attempts;counts=dict(restored=restoration.get('restored') is True,nativeConfigurationWrites=batch.write_count,restorationWrites=batch.restoration_writes,initialBaselineSubmissions=baseline_attempts,selectedProbeAttempts=selected_attempts,actualOutboxTargetAttempts=attempts-baseline_attempts,protocolSubmissions=attempts,credentialPosts=client.credential_posts,credentialPostAttempts=client.credential_attempts,nativePostAttempts=client.native_post_attempts,nativeRedirectAttempts=client.native_redirect_attempts,personOperations=0,productRestarts=0,nativeCliExecutions=sum(x['container']==CONTAINER and x['executable']=='php' for x in commands),suiteOnlySkippedActions=len(skips));save(receipt/'operation-counts.json',counts);save(out/'restoration.json',restoration);save(out/'native-protocol-posts.json',client.protocol_posts)
  if run:entries=api('/api/runs/'+run+'/transcript');save(receipt/'transcript.json',entries);capture(receipt,run,entries)
 if not restoration.get('restored') or len(epochs)!=5:raise ValueError('Incomplete campaign not adoptable')
 bodies=[]
 for e in entries:
  if e.get('method')=='BROWSER':
   ref='transcripts/'+run+'/'+e['id']+'.body';assert e.get('bodyRef')==ref;raw=docker('cat','/data/'+ref,container=SUITE);assert len(raw)==e['bodyBytes'] and public_terminal(raw.decode());d=receipt/'browser-originals';d.mkdir(exist_ok=True);(d/(e['id']+'.body')).write_bytes(raw);bodies.append(dict(id=e['id'],reference=ref,bytes=len(raw),file='browser-originals/'+e['id']+'.body',sha256=SHA(raw)))
 save(receipt/'browser-originals-manifest.json',bodies);m=dict(schema='samlscope-simplesamlphp-certificate-runtime-v1',adapter='simplesamlphp-native-certificate-runtime-v1',campaignId=CAMPAIGN,runId=run,planId=plan,entityId=entity,targetEntityId=TARGET,targetMetadataSha256=SHA((receipt/'target-metadata.xml').read_bytes()),epochs=epochs,originals=refs,files={str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in sorted(receipt.rglob('*')) if p.is_file()});save(receipt/'manifest.json',m);save(out/'collector-operation-audit.json',dict(finalReceiptInstalled=False,oldStoredOutcomeRequiredBeforeFinalInstallation=True,productConfigurationWrites=batch.write_count,restorationWrites=batch.restoration_writes,protocolSubmissions=counts['protocolSubmissions'],credentialPosts=client.credential_posts,personOperations=0,nativeCliExecutions=counts['nativeCliExecutions']));print(json.dumps(dict(status='collected-not-adopted',runId=run,counts=counts)))
if __name__=='__main__':main()
