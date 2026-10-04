#!/usr/bin/env python3
"""Full dual-role native parser epochs and eleven outbox probes with one shared login."""
import argparse,base64,datetime,hashlib,json,os,pathlib,subprocess,sys,time,urllib.request,xml.etree.ElementTree as ET
REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'dev/simplesamlphp'),str(REPO/'dev/keycloak'),str(REPO/'dev/reference-acceptance')]
from registered_signer_campaign import SharedClient,canonical,public_terminal,READBACK as BASE_READBACK,SOURCES as BASE_SOURCES,CONTAINER,SUITE,REMOTE,CONFIG
from configuration_batch import ConfigurationBatch
from metadata_validity_epoch_campaign import reject_sensitive
from import_metadata_batch import api,save,BASE
from capture_run_originals import capture
from reference_flow import parse_forms
from browser_probe_selection import prepare_and_skip
CASE='IIP-MD06-a2-idp-01';CAMPAIGN='native-role-key-consumption';TARGET='http://localhost:18380/idp'
VARIANTS=('role-keys-sp-first-explicit-a','role-keys-idp-first-explicit-b','role-keys-sp-first-omitted-a','role-keys-idp-first-omitted-b')
FIXTURES=('explicit-a-normal','explicit-a-peer-key','explicit-a-encryption-key','explicit-a-invalid-signature','explicit-b-normal','explicit-b-peer-key','explicit-b-encryption-key','omitted-a-normal','omitted-a-peer-key','omitted-b-normal','omitted-b-peer-key')
SOURCES=BASE_SOURCES|{'native-utils.php':'/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/Utils.php','native-xml-security-key.php':'/var/simplesamlphp/vendor/robrichards/xmlseclibs/src/XMLSecurityKey.php','native-xml-security-dsig.php':'/var/simplesamlphp/vendor/robrichards/xmlseclibs/src/XMLSecurityDSig.php'}
PARSER=r'''require '/var/simplesamlphp/lib/_autoload.php';$xml=stream_get_contents(STDIN);(new \SimpleSAML\Utils\XML())->checkSAMLMessage($xml,'saml-meta');$entities=\SimpleSAML\Metadata\SAMLParser::parseDescriptorsString($xml);$entity=$argv[1];if(!isset($entities[$entity]))throw new \RuntimeException('Expected entity missing');$sp=$entities[$entity]->getMetadata20SP();$peerIdp=$entities[$entity]->getMetadata20IdP();if($sp===null)throw new \RuntimeException('SP role missing');unset($sp['entityDescriptor'],$sp['expire']);$nativeSp=$sp;$encrypt=($argv[2]??'')==='encrypt';if($encrypt)$sp['assertion.encryption']=true;echo json_encode(['entityId'=>$entity,'validateAuthnRequest'=>$sp['validate.authnrequest']??null,'nativeSpMetadata'=>$nativeSp,'nativePeerIdpMetadata'=>$peerIdp,'metadata'=>$sp,'nativePolicy'=>['assertionEncryption'=>$encrypt,'keysModified'=>false],'php'=>'$metadata['.var_export($entity,true).'] = '.var_export($sp,true).';'],JSON_THROW_ON_ERROR);'''
READBACK=BASE_READBACK.replace("$keys=$native->getPublicKeys('signing');", "$keys=$native->getPublicKeys('signing');$encryptionKeys=$native->getPublicKeys('encryption');").replace('$resolved=null;$keys=[];', '$resolved=null;$keys=[];$encryptionKeys=[];').replace("'signingKeys'=>$keys", "'signingKeys'=>$keys,'encryptionKeys'=>$encryptionKeys")
SHA=lambda b:hashlib.sha256(b).hexdigest();NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def variant(f):return VARIANTS[0] if f.startswith('explicit-a-') else VARIANTS[1] if f.startswith('explicit-b-') else VARIANTS[2] if f.startswith('omitted-a-') else VARIANTS[3]
def validate_role_purposes(xml,n):
 root=ET.fromstring(xml)
 for local,label in [('SPSSODescriptor','nativeSpMetadata'),('IDPSSODescriptor','nativePeerIdpMetadata')]:
  role=root.find('{urn:oasis:names:tc:SAML:2.0:metadata}'+local)
  if role is None:raise ValueError('Full dual-role import prerequisite absent')
  for purpose in ['signing','encryption']:
   expected={SHA(base64.b64decode(''.join(k.find('.//{http://www.w3.org/2000/09/xmldsig#}X509Certificate').text.split()))) for k in role.findall('{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor') if not k.get('use') or k.get('use')==purpose}
   actual={SHA(base64.b64decode(''.join(k['X509Certificate'].split()))) for k in n[label]['keys'] if k.get(purpose)}
   if expected!=actual:raise ValueError('Native role/purpose import mismatch; no test-user login')
def normalised_native(n):return dict(requestMethod=n['method'],requestUrl=n['requestUrl'],requestId=n['requestId'],requestSha256=n['requestSha256'],startedAt=n['startedAt'],completedAt=n['finishedAt'],responseUrl=n['responseUrl'],responseStatus=n['responseStatus'],responseBodyBytes=n['responseBodyBytes'],responseBodySha256=n['responseBodySha256'],samlResponseFormPresent=n.get('samlResponseFormPresent',False),**({'responseSamlSha256':n['responseSamlSha256']} if n.get('samlResponseFormPresent') else {}))
class RoleClient(SharedClient):
 def request(self,url,fields=None):
  result=super().request(url,fields)
  if fields and 'SAMLRequest' in fields and self.protocol_posts:
   forms=[f for f in parse_forms(result[1]) if 'SAMLResponse' in f.fields]
   if len(forms)>1:raise ValueError('Ambiguous native SAML response form')
   self.protocol_posts[-1]['samlResponseFormPresent']=len(forms)==1
   if forms:self.protocol_posts[-1]['responseSamlSha256']=SHA(base64.b64decode(forms[0].fields['SAMLResponse'],validate=True))
  return result
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--min-free-mib',type=int,default=96);a=p.parse_args();space=os.statvfs(REPO)
 if a.min_free_mib<32 or space.f_bavail*space.f_frsize<a.min_free_mib*1024*1024:p.error('Insufficient disk before native settings/protocol/login')
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);receipt=out/'receipt';receipt.mkdir();(out/'collector-source.py').write_bytes(pathlib.Path(__file__).read_bytes());(receipt/'native-parser-command.php').write_text(PARSER);(receipt/'native-readback-command.php').write_text(READBACK)
 batch=ConfigurationBatch(CONFIG);batch.container,batch.container_path=CONTAINER,REMOTE;client=RoleClient();user=os.getenv('REFERENCE_USERNAME','samlscope-m0-user');password=os.getenv('REFERENCE_PASSWORD','samlscope-m0-password');refs={};commands=[];observations=[];skips=[];created=None;run=plan=entity=None;baseline=selected=0;restoration={'restored':False};baseline_safe=False
 def docker(*args,data=None,container=CONTAINER):
  start=NOW();r=subprocess.run(['docker','exec','-i',container,*args],input=data,capture_output=True,timeout=40);commands.append(dict(container=container,executable=args[0],startedAt=start,completedAt=NOW(),exitCode=r.returncode));save(out/'native-command-counts.json',commands)
  if r.returncode:raise ValueError('Native diagnostic failed; stop before more test-user operations')
  return r.stdout
 def runtime():
  fmt='{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}}}';r=subprocess.run(['docker','inspect','--format',fmt,CONTAINER],capture_output=True,check=True,timeout=20);n=json.loads(r.stdout);assert n['running'] is True;return n
 def inspect_original(name):
  fmt='[{"Id":{{json .Id}},"Image":{{json .Image}},"State":{"Running":{{json .State.Running}},"StartedAt":{{json .State.StartedAt}}},"Config":{}}]'
  raw=subprocess.check_output(['docker','inspect','--format',fmt,CONTAINER],timeout=20);assert json.loads(raw)[0]['State']['Running'] is True;(receipt/name).write_bytes(raw)
 def record(label,kind,**value):
  n=dict(schema='samlscope-simplesamlphp-role-key-original-v1',runId=run,campaignId=CAMPAIGN,targetMetadataSha256=SHA((receipt/'target-metadata.xml').read_bytes()),recordedAt=NOW(),kind=kind,**value);reject_sensitive(n);raw=canonical(n);before={e['id'] for e in api('/api/runs/'+run+'/transcript')};q=urllib.request.Request(BASE+'/p/'+plan+'/sp/paos?run='+run,data=raw,method='POST',headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(q,timeout=40) as r:assert r.status==204
  new=[e for e in api('/api/runs/'+run+'/transcript') if e['id'] not in before and e.get('decodedSamlRef')];assert len(new)==1;file='native-original-'+label+'.json';(receipt/file).write_bytes(raw);refs[label]=dict(reference=new[0]['id'],sha256=SHA(raw),file=file);return n
 def state(label,phase,v=None):
  start=NOW();raw=docker('php','-r',READBACK,data=canonical(dict(entities=[entity],sourcePaths=SOURCES)));end=NOW();n=json.loads(raw);reject_sensitive(n);actual=docker('cat',REMOTE);assert actual==batch.expected and n['configurationSha256']==SHA(actual);file='native-readback-'+label+'.json';(receipt/file).write_bytes(raw);return record(label,'native-role-key-state',phase=phase,variant=v,runtime=runtime(),nativeReadbackFile=file,nativeReadbackSha256=SHA(raw),nativeStartedAt=start,nativeFinishedAt=end,**n)
 def convert(v,xml,encrypt):
  start=NOW();raw=docker('php','-r',PARSER,entity,'encrypt' if encrypt else 'baseline',data=xml);end=NOW();n=json.loads(raw);reject_sensitive(n);assert n['entityId']==entity and n['validateAuthnRequest'] is True and n['metadata']['keys']==n['nativeSpMetadata']['keys'];(receipt/(v+'-parser-output.json')).write_bytes(raw);
  if encrypt:validate_role_purposes(xml,n)
  record(v+'-conversion','native-role-key-conversion',variant=v,entityId=entity,fixtureSha256=SHA(xml),parserOutputSha256=SHA(raw),parserOutput=n,nativeStartedAt=start,nativeFinishedAt=end);return n
 try:
  assert b'?>' not in batch.original and docker('cat',REMOTE)==batch.original
  if any(s in batch.original.lower() for s in (b'private.key',b'password',b'authorization',b'cookie')):raise ValueError('Credential-bearing metadata baseline; stop before capture')
  baseline_safe=True;(receipt/'original-configuration.php').write_bytes(batch.original);inspect_original('target-container-inspect-start.json')
  for name,path in SOURCES.items():
   prior=REPO/'build/acceptance/reference-20261002/simplesamlphp-certificate-runtime-r2/receipt/native-source'/name
   if prior.exists():os.link(prior,receipt/name)
   else:(receipt/name).write_bytes(docker('cat',path))
  response=api('/api/plans',dict(name='SimpleSAMLphp shared-session role/key and purpose scope',profile='metadata_idp',targetKind='IDP',targetEntityId=TARGET,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=30,testUserHint=user,requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',response);plan=response['plan']['plan']['id'];entity=BASE+'/p/'+plan;created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);save(receipt/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));assert entity.encode() not in batch.original
  subprocess.run(['docker','cp',SUITE+':/data/target-metadata/'+run+'.xml',str(receipt/'target-metadata.xml')],capture_output=True,check=True,timeout=40);(out/'target-metadata.xml').write_bytes((receipt/'target-metadata.xml').read_bytes());state('initial','initial')
  with urllib.request.urlopen(entity+'/metadata',timeout=30) as r:xml=r.read()
  (receipt/'baseline-fixture.xml').write_bytes(xml);base=convert('baseline',xml,False);parsed={};prepared={}
  # Validate ALL dual-role imports before the first test-user credential submission.
  for v in VARIANTS:
   save(out/(v+'-campaign.json'),api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=[v],pollingDelaySeconds=0)));lab=api('/api/runs/'+run+'/metadata-lab')
   with urllib.request.urlopen(lab['automaticStartUrl'],timeout=30) as r:assert r.status==202
   with urllib.request.urlopen(lab['metadataUrl'],timeout=30) as r:xml=r.read()
   root=ET.fromstring(xml);assert root.find('{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor') is not None and root.find('{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor') is not None;(receipt/(v+'-fixture.xml')).write_bytes(xml);parsed[v]=convert(v,xml,True);assert parsed[v]['nativePeerIdpMetadata'] is not None
   rows=[e for e in api('/api/runs/'+run+'/transcript') if e.get('samlSummary',{}).get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==v and e['samlSummary'].get('feed')=='live'];assert len(rows)==1;prepared[v]=rows[0]
  batch.apply(base['php'].encode());assert docker('cat',REMOTE)==batch.expected;(receipt/'baseline-configuration.php').write_bytes(batch.expected);time.sleep(3);state('baseline-before','configured','baseline');before={e['id'] for e in api('/api/runs/'+run+'/transcript')};count=client.native_post_attempts+client.native_redirect_attempts;result=client.flow(entity+'/start/m0-roundtrip?run='+run,None,user,password);baseline=client.native_post_attempts+client.native_redirect_attempts-count;assert result=='recorded' and baseline==1 and client.credential_posts==1;save(receipt/'baseline.json',dict(receipt=result,outboundReferences=[e['id'] for e in api('/api/runs/'+run+'/transcript') if e['id'] not in before and e['direction']=='OUTBOUND' and e.get('samlSummary',{}).get('type')=='AuthnRequest'],credentialPosts=1,protocolSubmissions=baseline));state('baseline-after','configured','baseline')
  batch.apply(parsed[VARIANTS[0]]['php'].encode());(receipt/(VARIANTS[0]+'-configuration.php')).write_bytes(batch.expected);time.sleep(3);save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));current=None;epoch=None
  for _ in range(400):
   if selected==11:break
   status=api('/api/runs/'+run+'/active-probe')
   if status['state']!='READY' and any(x.get('caseId')==CASE and x.get('kind')=='CONFIGURATION' for x in api('/api/runs/'+run+'/interactions')):save(out/'configure.json',api('/api/runs/'+run+'/cases/'+CASE+'/configure',dict(value='confirmed')));continue
   assert status['state']=='READY','Selected role-key outbox unavailable'
   if status.get('caseId')!=CASE:skips.append(prepare_and_skip(BASE,run,status,api));save(out/'suite-only-skips.json',skips);continue
   assert status.get('requiresFreshSession') is False,'No extra test-user login allowed';f=FIXTURES[selected];v=variant(f)
   if v!=current:
    if epoch is not None:state(current+'-after','configured',current);epoch['completedAt']=NOW();observations.append(epoch)
    if current is not None:batch.apply(parsed[v]['php'].encode());(receipt/(v+'-configuration.php')).write_bytes(batch.expected);time.sleep(3)
    epoch=dict(variant=v,startedAt=NOW(),preparedReference=prepared[v]['id'],fetchReference=prepared[v]['samlSummary']['fetchTranscriptId'],exchanges=[]);state(v+'-before','configured',v);current=v
   action=status['actionId'];old={e['id'] for e in api('/api/runs/'+run+'/transcript')};index=len(client.protocol_posts)
   def terminal(url,page,code,reason):
    if not public_terminal(page):raise ValueError('Unsafe native terminal body; never record forms')
    api('/api/runs/'+run+'/active-probe/browser-response',dict(actionId=action,status=code,url=url,body=page))
   result=client.flow(status['startUrl'],None,user,password,terminal_observer=terminal);entries=api('/api/runs/'+run+'/transcript');requests=[e for e in entries if e['id'] not in old and e['direction']=='OUTBOUND' and e.get('correlationId')==action and e.get('samlSummary',{}).get('type')=='AuthnRequest'];assert len(requests)==1 and len(client.protocol_posts)-index==1;request=requests[0];rid='_'+action;assert client.protocol_posts[index]['requestId']==rid
   replies=[e for e in entries if e['direction']=='INBOUND' and (e.get('samlSummary',{}).get('inResponseTo')==rid or e.get('correlationId')==action and e.get('samlSummary',{}).get('type')=='BrowserResponseObservation')];assert len(replies)==1;reply=replies[0];native=normalised_native(client.protocol_posts[index]);exchange=dict(fixtureId=f,requestReference=request['id'],responseReference=reply['id'],nativeHttp=[native]);epoch['exchanges'].append(exchange);record(f+'-http','native-role-key-http',fixtureId=f,requestReference=request['id'],responseReference=reply['id'],actionId=action,native=native);save(out/'current-epoch.json',epoch)
   if f.endswith('normal'):assert reply['method']!='BROWSER','Normal proof missing: stop without another login'
   after=api('/api/runs/'+run+'/active-probe')
   if after.get('state')=='AWAITING_RESPONSE' and after.get('actionId')==action:api('/api/runs/'+run+'/active-probe/abort',{})
   selected+=1
  assert selected==11;state(current+'-after','configured',current);epoch['completedAt']=NOW();observations.append(epoch);save(out/'observations.json',observations)
 finally:
  try:
   restoration=batch.restore();final=docker('cat',REMOTE);restoration['restored']=restoration.get('restored') is True and final==batch.original
   if baseline_safe and final==batch.original:(receipt/'final-configuration.php').write_bytes(final)
   if run:state('restoration','restored');inspect_original('target-container-inspect-end.json')
  except Exception as error:restoration=dict(restored=False,errorType=type(error).__name__)
  count=client.native_post_attempts+client.native_redirect_attempts;counts=dict(restored=restoration.get('restored') is True,nativeConfigurationWrites=batch.write_count,restorationWrites=batch.restoration_writes,initialBaselineSubmissions=baseline,selectedProbeAttempts=selected,outboxProtocolSubmissions=count-baseline,protocolSubmissions=count,credentialPosts=client.credential_posts,credentialPostAttempts=client.credential_attempts,personOperations=0,productRestarts=0,suiteOnlySkippedActions=len(skips),nativeCliExecutions=sum(c['executable']=='php' for c in commands));save(receipt/'operation-counts.json',counts);save(receipt/'restoration.json',restoration);save(out/'restoration.json',restoration);save(out/'native-protocol-posts.json',client.protocol_posts)
  if run:entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
 if not restoration.get('restored') or len(observations)!=4:raise ValueError('Incomplete campaign is not adoptable')
 for e in entries:
  if e['method']=='BROWSER':
   assert e['bodyRef']=='transcripts/'+run+'/'+e['id']+'.body';raw=docker('cat','/data/'+e['bodyRef'],container=SUITE);assert len(raw)==e['bodyBytes'] and public_terminal(raw.decode());(receipt/('browser-'+e['id']+'.body')).write_bytes(raw)
 files={x.name:SHA(x.read_bytes()) for x in receipt.iterdir() if x.is_file()};manifest=dict(schema='samlscope-metadata-role-key-consumption-v1',adapter='simplesamlphp-native-role-key-consumption-v1',campaignId=CAMPAIGN,runId=run,planId=plan,entityId=entity,targetMetadataSha256=SHA((receipt/'target-metadata.xml').read_bytes()),observations=observations,nativeOriginals=refs,originals=files);save(receipt/'manifest.json',manifest);print(json.dumps(dict(status='collected-not-adopted',runId=run,counts=counts)))
if __name__=='__main__':main()
