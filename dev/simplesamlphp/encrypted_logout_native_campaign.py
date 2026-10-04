#!/usr/bin/env python3
"""Two native decryption keys and selected Suite outbox logout probes; no adoption.

Private keys, authentication cookies and credentials remain only in native
configuration/in-memory clients. All configuration changes restore in finally.
"""
import argparse,base64,json,os,subprocess,time,zlib,urllib.request,urllib.parse,xml.etree.ElementTree as ET
from pathlib import Path
from transient_allow_create_campaign import REPO,CONTAINER,IDP,PREFIX,BASE,api,save,native,batch,raw,settled,ConfigurationBatch,NativeClient,STATE,sha,now,inspect_identity
from subject_confirmation_campaign import POLICY,SOURCES as BASE_SOURCES
from browser_probe_selection import prepare_and_skip
from metadata_replacement_campaign import arm
from import_metadata_batch import flow
from native_ui_privacy import sanitized,contains_state_secret
from capture_run_originals import capture
from keyvalue_runtime_campaign import RedirectTracker
SELECTED={'IIP-IDP17-a-idp-01','IIP-IDP19-c-idp-01'}
KEY_PATH='/tmp/samlscope-encrypted-logout-key.pem';CERT_PATH='/tmp/samlscope-encrypted-logout-cert.pem'
SOURCES={**BASE_SOURCES,'session':'src/SimpleSAML/Session.php','logout-request':'vendor/simplesamlphp/saml2-legacy/src/SAML2/LogoutRequest.php','crypto':'src/SimpleSAML/Utils/Crypto.php'}
GENERATE=r'''
foreach(array_slice($argv,1) as $p)if(file_exists($p)||is_link($p))throw new RuntimeException('Key path already owned');
$k=openssl_pkey_new(['private_key_type'=>OPENSSL_KEYTYPE_RSA,'private_key_bits'=>2048]);if($k===false)throw new RuntimeException('RSA generation failed');
$csr=openssl_csr_new(['commonName'=>'SAMLscope native decryption reference'],$k,['digest_alg'=>'sha256']);$cert=openssl_csr_sign($csr,null,$k,1,['digest_alg'=>'sha256']);openssl_pkey_export($k,$private);openssl_x509_export($cert,$public);
file_put_contents($argv[1],$private);chmod($argv[1],0600);file_put_contents($argv[2],$public);echo $public;
'''
KEYS=r'''
require '/var/simplesamlphp/lib/_autoload.php';$h=\SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();$idp=$h->getMetaDataConfig($argv[1],'saml20-idp-hosted');$sp=$h->getMetaDataConfig($argv[2],'saml20-sp-remote');
$keys=\SimpleSAML\Module\saml\Message::getDecryptionKeys($sp,$idp);$rows=[];foreach($keys as $key){$public=openssl_pkey_get_details($key->key)['key'];$der=base64_decode(preg_replace('/-----(?:BEGIN|END) PUBLIC KEY-----|\s/','',$public));$rows[]=['spkiBase64'=>base64_encode($der),'spkiSha256'=>hash('sha256',$der)];}
echo json_encode(['targetEntityId'=>$argv[1],'spEntityId'=>$argv[2],'keys'=>$rows,'privateMaterialPersisted'=>false],JSON_THROW_ON_ERROR);
'''
SESSION=r'''
require '/var/simplesamlphp/lib/_autoload.php';$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);$_COOKIE=$input['cookies'];$s=\SimpleSAML\Session::getSessionFromRequest();$auth=$s->getAuthState('example-userpass');$rows=[];
foreach($s->getAssociations('saml2:'.$input['entity']) as $a){$n=$a['saml:NameID'];$rows[]=['entity'=>$a['saml:entityID'],'handler'=>$a['Handler'],'nameId'=>$n->getValue(),'nameIdFormat'=>$n->getFormat()];}
echo json_encode(['authenticated'=>$s->isValid('example-userpass'),'sessionSha256'=>hash('sha256',$s->getSessionId()),'uid'=>$auth['Attributes']['uid']??null,'authnInstant'=>$auth['AuthnInstant']??null,'associations'=>$rows,'credentialsPersisted'=>false],JSON_THROW_ON_ERROR);
'''
DECRYPT=r'''
require '/var/simplesamlphp/lib/_autoload.php';$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);$h=\SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();$idp=$h->getMetaDataConfig($input['idp'],'saml20-idp-hosted');$sp=$h->getMetaDataConfig($input['sp'],'saml20-sp-remote');$d=\SAML2\DOMDocumentFactory::fromString($input['request']);$keys=\SimpleSAML\Module\saml\Message::getDecryptionKeys($sp,$idp);$rows=[];
foreach($keys as $i=>$key){$r=new \SAML2\LogoutRequest($d->documentElement);if(!$r->isNameIdEncrypted())throw new RuntimeException('Expected encrypted identifier');$public=openssl_pkey_get_details($key->key)['key'];$der=base64_decode(preg_replace('/-----(?:BEGIN|END) PUBLIC KEY-----|\s/','',$public));$row=['keyIndex'=>$i,'spkiSha256'=>hash('sha256',$der),'encryptedBefore'=>true];try{$r->decryptNameId($key);$n=$r->getNameId();$row['decrypted']=true;$row['nameId']=$n->getValue();$row['nameIdFormat']=$n->getFormat();}catch(Throwable $e){$row['decrypted']=false;$row['exceptionClass']=get_class($e);}$rows[]=$row;}
echo json_encode(['requestId'=>$d->documentElement->getAttribute('ID'),'requestSha256'=>hash('sha256',$input['request']),'targetEntityId'=>$input['idp'],'spEntityId'=>$input['sp'],'keysTried'=>$rows,'privateMaterialPersisted'=>false],JSON_THROW_ON_ERROR);
'''
VERIFY=r'''
require '/var/simplesamlphp/lib/_autoload.php';$i=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);$h=\SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();$m=$h->getMetaDataConfig($i['sp'],'saml20-sp-remote');$valid=false;
if($i['rawQuery']!==null){$parts=[];foreach(explode('&',$i['rawQuery']) as $piece){$v=explode('=',$piece,2);if(isset($parts[$v[0]]))throw new RuntimeException('Duplicate redirect component');$parts[$v[0]]=$piece;}$data=$parts['SAMLRequest'].'&'.$parts['RelayState'].'&'.$parts['SigAlg'];parse_str($i['rawQuery'],$q);$algorithm=['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'=>OPENSSL_ALGO_SHA256,'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'=>OPENSSL_ALGO_SHA384,'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'=>OPENSSL_ALGO_SHA512][$q['SigAlg']]??null;if($algorithm===null)throw new RuntimeException('Unknown signature algorithm');foreach($m->getPublicKeys('signing') as $k){$pem="-----BEGIN CERTIFICATE-----\n".chunk_split($k['X509Certificate'],64)."-----END CERTIFICATE-----\n";if(openssl_verify($data,base64_decode($q['Signature']),$pem,$algorithm)===1)$valid=true;}}else{$d=\SAML2\DOMDocumentFactory::fromString($i['request']);$c='\\SAML2\\'.$d->documentElement->localName;try{$valid=\SimpleSAML\Module\saml\Message::checkSign($m,new $c($d->documentElement));}catch(Throwable $e){$valid=false;}}
echo json_encode(['spEntityId'=>$i['sp'],'requestId'=>$i['requestId'],'requestSha256'=>hash('sha256',$i['request']),'rawQuerySha256'=>$i['rawQuery']===null?null:hash('sha256',$i['rawQuery']),'valid'=>$valid,'privateMaterialPersisted'=>false],JSON_THROW_ON_ERROR);
'''
def public_session(client):
 cookies={c.name:c.value for c in client.jar if c.domain in ['localhost.local','localhost','127.0.0.1']}
 return json.loads(subprocess.check_output(['docker','exec','-i',CONTAINER,'php','-r',SESSION],input=json.dumps(dict(cookies=cookies,entity=IDP)).encode(),timeout=30))
def public_redirect_location(url):
 params=urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
 return url if 'SAMLResponse' in params else urllib.parse.urlunsplit(urllib.parse.urlsplit(url)._replace(query='',fragment=''))
class LogoutClient(NativeClient):
 def __init__(self,records,responses,requests,states,sessions,entity):
  super().__init__(records,responses,requests,states);self.sessions=sessions;self.entity=entity;self.requests=requests;self.responses=responses;self.signatureChecks=[];self.allowInvalidControl=False;self.nativeGets={};self.pendingLogoutRecord=None
  owner=self
  class ObserveRedirect(RedirectTracker):
   def redirect_request(self,req,fp,code,msg,headers,newurl):
    params=urllib.parse.parse_qs(urllib.parse.urlsplit(newurl).query)
    if req.full_url in owner.nativeGets:
     record=owner.nativeGets[req.full_url];record.update(response_status=code,native_redirect_response_url=public_redirect_location(newurl),native_redirect_location_sha256=sha(newurl.encode()),redirect_received_at=now())
    if owner.pendingLogoutRecord is not None and urllib.parse.urlparse(req.full_url).port==18380 and 'SAMLResponse' in params:
     record=owner.pendingLogoutRecord;record.update(native_signed_response_url=newurl,native_signed_response_source_url=urllib.parse.urlunsplit(urllib.parse.urlsplit(req.full_url)._replace(query='',fragment='')),native_signed_response_status=code,observed_at=now());owner.sessions.append(dict(requestId=record['request_id'],phase='after-native-response',recordedAt=now(),session=public_session(owner)));owner.pendingLogoutRecord=None
    if urllib.parse.urlparse(newurl).port==18380 and 'SAMLRequest' in params:owner.before_native_redirect(newurl)
    return super().redirect_request(req,fp,code,msg,headers,newurl)
  self.redirects=ObserveRedirect();self.op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),self.redirects)
 def before_native_redirect(self,url):
  query=urllib.parse.urlsplit(url).query;params=urllib.parse.parse_qs(query);rawRequest=zlib.decompress(base64.b64decode(params['SAMLRequest'][0],validate=True),-15);root=ET.fromstring(rawRequest);ident=root.get('ID')
  if not root.tag.endswith('}LogoutRequest'):raise ValueError('Unexpected native Redirect request type')
  if url in self.nativeGets:raise ValueError('Duplicate native Redirect dispatch')
  checked=json.loads(subprocess.check_output(['docker','exec','-i',CONTAINER,'php','-r',VERIFY],input=json.dumps(dict(sp=self.entity,request=rawRequest.decode(),requestId=ident,rawQuery=query)).encode(),timeout=30));checked['allowInvalidControl']=False;self.signatureChecks.append(checked)
  if not checked['valid']:raise ValueError('Native Redirect signature failed before actual dispatch')
  self.sessions.append(dict(requestId=ident,phase='before-native-dispatch',recordedAt=now(),session=public_session(self)));self.requests[ident]=(rawRequest,query.encode());self.responses[ident]=b''
  record=dict(request_id=ident,request_sha256=sha(rawRequest),request_url=url,request_type=root.tag,request_method='GET',raw_query_sha256=sha(query.encode()),request_body_sha256=sha(query.encode()),started_at=now(),native_signature_rejection=None,nativeDirectResponseBody=False,saml_response_form_present=False)
  self.nativeGets[url]=record;self.pendingLogoutRecord=record;self.records.append(record)

 def request(self,url,fields=None):
  candidate=None;query=None;logout=False;started=now();before=len(self.records)
  if urllib.parse.urlparse(url).port==18380:
   if fields and 'SAMLRequest' in fields:candidate=base64.b64decode(fields['SAMLRequest'],validate=True)
   elif fields is None and 'SAMLRequest' in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query):
    query=urllib.parse.urlsplit(url).query;params=urllib.parse.parse_qs(query);candidate=zlib.decompress(base64.b64decode(params['SAMLRequest'][0],validate=True),-15)
  if candidate is not None:
   root=ET.fromstring(candidate);ident=root.get('ID');logout=root.tag.endswith('}LogoutRequest');r=json.loads(subprocess.check_output(['docker','exec','-i',CONTAINER,'php','-r',VERIFY],input=json.dumps(dict(sp=self.entity,request=candidate.decode(),requestId=ident,rawQuery=query)).encode(),timeout=30));r['allowInvalidControl']=self.allowInvalidControl;self.signatureChecks.append(r)
   if not r['valid'] and not self.allowInvalidControl:raise ValueError('Native requester signature self-check failed before submission')
   if logout:self.sessions.append(dict(requestId=ident,phase='before-native-dispatch',recordedAt=now(),session=public_session(self)))
  result=super().request(url,fields)
  if query is not None:
   final,page,status=result;self.requests[ident]=(candidate,query.encode());self.responses[ident]=page.encode();self.records.append(dict(request_id=ident,request_sha256=sha(candidate),request_url=url,request_type=root.tag,request_method='GET',raw_query_sha256=sha(query.encode()),request_body_sha256=sha(query.encode()),response_url=urllib.parse.urlunsplit(urllib.parse.urlsplit(final)._replace(query='',fragment='')),response_status=status,response_body_sha256=sha(page.encode()),started_at=started,observed_at=now(),native_signature_rejection=None,redirect_hops=self.redirects.count,saml_response_form_present='name="SAMLResponse"' in page,nativeDirectResponseBody=False))
  if logout:self.sessions.append(dict(requestId=ident,phase='after-native-response',recordedAt=now(),session=public_session(self)))
  return result
def readback(out,label,configs,entity):
 f=out/label;f.mkdir()
 for name,c in configs.items():(f/(name+'.php')).write_bytes(settled(c.container_path,c.expected))
 (f/'policy.json').write_bytes(subprocess.check_output(['docker','exec',CONTAINER,'php','-r',POLICY,IDP,entity],timeout=30));(f/'decryption-keys.json').write_bytes(subprocess.check_output(['docker','exec',CONTAINER,'php','-r',KEYS,IDP,entity],timeout=30));save(f/'observed.json',dict(recordedAt=now()))
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 remote=batch('saml20-sp-remote.php');hosted=batch('saml20-idp-hosted.php');override=ConfigurationBatch(PREFIX/'config-override.php');override.container_path='/var/simplesamlphp/config/config-override.php';configs=dict(remote=remote,hosted=hosted,override=override)
 for name,c in configs.items():(out/(name+'-original.php')).write_bytes(settled(c.container_path,c.original))
 for name,path in SOURCES.items():(out/('native-'+name+'.php')).write_bytes(raw('/var/simplesamlphp/'+path))
 for name,command in [('generate',GENERATE),('verify',VERIFY),('keys',KEYS),('session',SESSION),('decrypt',DECRYPT),('policy',POLICY),('state',STATE),('parser',native.PHP)]:(out/('native-'+name+'-command.php')).write_text(command)
 (out/'collector.py').write_bytes(Path(__file__).read_bytes())
 for name,path in {'native-client-collector.py':Path(__file__).with_name('subject_confirmation_campaign.py'),'native-keyvalue-client.py':Path(__file__).with_name('keyvalue_runtime_campaign.py'),'native-refresh-client.py':Path(__file__).with_name('metadata_refresh_campaign.py'),'native-http-client.py':REPO/'dev/keycloak/reference_flow.py','native-signature-client.py':Path(__file__).with_name('signed_request_observation.py'),'native-ui-privacy.py':Path(__file__).with_name('native_ui_privacy.py')}.items():(out/name).write_bytes(path.read_bytes())
 save(out/'identity-before.json',inspect_identity());run=None;entity=None;keyCreated=False;records=[];responses={};requests={};states=[];sessions=[];steps=[];clients=[];decrypt=[];parsers=skips=0
 credentials=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
 try:
  cert=subprocess.check_output(['docker','exec',CONTAINER,'php','-r',GENERATE,KEY_PATH,CERT_PATH],timeout=30);keyCreated=True;(out/'new-public-certificate.pem').write_bytes(cert)
  hosted.apply(("$metadata['"+IDP+"']['new_privatekey']='"+KEY_PATH+"';\n$metadata['"+IDP+"']['new_certificate']='"+CERT_PATH+"';\n$metadata['"+IDP+"']['sign.logout']=true;").encode());time.sleep(3)
  plan=api('/api/plans',dict(name='SimpleSAMLphp native encrypted logout two-key campaign',profile='single_logout_idp',targetKind='IDP',targetEntityId=IDP,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint=credentials[0],requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];entity=BASE+'/p/'+pid
  created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
  save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=['control'],pollingDelaySeconds=0)));control=out/'control';control.mkdir();state,fixture=arm(run,control,'control');parsers+=1
  r=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],input=fixture,capture_output=True,timeout=30);(control/'parser.stdout').write_bytes(r.stdout);(control/'parser.stderr').write_bytes(r.stderr)
  if r.returncode:raise ValueError('Native baseline parser rejected fixture')
  remote.apply(json.loads(r.stdout)['php'].encode());time.sleep(3);readback(out,'before',configs,entity)
  keys=json.loads((out/'before/decryption-keys.json').read_bytes())['keys'];assert len(keys)==2 and len({r['spkiSha256'] for r in keys})==2
  policy=json.loads((out/'before/policy.json').read_bytes());assert policy['hosted']['sign.logout'] is True
  save(out/'pre-send-checks.json',dict(nativeDecryptionKeyCount=2,nativeDistinctPublicKeys=True,nativeSignLogout=True,collectorTransportGuards='encrypted_logout_native_campaign_test.py:6-pass',actualRequestsRequireNativeSignatureSelfcheck=True,privateMaterialArchived=False))
  scope=api('/api/runs/'+run+'/supplemental-decryption-keys');save(out/'supplemental-before.json',scope);save(out/'supplemental-submit.json',api('/api/runs/'+run+'/supplemental-decryption-keys/submit',dict(targetEntityId=IDP,metadataSha256=scope['metadataSha256'],sourceUri='http://localhost:18380/simplesaml/module.php/saml/idp/metadata',publicKeysSpkiBase64=[r['spkiBase64'] for r in keys])))
  client=LogoutClient(records,responses,requests,states,sessions,entity);clients.append(client);client.allowInvalidControl=True;flow(run,control/'flow.json',suite_signature_control=True,login_inputs=credentials,client_factory=lambda **kw:client)
  baseline=out/'baseline';baseline.mkdir()
  with urllib.request.urlopen(entity+'/metadata',timeout=30) as response:baselineFixture=response.read()
  (baseline/'fixture.xml').write_bytes(baselineFixture);parsers+=1
  parsed=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],input=baselineFixture,capture_output=True,timeout=30);(baseline/'parser.stdout').write_bytes(parsed.stdout);(baseline/'parser.stderr').write_bytes(parsed.stderr)
  if parsed.returncode:raise ValueError('Native ordinary Suite metadata parser rejected baseline')
  remote.apply(json.loads(parsed.stdout)['php'].encode());time.sleep(3);readback(out,'baseline-before',configs,entity)
  save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));seen=set();active=None
  for _ in range(240):
   status=api('/api/runs/'+run+'/active-probe')
   if status['state']=='AWAITING_RESPONSE':api('/api/runs/'+run+'/active-probe/abort',{});steps.append(dict(caseId=status['caseId'],actionId=status['actionId'],action='unexpected-await-aborted'));continue
   if status['state']!='READY':break
   case=status['caseId']
   if case not in SELECTED:steps.append(prepare_and_skip(BASE,run,status,api));skips+=1;continue
   if active!=case:client=LogoutClient(records,responses,requests,states,sessions,entity);clients.append(client);active=case
   readback(out,'stage-'+str(len(steps))+'-before',configs,entity);result=client.flow(status['startUrl'],dict(freshSessionConfirmed='true'),*credentials);after=api('/api/runs/'+run+'/active-probe');steps.append(dict(caseId=case,actionId=status['actionId'],startedAt=now(),result=result,sentToTarget=True,nextState=after['state']));save(out/'steps.json',steps)
   if after.get('caseId')!=case:seen.add(case)
   if after['state']=='AWAITING_RESPONSE' and after.get('actionId')==status['actionId']:api('/api/runs/'+run+'/active-probe/abort',{});steps[-1]['unavailableReported']=True
   if seen==SELECTED:break
  readback(out,'after',configs,entity)
  for row in records:
   if row['request_type'].endswith('}LogoutRequest'):
    ident=row['request_id'];root=ET.fromstring(requests[ident][0]);encrypted=root.find('{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedID')
    if encrypted is not None:
     result=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',DECRYPT],input=json.dumps(dict(idp=IDP,sp=entity,request=requests[ident][0].decode())).encode(),capture_output=True,timeout=30);name='native-decrypt-'+ident+'.json';(out/name).write_bytes(result.stdout);(out/(name+'.stderr')).write_bytes(result.stderr);decrypt.append(dict(requestId=ident,file=name,returncode=result.returncode));
  save(out/'native-decryption-attempts.json',decrypt);save(out/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}))
 except Exception as error:
  save(out/'campaign-error.json',dict(errorType=type(error).__name__,message=str(error)[:800],runId=run,verdictAdopted=False));raise
 finally:
  restore={}
  for name,c in configs.items():restore[name]=c.restore();(out/(name+'-final.php')).write_bytes(settled(c.container_path,c.original))
  if keyCreated:subprocess.run(['docker','exec',CONTAINER,'rm','--',KEY_PATH,CERT_PATH],check=True,capture_output=True)
  save(out/'ephemeral-key-cleanup.json',dict(created=keyCreated,removed=keyCreated,privateMaterialArchived=False));save(out/'restoration.json',restore);save(out/'identity-after.json',inspect_identity())
  for name,path in SOURCES.items():(out/('native-'+name+'-after.php')).write_bytes(raw('/var/simplesamlphp/'+path))
  save(out/'native-signature-selfchecks.json',dict(records=[r for c in clients for r in c.signatureChecks],nativeVerificationInvocations=sum(len(c.signatureChecks) for c in clients)));save(out/'native-state-observations.json',dict(runId=run,observations=states));save(out/'native-session-observations.json',dict(runId=run,observations=sessions));dest=out/'native-http-originals';dest.mkdir()
  for row in records:
   ident=row['request_id'];page=sanitized(responses[ident].decode(),None).encode();assert not contains_state_secret(page.decode());(dest/(ident+'.html')).write_bytes(page);row['persisted_body_sha256']=sha(page);row['body_sanitized']=page!=responses[ident];xml,body=requests[ident];(dest/(ident+'.request.xml')).write_bytes(xml);(dest/(ident+'.request.body')).write_bytes(body)
  save(out/'native-http-observations.json',dict(runId=run,records=records,productVerdictAssigned=False));save(out/'steps.json',steps);save(out/'operation-counts.json',dict(productConfigurationWriteAttempts=sum(c.write_count for c in configs.values()),configurationApplyWrites=sum(c.applied_count for c in configs.values()),restorationWrites=sum(c.restoration_writes for c in configs.values()),nativeParserInvocations=parsers,nativeDecryptInvocations=len(decrypt),nativeVerificationInvocations=sum(len(c.signatureChecks) for c in clients),protocolOperationsAttempted=len(records),credentialPosts=sum(c.credentialPosts for c in clients),suiteOnlyPreparedAborts=skips,runCreations=int(run is not None),productRestarts=0,humanOperations=0,nativeEphemeralKeyCreations=int(keyCreated),nativeEphemeralFileWrites=2 if keyCreated else 0,nativeEphemeralFileRemovals=2 if keyCreated else 0,restored=all(v['restored'] for v in restore.values())))
  if run:
   for suffix in ['result.json','protocol-evidence','transcript']:
    try:save(out/(suffix if '.' in suffix else suffix+'.json'),api('/api/runs/'+run+'/'+suffix))
    except Exception as unavailable:save(out/(suffix.replace('.','-')+'-unavailable.json'),dict(errorType=type(unavailable).__name__,message=str(unavailable)[:800]))
   capture(out,run,json.loads((out/'transcript.json').read_bytes()));subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,capture_output=True)
 print(run,'native two-key logout diagnostics; restored; no adoption')
if __name__=='__main__':main()
