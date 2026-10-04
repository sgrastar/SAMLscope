#!/usr/bin/env python3
"""Reference-only ambient-auth exclusion proof, normal login and native passive error.

Requires local reference Docker read/write, public Suite APIs and a demo credential
in memory; this is not a generic remote-user capability or an attestation adapter.
"""
import argparse,base64,json,os,subprocess,time,urllib.request,urllib.parse,xml.etree.ElementTree as ET
from pathlib import Path
from subject_confirmation_campaign import SOURCES,POLICY,STATE,NativeClient,readback,sha,now
from persistent_nameid_normal_campaign import REPO,CONTAINER,IDP,PREFIX,api,save,BASE,native,batch,raw,settled,ConfigurationBatch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from encrypted_logout_native_campaign import VERIFY,SESSION,public_session
from keyvalue_runtime_campaign import inspect_identity
from metadata_replacement_campaign import arm
from import_metadata_batch import flow
from browser_probe_selection import prepare_and_skip
from capture_run_originals import capture
from native_ui_privacy import sanitized,contains_state_secret
SOURCES={**SOURCES,'session':'src/SimpleSAML/Session.php'}
CASE='IIP-SSO01-ae-idp-01';PROBE='IIP-IDP06-c-idp-01'
PRINCIPAL=r'''
require '/var/simplesamlphp/lib/_autoload.php';$i=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);$a=\SimpleSAML\Configuration::getConfig('authsources.php')->getArray('example-userpass');$rows=[];foreach($a['users'] as $k=>$v){$p=explode(':',$k,2);$rows[]=['principal'=>$p[0],'attributes'=>$v];}$s=new \SimpleSAML\Module\exampleauth\Auth\Source\UserPass(['AuthId'=>'example-userpass'],$a);$m=new ReflectionMethod($s,'login');$m->setAccessible(true);$attrs=$m->invoke($s,$i['principal'],$i['password']);echo json_encode(['class'=>$a[0],'sourceSha256'=>hash_file('sha256','/var/simplesamlphp/config/authsources.php'),'users'=>$rows,'authenticatedPrincipal'=>$i['principal'],'authenticatedAttributes'=>$attrs,'credentialsPersisted'=>false],JSON_THROW_ON_ERROR);
'''
PRODUCER=r'''
require '/var/simplesamlphp/lib/_autoload.php';$i=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);$d=\SAML2\DOMDocumentFactory::fromString($i['response']);$x=new DOMXPath($d);$x->registerNamespace('s','urn:oasis:names:tc:SAML:2.0:assertion');$x->registerNamespace('ds','http://www.w3.org/2000/09/xmldsig#');foreach(iterator_to_array($x->query('//ds:Signature')) as $n)$n->parentNode->removeChild($n);if($i['kind']==='wrong-principal'){$a=$x->query('//s:Attribute[@Name="uid"]/s:AttributeValue')->item(0);if($a===null)throw new RuntimeException('No UID');$a->nodeValue='samlscope-wrong-principal';}elseif($i['kind']==='error-with-assertion'){$p=\SAML2\DOMDocumentFactory::fromString($i['positive']);$a=$p->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion','Assertion')->item(0);if($a===null)throw new RuntimeException('No plain positive assertion');$d->documentElement->appendChild($d->importNode($a,true));}else throw new RuntimeException('Unknown producer');$key=new \RobRichards\XMLSecLibs\XMLSecurityKey(\RobRichards\XMLSecLibs\XMLSecurityKey::RSA_SHA256,['type'=>'private']);$key->loadKey('/var/simplesamlphp/cert/server.pem',true);$cert=file_get_contents('/var/simplesamlphp/cert/server.crt');$r=$d->documentElement;$status=$r->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol','Status')->item(0);\SAML2\Utils::insertSignature($key,[$cert],$r,$status);echo $d->saveXML();
'''
class IdentityClient(NativeClient):
 def __init__(self,records,responses,requests,states,sessions,entity):super().__init__(records,responses,requests,states);self.sessions=sessions;self.entity=entity;self.verifications=[];self.allowInvalidControl=False;self.actions=[]
 def request(self,url,fields=None):
  if fields and 'SAMLRequest' in fields and urllib.parse.urlparse(url).port==18380:
   xml=base64.b64decode(fields['SAMLRequest'],validate=True);root=ET.fromstring(xml);checked=json.loads(subprocess.check_output(['docker','exec','-i',CONTAINER,'php','-r',VERIFY],input=json.dumps(dict(sp=self.entity,request=xml.decode(),requestId=root.get('ID'),rawQuery=None)).encode(),timeout=30));checked['allowInvalidControl']=self.allowInvalidControl;self.verifications.append(checked)
   if not checked['valid'] and not self.allowInvalidControl:raise ValueError('Actual native signature preflight rejected request before dispatch')
  if fields and 'password' in fields and urllib.parse.urlparse(url).port==18380:self.actions.append(dict(kind='credential-post',at=now(),valuesPersisted=False))
  result=super().request(url,fields);final,page,status=result
  if status==200 and '/core/loginuserpass' in final and 'name="username"' in page:self.sessions.append(dict(kind='native-login-challenge',at=now(),session=public_session(self),credentialPostsSoFar=self.credentialPosts))
  return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 remote=batch('saml20-sp-remote.php');hosted=batch('saml20-idp-hosted.php');override=ConfigurationBatch(PREFIX/'config-override.php');override.container_path='/var/simplesamlphp/config/config-override.php';configs=dict(remote=remote,hosted=hosted,override=override)
 for n,c in configs.items():(out/(n+'-original.php')).write_bytes(settled(c.container_path,c.original))
 for n,path in SOURCES.items():(out/('native-'+n+'.php')).write_bytes(raw('/var/simplesamlphp/'+path))
 for n,s in [('policy',POLICY),('state',STATE),('session',SESSION),('verify',VERIFY),('principal',PRINCIPAL),('producer',PRODUCER),('parser',native.PHP)]:(out/('native-'+n+'-command.php')).write_text(s)
 (out/'collector.py').write_bytes(Path(__file__).read_bytes())
 for n in ['subject_confirmation_campaign.py','keyvalue_runtime_campaign.py','metadata_refresh_campaign.py','signed_request_observation.py','native_ui_privacy.py']:(out/('helper-'+n)).write_bytes(Path(__file__).with_name(n).read_bytes())
 save(out/'identity-before.json',inspect_identity());credentials=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'));records=[];responses={};requests={};states=[];sessions=[];clients=[];steps=[];run=None;parsers=skips=producers=0
 try:
  plan=api('/api/plans',dict(name='SimpleSAMLphp native identity prerequisite',profile='browser_sso_idp',targetKind='IDP',targetEntityId=IDP,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint=credentials[0],requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];entity=BASE+'/p/'+pid;created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=['control'],pollingDelaySeconds=0)))
  control=out/'control';control.mkdir();_,fixture=arm(run,control,'control');parsers+=1;r=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],input=fixture,capture_output=True,timeout=30);(control/'parser.stdout').write_bytes(r.stdout);(control/'parser.stderr').write_bytes(r.stderr);save(control/'parser-return.json',dict(returncode=r.returncode));assert r.returncode==0;remote.apply(json.loads(r.stdout)['php'].encode());time.sleep(3);readback(out,'control-before',configs,entity)
  client=IdentityClient(records,responses,requests,states,sessions,entity);clients.append(client);client.allowInvalidControl=True;flow(run,control/'flow.json',suite_signature_control=True,login_inputs=credentials,client_factory=lambda **kw:client);readback(out,'control-after',configs,entity)
  principal=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',PRINCIPAL],input=json.dumps(dict(principal=credentials[0],password=credentials[1])).encode(),capture_output=True,timeout=30);assert principal.returncode==0;(out/'native-principal.json').write_bytes(principal.stdout)
  baseline=out/'baseline';baseline.mkdir()
  with urllib.request.urlopen(entity+'/metadata',timeout=30) as response:fixture=response.read()
  (baseline/'fixture.xml').write_bytes(fixture);parsers+=1;r=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],input=fixture,capture_output=True,timeout=30);(baseline/'parser.stdout').write_bytes(r.stdout);(baseline/'parser.stderr').write_bytes(r.stderr);save(baseline/'parser-return.json',dict(returncode=r.returncode));assert r.returncode==0;remote.apply(json.loads(r.stdout)['php'].encode());time.sleep(3);readback(out,'passive-before',configs,entity);save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));passive=IdentityClient(records,responses,requests,states,sessions,entity);clients.append(passive);save(out/'fresh-passive-client.json',dict(cookieCount=len(list(passive.jar)),credentialPosts=0,session=public_session(passive),at=now()))
  for _ in range(240):
   status=api('/api/runs/'+run+'/active-probe')
   if status['state']!='READY':raise ValueError('Passive scenario not ready: '+status['state'])
   if status['caseId']!=PROBE:steps.append(prepare_and_skip(BASE,run,status,api));skips+=1;continue
   result=passive.flow(status['startUrl'],dict(freshSessionConfirmed='true'),*credentials);steps.append(dict(caseId=PROBE,actionId=status['actionId'],result=result,sentToTarget=True));break
  readback(out,'passive-after',configs,entity);entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
  refs=json.loads((control/'flow.json').read_bytes())['positive_exchange']['transcript_ids'];positive=next(e for e in entries if e['id'] in refs and e['direction']=='INBOUND');errors=[e for e in entries if e['direction']=='INBOUND' and e['samlSummary'].get('fixture_id')=='force-authn-passive'];assert len(errors)==1;normal=(out/'decoded'/(positive['id']+'.xml')).read_bytes();error=(out/'decoded'/(errors[0]['id']+'.xml')).read_bytes()
  for kind,body in [('wrong-principal',normal),('error-with-assertion',error)]:
   r=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',PRODUCER],input=json.dumps(dict(kind=kind,response=body.decode(),positive=normal.decode())).encode(),capture_output=True,timeout=30);producers+=1;(out/(kind+'.xml')).write_bytes(r.stdout);(out/(kind+'.stderr')).write_bytes(r.stderr);assert r.returncode==0
  save(out/'producer.json',dict(positiveResponseReference=positive['id'],errorResponseReference=errors[0]['id'],privateMaterialExported=False,adopted=False))
 except Exception as e:save(out/'campaign-error.json',dict(type=type(e).__name__,message=str(e)[:400],adopted=False));raise
 finally:
  restore={}
  for n,c in configs.items():restore[n]=c.restore();(out/(n+'-final.php')).write_bytes(settled(c.container_path,c.original))
  save(out/'restoration.json',restore);save(out/'identity-after.json',inspect_identity())
  for n,path in SOURCES.items():(out/('native-'+n+'-after.php')).write_bytes(raw('/var/simplesamlphp/'+path))
  dest=out/'native-http-originals';dest.mkdir()
  for row in records:
   ident=row['request_id'];page=sanitized(responses[ident].decode(),None).encode();assert not contains_state_secret(page.decode());(dest/(ident+'.html')).write_bytes(page);row['persisted_body_sha256']=sha(page);xml,body=requests[ident];(dest/(ident+'.request.xml')).write_bytes(xml);(dest/(ident+'.request.body')).write_bytes(body)
  for n,v in [('native-http-observations',dict(records=records)),('native-state-observations',dict(observations=states)),('native-session-observations',dict(observations=sessions)),('native-signature-selfchecks',dict(records=[r for c in clients for r in c.verifications])),('native-credential-actions',dict(records=[r for c in clients for r in c.actions])),('steps',steps)]:save(out/(n+'.json'),v)
  save(out/'operation-counts.json',dict(productConfigurationWriteAttempts=sum(c.write_count for c in configs.values()),configurationApplyWrites=sum(c.applied_count for c in configs.values()),restorationWrites=sum(c.restoration_writes for c in configs.values()),nativeParserInvocations=parsers,protocolOperationsAttempted=len(records),credentialPosts=sum(c.credentialPosts for c in clients),nativeSignedProducerInvocations=producers,runCreations=int(run is not None),suiteOnlyPreparedAborts=skips,humanOperations=0,productRestarts=0,restored=all(r['restored'] for r in restore.values())))
  if run:
   for suffix in ['result.json','protocol-evidence','transcript']:save(out/(suffix if '.' in suffix else suffix+'.json'),api('/api/runs/'+run+'/'+suffix))
   capture(out,run,json.loads((out/'transcript.json').read_bytes()));subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,capture_output=True)
  assert all(r['restored'] for r in restore.values())
 print(run,'native identity observations restored; no adoption')
if __name__=='__main__':main()
