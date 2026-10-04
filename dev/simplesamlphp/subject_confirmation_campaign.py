#!/usr/bin/env python3
"""One native browser SSO, fixed factory closure and signed attester controls.

Controls are produced inside the product for oracle calibration; they are never
submitted as target observations. Passwords, cookies and authentication state
handles exist only in memory. Only the isolated native SP registration changes.
"""
import argparse,base64,hashlib,json,os,subprocess,sys,time,urllib.parse,xml.etree.ElementTree as ET
from datetime import datetime,timezone
from pathlib import Path
from persistent_nameid_normal_campaign import REPO,CONTAINER,IDP,PREFIX,api,save,BASE,native,batch,raw,settled,ConfigurationBatch
from metadata_replacement_campaign import arm
from keyvalue_runtime_campaign import KeyValueClient,inspect_identity
from import_metadata_batch import flow
from native_ui_privacy import sanitized,contains_state_secret
sys.path.insert(0,str(REPO/'dev/keycloak'));from reference_flow import parse_forms

SOURCES={
 'idp-saml2':'modules/saml/src/IdP/SAML2.php','idp':'src/SimpleSAML/IdP.php',
 'auth-processing':'src/SimpleSAML/Auth/ProcessingChain.php','auth-source':'src/SimpleSAML/Auth/Source.php',
 'userpass':'modules/exampleauth/src/Auth/Source/UserPass.php','userpass-base':'modules/core/src/Auth/UserPassBase.php',
 'language-adaptor':'modules/core/src/Auth/Process/LanguageAdaptor.php','attribute-limit':'modules/core/src/Auth/Process/AttributeLimit.php',
 'assertion':'vendor/simplesamlphp/saml2-legacy/src/SAML2/Assertion.php',
 'subject-confirmation':'vendor/simplesamlphp/saml2-legacy/src/SAML2/XML/saml/SubjectConfirmation.php',
 'subject-confirmation-data':'vendor/simplesamlphp/saml2-legacy/src/SAML2/XML/saml/SubjectConfirmationData.php',
 'response':'vendor/simplesamlphp/saml2-legacy/src/SAML2/Response.php',
 'xml-signer':'vendor/simplesamlphp/saml2-legacy/src/SAML2/Utils.php',
 'message':'modules/saml/src/Message.php','web-browser-sso':'modules/saml/src/Controller/WebBrowserSingleSignOn.php',
 'login-controller':'modules/core/src/Controller/Login.php','auth-state':'src/SimpleSAML/Auth/State.php',
 'configuration':'src/SimpleSAML/Configuration.php','parser':'src/SimpleSAML/Metadata/SAMLParser.php'}
POLICY=r'''
require '/var/simplesamlphp/lib/_autoload.php';
$c=\SimpleSAML\Configuration::getInstance();$h=\SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();
$idp=$h->getMetaData($argv[1],'saml20-idp-hosted');$peer=$h->getMetaData($argv[2],'saml20-sp-remote');
$a=\SimpleSAML\Configuration::getConfig('authsources.php')->getArray($idp['auth']);
echo json_encode(['targetEntityId'=>$argv[1],'spEntityId'=>$argv[2],'hosted'=>$idp,'peer'=>$peer,
 'globalAuthproc'=>$c->getOptionalArray('authproc.idp',[]),'authsource'=>['id'=>$idp['auth'],'class'=>$a[0],'authproc'=>$a['authproc']??null],
 'proxyAuthnContext'=>$c->getOptionalBoolean('proxymode.passAuthnContextClassRef',false),
 'metadataSources'=>$c->getArray('metadata.sources'),'configSha256'=>hash_file('sha256','/var/simplesamlphp/config/config.php'),
 'authsourceSha256'=>hash_file('sha256','/var/simplesamlphp/config/authsources.php')],JSON_THROW_ON_ERROR);
'''
STATE=r'''
require '/var/simplesamlphp/lib/_autoload.php';$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);$_COOKIE=$input['cookies'];
$s=\SimpleSAML\Auth\State::loadState($input['authState'],\SimpleSAML\Module\core\Auth\UserPassBase::STAGEID);
echo json_encode(['requestId'=>$s['saml:RequestId'],'consumerURL'=>$s['saml:ConsumerURL'],'binding'=>$s['saml:Binding'],
 'responder'=>$s['Responder'],'returnCall'=>$s['ReturnCall']??null,'idpMetadata'=>$s['IdPMetadata'],
 'spMetadata'=>$s['SPMetadata'],'forceAuthn'=>$s['ForceAuthn'],'isPassive'=>$s['isPassive']],JSON_THROW_ON_ERROR);
'''
PRODUCER=r'''
require '/var/simplesamlphp/lib/_autoload.php';$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$d=\SAML2\DOMDocumentFactory::fromString($input['response']);$xp=new DOMXPath($d);$xp->registerNamespace('s','urn:oasis:names:tc:SAML:2.0:assertion');$xp->registerNamespace('d','http://www.w3.org/2000/09/xmldsig#');
foreach(iterator_to_array($xp->query('//d:Signature')) as $n)$n->parentNode->removeChild($n);
$a=$xp->query('//s:Assertion')->item(0);$subject=$xp->query('./s:Subject',$a)->item(0);$sc=$xp->query('./s:SubjectConfirmation',$subject)->item(0);$kind=$input['kind'];
$add=function($sc,$value)use($d){$n=$d->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion','saml:NameID');$n->setAttribute('Format','urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');$n->nodeValue=$value;$sc->insertBefore($n,$sc->firstChild);};
if($kind==='foreign-positive')$add($sc,$input['attesters'][0]);
elseif($kind==='foreign-missing-identifier'){}
elseif($kind==='multiple-positive'){$clone=$sc->cloneNode(true);$add($sc,$input['attesters'][0]);$add($clone,$input['attesters'][1]);$subject->appendChild($clone);}
elseif($kind==='multiple-packed-identifiers'){$add($sc,$input['attesters'][1]);$add($sc,$input['attesters'][0]);}
else throw new \RuntimeException('Unknown control');
$key=new \RobRichards\XMLSecLibs\XMLSecurityKey(\RobRichards\XMLSecLibs\XMLSecurityKey::RSA_SHA256,['type'=>'private']);$key->loadKey('/var/simplesamlphp/cert/server.pem',true);$cert=file_get_contents('/var/simplesamlphp/cert/server.crt');
\SAML2\Utils::insertSignature($key,[$cert],$a,$subject);$r=$d->documentElement;$status=$r->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol','Status')->item(0);\SAML2\Utils::insertSignature($key,[$cert],$r,$status);echo $d->saveXML();
'''
def sha(v):return hashlib.sha256(v).hexdigest()
def now():return datetime.now(timezone.utc).isoformat()
class NativeClient(KeyValueClient):
 def __init__(self,records,responses,requests,observations):super().__init__(records,responses,requests);self.observations=observations;self.credentialPosts=0
 def request(self,url,fields=None):
  if fields and 'password' in fields and urllib.parse.urlparse(url).port==18380:self.credentialPosts+=1
  final,page,status=super().request(url,fields)
  if status==200 and '/core/loginuserpass' in final and 'name="username"' in page:
   matches=[f for f in parse_forms(page) if 'AuthState' in f.fields]
   if len(matches)!=1:raise ValueError('Native login state ambiguous')
   token=matches[0].fields['AuthState'];cookies={c.name:c.value for c in self.jar if c.domain in ['localhost.local','localhost','127.0.0.1']}
   r=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',STATE],input=json.dumps(dict(cookies=cookies,authState=token)).encode(),capture_output=True,timeout=30)
   if r.returncode:raise ValueError('Native public state readback unavailable')
   self.observations.append(dict(recordedAt=now(),state=json.loads(r.stdout),stateHandlePersisted=False))
  return final,page,status
def readback(out,label,configs,entity):
 folder=out/label;folder.mkdir()
 for name,c in configs.items():(folder/(name+'.php')).write_bytes(settled(c.container_path,c.expected))
 (folder/'policy.json').write_bytes(subprocess.check_output(['docker','exec',CONTAINER,'php','-r',POLICY,IDP,entity],timeout=30));save(folder/'observed.json',dict(recordedAt=now()))
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 remote=batch('saml20-sp-remote.php');hosted=batch('saml20-idp-hosted.php');override=ConfigurationBatch(PREFIX/'config-override.php');override.container_path='/var/simplesamlphp/config/config-override.php';configs=dict(remote=remote,hosted=hosted,override=override)
 for name,c in configs.items():
  if raw(c.container_path)!=c.original:raise ValueError('Native baseline differs')
  (out/(name+'-original.php')).write_bytes(c.original)
 for name,path in SOURCES.items():(out/('native-'+name+'.php')).write_bytes(raw('/var/simplesamlphp/'+path))
 for name,value in [('policy',POLICY),('state',STATE),('producer',PRODUCER),('parser',native.PHP)]:(out/('native-'+name+'-command.php')).write_text(value)
 (out/'collector.py').write_bytes(Path(__file__).read_bytes());(out/'native-ui-privacy.py').write_bytes(Path(__file__).with_name('native_ui_privacy.py').read_bytes());save(out/'identity-before.json',inspect_identity())
 records=[];responses={};requests={};observations=[];client=NativeClient(records,responses,requests,observations);run=None;parsers=protocol=producers=0
 credentials=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
 try:
  plan=api('/api/plans',dict(name='SimpleSAMLphp native attester factory closure',profile='browser_sso_idp',targetKind='IDP',targetEntityId=IDP,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint=credentials[0],requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];entity=BASE+'/p/'+pid
  created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=['control'],pollingDelaySeconds=0)))
  folder=out/'control';folder.mkdir();state,fixture=arm(run,folder,'control');parsers+=1
  parsed=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],input=fixture,capture_output=True,timeout=30);(folder/'parser.stdout').write_bytes(parsed.stdout);(folder/'parser.stderr').write_bytes(parsed.stderr)
  save(out/'parser-attempt.json',dict(returncode=parsed.returncode))
  if parsed.returncode:raise ValueError('Native product parser rejected ordinary control')
  remote.apply(json.loads(parsed.stdout)['php'].encode());time.sleep(3);readback(out,'before',configs,entity);protocol+=2
  flow(run,folder/'flow.json',suite_signature_control=True,login_inputs=credentials,client_factory=lambda **kw:client)
  readback(out,'after',configs,entity);save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
  sys.path.insert(0,str(REPO/'dev/reference-acceptance'));from capture_run_originals import capture
  entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
  ref=json.loads((folder/'flow.json').read_bytes())['positive_exchange']['transcript_ids'];positive=[e for e in entries if e['id'] in ref and e['direction']=='INBOUND'];assert len(positive)==1
  source=(out/'decoded'/(positive[0]['id']+'.xml')).read_bytes();attesters=['urn:samlscope:attester-control:one','urn:samlscope:attester-control:two']
  for kind in ['foreign-positive','foreign-missing-identifier','multiple-positive','multiple-packed-identifiers']:
   producers+=1;r=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',PRODUCER],input=json.dumps(dict(response=source.decode(),kind=kind,attesters=attesters)).encode(),capture_output=True,timeout=30)
   if r.returncode:raise ValueError('Native signed attester producer unavailable')
   (out/(kind+'.xml')).write_bytes(r.stdout)
  save(out/'producer.json',dict(baseResponseReference=positive[0]['id'],baseResponseSha256=sha(source),attesters=attesters,nativePrivateKeyExported=False,controlsAdopted=False,commandSha256=sha(PRODUCER.encode())))
 finally:
  restore={}
  for name,c in configs.items():restore[name]=c.restore();(out/(name+'-final.php')).write_bytes(settled(c.container_path,c.original))
  for name,path in SOURCES.items():(out/('native-'+name+'-after.php')).write_bytes(raw('/var/simplesamlphp/'+path))
  save(out/'restoration.json',restore);save(out/'identity-after.json',inspect_identity());save(out/'native-state-observations.json',dict(runId=run,observations=observations))
  h=out/'native-http-originals';h.mkdir()
  for row in records:
   ident=row['request_id'];body=sanitized(responses[ident].decode(),None).encode()
   if contains_state_secret(body.decode()):raise ValueError('Native state secret retained')
   (h/(ident+'.html')).write_bytes(body);row['persisted_body_sha256']=sha(body);row['body_sanitized']=body!=responses[ident]
   xml,body=requests[ident];(h/(ident+'.request.xml')).write_bytes(xml);(h/(ident+'.request.body')).write_bytes(body)
  save(out/'native-http-observations.json',dict(runId=run,records=records,productVerdictAssigned=False))
  save(out/'operation-counts.json',dict(productConfigurationWriteAttempts=sum(c.write_count for c in configs.values()),configurationApplyWrites=sum(c.applied_count for c in configs.values()),restorationWrites=sum(c.restoration_writes for c in configs.values()),nativeParserInvocations=parsers,protocolOperationsAttempted=protocol,nativeSignedProducerInvocations=producers,runCreations=int(run is not None),credentialPosts=client.credentialPosts,productRestarts=0,humanOperations=0,restored=all(r['restored'] for r in restore.values())))
  if run:
   for suffix in ['result.json','protocol-evidence','transcript']:save(out/(suffix if '.' in suffix else suffix+'.json'),api('/api/runs/'+run+'/'+suffix))
  if not all(r['restored'] for r in restore.values()):raise ValueError('Native exact restoration failed')
 print(run,'one native login and four signed attester controls; restored; no adoption')
if __name__=='__main__':main()
