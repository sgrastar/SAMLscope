#!/usr/bin/env python3
"""One fixed stock-native SSP policy, six AllowCreate requests, exact restore.

Only Suite outbox/browser-probe operations send test requests. Authentication
credentials, cookies and AuthState handles remain in memory. A normal native
positive/invalid-signature pair calibrates the unchanged product path first.
"""
import argparse,base64,hashlib,json,os,subprocess,sys,time,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from subject_confirmation_campaign import REPO,CONTAINER,IDP,PREFIX,api,save,BASE,native,batch,raw,settled,ConfigurationBatch,SOURCES as BASE_SOURCES,POLICY,STATE,NativeClient
from metadata_replacement_campaign import arm
from import_metadata_batch import flow
from keyvalue_runtime_campaign import inspect_identity
from native_ui_privacy import sanitized,contains_state_secret
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from browser_probe_selection import prepare_and_skip
from capture_run_originals import capture
SESSION=r"""
require '/var/simplesamlphp/lib/_autoload.php';$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);$_COOKIE=$input['cookies'];
$s=\SimpleSAML\Session::getSessionFromRequest();$auth=$s->getAuthState('example-userpass');if($auth===null)throw new \RuntimeException('Native authentication session unavailable');
$associations=$s->getAssociations('saml2:'.$input['entity']);$peers=[];foreach($associations as $v){$name=$v['saml:NameID'];$peers[]=['entity'=>$v['saml:entityID'],'handler'=>$v['Handler'],'nameIdFormat'=>$name->getFormat()];}
echo json_encode(['sessionSha256'=>hash('sha256',$s->getSessionId()),'authenticated'=>$s->isValid('example-userpass'),
 'authnInstant'=>$auth['AuthnInstant']??null,'uid'=>$auth['Attributes']['uid']??null,'associations'=>$peers,'credentialsPersisted'=>false],JSON_THROW_ON_ERROR);
"""
CASE='IIP-SSO01-fp-idp-01'
SOURCES={**BASE_SOURCES,'session':'src/SimpleSAML/Session.php','random':'src/SimpleSAML/Utils/Random.php','transient-filter':'modules/saml/src/Auth/Process/TransientNameID.php','nameid-generator':'modules/saml/src/BaseNameIDGenerator.php'}
KEYS=['transient-allow-create-'+v for v in ['true','false','omitted']]+['implicit-transient-allow-create-'+v for v in ['true','false','omitted']]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def now():return datetime.now(timezone.utc).isoformat()
def readback(out,label,configs,entity,client=None):
 folder=out/label;folder.mkdir()
 for name,c in configs.items():(folder/(name+'.php')).write_bytes(settled(c.container_path,c.expected))
 (folder/'policy.json').write_bytes(subprocess.check_output(['docker','exec',CONTAINER,'php','-r',POLICY,IDP,entity],timeout=30));save(folder/'observed.json',dict(recordedAt=now()))
 if client is not None and label not in ['control-before','control-after']:
  cookies={c.name:c.value for c in client.jar if c.domain in ['localhost.local','localhost','127.0.0.1']}
  r=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',SESSION],input=json.dumps(dict(cookies=cookies,entity=IDP)).encode(),capture_output=True,timeout=30)
  if r.returncode:raise ValueError('Native authentication session readback unavailable')
  (folder/'session.json').write_bytes(r.stdout)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 remote=batch('saml20-sp-remote.php');hosted=batch('saml20-idp-hosted.php');override=ConfigurationBatch(PREFIX/'config-override.php');override.container_path='/var/simplesamlphp/config/config-override.php';configs=dict(remote=remote,hosted=hosted,override=override)
 for name,c in configs.items():
  if raw(c.container_path)!=c.original:raise ValueError('Native original config differs')
  (out/(name+'-original.php')).write_bytes(c.original)
 for name,path in SOURCES.items():(out/('native-'+name+'.php')).write_bytes(raw('/var/simplesamlphp/'+path))
 for name,value in [('policy',POLICY),('session',SESSION),('state',STATE),('parser',native.PHP)]:(out/('native-'+name+'-command.php')).write_text(value)
 (out/'native-client-collector.py').write_bytes(Path(__file__).with_name('subject_confirmation_campaign.py').read_bytes());(out/'native-http-client.py').write_bytes(Path(__file__).with_name('keyvalue_runtime_campaign.py').read_bytes());(out/'collector.py').write_bytes(Path(__file__).read_bytes());(out/'native-ui-privacy.py').write_bytes(Path(__file__).with_name('native_ui_privacy.py').read_bytes());save(out/'identity-before.json',inspect_identity())
 records=[];responses={};requests={};states=[];client=NativeClient(records,responses,requests,states);run=None;parsers=protocol=skips=0;steps=[]
 credentials=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
 try:
  plan=api('/api/plans',dict(name='SimpleSAMLphp stock transient AllowCreate independence',profile='browser_sso_idp',targetKind='IDP',targetEntityId=IDP,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint=credentials[0],requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];entity=BASE+'/p/'+pid
  created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=['control'],pollingDelaySeconds=0)))
  folder=out/'control';folder.mkdir();state,fixture=arm(run,folder,'control');parsers+=1
  parsed=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],input=fixture,capture_output=True,timeout=30);(folder/'parser.stdout').write_bytes(parsed.stdout);(folder/'parser.stderr').write_bytes(parsed.stderr)
  if parsed.returncode:raise ValueError('Native normal control parser rejected fixture')
  remote.apply(json.loads(parsed.stdout)['php'].encode());time.sleep(3);readback(out,'control-before',configs,entity);protocol+=2;flow(run,folder/'flow.json',suite_signature_control=True,login_inputs=credentials,client_factory=lambda **kw:client);readback(out,'control-after',configs,entity)
  # Generic outbox fixtures use the Plan key/endpoints, not the metadata-lab poll key.
  with urllib.request.urlopen(entity+'/metadata',timeout=30) as r:fixture=r.read()
  (out/'suite-sp-metadata.xml').write_bytes(fixture);parsers+=1
  parsed=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],input=fixture,capture_output=True,timeout=30);(out/'parser.stdout').write_bytes(parsed.stdout);(out/'parser.stderr').write_bytes(parsed.stderr)
  if parsed.returncode:raise ValueError('Native active matrix metadata parser rejected fixture')
  remote.apply(json.loads(parsed.stdout)['php'].encode());time.sleep(3);readback(out,'before',configs,entity,client);save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
  sent=0
  for index in range(400):
   status=api('/api/runs/'+run+'/active-probe')
   if sent==6:break
   if status['state']!='READY':raise ValueError('Native six-step scenario not ready: '+status['state'])
   if status.get('caseId')!=CASE:
    steps.append(prepare_and_skip(BASE,run,status,api));skips+=1;save(out/'steps.json',steps);continue
   protocol+=1;before_ids={e['id'] for e in api('/api/runs/'+run+'/transcript')};readback(out,'matrix-'+str(sent)+'-before',configs,entity,client)
   dispatch_at=now();receipt=client.flow(status['startUrl'],None,*credentials);completed_at=now();after=api('/api/runs/'+run+'/active-probe');readback(out,'matrix-'+str(sent)+'-after',configs,entity,client)
   entries=api('/api/runs/'+run+'/transcript');new=[e['id'] for e in entries if e['id'] not in before_ids];steps.append(dict(caseId=CASE,actionId=status['actionId'],key=KEYS[sent],receipt=receipt,transcriptIds=new,prepared=True,sentToTarget=True,nextState=after['state'],dispatchStartedAt=dispatch_at,dispatchCompletedAt=completed_at,recordedAt=now()));save(out/'steps.json',steps)
   if after.get('actionId')==status.get('actionId'):raise ValueError('Native SAML request did not advance outbox scenario')
   sent+=1
  if sent!=6:raise ValueError('All approved six conditions not completed')
  readback(out,'after',configs,entity,client)
 finally:
  restore={}
  for name,c in configs.items():restore[name]=c.restore();(out/(name+'-final.php')).write_bytes(settled(c.container_path,c.original))
  for name,path in SOURCES.items():(out/('native-'+name+'-after.php')).write_bytes(raw('/var/simplesamlphp/'+path))
  save(out/'restoration.json',restore);save(out/'identity-after.json',inspect_identity());save(out/'native-state-observations.json',dict(runId=run,observations=states))
  h=out/'native-http-originals';h.mkdir()
  for row in records:
   ident=row['request_id'];body=sanitized(responses[ident].decode(),None).encode()
   if contains_state_secret(body.decode()):raise ValueError('Native state secret retained')
   (h/(ident+'.html')).write_bytes(body);row['persisted_body_sha256']=sha(body);row['body_sanitized']=body!=responses[ident];xml,body=requests[ident];(h/(ident+'.request.xml')).write_bytes(xml);(h/(ident+'.request.body')).write_bytes(body)
  save(out/'native-http-observations.json',dict(runId=run,records=records,productVerdictAssigned=False));save(out/'operation-counts.json',dict(productConfigurationWriteAttempts=sum(c.write_count for c in configs.values()),configurationApplyWrites=sum(c.applied_count for c in configs.values()),restorationWrites=sum(c.restoration_writes for c in configs.values()),nativeParserInvocations=parsers,protocolOperationsAttempted=protocol,suiteOnlyPreparedAborts=skips,nativeSessionReadbacks=len(list(out.glob('*/session.json'))),runCreations=int(run is not None),credentialPosts=client.credentialPosts,productRestarts=0,humanOperations=0,restored=all(r['restored'] for r in restore.values())))
  if run:
   for suffix in ['result.json','protocol-evidence','transcript']:save(out/(suffix if '.' in suffix else suffix+'.json'),api('/api/runs/'+run+'/'+suffix))
   capture(out,run,json.loads((out/'transcript.json').read_bytes()));subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,capture_output=True)
  if not all(r['restored'] for r in restore.values()):raise ValueError('Native exact restoration failed')
 print(run,'six stock native AllowCreate cases; restored; no adoption')
if __name__=='__main__':main()
