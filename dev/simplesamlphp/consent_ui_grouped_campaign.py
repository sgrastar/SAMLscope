#!/usr/bin/env python3
"""Native UI fixtures with one authenticated session and one real shared Chrome instance."""
import argparse,base64,json,os,select,subprocess,sys,time,urllib.parse,urllib.request,xml.etree.ElementTree as ET
from pathlib import Path
from consent_ui_campaign import (REPO,CONTAINER,IDP,PREFIX,api,save,BASE,native,batch,raw,settled,ConfigurationBatch,
 DISPLAY,LOGO,URLS,SOURCES as BASE_SOURCES,STATE,POLICY as BASE_POLICY,sha,now,parse_forms,readback)
from native_ui_privacy import sanitized,contains_state_secret
from metadata_replacement_campaign import arm,READBACK
from keyvalue_runtime_campaign import KeyValueClient,inspect_identity
from import_metadata_batch import flow
from subject_confirmation_campaign import SOURCES as AUTH_SOURCES, POLICY as AUTH_POLICY, STATE as AUTH_STATE
SOURCES={**BASE_SOURCES,'footer-template':'templates/_footer.twig','table-template':'templates/_table.twig',
 'login-controller':'modules/core/src/Controller/Login.php','login-template':'modules/core/templates/loginuserpass.twig','core-base-template':'modules/core/templates/base.twig',
 'base-script':'public/assets/base/js/bundle.js','base-stylesheet':'public/assets/base/css/stylesheet.css','consent-stylesheet':'modules/consent/public/assets/css/consent.css',
 'logo-model':'vendor/simplesamlphp/saml2-legacy/src/SAML2/XML/mdui/Logo.php','uiinfo-model':'vendor/simplesamlphp/saml2-legacy/src/SAML2/XML/mdui/UIInfo.php',
 'noconsent-template':'modules/consent/templates/noconsent.twig','template-loader':'src/SimpleSAML/XHTML/TemplateLoader.php',
 'footer-image':'public/assets/base/icons/ssplogo-fish-small.png',
 'security-configuration':'src/SimpleSAML/Configuration.php','module-entry':'public/module.php'}
POLICY=BASE_POLICY.replace("'theme'=>$c->", "'securityHeaders'=>$c->getOptionalArray('headers.security',\\SimpleSAML\\Configuration::DEFAULT_SECURITY_HEADERS),'themeController'=>$c->getOptionalString('theme.controller',null),'optionalHeadExists'=>file_exists('/var/simplesamlphp/templates/_head.twig'),'theme'=>$c->")
class BrowserWorker:
 def __init__(self,script=None):self.process=None;self.attempts=0;self.observations=0;self.script=script or Path(__file__).with_name('consent_browser_worker.mjs')
 def observe(self,value):
  self.attempts+=1
  if self.process is None:self.process=subprocess.Popen(['node',str(self.script)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
  self.process.stdin.write(json.dumps(value)+'\n');self.process.stdin.flush()
  if not select.select([self.process.stdout],[],[],50)[0]:raise ValueError('Public native browser worker timeout')
  line=self.process.stdout.readline()
  if not line:raise ValueError('Public native browser worker unavailable')
  result=json.loads(line)
  if not result.get('ok'):return None,result
  self.observations+=1;return json.dumps(result['observation']).encode(),None
 def close(self):
  if self.process:
   try:self.process.stdin.write('{"stop":true}\n');self.process.stdin.flush();self.process.communicate(timeout=10)
   except Exception:self.process.kill();self.process.communicate(timeout=5)
class GroupedConsentClient(KeyValueClient):
 def __init__(self,records,responses,requests,observations,worker):
  super().__init__(records,responses,requests);self.observations=observations;self.authObservations=[];self.worker=worker;self.folder=None;self.request_id=None;self.credentialPosts=0;self.op.addheaders=[('Accept-Language','en-US')]
 def request(self,url,fields=None):
  if fields and 'password' in fields and urllib.parse.urlparse(url).port==18380:self.credentialPosts+=1
  if fields and 'SAMLRequest' in fields and urllib.parse.urlparse(url).port==18380:self.request_id=ET.fromstring(base64.b64decode(fields['SAMLRequest'])).get('ID')
  final,page,status=super().request(url,fields)
  if status==200 and '/core/loginuserpass' in final and 'name="username"' in page:
   forms=[f for f in parse_forms(page) if 'AuthState' in f.fields]
   if len(forms)!=1:raise ValueError('Native password challenge state ambiguous')
   token=forms[0].fields['AuthState'];cookies={c.name:c.value for c in self.jar if c.domain in ['localhost.local','localhost','127.0.0.1']}
   result=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',AUTH_STATE],input=json.dumps(dict(cookies=cookies,authState=token)).encode(),capture_output=True,timeout=30)
   if result.returncode:raise ValueError('Native public authentication state unavailable')
   self.authObservations.append(dict(recordedAt=now(),state=json.loads(result.stdout),stateHandlePersisted=False,urlPath=urllib.parse.urlsplit(final).path,credentialSubmitted=False))
  if 'id="consent-yes"' not in page:return final,page,status
  forms=parse_forms(page);yes=[f for f in forms if 'StateId' in f.fields and '/consent/getconsent' in f.action]
  if len(yes)!=1:raise ValueError('Ambiguous native consent form')
  stateId=yes[0].fields['StateId'];cookies={c.name:c.value for c in self.jar if c.domain in ['localhost.local','localhost','127.0.0.1']};payload=json.dumps(dict(cookies=cookies,stateId=stateId)).encode();observed=now()
  def state():
   result=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',STATE],input=payload,capture_output=True,timeout=30)
   if result.returncode:raise ValueError('Native public state unavailable')
   return result.stdout
  before=state();public=json.loads(before)
  if public['requestId']!=self.request_id:raise ValueError('Native state differs from actual request')
  browser,failure=self.worker.observe(dict(url=final,cookies=[dict(name=k,value=v) for k,v in cookies.items()],tokens=[stateId,*cookies.values()],variant=self.folder.parent.name))
  if failure:save(self.folder/'browser-failure.json',failure);raise ValueError('Real native UI browser observation failed')
  after=state()
  if json.loads(after)!=public:raise ValueError('Native browser changed the SAML request state')
  ident=self.request_id;safe=sanitized(page,stateId).encode()
  if contains_state_secret(safe.decode()):raise ValueError('Native public HTML projection contains authentication state')
  (self.folder/(ident+'.html')).write_bytes(safe);(self.folder/(ident+'.state.json')).write_bytes(before);(self.folder/(ident+'.state-after.json')).write_bytes(after);(self.folder/(ident+'.browser.json')).write_bytes(browser)
  self.observations.append(dict(requestId=ident,recordedAt=observed,status=status,url=urllib.parse.urlunsplit(urllib.parse.urlsplit(final)._replace(query='')),bodySha256=sha(safe),bodySanitized=True,stateSha256=sha(before),stateAfterSha256=sha(after),browserSha256=sha(browser),stateIdSha256=sha(stateId.encode()),preferredLanguage='en-US'))
  target=urllib.parse.urljoin(final,yes[0].action)+'?'+urllib.parse.urlencode(dict(yes='yes',StateId=stateId));return super().request(target,None)
def readback_native(out,label,configs,entity,authentication=False):
 readback(out,label,configs,entity);folder=out/label;(folder/'policy.json').write_bytes(subprocess.check_output(['docker','exec',CONTAINER,'php','-r',POLICY,IDP],timeout=30))
 if authentication and entity:(folder/'authentication-policy.json').write_bytes(subprocess.check_output(['docker','exec',CONTAINER,'php','-r',AUTH_POLICY,IDP,entity],timeout=30))
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--mode',choices=['logo','uri','safety','all'],default='logo');p.add_argument('--worker-path',type=Path);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);variants=['control']+(LOGO if a.mode=='logo' else URLS if a.mode=='uri' else ['ui-safety-logo-data','ui-safety-information-javascript','ui-safety-privacy-javascript'] if a.mode=='safety' else DISPLAY+LOGO+URLS)
 remote=batch('saml20-sp-remote.php');hosted=batch('saml20-idp-hosted.php');override=ConfigurationBatch(PREFIX/'config-override.php');override.container_path='/var/simplesamlphp/config/config-override.php';configs=dict(remote=remote,hosted=hosted,override=override)
 for label,c in configs.items():
  if raw(c.container_path)!=c.original:raise ValueError('Native baseline differs')
  (out/(label+'-original.php')).write_bytes(c.original)
 sources={**SOURCES,**AUTH_SOURCES} if a.mode=='uri' else SOURCES
 for name,path in sources.items():(out/('native-'+name+'.txt')).write_bytes(raw('/var/simplesamlphp/'+path))
 (out/'native-state-command.php').write_text(STATE);(out/'native-policy-command.php').write_text(POLICY);(out/'native-parser-command.php').write_text(native.PHP);(out/'native-readback-command.php').write_text(READBACK)
 if a.mode=='uri':(out/'native-authentication-policy-command.php').write_text(AUTH_POLICY);(out/'native-authentication-state-command.php').write_text(AUTH_STATE)
 (out/'collector.py').write_bytes(Path(__file__).read_bytes());(out/'browser.mjs').write_bytes((a.worker_path or Path(__file__).with_name('consent_browser_worker.mjs')).read_bytes());(out/'native-ui-privacy.py').write_bytes(Path(__file__).with_name('native_ui_privacy.py').read_bytes());save(out/'identity-before.json',inspect_identity())
 run=None;operations=[];records=[];responses={};requests={};observations=[];parsers=attempts=0;worker=BrowserWorker(a.worker_path);client=GroupedConsentClient(records,responses,requests,observations,worker)
 credentials=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
 try:
  override.apply(b"$config['module.enable']['consent'] = true;\n$config['language.default']='en';\n");hosted.apply(("$metadata['"+IDP+"']['authproc']=[90=>['class'=>'consent:Consent','includeValues'=>false,'checked'=>false,'identifyingAttribute'=>'uid']];").encode());time.sleep(3);readback_native(out,'prepared',configs,None)
  plan=api('/api/plans',dict(name='SimpleSAMLphp native shared-session UI campaign',profile='metadata_idp',targetKind='IDP',targetEntityId=IDP,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint=credentials[0],requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];entity=BASE+'/p/'+pid
  created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=variants,pollingDelaySeconds=0)))
  for variant in variants:
   folder=out/variant;folder.mkdir();row=dict(variant=variant,startedAt=now(),status='incomplete');operations.append(row);save(out/'operations.json',operations);state,fixture=arm(run,folder,variant);parsers+=1
   parsed=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],input=fixture,capture_output=True,timeout=30);(folder/'parser.stdout').write_bytes(parsed.stdout);(folder/'parser.stderr').write_bytes(parsed.stderr);row['nativeParserReturncode']=parsed.returncode
   if parsed.returncode:
    row['status']='native-parser-rejected';save(out/'operations.json',operations)
    # Orchestration only: this missing active fixture cannot support a product verdict.
    pending=api('/api/runs/'+run+'/metadata-lab')
    with urllib.request.urlopen(urllib.request.Request(pending['automaticContinueUrl'],data=b''),timeout=30) as response:response.read()
    row['continuedWithoutProductVerdict']=True;save(out/'operations.json',operations);continue
   remote.apply(json.loads(parsed.stdout)['php'].encode());time.sleep(3);readback_native(folder,'before',configs,entity,a.mode=='uri');ui=folder/'ui';ui.mkdir();client.folder=ui;attempts+=2
   flow(run,folder/'flow.json',suite_signature_control=True,login_inputs=credentials,client_factory=lambda **kw:client)
   readback_native(folder,'after',configs,entity,a.mode=='uri');row.update(status='correlated-success',completedAt=now());save(out/'operations.json',operations)
   if variant=='control':save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
 finally:
  worker.close();restoration={}
  for label,c in configs.items():restoration[label]=c.restore();(out/(label+'-final.php')).write_bytes(settled(c.container_path,c.original))
  for name,path in sources.items():(out/('native-'+name+'-after.txt')).write_bytes(raw('/var/simplesamlphp/'+path))
  save(out/'restoration.json',restoration);save(out/'identity-after.json',inspect_identity());save(out/'native-ui-observations.json',dict(runId=run,observations=observations,productVerdictAssigned=False))
  if a.mode=='uri':save(out/'native-authentication-observations.json',dict(runId=run,observations=client.authObservations,productVerdictAssigned=False))
  http=out/'native-http-originals';http.mkdir()
  for item in records:
   ident=item['request_id'];body=sanitized(responses[ident].decode(),None).encode()
   if contains_state_secret(body.decode()):raise ValueError('Native public HTTP projection contains authentication state')
   (http/(ident+'.html')).write_bytes(body);item['persisted_body_sha256']=sha(body);item['body_sanitized']=body!=responses[ident];xml,body=requests[ident];(http/(ident+'.request.xml')).write_bytes(xml);(http/(ident+'.request.body')).write_bytes(body)
  save(out/'native-http-observations.json',dict(runId=run,records=records,productVerdictAssigned=False));save(out/'operation-counts.json',dict(productConfigurationWriteAttempts=sum(c.write_count for c in configs.values()),configurationApplyWrites=sum(c.applied_count for c in configs.values()),restorationWrites=sum(c.restoration_writes for c in configs.values()),nativeParserInvocations=parsers,protocolOperationsAttempted=attempts,runCreations=int(run is not None),productRestarts=0,humanOperations=0,restored=all(r['restored'] for r in restoration.values()),credentialPosts=client.credentialPosts,chromeLaunches=int(worker.process is not None),browserObservationAttempts=worker.attempts,browserObservations=worker.observations))
  if run:
   sys.path.insert(0,str(REPO/'dev/reference-acceptance'));from capture_run_originals import capture
   entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
   try:save(out/'result-before.json',api('/api/runs/'+run+'/result.json'))
   except RuntimeError:pass
   save(out/'protocol-evidence-before.json',api('/api/runs/'+run+'/protocol-evidence'))
  if not all(r['restored'] for r in restoration.values()):raise ValueError('Native settings not restored')
 print(run,'shared-session native UI originals collected and restored, no adoption')
if __name__=='__main__':main()
