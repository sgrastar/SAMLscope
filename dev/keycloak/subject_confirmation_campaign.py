#!/usr/bin/env python3
"""Capture a stock native bearer/configuration scope, never synthetic product behavior."""
import argparse,base64,hashlib,json,pathlib,re,subprocess,sys,urllib.request,urllib.error,urllib.parse,datetime
from import_metadata_batch import api,save,flow,BASE
from schema_admission_campaign import JARS as BASE_JARS,reject_sensitive
JARS=BASE_JARS+["org.keycloak.keycloak-common-26.7.2.jar"]
from attribute_policy_capability_absence import product_token
from mdiop_representation_campaign import runtime
REPO=pathlib.Path(__file__).resolve().parents[2];sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture
ADMIN='http://localhost:18180/admin/realms/samlscope';TARGET='http://localhost:18180/realms/samlscope';CONTAINER='samlscope-reference-keycloak'
SCHEMA='samlscope-keycloak-subject-confirmation-v1';CAMPAIGN='native-subject-confirmation'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);args=p.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False);originals=out/'originals';originals.mkdir();operations=[];token=product_token()
 def native(path,method='GET',body=None,xml=False,server=False):
  url=('http://localhost:18180/admin/serverinfo' if server else ADMIN+path);raw=body if isinstance(body,bytes) else None if body is None else json.dumps(body,separators=(',',':')).encode()
  if body is not None and not isinstance(body,bytes):reject_sensitive(body)
  row=dict(path=path,method=method,attemptedAt=now(),product_setting_write=method in ['PUT','DELETE'] or method=='POST' and path!='/client-description-converter',status='attempted');operations.append(row);save(out/'operations.json',operations)
  req=urllib.request.Request(url,data=raw,method=method,headers={'Authorization':'Bearer '+token,'Content-Type':'application/xml' if xml else 'application/json'})
  try:
   with urllib.request.urlopen(req,timeout=40) as response:status=response.status;reply=response.read();location=response.headers.get('Location')
  except urllib.error.HTTPError as error:status=error.code;reply=error.read();location=error.headers.get('Location')
  row.update(status=status,finishedAt=now());save(out/'operations.json',operations);value=json.loads(reply) if reply else None;redactions=[]
  if method=='GET' and re.fullmatch('/clients/[0-9a-f-]{36}',path):
   for key in ['secret','registrationAccessToken']:
    if key in value:del value[key];redactions.append('$.'+key)
   reply=json.dumps(value,separators=(',',':')).encode()
  # Server-info contains public factory schemas (including password-policy field names), not credentials.
  if value is not None and not server:reject_sensitive(value)
  record=dict(method=method,url=url,status=status,response_base64=base64.b64encode(reply).decode(),response_sha256=sha(reply),recordedAt=now())
  if redactions:record.update(response_projection='native-client-public-readback-v1',redactions=redactions)
  if raw is not None:record.update(request_base64=base64.b64encode(raw).decode(),request_sha256=sha(raw))
  return value,record,location
 def scopes(client):
  result={}
  for kind in ['default','optional']:
   value,record,_=native('/clients/'+client+'/'+kind+'-client-scopes');members=[]
   for scope in value:
    detail,detail_record,_=native('/client-scopes/'+scope['id']);mappers,mapper_record,_=native('/client-scopes/'+scope['id']+'/protocol-mappers/models')
    members.append(dict(scope=detail_record,mappers=mapper_record))
   result[kind]=dict(index=record,members=members)
  _,mappers,_=native('/clients/'+client+'/protocol-mappers/models');result['clientMappers']=mappers
  return result
 def environment(phase):
  record=dict(runtime=runtime(),recordedAt=now());row=json.loads(subprocess.check_output(['docker','inspect',CONTAINER]))[0];record['mounts']=[dict(destination=m['Destination'],type=m['Type'],rw=m['RW']) for m in row['Mounts']]
  inv=subprocess.check_output(['docker','exec',CONTAINER,'sh','-c','find /opt/keycloak/lib /opt/keycloak/providers -type f -name "*.jar" | sort | while IFS= read -r p; do sha256sum "$p"; done']);(originals/(phase+'.native-classpath.txt')).write_bytes(inv)
  # Preserve native JVM arguments while irreversibly removing any credential values.
  command=subprocess.check_output(['docker','exec',CONTAINER,'cat','/proc/1/cmdline']).decode().split('\0');public=[];removed=[];redact_next=False
  for arg in command:
   if not arg:continue
   if redact_next:public.append('[REDACTED]');redact_next=False;continue
   if re.search('password|secret|credential|token',arg.split('=',1)[0],re.I):
    key=arg.split('=',1)[0];public.append(key+'=[REDACTED]' if '=' in arg else key);removed.append(key);redact_next='=' not in arg
   else:public.append(arg)
  record['publicProcessArguments']=public;record['processRedactions']=removed;record['nativeClasspathSha256']=sha(inv);return record
 before=environment('before');save(originals/'environment-before.json',before)
 jars=originals/'native-runtime';jars.mkdir();pins={}
 for name in JARS:
  jar_dir='boot' if name.startswith('org.jboss.logging.jboss-logging-') else 'main';subprocess.run(['docker','cp',CONTAINER+':/opt/keycloak/lib/lib/'+jar_dir+'/'+name,str(jars/name)],check=True,capture_output=True);pins[name]=sha((jars/name).read_bytes())
 save(jars/'pins.json',pins)
 plan=api('/api/plans',dict(name='Keycloak native ordinary bearer confirmation',profile='browser_sso_idp',targetKind='IDP',targetEntityId=TARGET,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,capture_output=True)
 peer=BASE+'/p/'+pid;lookup='/clients?clientId='+urllib.parse.quote(peer,safe='');existing,inventory,_=native(lookup)
 if existing!=[]:raise ValueError('Existing native client; no mutation')
 save(originals/'client-inventory-before.json',inventory);_,info,_=native('',server=True);save(originals/'server-info-before.json',info);policies={}
 for kind in ['policies','profiles']:_,policies[kind],_=native('/client-policies/'+kind)
 save(originals/'global-policy-before.json',policies);client=None;normal=False
 try:
  save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=['control'],pollingDelaySeconds=0)));state=api('/api/runs/'+run+'/metadata-lab')
  with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as r:
   if r.status!=202:raise ValueError('Preparation gate missing')
  with urllib.request.urlopen(state['metadataUrl'],timeout=30) as r:fixture=r.read()
  (out/'fixture.xml').write_bytes(fixture);converted,conversion,_=native('/client-description-converter','POST',fixture,True);save(originals/'native-converter.json',conversion)
  if conversion['status']!=200 or converted['clientId']!=peer or converted['protocol']!='saml':raise ValueError('Native metadata conversion unavailable')
  if converted.get('protocolMappers')!=[]:raise ValueError('Unexpected converter mappers')
  configured=json.loads(json.dumps(converted));configured['attributes']['saml.encrypt']='false';_,application,location=native('/clients','POST',configured);save(originals/'native-client-application.json',dict(native=application,only_native_override='saml.encrypt=false',purpose='plain signed bearer subject observation, not encryption compliance'))
  if application['status']!=201 or not location:raise ValueError('Native creation unavailable')
  client=location.rsplit('/',1)[-1];saved,readback,_=native('/clients/'+client);save(originals/'native-client-before.json',readback);save(originals/'native-scopes-before.json',scopes(client))
  flow(run,out/'flow.json',suite_signature_control=True);normal=True
  _,readback,_=native('/clients/'+client);save(originals/'native-client-after.json',readback);save(originals/'native-scopes-after.json',scopes(client));save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
 finally:
  recovery=0
  if client:
   _,deleted,_=native('/clients/'+client,'DELETE');save(originals/'native-client-removal.json',deleted);client=None;recovery=0 if deleted['status']==204 else 1
  final,inventory,_=native(lookup);save(originals/'client-inventory-after.json',inventory);_,info,_=native('',server=True);save(originals/'server-info-after.json',info);after_policies={}
  for kind in ['policies','profiles']:_,after_policies[kind],_=native('/client-policies/'+kind)
  save(originals/'global-policy-after.json',after_policies);after=environment('after');save(originals/'environment-after.json',after)
  restored=existing==final==[] and before['runtime']==after['runtime'] and before['mounts']==after['mounts'] and before['publicProcessArguments']==after['publicProcessArguments'] and before['nativeClasspathSha256']==after['nativeClasspathSha256'] and all(policies[k]['response_sha256']==after_policies[k]['response_sha256'] for k in policies) and recovery==0
  save(out/'restoration.json',dict(restored=restored,remaining_clients=final,originally_absent=existing==[],client_removed=client is None,recovery_failures=recovery));save(out/'operation-counts.json',dict(product_setting_write_attempts=sum(r['product_setting_write'] for r in operations),product_setting_writes=sum(r['product_setting_write'] and r['status'] in [201,204] for r in operations),native_http_attempts=len(operations),protocol_operations_attempted=2 if normal else 0,normal_protocol_success=normal,product_restarts=0,human_operations=0,restored=restored,calibration_network_operations=0,calibration_target_trust_changes=0))
  entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
  try:save(out/'result-before.json',api('/api/runs/'+run+'/result.json'))
  except RuntimeError as error:save(out/'result-before-unavailable.json',dict(reason=str(error)))
 print('Native ordinary bearer campaign restored',run,flush=True)
if __name__=='__main__':main()
