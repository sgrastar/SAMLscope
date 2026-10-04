#!/usr/bin/env python3
"""Record a native EndpointType admission counterexample, with no runtime key conclusion."""
import argparse,base64,hashlib,json,pathlib,re,subprocess,sys,urllib.request,urllib.error,urllib.parse
from import_metadata_batch import api,save,flow,BASE
from algorithm_preference_campaign import recorded
from attribute_policy_capability_absence import product_token
from mdiop_representation_campaign import runtime
REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture
ADMIN='http://localhost:18180/admin/realms/samlscope'
TARGET='http://localhost:18180/realms/samlscope'
CAMPAIGN='metadata-native-schema-admission'
JARS=['org.keycloak.keycloak-saml-core-26.7.2.jar','org.keycloak.keycloak-saml-core-public-26.7.2.jar',
 'org.keycloak.keycloak-services-26.7.2.jar','org.apache.santuario.xmlsec-3.0.6.jar','org.jboss.logging.jboss-logging-3.6.2.Final.jar']
VARIANTS=['control','schema-sso-endpoint-set','schema-sso-endpoint-without-foreign',
 'schema-global-element-families','schema-affiliation-only','schema-additional-metadata-location',
 'schema-localized-name-boundary','schema-attribute-consuming-service','schema-invalid-endpoint-location']
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(path):return json.loads(path.read_bytes())
def reject_sensitive(value):
 if isinstance(value,dict):
  for key,item in value.items():
   if re.search('private|password|secret|credential|token',key,re.I) and not (key=='client.secret.creation.time' and isinstance(item,str) and re.fullmatch(r'[0-9]+',item)):raise ValueError('Sensitive native field '+key+'; no persistence')
   reject_sensitive(item)
 elif isinstance(value,list):
  for item in value:reject_sensitive(item)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True)
 args=p.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
 token=product_token();operations=[]
 def native(path,method='GET',body=None,xml=False):
  raw=body if isinstance(body,bytes) else None if body is None else json.dumps(body,separators=(',',':')).encode()
  if body is not None and not isinstance(body,bytes):reject_sensitive(body)
  req=urllib.request.Request(ADMIN+path,data=raw,method=method,headers={'Authorization':'Bearer '+token,'Content-Type':'application/xml' if xml else 'application/json'})
  row=dict(method=method,path=path.split('?')[0],status='attempted',product_setting_write=method in ['PUT','DELETE'] or (method=='POST' and path!='/client-description-converter'))
  operations.append(row);save(out/'operations.json',operations)
  try:
   with urllib.request.urlopen(req,timeout=40) as r:status=r.status;response=r.read();location=r.headers.get('Location')
  except urllib.error.HTTPError as e:status=e.code;response=e.read();location=e.headers.get('Location')
  row['status']=status;save(out/'operations.json',operations)
  value=json.loads(response) if response else None
  redactions=[]
  if method=='GET' and re.fullmatch('/clients/[0-9a-f-]{36}',path) and isinstance(value,dict):
   # Native client readback contains credentials irrelevant to SAML admission.
   # Remove only the two native top-level credential fields before persistence/Recorder.
   for key in ['secret','registrationAccessToken']:
    if key in value:redactions.append(key);del value[key]
   response=json.dumps(value,separators=(',',':')).encode()
  if value is not None:reject_sensitive(value)
  original=dict(method=method,url=ADMIN+path,status=status,response_base64=base64.b64encode(response).decode(),response_sha256=sha(response))
  if method=='GET' and re.fullmatch('/clients/[0-9a-f-]{36}',path):original.update(redactions=['$.'+key for key in redactions],response_projection='native-client-public-readback-v1')
  if raw is not None:original.update(request_base64=base64.b64encode(raw).decode(),request_sha256=sha(raw))
  return value,original,location
 before_runtime=runtime();save(out/'native-runtime-before.json',before_runtime)
 jars=out/'native-runtime';jars.mkdir();pins={}
 for name in JARS:
  jar_dir='boot' if name.startswith('org.jboss.logging.jboss-logging-') else 'main'
  subprocess.run(['docker','cp','samlscope-reference-keycloak:/opt/keycloak/lib/lib/'+jar_dir+'/'+name,str(jars/name)],check=True,capture_output=True)
  pins[name]=sha((jars/name).read_bytes())
 save(jars/'pins.json',pins)
 plan=api('/api/plans',dict(name='Keycloak native schema EndpointType admission',profile='metadata_idp',targetKind='IDP',targetEntityId=TARGET,
  metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',
  suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),
  interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
 save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=created['run']['id']
 save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
 subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,capture_output=True)
 target_hash=sha((out/'target-metadata.xml').read_bytes());peer=BASE+'/p/'+pid;lookup='/clients?clientId='+urllib.parse.quote(peer,safe='')
 base=dict(runId=run,campaignId=CAMPAIGN,targetMetadataSha256=target_hash)
 before_policy={kind:native('/client-policies/'+kind)[0] for kind in ['policies','profiles']}
 original,inventory,_=native(lookup)
 if original!=[]:raise ValueError('Refusing existing client')
 scope_before=dict(**base,schema='samlscope-keycloak-schema-runtime-scope-v1',peerEntityId=peer,runtime=before_runtime,globalPolicy=before_policy,nativeJars=pins,native=inventory)
 before_ref=recorded(out,created,scope_before,'scope-before')
 members={};baseline_client_ref=None;baseline_conversion_ref=None;client_id=None;normal=False
 try:
  save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=VARIANTS,pollingDelaySeconds=0)))
  for variant in VARIANTS:
   folder=out/variant;folder.mkdir();state=api('/api/runs/'+run+'/metadata-lab')
   if state['selectedVariant']!=variant:raise ValueError('Unexpected fixture selection')
   with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as response:
    if response.status!=202:raise ValueError('Preparation fetch gate missing')
   with urllib.request.urlopen(state['metadataUrl'],timeout=30) as response:fixture=response.read()
   (folder/'fixture.xml').write_bytes(fixture)
   converted,conversion,_=native('/client-description-converter','POST',fixture,True)
   value=dict(**base,schema='samlscope-keycloak-schema-conversion-v1',variant=variant,fixtureSha256=sha(fixture),native=conversion)
   save(folder/'native-conversion.json',value);ref=recorded(out,created,value,variant+'-conversion')
   entries=api('/api/runs/'+run+'/transcript')
   prepared=[e for e in entries if e.get('samlSummary',{}).get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==variant and e['samlSummary'].get('metadataSha256')==sha(fixture)]
   if len(prepared)!=1:raise ValueError('Prepared original ambiguous')
   members[variant]=dict(preparedReference=prepared[0]['id'],fixtureSha256=sha(fixture),conversion=ref)
   if variant=='control':
    if conversion['status']!=200 or converted.get('clientId')!=peer or converted.get('protocol')!='saml':raise ValueError('Normal native conversion unavailable')
    _,inserted,location=native('/clients','POST',converted)
    if inserted['status']!=201 or not location:raise ValueError('Normal native persistence unavailable')
    client_id=location.rsplit('/',1)[-1]
    if not re.fullmatch('[0-9a-f-]{36}',client_id):raise ValueError('Native client identity invalid')
    saved,readback,_=native('/clients/'+client_id)
    if saved.get('clientId')!=peer:raise ValueError('Native saved client differs')
    value=dict(**base,schema='samlscope-keycloak-schema-baseline-client-v1',nativeClientId=client_id,native=readback)
    baseline_client_ref=recorded(out,created,value,'baseline-client');baseline_conversion_ref=ref
    flow(run,folder/'flow.json');normal=True
    _,deleted,_=native('/clients/'+client_id,'DELETE')
    if deleted['status']!=204:raise ValueError('Normal client removal failed')
    client_id=None
    save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
   else:
    pending=api('/api/runs/'+run+'/metadata-lab')
    if pending['campaignIndex']==state['campaignIndex']:
     with urllib.request.urlopen(urllib.request.Request(pending['automaticContinueUrl'],data=b''),timeout=30) as response:response.read()
   print(variant+' native HTTP '+str(conversion['status'])+' recorded',flush=True)
 finally:
  recovery=0
  if client_id:
   native('/clients/'+client_id,'DELETE');recovery+=1
  remaining,inventory,_=native(lookup);after_runtime=runtime();after_policy={kind:native('/client-policies/'+kind)[0] for kind in ['policies','profiles']}
  scope_after=dict(**base,schema='samlscope-keycloak-schema-runtime-scope-v1',peerEntityId=peer,runtime=after_runtime,globalPolicy=after_policy,nativeJars=pins,native=inventory)
  after_ref=recorded(out,created,scope_after,'scope-after')
  restored=remaining==original==[] and before_runtime==after_runtime and before_policy==after_policy
  save(out/'restoration.json',dict(restored=restored,recovery_client_removals=recovery,remaining_clients=remaining))
  save(out/'operation-counts.json',dict(native_http_attempts=len(operations),native_conversion_attempts=sum(r['path']=='/client-description-converter' for r in operations),
   product_setting_write_attempts=sum(r['product_setting_write'] for r in operations),product_setting_writes=sum(r['product_setting_write'] and r['status'] in [200,201,204] for r in operations),
   protocol_flows_attempted=int(baseline_client_ref is not None),normal_protocol_success=normal,product_restarts=0,human_operations=0,restored=restored,verdict_adopted=False))
  entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
  if restored and normal and {'control','schema-sso-endpoint-set','schema-sso-endpoint-without-foreign'}<=set(members):
   save(out/'qualified-receipt.json',dict(**base,schema='samlscope-keycloak-native-schema-admission-v1',adapter='keycloak-native-endpoint-parser-v1',targetEntityId=TARGET,
    before=before_ref,after=after_ref,baseline=members['control'],baselineConversion=baseline_conversion_ref,baselineClient=baseline_client_ref,
    test=members['schema-sso-endpoint-set'],contrast=members['schema-sso-endpoint-without-foreign'],schemaInvalidControl=members.get('schema-invalid-endpoint-location')))
  try:save(out/'result-before.json',api('/api/runs/'+run+'/result.json'))
  except RuntimeError as error:save(out/'result-before-unavailable.json',dict(reason=str(error),verdict_adopted=False))
 print('Native schema campaign restored; no result adopted',run,flush=True)
if __name__=='__main__':main()
