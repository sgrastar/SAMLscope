#!/usr/bin/env python3
"""Native XML conversion and same-client replacement, followed by Suite outbox controls.

The product's original converter output is persisted unchanged. This collector never maps
XML into client attributes and never infers a verdict from an HTTP error or a missing reply.
"""
import argparse, base64, datetime, hashlib, json, os, pathlib, sys, subprocess, zipfile
import urllib.error, urllib.parse, urllib.request
from import_metadata_batch import api, save, flow, BASE
from attribute_policy_capability_absence import product_token
from algorithm_preference_campaign import recorded
from reference_flow import Client
from mdiop_representation_campaign import runtime

REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture
from browser_probe_selection import prepare_and_skip
from capture_browser_originals import capture as capture_browser
ADMIN='http://localhost:18180/admin/realms/samlscope'
VARIANTS=['control','multiple-signing-keys-first','multiple-signing-keys','no-valid-until']
FIXTURES={'new-key-explicit-acs','new-key-default-acs','new-key-second-acs','new-key-redirect',
 'old-key-new-acs','rollover-first-key-new-acs','rollover-second-key-new-acs','new-key-old-acs','new-key-invalid-signature'}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def public(value):
 value=dict(value)
 for key in ['secret','registrationAccessToken']:value.pop(key,None)
 if any(__import__('re').search('private|password',k,__import__('re').I) and v for k,v in value.get('attributes',{}).items()):
  raise ValueError('Sensitive native attribute; refuse recording')
 return value
def native(path,body=None,method='GET',content_type='application/json'):
 raw=None if body is None else body if isinstance(body,bytes) else json.dumps(body,separators=(',',':')).encode()
 q=urllib.request.Request(ADMIN+path,data=raw,method=method,headers={'Authorization':'Bearer '+product_token(),'Content-Type':content_type})
 started=now()
 try:
  with urllib.request.urlopen(q,timeout=40) as r:status,response=r.status,r.read()
 except urllib.error.HTTPError as r:status,response=r.code,r.read()
 return status,response,dict(method=method,url=ADMIN+path,status=status,startedAt=started,finishedAt=now(),
  requestSha256=sha(raw) if raw is not None else None,responseBase64=base64.b64encode(response).decode(),responseSha256=sha(response))
def read(path):
 status,raw,_=native(path)
 if status!=200:raise ValueError('Native read-back unavailable '+str(status))
 return json.loads(raw)
NATIVE_CLASSES=['org/keycloak/protocol/saml/EntityDescriptorDescriptionConverter.class',
 'org/keycloak/protocol/saml/SamlService.class','org/keycloak/protocol/saml/SamlService$BindingProtocol.class']
def native_paths(out,phase):
 folder=out/'native-runtime';folder.mkdir(exist_ok=True);path=folder/(phase+'-services.jar')
 subprocess.run(['docker','cp','samlscope-reference-keycloak:/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar',str(path)],check=True,capture_output=True)
 with zipfile.ZipFile(path) as z:classes={key:base64.b64encode(z.read(key)).decode() for key in NATIVE_CLASSES}
 return dict(jarSha256=sha(path.read_bytes()),classes=classes)
class NativeHttpClient(Client):
 def __init__(self,observations):super().__init__();self.observations=observations
 def request(self,url,fields=None):
  target=url=='http://localhost:18180/realms/samlscope/protocol/saml' and fields and 'SAMLRequest' in fields
  if target:
   raw=base64.b64decode(fields['SAMLRequest'],validate=True);root=__import__('xml.etree.ElementTree',fromlist=['']).fromstring(raw)
   observation=dict(method='POST',requestUrl=url,requestId=root.get('ID'),requestSha256=sha(raw),startedAt=now())
  final,page,status=super().request(url,fields)
  if target:
   observation.update(responseUrl=final,responseStatus=status,responseBodySha256=sha(page.encode()),responseBodyBytes=len(page.encode()),finishedAt=now())
   self.observations.append(observation)
  return final,page,status
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True)
 p.add_argument('--probe-case',choices=['IIP-MD06-a-idp-01','IIP-MD06-ab-idp-01'],default='IIP-MD06-a-idp-01')
 args=p.parse_args()
 out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
 plan=api('/api/plans',dict(name='Keycloak native accepted metadata replacement',profile='metadata_idp',targetKind='IDP',targetEntityId='http://localhost:18180/realms/samlscope',metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
 save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=created['run']['id']
 save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));entity=BASE+'/p/'+pid
 subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,capture_output=True)
 lookup='/clients?clientId='+urllib.parse.quote(entity,safe='');before=read(lookup)
 if before:raise ValueError('Refusing existing native client')
 target_sha=sha((out/'target-metadata.xml').read_bytes());operations=[];phases=[];probes=[];skipped=[];client_id=None
 before_runtime=runtime();before_policy={key:read('/client-policies/'+key) for key in ['policies','profiles']};source_before=native_paths(out,'before')
 def original(label,value):
  value=dict(schema='samlscope-keycloak-native-supersession-original-v1',runId=run,campaignId='native-metadata-supersession',targetMetadataSha256=target_sha,peerEntityId=entity,recordedAt=now(),**value)
  save(out/(label+'.json'),value);return recorded(out,created,value,label)
 before_ref=original('before',dict(kind='restoration-state',runtime=before_runtime,policies=before_policy,clients=before,nativePaths=source_before))
 def operation(kind,**kw):
  row=dict(kind=kind,startedAt=now(),**kw);operations.append(row);save(out/'operations.json',operations);return row
 try:
  save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=VARIANTS,pollingDelaySeconds=0)))
  for variant in VARIANTS:
   folder=out/variant;folder.mkdir();state=api('/api/runs/'+run+'/metadata-lab')
   if state['selectedVariant']!=variant:raise ValueError('Prepared variant differs')
   with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as r:
    if r.status!=202:raise ValueError('Expected native fixture retrieval gate')
   with urllib.request.urlopen(state['metadataUrl'],timeout=30) as r:raw=r.read()
   (folder/'fixture.xml').write_bytes(raw)
   status,response,obs=native('/client-description-converter',raw,'POST','application/xml')
   if status!=200:raise ValueError('Native conversion incomplete '+str(status))
   recipe=json.loads(response)
   if recipe.get('clientId')!=entity or recipe.get('protocol')!='saml' or public(recipe)!=recipe:raise ValueError('Native converter output identity/safety differs')
   converter=original(variant+'-converter',dict(kind='converter',variant=variant,fixtureSha256=sha(raw),native=obs))
   if client_id is None:
    row=operation('native-client-create',variant=variant);status,_,mutation=native('/clients',recipe,'POST')
    row.update(status=status,finishedAt=now());save(out/'operations.json',operations)
    if status!=201:raise ValueError('Native client create failed '+str(status))
    found=read(lookup)
    if len(found)!=1:raise ValueError('Created native client ambiguous')
    client_id=found[0]['id']
   else:
    row=operation('native-client-replace',variant=variant,clientId=client_id);status,_,mutation=native('/clients/'+client_id,recipe,'PUT')
    row.update(status=status,finishedAt=now());save(out/'operations.json',operations)
    if status!=204:raise ValueError('Native same-client replacement failed '+str(status))
   saved=public(read('/clients/'+client_id))
   if saved['id']!=client_id or saved['clientId']!=entity or saved['protocol']!='saml':raise ValueError('Native saved identity mismatch')
   saved_raw=json.dumps(saved,separators=(',',':')).encode();readback=original(variant+'-persisted',dict(kind='persisted',variant=variant,fixtureSha256=sha(raw),clientDatabaseId=client_id,mutation=mutation,native=dict(method='GET',url=ADMIN+'/clients/'+client_id,status=200,responseBase64=base64.b64encode(saved_raw).decode(),responseSha256=sha(saved_raw),recordedAt=now())))
   row=operation('metadata-phase-flow',variant=variant)
   try:flow(run,folder/'flow.json',suite_signature_control=variant in {'control','no-valid-until'})
   except Exception as e:save(folder/'incomplete.json',dict(reason=str(e),verdict_assigned=False))
   row.update(finishedAt=now());save(out/'operations.json',operations)
   phases.append(dict(variant=variant,fixtureSha256=sha(raw),converter=converter,persisted=readback));save(out/'phases.json',phases)
   pending=api('/api/runs/'+run+'/metadata-lab')
   if pending['campaignIndex']==state['campaignIndex']:
    with urllib.request.urlopen(urllib.request.Request(pending['automaticContinueUrl'],data=b''),timeout=30) as r:r.read()
    row['orchestrationOnlyContinue']=True;save(out/'operations.json',operations)
   print(variant+' native same-client replacement recorded',flush=True)
  save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
  probe_before=original('probes-before',dict(kind='operative-client',client=public(read('/clients/'+client_id)),runtime=runtime(),policies={key:read('/client-policies/'+key) for key in ['policies','profiles']}))
  seen=False;selected=args.probe_case
  save(out/'selected-probe-case.json',dict(caseId=selected,evidenceCampaignId='native-metadata-supersession'))
  for _ in range(1000):
   status=api('/api/runs/'+run+'/active-probe')
   if seen and status.get('caseId')!=selected:break
   if status.get('state')!='READY':raise ValueError('Native supersession probe not ready '+repr(status))
   if status.get('caseId')!=selected:
    skipped.append(prepare_and_skip(BASE,run,status,api));save(out/'skipped.json',skipped);continue
   seen=True;old_ids={e['id'] for e in api('/api/runs/'+run+'/transcript')}
   def terminal(url,page,code,reason,action=status['actionId']):
    api('/api/runs/'+run+'/active-probe/browser-response',dict(actionId=action,status=code,url=url,body=page))
   direct=[];row=operation('supersession-outbox-flow',actionId=status['actionId']);receipt=NativeHttpClient(direct).flow(status['startUrl'],None,os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'),terminal_observer=terminal)
   entries=api('/api/runs/'+run+'/transcript');issued=[e for e in entries if e['id'] not in old_ids and e['direction']=='OUTBOUND' and e['samlSummary'].get('action_id')==status['actionId']]
   if len(issued)!=1:raise ValueError('One native outbox request required')
   request=issued[0];row.update(fixture=request['samlSummary']['fixture_id'],finishedAt=now());save(out/'operations.json',operations)
   record=dict(fixture=request['samlSummary']['fixture_id'],requestReference=request['id'],actionId=status['actionId'],receipt=receipt,completedAt=now())
   if direct:
    if len(direct)!=1:raise ValueError('Native direct SAML submission ambiguous')
    terminal_refs=[e['id'] for e in entries if e['id'] not in old_ids and e['direction']=='INBOUND' and (e['correlationId']==status['actionId'] or e['samlSummary'].get('inResponseTo')=='_'+status['actionId'])]
    if len(terminal_refs)!=1:raise ValueError('Native direct response reference ambiguous')
    record['nativeHttp']=original(request['samlSummary']['fixture_id']+'-native-http',dict(kind='native-http-response',fixture=request['samlSummary']['fixture_id'],actionId=status['actionId'],requestReference=request['id'],responseReference=terminal_refs[0],native=direct[0]))
   probes.append(record);save(out/'probes.json',probes)
   if api('/api/runs/'+run+'/active-probe').get('actionId')==status['actionId']:raise ValueError('Outbox did not complete from actual evidence')
   print(request['samlSummary']['fixture_id']+' '+receipt,flush=True)
  if len(probes)!=len(FIXTURES) or {r['fixture'] for r in probes}!=FIXTURES:raise ValueError('Complete nine outbox matrix unavailable')
  probe_after=original('probes-after',dict(kind='operative-client',client=public(read('/clients/'+client_id)),runtime=runtime(),policies={key:read('/client-policies/'+key) for key in ['policies','profiles']}))
  save(out/'probe-state-references.json',dict(before=probe_before,after=probe_after))
 finally:
  found=read(lookup)
  for owned in found:
   if owned['clientId']!=entity or owned['protocol']!='saml':raise ValueError('Restoration ownership not established')
   row=operation('native-client-delete',clientId=owned['id']);status,_,_=native('/clients/'+owned['id'],method='DELETE');row.update(status=status,finishedAt=now());save(out/'operations.json',operations)
   if status!=204:raise ValueError('Native cleanup failed')
  after=read(lookup);after_runtime=runtime();after_policy={key:read('/client-policies/'+key) for key in ['policies','profiles']}
  source_after=native_paths(out,'after');after_ref=original('restored',dict(kind='restoration-state',runtime=after_runtime,policies=after_policy,clients=after,nativePaths=source_after,operations=operations))
  restored=before==after and before_runtime==after_runtime and before_policy==after_policy and source_before==source_after
  save(out/'restoration.json',dict(restored=restored,before=before_ref,after=after_ref))
  save(out/'operation-counts.json',dict(native_config_writes=sum(r['kind'].startswith('native-client-') for r in operations),native_creates=sum(r['kind']=='native-client-create' for r in operations),native_replacements=sum(r['kind']=='native-client-replace' for r in operations),native_deletes=sum(r['kind']=='native-client-delete' for r in operations),metadata_phase_flows=sum(r['kind']=='metadata-phase-flow' for r in operations),outbox_flows=sum(r['kind']=='supersession-outbox-flow' for r in operations),product_restarts=0,human_operations=0,restored=restored))
  entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries);capture_browser(out,entries)
  for suffix in ['result.json','protocol-evidence']:
   try:save(out/(suffix if '.' in suffix else suffix+'.json'),api('/api/runs/'+run+'/'+suffix))
   except Exception as e:save(out/(suffix+'-unavailable.json'),dict(reason=str(e)))
  if not restored:raise ValueError('Native restoration failed; stop further product mutation')
 print('Native originals restored; no verdict assigned '+run,flush=True)
if __name__=='__main__':main()
