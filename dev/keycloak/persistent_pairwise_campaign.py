#!/usr/bin/env python3
"""Two fresh native SAML clients and one temporary native principal, always restored.

The password is random, held only in memory, and omitted before any Recorder call.
Product metadata conversion consumes original Suite XML; this script assigns no verdict.
"""
import argparse,base64,hashlib,json,pathlib,re,secrets,subprocess,sys,urllib.parse,urllib.request,xml.etree.ElementTree as ET
from metadata_supersession_campaign import api,native,read,public,sha,now,BASE,ADMIN
from mdiop_representation_campaign import runtime
from algorithm_preference_campaign import recorded
from reference_flow import Client
REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture
from browser_probe_selection import prepare_and_skip
CASE='IIP-SSO05-a3-idp-01'
TARGET='http://localhost:18180/realms/samlscope'
USERNAME_MAPPER=dict(name='samlscope-native-principal-username',protocol='saml',protocolMapper='saml-user-property-mapper',consentRequired=False,config={'user.attribute':'username','attribute.name':'samlscope.native.username','attribute.nameformat':'Basic'})

def exchange(run, previous):
 entries=[e for e in api('/api/runs/'+run+'/transcript') if e['id'] not in previous]
 requests=[e for e in entries if e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='AuthnRequest']
 if len(requests)!=1:return dict(success=False,reason='ambiguous-issued-request')
 request=requests[0];ref=request.get('decodedSamlRef')
 if not re.fullmatch(r'transcripts/'+run+r'/tx_[0-9A-HJKMNP-TV-Z]{26}\.saml\.xml',ref or ''):raise ValueError('Foreign request content path')
 raw=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat','/data/'+ref],timeout=30)
 if len(raw)!=request['decodedSamlBytes']:raise ValueError('Request original length differs')
 request_id=ET.fromstring(raw).get('ID')
 if not request_id:return dict(success=False,reason='request-correlation-unavailable')
 responses=[e for e in entries if e['direction']=='INBOUND' and e['samlSummary'].get('type')=='Response' and e['samlSummary'].get('inResponseTo')==request_id]
 if len(responses)!=1:return dict(success=False,reason='ambiguous-native-response')
 response=responses[0]
 return dict(success=response['samlSummary'].get('statusCode')=='urn:oasis:names:tc:SAML:2.0:status:Success' and any(response['samlSummary'].get(k) is True for k in ['normalFlowAccepted','activeProbeAccepted']),requestId=request_id,requestSha256=sha(raw),transcript_ids=[request['id'],response['id']])

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--same-value-native-mutant',action='store_true');a=p.parse_args()
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);operations=[];peers=[];user_id=None
 username='samlscope-pairwise-'+secrets.token_hex(10);password=secrets.token_urlsafe(40)
 lookup_user='/users?username='+urllib.parse.quote(username,safe='')+'&exact=true'
 def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
 def op(kind,**fields):row=dict(kind=kind,startedAt=now(),**fields);operations.append(row);save(out/'operations.json',operations);return row
 def scope():
  realm=read('');return dict(runtime=runtime(),realm={key:realm.get(key) for key in ['id','realm','enabled','defaultDefaultClientScopes','defaultOptionalClientScopes','loginTheme','internationalizationEnabled']},policies={key:read('/client-policies/'+key) for key in ['policies','profiles']},userProfile=read('/users/profile'),samlClientScopes=[s for s in read('/client-scopes') if s['protocol']=='saml'])
 before_scope=scope();scope_captured_at=now();profile_control=None;profile_restore=None;save(out/'scope-before.json',before_scope);save(out/'campaign.json',dict(caseId=CASE,sameValueNativeMutant=a.same_value_native_mutant,productOutcomeAdopted=False));profile_changed=False
 if read(lookup_user):raise ValueError('Fresh principal already exists')
 save(out/'user-before.json',dict(query=ADMIN+lookup_user,users=[]))
 source=out/'native-source';source.mkdir();subprocess.run(['docker','cp','samlscope-reference-keycloak:/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar',str(source/'before-services.jar')],check=True,capture_output=True)
 def original(peer,label,value):
  value=dict(schema='samlscope-keycloak-persistent-pairwise-original-v1',runId=peer['run'],campaignId='native-persistent-pairwise',targetMetadataSha256=peer['targetSha256'],peerEntityId=peer['entity'],recordedAt=now(),**value);save(peer['folder']/(label+'.json'),value);return recorded(peer['folder'],peer['created'],value,label)
 def readback(peer,label):
  current=public(read('/clients/'+peer['clientId']));user=public(read('/users/'+user_id))
  if current.get('clientId')!=peer['entity'] or user.get('id')!=user_id or user.get('username')!=username:raise ValueError('Native peer or principal identity differs')
  return original(peer,label,dict(kind='operative-pairwise-state',client=current,user=user,scope=scope()))
 try:
  if a.same_value_native_mutant:
   configured_profile=dict(before_scope['userProfile'],unmanagedAttributePolicy='ADMIN_EDIT');row=op('native-user-profile-configure');status,_,profile_control=native('/users/profile',configured_profile,'PUT');row.update(status=status,finishedAt=now());save(out/'operations.json',operations);profile_changed=True
   if status!=200 or read('/users/profile')!=configured_profile:raise ValueError('Native wildcard input profile not read back')
  recipe=dict(username=username,enabled=True,emailVerified=True,firstName='SAMLscope',lastName='Pairwise',email=username+'@example.invalid',requiredActions=[])
  if a.same_value_native_mutant:recipe['attributes']={'saml.persistent.name.id.for.*':['N'*257]}
  request=dict(recipe,credentials=[dict(type='password',temporary=False,value=password)])
  row=op('native-temporary-user-create');status,_,obs=native('/users',request,'POST');row.update(status=status,finishedAt=now());save(out/'operations.json',operations)
  # Remove credential-bearing request fingerprint as well as credential bytes before persistence.
  obs.pop('requestSha256',None);save(out/'user-create.json',dict(publicRecipe=recipe,native=obs,credentialInputRetained=False))
  if status!=201:raise ValueError('Native temporary principal creation failed')
  found=read(lookup_user)
  if len(found)!=1:raise ValueError('Temporary principal identity ambiguous')
  user_id=found[0]['id'];save(out/'user-created.json',public(read('/users/'+user_id)))
  for label in ['primary','secondary']:
   folder=out/label;folder.mkdir()
   plan=api('/api/plans',dict(name='Keycloak native persistent pairwise '+label,profile='browser_sso_idp',targetKind='IDP',targetEntityId=TARGET,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint=username,requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
   save(folder/'plan.json',plan);pid=plan['plan']['plan']['id'];created=api('/api/plans/'+pid+'/runs',{});save(folder/'created.json',created);run=created['run']['id'];entity=BASE+'/p/'+pid
   peer=dict(label=label,folder=folder,created=created,run=run,entity=entity,clientId=None);peers.append(peer)
   save(folder/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
   subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(folder/'target-metadata.xml')],check=True,capture_output=True);peer['targetSha256']=sha((folder/'target-metadata.xml').read_bytes())
   with urllib.request.urlopen(entity+'/metadata',timeout=30) as response:fixture=response.read()
   (folder/'fixture.xml').write_bytes(fixture);lookup='/clients?clientId='+urllib.parse.quote(entity,safe='');peer['lookup']=lookup
   if read(lookup):raise ValueError('Fresh peer already exists')
   original(peer,'initial-inventory',dict(kind='initial-inventory',clients=[],usersBefore=dict(query=ADMIN+lookup_user,users=[]),publicUserCreation=json.loads((out/'user-create.json').read_bytes()),userCreated=json.loads((out/'user-created.json').read_bytes()),originalScope=before_scope,originalScopeCapturedAt=scope_captured_at,profileControl=profile_control))
   status,raw,obs=native('/client-description-converter',fixture,'POST','application/xml');peer['converter']=original(peer,'converter',dict(kind='native-converter',fixtureSha256=sha(fixture),native=obs))
   if status!=200:raise ValueError('Native peer converter failed')
   converted=json.loads(raw)
   if public(converted)!=converted or converted.get('clientId')!=entity or converted.get('protocol')!='saml':raise ValueError('Native converter output differs')
   if converted.get('protocolMappers')!=[]:raise ValueError('Native converter unexpected mapper')
   configured=dict(converted,protocolMappers=[USERNAME_MAPPER]);row=op('native-client-create',peer=label);status,_,obs=native('/clients',configured,'POST');row.update(status=status,finishedAt=now());save(out/'operations.json',operations);peer['application']=original(peer,'application',dict(kind='native-client-application',fixtureSha256=sha(fixture),native=obs,identifyingAttributeMapper=USERNAME_MAPPER))
   if status!=201:raise ValueError('Native peer create failed')
   found=read(lookup)
   if len(found)!=1:raise ValueError('Created peer ambiguous')
   peer['clientId']=found[0]['id']
  for peer in peers:
   folder=peer['folder'];run=peer['run'];peer['before']=readback(peer,'before')
   before_ids={e['id'] for e in api('/api/runs/'+run+'/transcript')};row=op('native-baseline-flow',peer=peer['label']);result=Client().flow(peer['entity']+'/start/m0-roundtrip?run='+run,None,username,password);row.update(result=result,finishedAt=now());save(out/'operations.json',operations)
   observed=exchange(run,before_ids);save(folder/'baseline-exchange.json',observed)
   if result!='recorded' or not observed['success']:raise ValueError('Native baseline was not successful')
   save(folder/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));skipped=[];probe=None
   for _ in range(1000):
    pending=api('/api/runs/'+run+'/active-probe')
    if pending.get('state')!='READY':raise ValueError('Persistent case unavailable '+str(pending.get('state')))
    if pending.get('caseId')!=CASE:skipped.append(prepare_and_skip(BASE,run,pending,api));save(folder/'skipped.json',skipped);continue
    probe=pending;break
   if probe is None:raise ValueError('Native persistent case was not found')
   before_ids={e['id'] for e in api('/api/runs/'+run+'/transcript')};row=op('native-persistent-flow',peer=peer['label'],caseId=CASE,actionId=probe['actionId']);result=Client().flow(probe['startUrl'],None,username,password);row.update(result=result,finishedAt=now());save(out/'operations.json',operations)
   observed=exchange(run,before_ids);save(folder/'persistent-exchange.json',observed);save(folder/'probe.json',probe)
   if result!='recorded' or not observed['success']:raise ValueError('Native persistent request was not successful')
   peer['after']=readback(peer,'after');save(folder/'evaluation-before-native-proof.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}));print(peer['label']+' baseline+persistent recorded',flush=True)
 finally:
  restored=True
  for peer in reversed(peers):
   if not peer.get('lookup'):continue
   current=read(peer['lookup'])
   for client in current:
    if client.get('clientId')!=peer['entity'] or client.get('protocol')!='saml' or peer.get('clientId') not in [None,client['id']]:raise ValueError('Recovery ownership differs')
    row=op('native-client-delete',peer=peer['label']);status,_,_=native('/clients/'+client['id'],method='DELETE');row.update(status=status,finishedAt=now());save(out/'operations.json',operations)
    if status!=204:restored=False
   peer['finalClients']=read(peer['lookup']);restored=restored and peer['finalClients']==[]
  for user in read(lookup_user):
   if user.get('username')!=username or user_id not in [None,user['id']]:raise ValueError('Temporary principal recovery ownership differs')
   row=op('native-temporary-user-delete');status,_,_=native('/users/'+user['id'],method='DELETE');row.update(status=status,finishedAt=now());save(out/'operations.json',operations)
   if status!=204:restored=False
  final_users=read(lookup_user)
  if profile_changed:
   row=op('native-user-profile-restore');status,_,profile_restore=native('/users/profile',before_scope['userProfile'],'PUT');row.update(status=status,finishedAt=now());save(out/'operations.json',operations)
   if status!=200 or read('/users/profile')!=before_scope['userProfile']:restored=False
  after_scope=scope();save(out/'scope-after.json',after_scope);save(out/'user-after.json',dict(query=ADMIN+lookup_user,users=final_users));restored=restored and final_users==[] and before_scope==after_scope
  subprocess.run(['docker','cp','samlscope-reference-keycloak:/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar',str(source/'after-services.jar')],check=True,capture_output=True)
  restored=restored and (source/'before-services.jar').read_bytes()==(source/'after-services.jar').read_bytes();save(out/'restoration.json',dict(restored=restored,finalUsers=final_users,finalClients={peer['label']:peer.get('finalClients') for peer in peers}))
  for peer in peers:
   if not peer.get('targetSha256'):continue
   peer['restoration']=original(peer,'restored',dict(kind='restoration',clients=peer.get('finalClients'),users=final_users,scope=after_scope,profileRestoration=profile_restore,sourceJarSha256=sha((source/'after-services.jar').read_bytes())))
   entries=api('/api/runs/'+peer['run']+'/transcript');save(peer['folder']/'transcript.json',entries);capture(peer['folder'],peer['run'],entries)
   for endpoint in ['result.json','protocol-evidence']:
    try:save(peer['folder']/(endpoint if '.' in endpoint else endpoint+'.json'),api('/api/runs/'+peer['run']+'/'+endpoint))
    except Exception:pass
  save(out/'operation-counts.json',dict(nativeConfigurationWriteAttempts=sum(row['kind'] in ['native-temporary-user-create','native-temporary-user-delete','native-client-create','native-client-delete','native-user-profile-configure','native-user-profile-restore'] for row in operations),normalFlowsAttempted=sum(row['kind'] in ['native-baseline-flow','native-persistent-flow'] for row in operations),productRestarts=0,humanOperations=0,runCreations=len(peers),restored=restored))
  if any(password.encode() in path.read_bytes() for path in out.rglob('*') if path.is_file()):raise ValueError('Credential leak detected')
  if not restored:raise ValueError('Exact native restoration failed')
 save(out/'peers.json',[{k:v for k,v in peer.items() if k not in ['folder','created']} for peer in peers])
 print('Native pairwise originals captured, configurations restored; no verdict adopted',flush=True)
if __name__=='__main__':main()
