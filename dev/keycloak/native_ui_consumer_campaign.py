#!/usr/bin/env python3
"""One native import and browser consumer campaign for two Logo and fifteen URL conditions."""
import argparse,base64,datetime,hashlib,json,os,pathlib,subprocess,sys,urllib.parse,urllib.request,xml.etree.ElementTree as ET
from metadata_supersession_campaign import api,native,read,public,sha,now,BASE,ADMIN
from mdiop_representation_campaign import runtime
from algorithm_preference_campaign import recorded
REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture
from import_metadata_batch import recorded_exchange
VARIANTS=['control','ui-consumer-logo-localized','ui-consumer-logo-fallback']+['ui-url-'+element+'-'+scheme for element in ['logo','information','privacy'] for scheme in ['http','https','data','javascript','file']]
UI='{urn:oasis:names:tc:SAML:metadata:ui}'
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--playwright-module',type=pathlib.Path,required=True);p.add_argument('--variants',help='Diagnostic subset only; complete adoption requires all eighteen including control');a=p.parse_args()
 variants=a.variants.split(',') if a.variants else VARIANTS
 if not variants or variants[0]!='control' or not set(variants)<=set(VARIANTS):raise ValueError('Control first, known Suite originals only')
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);operations=[];members=[];created=run=entity=None;worker=None;restored=False;lookup=None
 def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
 def op(kind,**fields):value=dict(kind=kind,startedAt=now(),**fields);operations.append(value);save(out/'operations.json',operations);return value
 plan=api('/api/plans',dict(name='Keycloak native metadata UI consumer matrix',profile='metadata_idp',targetKind='IDP',targetEntityId='http://localhost:18180/realms/samlscope',metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
 save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=created['run']['id'];entity=BASE+'/p/'+pid;lookup='/clients?clientId='+urllib.parse.quote(entity,safe='')
 save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
 subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,capture_output=True)
 target=sha((out/'target-metadata.xml').read_bytes())
 def original(label,value):
  value=dict(schema='samlscope-keycloak-native-ui-original-v1',runId=run,targetMetadataSha256=target,peerEntityId=entity,recordedAt=now(),**value);save(out/(label+'.json'),value);return recorded(out,created,value,label)
 def scope(phase):
  folder=out/'native-source';folder.mkdir(exist_ok=True);jars={}
  for key in ['services','themes']:
   path=folder/(phase+'-'+key+'.jar');subprocess.run(['docker','cp','samlscope-reference-keycloak:/opt/keycloak/lib/lib/main/org.keycloak.keycloak-'+key+'-26.7.2.jar',str(path)],check=True,capture_output=True);jars[key]=sha(path.read_bytes())
  realm=read('');realm={key:realm.get(key) for key in ['id','realm','loginTheme','internationalizationEnabled','defaultLocale','enabled']}
  return dict(kind='native-scope',runtime=runtime(),realm=realm,clientPolicies={key:read('/client-policies/'+key) for key in ['policies','profiles']},sourceJarSha256=jars)
 before=read(lookup)
 if before:raise ValueError('Refuse preexisting native client')
 before_scope=scope('before');before_ref=original('before',dict(kind='client-inventory',clients=before));scope_before_ref=original('scope-before',before_scope)
 env=dict(os.environ,SAMLSCOPE_PLAYWRIGHT_MODULE=str(a.playwright_module.resolve()))
 worker=subprocess.Popen(['node',str(REPO/'dev/keycloak/native_ui_consumer_worker.mjs')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
 try:
  save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=variants,pollingDelaySeconds=0)))
  for variant in variants:
   folder=out/variant;folder.mkdir();state=api('/api/runs/'+run+'/metadata-lab')
   if state['selectedVariant']!=variant:raise ValueError('Prepared fixture differs')
   with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as response:
    if response.status!=202:raise ValueError('Expected preparation gate')
   with urllib.request.urlopen(state['metadataUrl'],timeout=30) as response:fixture=response.read()
   (folder/'fixture.xml').write_bytes(fixture);root=ET.fromstring(fixture);candidates=[e.text for name in ['Logo','InformationURL','PrivacyStatementURL'] for e in root.findall('.//'+UI+name)]
   status,raw,converter=native('/client-description-converter',fixture,'POST','application/xml');conv_ref=original(variant+'-converter',dict(kind='converter',variant=variant,fixtureSha256=sha(fixture),native=converter))
   if status!=200:raise ValueError('Native converter did not admit the fixture')
   recipe=json.loads(raw)
   if public(recipe)!=recipe or recipe.get('clientId')!=entity or recipe.get('protocol')!='saml':raise ValueError('Native converter identity differs')
   configured=dict(recipe,consentRequired=True);mutation=op('native-client-create-attempt',variant=variant)
   status,raw,created_native=native('/clients',configured,'POST');mutation.update(status=status,finishedAt=now());save(out/'operations.json',operations)
   applied_ref=original(variant+'-application',dict(kind='ui-prerequisite-application',variant=variant,fixtureSha256=sha(fixture),converterSha256=sha(json.dumps(recipe,separators=(',',':')).encode()),consentRequired=True,native=created_native))
   member=dict(variant=variant,fixtureSha256=sha(fixture),converter=conv_ref,application=applied_ref)
   if status==400:
    # This is an explicit native client-validation refusal. It is never a SAML rejection.
    if read(lookup):raise ValueError('Failed native import left a client')
    member['nativeAdmission']='rejected';member['rejection']=json.loads(raw)
   elif status==201:
    ids=read(lookup)
    if len(ids)!=1:raise ValueError('Native UI client ambiguous')
    client=public(read('/clients/'+ids[0]['id']));client_id=client['id'];save(folder/'client-readback.json',client)
    member['persisted']=original(variant+'-persisted',dict(kind='operative-client',variant=variant,fixtureSha256=sha(fixture),client=client));member['nativeAdmission']='accepted'
    before_ids={e['id'] for e in api('/api/runs/'+run+'/transcript')};payload=dict(runId=run,variant=variant,startUrl=state['automaticStartUrl'],candidates=candidates,publicHtmlFile=str(folder/'native-consent-public.html'),startedAt=now())
    row=op('native-browser-saml-flow',variant=variant);worker.stdin.write(json.dumps(payload)+'\n');worker.stdin.flush();line=worker.stdout.readline()
    if not line:raise ValueError('Native browser worker stopped')
    browser=json.loads(line);save(folder/'browser.json',browser);row.update(finishedAt=now(),browserStatus=browser.get('ok'));save(out/'operations.json',operations)
    if not browser.get('ok'):raise ValueError('Native browser incomplete '+browser.get('stage','unknown'))
    exchange=recorded_exchange(run,variant,before_ids);save(folder/'exchange.json',exchange)
    if not exchange['success']:raise ValueError('Native correlated Success absent')
    observation=browser['observation'];html=(folder/'native-consent-public.html').read_bytes() if (folder/'native-consent-public.html').exists() else None
    member['browser']=original(variant+'-browser',dict(kind='native-browser-ui',variant=variant,fixtureSha256=sha(fixture),observation=observation,publicHtmlBase64=None if html is None else base64.b64encode(html).decode(),exchange=exchange))
    row=op('native-client-delete',variant=variant);deleted,_,_=native('/clients/'+client_id,method='DELETE');row.update(status=deleted,finishedAt=now());save(out/'operations.json',operations)
    if deleted!=204 or read(lookup)!=before:raise ValueError('Native UI client restoration incomplete')
   else:raise ValueError('Native client application unexpected status '+str(status))
   member['restoration']=original(variant+'-restored',dict(kind='client-inventory',variant=variant,clients=read(lookup)));members.append(member);save(out/'members.json',members)
   pending=api('/api/runs/'+run+'/metadata-lab')
   if pending['campaignIndex']==state['campaignIndex']:
    with urllib.request.urlopen(urllib.request.Request(pending['automaticContinueUrl'],data=b''),timeout=30) as response:response.read()
    member['orchestrationOnlyContinue']=True;save(out/'members.json',members)
   if variant=='control':save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
   print(variant+' '+member['nativeAdmission']+' recorded',flush=True)
 finally:
  if worker:
   try:worker.stdin.write('{"stop":true}\n');worker.stdin.flush();worker.communicate(timeout=30)
   except Exception:worker.kill();worker.communicate()
  for client in read(lookup):
   if client.get('clientId')!=entity or client.get('protocol')!='saml':raise ValueError('Restoration ownership differs')
   row=op('native-recovery-delete',clientId=client['id']);status,_,_=native('/clients/'+client['id'],method='DELETE');row.update(status=status,finishedAt=now());save(out/'operations.json',operations)
   if status!=204:raise ValueError('Native recovery failed')
  after=read(lookup);after_scope=scope('after');after_ref=original('after',dict(kind='client-inventory',clients=after));scope_after_ref=original('scope-after',after_scope)
  restored=before==after and before_scope==after_scope;save(out/'restoration.json',dict(restored=restored,before=before_ref,after=after_ref,scopeBefore=scope_before_ref,scopeAfter=scope_after_ref))
  entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
  for name in ['result.json','protocol-evidence']:
   try:save(out/(name if '.' in name else name+'.json'),api('/api/runs/'+run+'/'+name))
   except Exception:pass
  save(out/'operation-counts.json',dict(product_configuration_write_attempts=sum(r['kind'].startswith('native-client-') or r['kind']=='native-recovery-delete' for r in operations),product_restarts=0,human_operations=0,browser_saml_flows=sum(r['kind']=='native-browser-saml-flow' for r in operations),metadata_fixture_count=len(members),restored=restored))
  if not restored:raise ValueError('Native restoration mismatch; stop product mutations')
 save(out/'qualified-receipt.json',dict(schema='samlscope-keycloak-native-ui-consumer-v1',runId=run,campaignId='native-ui-consumer-matrix',targetEntityId='http://localhost:18180/realms/samlscope',targetMetadataSha256=target,peerEntityId=entity,members=members,restoration=json.loads((out/'restoration.json').read_bytes())))
 print('Restored native UI campaign; no verdict assigned '+run,flush=True)
if __name__=='__main__':main()
