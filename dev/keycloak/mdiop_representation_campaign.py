#!/usr/bin/env python3
"""Native MDIOP representation admission; never a proof of runtime key interpretation."""
import argparse,hashlib,json,pathlib,re,shlex,shutil,subprocess,sys,urllib.parse,urllib.request
from import_metadata_batch import api,save,flow,BASE
from algorithm_preference_campaign import admin,recorded
REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture
REQUIRED=['control','entity-root','entities-root-one','keyvalue-only','keyvalue-and-x509',
 'certificate-expired','certificate-not-yet-valid','certificate-empty-subject','certificate-unknown-ca',
 'certificate-critical-extension','certificate-noncritical-extension','certificate-no-digital-signature',
 'certificate-unrelated-eku','key-use-omitted','multiple-signing-keys-first','multiple-signing-keys',
 'multiple-omitted-keys-first','multiple-omitted-keys-second','multiple-encryption-keys']
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(path):return json.loads(path.read_bytes())
def runtime():
 row=json.loads(subprocess.check_output(['docker','inspect','samlscope-reference-keycloak']))[0]
 return dict(containerId=row['Id'],image=row['Image'],startedAt=row['State']['StartedAt'],running=row['State']['Running'],ports=row['NetworkSettings']['Ports'],
   version=subprocess.check_output(['docker','exec','samlscope-reference-keycloak','/opt/keycloak/bin/kc.sh','--version'],text=True).strip())
def collect(out,folder):
 created=load(out/'created.json');run=created['run']['id'];entity=BASE+'/p/'+created['run']['planId']
 clients=admin('/clients?clientId='+urllib.parse.quote(entity,safe=''))
 if len(clients)!=1:raise ValueError('Native imported client ambiguous')
 native=admin('/clients/'+clients[0]['id']);attrs={k:v for k,v in native.get('attributes',{}).items() if k.startswith('saml')}
 if any(re.search('private|secret|token|credential|password',k,re.I) for k in attrs):raise ValueError('Native sensitive attribute; never persist')
 cfg=dict(schema='samlscope-keycloak-mdiop-representation-readback-v1',runId=run,fixtureSha256=sha((folder/'fixture.xml').read_bytes()),
   targetMetadataSha256=sha((out/'target-metadata.xml').read_bytes()),nativeClient={**{k:native.get(k) for k in ['id','clientId','protocol','enabled','name','description','rootUrl','baseUrl','adminUrl','redirectUris']},'samlAttributes':attrs},
   evidenceScope='representation-admission-only',runtimeKeyInterpretationProven=False)
 save(folder/'native-configuration.json',cfg);save(folder/'native-configuration-reference.json',recorded(out,created,cfg,folder.name+'-configuration'))
 native=load(folder/'import.admission-originals.json')
 for label,key in [('converter','converter'),('persisted','saved')]:
  value=dict(schema='samlscope-keycloak-mdiop-native-original-v1',runId=run,fixtureSha256=sha((folder/'fixture.xml').read_bytes()),
    targetMetadataSha256=sha((out/'target-metadata.xml').read_bytes()),native=native[key],phase='before-policy-change')
  save(folder/(label+'-original-reference.json'),recorded(out,created,value,folder.name+'-'+label))
  save(folder/(label+'-original.json'),value)
 try:flow(run,folder/'flow.json')
 except Exception as error:
  save(folder/'flow-diagnostic-incomplete.json',dict(reason=str(error),affects_verdict=False,runtime_key_interpretation_proven=False))
  if folder.name=='control':raise

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--playwright-modules',type=pathlib.Path);p.add_argument('--flow-member',type=pathlib.Path)
 args=p.parse_args();out=args.output.resolve()
 if args.flow_member:collect(out,args.flow_member.resolve());return
 if not args.playwright_modules:p.error('--playwright-modules required')
 out.mkdir(parents=True,exist_ok=False);stage=out/'driver';stage.mkdir();shutil.copy2(pathlib.Path(__file__).with_name('console_import.mjs'),stage/'console_import.mjs')
 (stage/'node_modules').symlink_to(args.playwright_modules.resolve(),target_is_directory=True)
 before=runtime();save(out/'native-runtime-before.json',before)
 plan=api('/api/plans',dict(name='Keycloak native MDIOP representation admission',profile='metadata_idp',targetKind='IDP',targetEntityId='http://localhost:18180/realms/samlscope',metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
 save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
 subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,capture_output=True)
 entity=BASE+'/p/'+pid
 if admin('/clients?clientId='+urllib.parse.quote(entity,safe='')):raise ValueError('Refusing original existing client')
 policies={key:admin('/client-policies/'+key) for key in ['policies','profiles']};save(out/'native-global-policy-before.json',policies)
 target_hash=sha((out/'target-metadata.xml').read_bytes())
 runtime_before_ref=recorded(out,created,dict(schema='samlscope-keycloak-mdiop-runtime-v1',runId=run,targetMetadataSha256=target_hash,runtime=before,globalPolicy=policies),'runtime-before')
 lookup=ADMIN_LOOKUP='http://localhost:18180/admin/realms/samlscope/clients?clientId='+urllib.parse.quote(entity,safe='')
 def inventory_original(value):
  raw=json.dumps(value,separators=(',',':')).encode()
  return dict(schema='samlscope-keycloak-mdiop-client-inventory-v1',runId=run,targetMetadataSha256=target_hash,peerEntityId=entity,native=dict(method='GET',url=lookup,status=200,response_base64=__import__('base64').b64encode(raw).decode(),response_sha256=sha(raw)))
 original_clients_ref=recorded(out,created,inventory_original([]),'clients-original')

 operations=[]
 try:
  save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=REQUIRED,pollingDelaySeconds=0)))
  for variant in REQUIRED:
   folder=out/variant;folder.mkdir();state=api('/api/runs/'+run+'/metadata-lab')
   if state['selectedVariant']!=variant:raise ValueError('Fixture selection differs')
   with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as r:
    if r.status!=202:raise ValueError('Preparation fetch gate missing')
   with urllib.request.urlopen(state['metadataUrl'],timeout=30) as r:(folder/'fixture.xml').write_bytes(r.read())
   follow=shlex.join([sys.executable,str(pathlib.Path(__file__).resolve()),'--output',str(out),'--flow-member',str(folder)])
   command=['node',str(stage/'console_import.mjs'),'--fixture',str(folder/'fixture.xml'),'--record',str(folder/'import.json'),'--entity-id',entity,'--verify-command',follow,'--delete','--capture-native-admission-originals']
   row=dict(variant=variant,native_import_attempted=True,native_write_attempts=0,restored=False,driver_exit=None);operations.append(row);save(out/'operations.json',operations)
   result=subprocess.run(command,capture_output=True,text=True,timeout=420);(folder/'driver.log').write_text(result.stdout+result.stderr)
   imported=load(folder/'import.json');row.update(driver_exit=result.returncode,restored=imported.get('cleanup',{}).get('read_back_absent') is True,
     native_write_attempts=imported.get('import',{}).get('representation_admission_only',{}).get('write_attempts',0));save(out/'operations.json',operations)
   if result.returncode or not row['restored']:raise ValueError('Native representation/control incomplete; retain NOT_VERIFIED')
   pending=api('/api/runs/'+run+'/metadata-lab')
   if pending['campaignIndex']==state['campaignIndex']:
    with urllib.request.urlopen(urllib.request.Request(pending['automaticContinueUrl'],data=b''),timeout=30) as response:response.read()
    row['continued_after_admission_only']=True;save(out/'operations.json',operations)
   print(variant+' native admission recorded/restored',flush=True)
   if variant=='control':save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
 finally:
  remaining=admin('/clients?clientId='+urllib.parse.quote(entity,safe=''));recovery=0
  for owned in remaining:
   if owned.get('clientId')!=entity or owned.get('protocol')!='saml':raise ValueError('Failure cleanup ownership unproven')
   admin('/clients/'+owned['id'],method='DELETE');recovery+=1
  remaining=admin('/clients?clientId='+urllib.parse.quote(entity,safe=''))
  save(out/'restoration.json',dict(restored=remaining==[],remaining_clients=[{k:r.get(k) for k in ['id','clientId','protocol']} for r in remaining],recovery_client_removals=recovery))
  after=runtime();save(out/'native-runtime-after.json',after)
  finalpolicy={key:admin('/client-policies/'+key) for key in ['policies','profiles']};save(out/'native-global-policy-after.json',finalpolicy)
  runtime_after_ref=recorded(out,created,dict(schema='samlscope-keycloak-mdiop-runtime-v1',runId=run,targetMetadataSha256=target_hash,runtime=after,globalPolicy=finalpolicy),'runtime-after')
  restored_clients_ref=recorded(out,created,inventory_original(remaining),'clients-restored')
  save(out/'operation-counts.json',dict(native_import_attempts=len(operations),temporary_clients_removed=sum(r['restored'] for r in operations),native_admission_policy_write_attempts=sum(r['native_write_attempts'] for r in operations),protocol_flows_attempted=len(operations),recovery_client_removals=recovery,product_restarts=0,human_operations=0,restored=remaining==[] and before==after and policies==finalpolicy,runtime_key_interpretation_proven=False))
  entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
  if len(operations)==len(REQUIRED) and all(r['restored'] and r['driver_exit']==0 for r in operations) and remaining==[] and before==after and policies==finalpolicy:
   members=[]
   for variant in REQUIRED:
    raw=(out/variant/'fixture.xml').read_bytes()
    prepared=[e for e in entries if e['samlSummary'].get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==variant and e['samlSummary'].get('metadataSha256')==sha(raw)]
    if len(prepared)!=1:raise ValueError('Ambiguous original preparation')
    members.append(dict(variant=variant,fixtureSha256=sha(raw),preparedReference=prepared[0]['id'],converter=load(out/variant/'converter-original-reference.json'),persisted=load(out/variant/'persisted-original-reference.json')))
   save(out/'qualified-receipt.json',dict(schema='samlscope-keycloak-mdiop-representation-v1',adapter='keycloak-console-native-admission-v1',runId=run,campaignId='metadata-fixture-refresh',targetEntityId='http://localhost:18180/realms/samlscope',targetMetadataSha256=target_hash,members=members,originalClients=original_clients_ref,restoredClients=restored_clients_ref,runtimeBefore=runtime_before_ref,runtimeAfter=runtime_after_ref))

  for suffix in ['result.json','protocol-evidence']:
   try:save(out/(suffix if '.' in suffix else suffix+'.json'),api('/api/runs/'+run+'/'+suffix))
   except Exception as error:save(out/(suffix+'-unavailable.json'),dict(reason=str(error)))
 print('Native complete representation originals restored; no verdict adopted',run,flush=True)
if __name__=='__main__':main()
