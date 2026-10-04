#!/usr/bin/env python3
"""Native multi-entity parser counterexample with signed single-entity controls."""
import argparse,base64,json,pathlib,shlex,shutil,subprocess,sys,urllib.error,urllib.parse,urllib.request
from import_metadata_batch import api,save,BASE
from algorithm_preference_campaign import admin,recorded,product_token
from mdiop_representation_campaign import runtime,collect,sha
REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture
REQUIRED=['control','entities-root-one','entities-root-two','entities-root-fifty']
ADMIN='http://localhost:18180/admin/realms/samlscope'
def load(path):return json.loads(path.read_bytes())
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--playwright-modules',type=pathlib.Path);p.add_argument('--flow-member',type=pathlib.Path)
 args=p.parse_args();out=args.output.resolve()
 if args.flow_member:collect(out,args.flow_member.resolve());return
 if not args.playwright_modules:p.error('--playwright-modules required')
 out.mkdir(parents=True,exist_ok=False);stage=out/'driver';stage.mkdir();shutil.copy2(pathlib.Path(__file__).with_name('console_import.mjs'),stage/'console_import.mjs')
 (stage/'node_modules').symlink_to(args.playwright_modules.resolve(),target_is_directory=True)
 save(out/'native-runtime-before.json',before:=runtime())
 plan=api('/api/plans',dict(name='Keycloak native metadata child cardinality',profile='metadata_idp',targetKind='IDP',targetEntityId='http://localhost:18180/realms/samlscope',metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
 save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];save(out/'created.json',created:=api('/api/plans/'+pid+'/runs',{}));run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
 subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,capture_output=True)
 peer=BASE+'/p/'+pid;lookup='/clients?clientId='+urllib.parse.quote(peer,safe='')
 if admin(lookup):raise ValueError('Refusing existing client')
 target_hash=sha((out/'target-metadata.xml').read_bytes());save(out/'native-global-policy-before.json',policy:={key:admin('/client-policies/'+key) for key in ['policies','profiles']})
 def state_ref(label,rt,pol):return recorded(out,created,dict(schema='samlscope-keycloak-mdiop-runtime-v1',runId=run,targetMetadataSha256=target_hash,runtime=rt,globalPolicy=pol),label)
 def inventory_ref(label,value):
  raw=json.dumps(value,separators=(',',':')).encode()
  return recorded(out,created,dict(schema='samlscope-keycloak-mdiop-client-inventory-v1',runId=run,targetMetadataSha256=target_hash,peerEntityId=peer,native=dict(method='GET',url=ADMIN+lookup,status=200,response_base64=base64.b64encode(raw).decode(),response_sha256=sha(raw))),label)
 runtime_before=state_ref('runtime-before',before,policy);original_clients=inventory_ref('original-clients',[]);operations=[]
 try:
  save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=REQUIRED,pollingDelaySeconds=0)))
  for variant in REQUIRED:
   folder=out/variant;folder.mkdir();state=api('/api/runs/'+run+'/metadata-lab')
   if state['selectedVariant']!=variant:raise ValueError('Wrong prepared variant')
   with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as r:
    if r.status!=202:raise ValueError('Preparation fetch gate missing')
   with urllib.request.urlopen(state['metadataUrl'],timeout=30) as r:(folder/'fixture.xml').write_bytes(raw:=r.read())
   row=dict(variant=variant,fixtureSha256=sha(raw),native_client_created=False,native_policy_puts=0,restored=False);operations.append(row);save(out/'operations.json',operations)
   if variant in REQUIRED[:2]:
    follow=shlex.join([sys.executable,str(pathlib.Path(__file__).resolve()),'--output',str(out),'--flow-member',str(folder)])
    result=subprocess.run(['node',str(stage/'console_import.mjs'),'--fixture',str(folder/'fixture.xml'),'--record',str(folder/'import.json'),'--entity-id',peer,'--verify-command',follow,'--delete','--capture-native-admission-originals'],capture_output=True,text=True,timeout=420)
    (folder/'driver.log').write_text(result.stdout+result.stderr);imported=load(folder/'import.json');row.update(native_client_created=bool(imported.get('client',{}).get('database_id')),driver_exit=result.returncode,restored=imported.get('cleanup',{}).get('read_back_absent') is True)
    if result.returncode or not row['restored']:raise ValueError('Positive control incomplete')
   else:
    url=ADMIN+'/client-description-converter';request=urllib.request.Request(url,data=raw,method='POST',headers={'Authorization':'Bearer '+product_token(),'Content-Type':'application/xml'})
    try:
     with urllib.request.urlopen(request,timeout=30) as response:status=response.status;body=response.read()
    except urllib.error.HTTPError as error:status=error.code;body=error.read()
    value=json.loads(body)
    if not isinstance(value,dict) or {'secret','registrationAccessToken'}&set(value):raise ValueError('Unsafe native response; no persistence')
    native=dict(url=url,method='POST',status=status,request_sha256=sha(raw),request_matches_original_fixture=True,response_base64=base64.b64encode(body).decode(),response_sha256=sha(body))
    original=dict(schema='samlscope-keycloak-mdiop-native-original-v1',runId=run,targetMetadataSha256=target_hash,fixtureSha256=sha(raw),native=native,phase='before-policy-change')
    save(folder/'converter-original.json',original);save(folder/'converter-original-reference.json',recorded(out,created,original,variant+'-converter'));row.update(native_status=status,native_error=value.get('error'),restored=admin(lookup)==[])
   save(out/'operations.json',operations)
   pending=api('/api/runs/'+run+'/metadata-lab')
   if pending['campaignIndex']==state['campaignIndex']:
    with urllib.request.urlopen(urllib.request.Request(pending['automaticContinueUrl'],data=b''),timeout=30) as response:response.read()
    row['continued_after_native_observation']=True;save(out/'operations.json',operations)
   if variant=='control':save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
   print(variant+' native original recorded and restored',flush=True)
 finally:
  remaining=admin(lookup);recovery=0
  for owned in remaining:
   if owned.get('clientId')!=peer or owned.get('protocol')!='saml':raise ValueError('Cleanup ownership unclear')
   admin('/clients/'+owned['id'],method='DELETE');recovery+=1
  remaining=admin(lookup);save(out/'restoration.json',dict(restored=remaining==[],remaining_clients=[r['id'] for r in remaining],recovery_client_removals=recovery));save(out/'native-runtime-after.json',after:=runtime());save(out/'native-global-policy-after.json',final:={key:admin('/client-policies/'+key) for key in ['policies','profiles']})
  runtime_after=state_ref('runtime-after',after,final);restored_clients=inventory_ref('restored-clients',remaining)
  save(out/'operation-counts.json',dict(native_conversion_attempts=len(operations),native_client_creates=sum(r['native_client_created'] for r in operations),native_client_deletes=sum(r['native_client_created'] and r['restored'] for r in operations),native_policy_puts=0,protocol_flows_attempted=sum(r['variant'] in REQUIRED[:2] for r in operations),product_restarts=0,human_operations=0,recovery_client_removals=recovery,restored=remaining==[] and before==after and policy==final))
  save(out/'transcript.json',entries:=api('/api/runs/'+run+'/transcript'));capture(out,run,entries)
  if len(operations)==len(REQUIRED) and all(r['restored'] for r in operations) and remaining==[] and before==after and policy==final:
   members=[]
   for variant in REQUIRED:
    raw=(out/variant/'fixture.xml').read_bytes();prepared=[e for e in entries if e['samlSummary'].get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==variant and e['samlSummary'].get('metadataSha256')==sha(raw)]
    if len(prepared)!=1:raise ValueError('Ambiguous prepared metadata')
    members.append(dict(variant=variant,fixtureSha256=sha(raw),preparedReference=prepared[0]['id'],converter=load(out/variant/'converter-original-reference.json')))
   save(out/'qualified-receipt.json',dict(schema='samlscope-keycloak-metadata-cardinality-v1',adapter='keycloak-native-description-converter-v1',runId=run,campaignId='metadata-fixture-refresh',targetEntityId='http://localhost:18180/realms/samlscope',targetMetadataSha256=target_hash,members=members,originalClients=original_clients,restoredClients=restored_clients,runtimeBefore=runtime_before,runtimeAfter=runtime_after))
  for suffix in ['result.json','protocol-evidence']:
   try:save(out/(suffix if '.' in suffix else suffix+'.json'),api('/api/runs/'+run+'/'+suffix))
   except Exception as error:save(out/(suffix+'-unavailable.json'),dict(reason=str(error)))
 print('Native cardinality originals restored; no verdict adopted',run,flush=True)
if __name__=='__main__':main()
