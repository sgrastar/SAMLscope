#!/usr/bin/env python3
"""Adopt the actual native accepted-metadata endpoint counterexample, never capability absence."""
import argparse,base64,hashlib,importlib.util,json,pathlib,subprocess,sys,urllib.parse,urllib.request,zipfile
REPO=pathlib.Path(__file__).resolve().parents[2]
CASE='IIP-MD06-a-idp-01';FOLDER='keycloak-native-supersession-v177-r3'
FOLDERS={'keycloak-native-supersession-v175-r2',FOLDER}
spec=importlib.util.spec_from_file_location('kc_supersession_runtime',REPO/'dev/reference-acceptance/verify_ssp_intersection_capability_acceptance.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
runtime.HELPER='VerifyKeycloakMetadataSupersessionEvidence'
runtime.CLASSES=('com/samlscope/runner/cases/KeycloakMetadataSupersessionEvidenceFile.class','com/samlscope/runner/cases/MetadataSupersessionProbeTestCase.class')
sha,load,require=runtime.sha,runtime.load,runtime.require
def api(path,body=None):
 q=urllib.request.Request('http://localhost:18080'+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(q,timeout=60) as r:return json.load(r)
def verify_adoption(root,live=False,formal=True):
 folder=pathlib.Path(root).resolve()
 if folder.name not in FOLDERS:folder=folder/FOLDER
 created=load(folder/'created.json')['run'];run,peer=created['id'],'http://localhost:18080/p/'+created['planId'];receipt=load(folder/'qualified-receipt.json')
 require(receipt['runId']==run and receipt['peerEntityId']==peer and receipt['adapter']=='keycloak-native-converter-same-client-v1' and receipt['campaignId']=='native-metadata-supersession' and receipt['targetMetadataSha256']==sha((folder/'target-metadata.xml').read_bytes()),'Native acceptance scope differs')
 entries=load(folder/'transcript.json');by={e['id']:e for e in entries};require(len(by)==len(entries) and all(e['runId']==run for e in entries),'Foreign/duplicate native history')
 originals={}
 for ref in load(folder/'decoded-manifest.json'):
  path=(folder/ref['file']).resolve();raw=path.read_bytes();require(path.parent==(folder/'decoded').resolve() and sha(raw)==ref['sha256'] and len(raw)==by[ref['id']]['decodedSamlBytes'] and ref['id'] not in originals,'Decoded original differs');originals[ref['id']]=raw
 def original(ref):
  raw=originals[ref['reference']];require(sha(raw)==ref['sha256'],'Native original hash differs');value=json.loads(raw)
  require(value['runId']==run and value['peerEntityId']==peer and value['targetMetadataSha256']==receipt['targetMetadataSha256'],'Native original identity differs');return value
 ids=set()
 for phase in receipt['phases']:
  xml=(folder/phase['variant']/'fixture.xml').read_bytes();require(sha(xml)==phase['fixtureSha256'] and originals[phase['preparedReference']]==xml,'Native converter fixture differs')
  converted=original(phase['converter']);persisted=original(phase['persisted']);require(converted==load(folder/(phase['variant']+'-converter.json')) and persisted==load(folder/(phase['variant']+'-persisted.json')),'Native references are not captured originals')
  response=base64.b64decode(converted['native']['responseBase64']);require(sha(response)==converted['native']['responseSha256'] and sha(xml)==converted['native']['requestSha256'],'Native converter XML/response differs')
  recipe=json.loads(response);sent=json.dumps(recipe,separators=(',',':')).encode();require(sha(sent)==persisted['mutation']['requestSha256'],'Suite changed the native client representation')
  require(persisted['mutation']['method'] in {'POST','PUT'} and persisted['clientDatabaseId'] not in {'',None},'Native application did not identify client');ids.add(persisted['clientDatabaseId'])
 require(len(ids)==1,'Native client was not replaced in place')
 for phase in ['before','after']:
  state=original(receipt['restoration'][phase]);jar=folder/'native-runtime'/(phase+'-services.jar');require(sha(jar.read_bytes())==state['nativePaths']['jarSha256'],'Native implementation source differs')
  with zipfile.ZipFile(jar) as z:
   for name,encoded in state['nativePaths']['classes'].items():require(z.read(name)==base64.b64decode(encoded),'Native source class bytes differ')
 require((folder/'native-runtime/before-services.jar').read_bytes()==(folder/'native-runtime/after-services.jar').read_bytes(),'Native source changed during campaign')
 for row in load(folder/'browser-originals-manifest.json'):
  raw=(folder/row['file']).read_bytes();require(sha(raw)==row['sha256'] and len(raw)==row['bytes']==by[row['id']]['bodyBytes'],'Browser original differs')
 counts=load(folder/'operation-counts.json');require(counts==dict(native_config_writes=5,native_creates=1,native_replacements=3,native_deletes=1,metadata_phase_flows=4,outbox_flows=9,product_restarts=0,human_operations=0,restored=True),'Native mutation/restoration count differs')
 operations=load(folder/'operations.json');require(sum(op['kind'].startswith('native-client-') for op in operations)==5 and all(op.get('status') in {201,204} for op in operations if op['kind'].startswith('native-client-')),'Native writes/restoration did not complete')
 history=load(folder/'operation-history.json');attempts=len(history['attempts']);require(attempts in {2,3} and history['restored'] and history['product_configuration_operations']==5*attempts and history['protocol_saml_requests']==15*attempts and history['run_creations']==attempts and history['product_restarts']==history['human_operations']==0,'Prior attempt costs omitted')
 if folder.name==FOLDER:
  require(attempts==3 and load(folder/'selected-probe-case.json')['caseId']==CASE and all(by[row['requestReference']]['samlSummary']['scenario_case_id']==CASE for row in receipt['probes']),'Formal native counterexample was not measured by its own case')
 require([row['folder'] for row in history['attempts']]==['keycloak-native-supersession-v175-r1','keycloak-native-supersession-v175-r2',FOLDER][:attempts] and history['additional_adoption_product_operations']==0,'Historical native attempts are duplicated or incomplete')
 for attempt in history['attempts']:
  prior=folder.parent/attempt['folder'];require(prior.parent==folder.parent and load(prior/'operation-counts.json')==counts,'Earlier native state/counts differ')
  require(set(attempt['sourceFiles'])=={'operations.json','operation-counts.json','restoration.json','transcript.json','phases.json','probes.json'},'Prior attempt cost originals omitted')
  for name,digest in attempt['sourceFiles'].items():require(pathlib.Path(name).name==name and sha((prior/name).read_bytes())==digest,'Prior attempt original changed')
 report=runtime.replay(folder);require(report==load(folder/'native-reader-replay.json'),'Archived production replay differs')
 require(report['runId']==run and report['caseId']==CASE and report['outcome']=='VIOLATED' and report['reasonCode']=='metadata.application.accepted-post-endpoint-rejected' and report['privateKeyExported'] is False,'Actual application counterexample not proven')
 require(len(report['checks'])==18 and report['checks']['accepted-second-post-acs-counterexample']=='VIOLATED' and all(v=='NOT_VERIFIED' for k,v in report['checks'].items() if k!='accepted-second-post-acs-counterexample'),'Altered original controls accepted')
 if live:
  sys.path.insert(0,str(REPO/'dev/keycloak'))
  from mdiop_representation_campaign import admin,runtime as native_runtime
  before=original(receipt['restoration']['before'])
  require(admin('/clients?clientId='+urllib.parse.quote(peer,safe=''))==[],'Live temporary native client remains')
  require(native_runtime()==before['runtime'] and {name:admin('/client-policies/'+name) for name in ['policies','profiles']}==before['policies'],'Live native runtime/policy restoration differs')
  live_hash=subprocess.check_output(['docker','exec','samlscope-reference-keycloak','sha256sum','/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar'],text=True).split()[0]
  require(live_hash==before['nativePaths']['jarSha256'],'Live native implementation differs')
  require(api('/api/runs/'+run+'/transcript')==entries,'Live Run history differs')
 if not formal:return report
 result=load(folder/'evaluation/result.json');cases={c['id']:c for req in result['requirements'] for c in req['cases']};case=cases[CASE]
 require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+receipt['targetMetadataSha256'],'Formal target/run differs')
 require((case['outcome'],case['verdict'],case['reason_code'],case['attested'])==('VIOLATED','FAIL','metadata.application.accepted-post-endpoint-rejected',False),'Formal native application outcome differs')
 require(load(folder/'evaluation/transcript-before.json')==load(folder/'evaluation/transcript.json')==entries,'Formal replay altered history')
 require(load(folder/'evaluation/receipt-readback.json')['sha256']==sha((folder/'qualified-receipt.json').read_bytes()),'Installed receipt differs')
 require({e['reference'] for e in report['evidence']}<={e['reference'] for e in case['evidence']},'Formal result lacks native originals')
 execution=load(folder/'evaluation/case-execution.json')
 require(execution['runId']==run and execution['caseId']==CASE and execution['status']=='FINISHED','Formal stored case identity differs')
 observed=execution['outcome'];details=dict(observed['details']);previous=details.pop('previous_recorded_evidence_result',None)
 original_case=next(c for q in load(folder/'result.json')['requirements'] for c in q['cases'] if c['id']==CASE)
 require(previous is not None and previous['outcome']==original_case['outcome']=='NOT_VERIFIED' and previous['reason_code']==original_case['reason_code']=='metadata.supersession.awaiting-native-receipt' and previous['evidence']==original_case['evidence']==[] and previous['details']=={} and previous['revision']+1==execution['revision'],'Formal reevaluation audit differs from the original pending case')
 require(observed['outcome']==report['outcome'] and observed['reasonCode']==report['reasonCode'] and details==report['details'] and observed['evidence']==report['evidence']==case['evidence'],'Formal wrapper differs from the archived native reader')
 require(not any(row['kind']=='UNKNOWN_DELIVERY' and row['case_id']==CASE for row in result['suite_incidents']),'Formal native case has unresolved delivery')
 require(cases['IIP-MD06-ab-idp-01']['verdict']=='NOT_VERIFIED','Partial supersession was silently adopted')
 return folder/'evaluation/result.json',{CASE:case}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--diagnostic-only',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=a.root.resolve()
 if folder.name not in FOLDERS:folder=folder/FOLDER
 if a.capture_runtime:runtime.capture_runtime(folder)
 if a.record_replay:require(not(folder/'native-reader-replay.json').exists(),'Immutable replay exists');(folder/'native-reader-replay.json').write_text(json.dumps(runtime.replay(folder),indent=2)+'\n')
 verify_adoption(folder,live=a.live,formal=not a.diagnostic_only);print('Native accepted metadata application counterexample verified')
