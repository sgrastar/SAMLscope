#!/usr/bin/env python3
"""Native MDIOP representation admission only; does not establish runtime key interpretation."""
import argparse,base64,hashlib,importlib.util,json,pathlib,subprocess,sys,urllib.request,urllib.parse,xml.etree.ElementTree as ET
REPO=pathlib.Path(__file__).resolve().parents[2]
CASE='IIP-MD05-c-idp-01';FOLDER='keycloak-mdiop-representation-native-v171-r5'
spec=importlib.util.spec_from_file_location('mdiop_archived_runtime',REPO/'dev/reference-acceptance/verify_ssp_intersection_capability_acceptance.py');runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
runtime.HELPER='VerifyKeycloakMdiopRepresentationEvidence'
runtime.CLASSES=('com/samlscope/runner/cases/KeycloakMdiopRepresentationEvidenceFile.class','com/samlscope/runner/cases/KeycloakMdiopRepresentationConfigurationTestCase.class','com/samlscope/runner/cases/MetadataAlgorithmEvidence.class','com/samlscope/runner/cases/MetadataConfigCaseFactory.class')
sys.path.insert(0,str(REPO/'dev/keycloak'))
from mdiop_representation_campaign import REQUIRED,admin
sha,load,require=runtime.sha,runtime.load,runtime.require
P='{urn:oasis:names:tc:SAML:2.0:protocol}';MD='{urn:oasis:names:tc:SAML:2.0:metadata}'
def api(path,body=None):
 q=urllib.request.Request('http://localhost:18080'+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(q,timeout=40) as r:return json.load(r)
def verify_adoption(root,live=False,formal=True):
 folder=pathlib.Path(root).resolve()
 if folder.name!=FOLDER:folder=folder/FOLDER
 created=load(folder/'created.json')['run'];run,peer=created['id'],'http://localhost:18080/p/'+created['planId']
 target=(folder/'target-metadata.xml').read_bytes();receipt=load(folder/'qualified-receipt.json');require(receipt['runId']==run and receipt['targetEntityId']==ET.fromstring(target).get('entityID') and receipt['targetMetadataSha256']==sha(target),'Native Run/target original differs')
 entries=load(folder/'transcript.json');by_id={e['id']:e for e in entries};require(len(entries)==len(by_id) and all(e['runId']==run for e in entries),'Foreign/ambiguous transcript')
 originals={}
 for row in load(folder/'decoded-manifest.json'):
  path=(folder/row['file']).resolve();raw=path.read_bytes();require(path.parent==(folder/'decoded').resolve() and row['id'] not in originals and sha(raw)==row['sha256'] and len(raw)==by_id[row['id']]['decodedSamlBytes'],'Original hash/length/path differs');originals[row['id']]=raw
 def original(ref):
  raw=originals[ref['reference']];require(sha(raw)==ref['sha256'],'Native original reference differs');return json.loads(raw)
 operations=load(folder/'operations.json');require(len(operations)==19 and [r['variant'] for r in operations]==REQUIRED and all(r['restored'] and r['driver_exit']==0 and r['native_write_attempts']==0 for r in operations),'Native admission matrix/policy/restoration differs')
 ids=set()
 for variant in REQUIRED:
  member=folder/variant;imported=load(member/'import.json');raw=(member/'fixture.xml').read_bytes()
  require(imported['status']=='success' and imported['fixture']['entity_id']==peer and imported['fixture']['sha256']==sha(raw) and imported['import']['save_clicked'] and imported['import']['ui_status']=='client-settings-page' and imported['cleanup']=={'deleted_status':204,'read_back_absent':True},'Native import/cleanup signal incomplete')
  require(not({'representation_admission_only','request_signature_policy','signing_capability_policy','native_default_signature_selector'}&set(imported['import'])),'Product policy changed')
  converter=original(load(member/'converter-original-reference.json'));saved=original(load(member/'persisted-original-reference.json'))
  require(converter==load(member/'converter-original.json') and saved==load(member/'persisted-original.json') and converter['phase']==saved['phase']=='before-policy-change','Converter/readback not recorded original')
  for source in [converter,saved]:require(source['runId']==run and source['fixtureSha256']==sha(raw) and source['targetMetadataSha256']==sha(target),'Native source scope differs')
  require(converter['native']==imported['import']['native_converter_original'] and saved['native']==imported['import']['native_saved_original'],'UI original differs from transcript')
  require(converter['native']['request_sha256']==sha(raw) and converter['native']['request_matches_original_fixture'],'Product converter did not receive original XML')
  parsed=[]
  for native in [converter['native'],saved['native']]:
   response=base64.b64decode(native['response_base64']);require(sha(response)==native['response_sha256'] and native['status']==200,'Native response original differs');value=json.loads(response);require('secret' not in value and 'registrationAccessToken' not in value,'Native credential persisted');parsed.append(value)
  conversion,readback=parsed;client=readback['id'];require(client==imported['client']['database_id'] and client not in ids and conversion['clientId']==readback['clientId']==peer and conversion['protocol']==readback['protocol']=='saml','Native client identity differs');ids.add(client)
  require({k:v for k,v in readback['attributes'].items() if k.startswith('saml')}==imported['import']['read_back']['saml_attributes'],'Native public SAML readback differs')
  require(any(e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='MetadataPrepared' and originals.get(e['id'])==raw for e in entries),'Native original fixture not prepared')
 require(load(folder/'native-runtime-before.json')==load(folder/'native-runtime-after.json') and load(folder/'native-global-policy-before.json')==load(folder/'native-global-policy-after.json'),'Product runtime/global policy changed')
 require(load(folder/'restoration.json')==dict(restored=True,remaining_clients=[],recovery_client_removals=0),'Native restoration incomplete')
 require(load(folder/'operation-counts.json')==dict(native_import_attempts=19,temporary_clients_removed=19,native_admission_policy_write_attempts=0,protocol_flows_attempted=19,recovery_client_removals=0,product_restarts=0,human_operations=0,restored=True,runtime_key_interpretation_proven=False),'Native operation counts differ')
 history=load(folder/'operation-history.json');require(history['schema']=='samlscope-keycloak-mdiop-operation-history-v1' and history['restored'] and history['product_restarts']==history['human_operations']==0 and history['total']==dict(native_import_attempts=49,temporary_clients_removed=49,native_policy_writes=4),'Prior attempt operation totals differ')
 require(history['configuration_operations']==dict(final_native_client_creates=19,final_native_client_deletes=19,final_attribute_puts=0,all_attempt_native_client_creates=49,all_attempt_native_client_deletes=49,all_attempt_attribute_puts=4,all_attempt_total=102),'Native temporary creation/deletion writes omitted')
 require(len(history['attempts'])==6 and history['attempts'][-1]['folder']==FOLDER,'Attempt history incomplete')
 totals=dict(native_import_attempts=0,temporary_clients_removed=0,native_policy_writes=0)
 for attempt in history['attempts']:
  earlier=folder.parent/attempt['folder'];require(earlier.parent==folder.parent and earlier.is_dir() and attempt['restored'],'Attempt scope/restoration differs')
  for ref in attempt['rawReferences']:
   path=(folder.parent/ref['file']).resolve();require(path.is_relative_to(earlier.resolve()) and sha(path.read_bytes())==ref['sha256'],'Attempt original changed')
  operations_before=load(earlier/'operations.json');removed=0;writes=0
  for op in operations_before:
   imported_before=load(earlier/op['variant']/'import.json');require(imported_before.get('cleanup',{}).get('read_back_absent') is True,'Earlier native client not restored');removed+=1;writes+=imported_before.get('import',{}).get('representation_admission_only',{}).get('write_attempts',0)
  require((attempt['native_import_attempts'],attempt['temporary_clients_removed'],attempt['native_policy_writes'])==(len(operations_before),removed,writes),'Attempt operation count differs')
  if (earlier/'operation-counts.json').exists():
   counts=load(earlier/'operation-counts.json');require(counts['restored'] and counts['product_restarts']==counts['human_operations']==0 and counts['native_admission_policy_write_attempts']==writes,'Attempt restoration/count proof differs')
   require(load(earlier/'native-runtime-before.json')==load(earlier/'native-runtime-after.json') and load(earlier/'native-global-policy-before.json')==load(earlier/'native-global-policy-after.json'),'Earlier native state changed')
  for key in totals:totals[key]+=attempt[key]
 require(totals==history['total'],'Attempt total mismatch')
 for name,digest in history['sourceHashes'].items():require(name in {'console_import.mjs','mdiop_representation_campaign.py'} and sha((folder/'driver'/name).read_bytes())==digest,'Captured collector source changed')
 recorded=load(folder/'native-reader-replay.json');require(runtime.replay(folder)==recorded,'Archived production Reader differs from recorded replay')
 require(recorded['runId']==run and recorded['caseId']==CASE and recorded['outcome']=='SATISFIED' and recorded['reasonCode']=='metadata.mdiop.native-representation-admission-observed' and len(recorded['checks'])==29 and recorded['privateKeyExported'] is False and recorded['configurationWrites']==0 and recorded['runtimeKeyInterpretationProven'] is False,'Reader scope/outcome differs')
 require(recorded['checks']['complete-native-admission']=='SATISFIED' and all(v=='NOT_VERIFIED' for k,v in recorded['checks'].items() if k!='complete-native-admission'),'Native altered-evidence control accepted')
 if live:
  require(admin('/clients?clientId='+urllib.parse.quote(peer,safe=''))==[],'Live temporary native client remains')
  require(api('/api/runs/'+run+'/transcript')==entries,'Live transcript differs')
 if not formal:return recorded
 result=load(folder/'evaluation/result.json');cases={c['id']:c for r in result['requirements'] for c in r['cases']};case=cases[CASE]
 require((case['outcome'],case['verdict'],case['reason_code'],case['attested'])==('SATISFIED','PASS','metadata.mdiop.native-representation-admission-observed',False),'Formal native outcome differs')
 require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+sha(target),'Formal Run/target differs')
 require(load(folder/'evaluation/transcript-before.json')==load(folder/'evaluation/transcript.json')==entries,'Formal evaluation altered original transcript')
 require(load(folder/'evaluation/receipt-readback.json')['sha256']==sha((folder/'qualified-receipt.json').read_bytes()),'Installed receipt readback differs')
 execution=load(folder/'evaluation/case-execution.json');require(execution['runId']==run and execution['caseId']==CASE and execution['status']=='FINISHED','Formal stored case scope differs');details=execution['outcome']['details']
 require(execution['outcome']['outcome']==case['outcome'] and execution['outcome']['reasonCode']==case['reason_code'] and details.get('configuration_confirmed') is True and all(details.get(name)==value for name,value in recorded['details'].items()),'Formal stored preparation/reader differs')
 require({row['reference'] for row in recorded['evidence']}<={row['reference'] for row in case['evidence']} and execution['outcome']['evidence']==case['evidence'],'Formal native original evidence differs')
 return folder/'evaluation/result.json',{CASE:case}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--live',action='store_true');p.add_argument('--diagnostic-only',action='store_true');args=p.parse_args();folder=args.root.resolve()
 if folder.name!=FOLDER:folder=folder/FOLDER
 if args.capture_runtime:runtime.capture_runtime(folder)
 if args.record_replay:require(not(folder/'native-reader-replay.json').exists(),'Immutable replay exists');(folder/'native-reader-replay.json').write_text(json.dumps(runtime.replay(folder),indent=2)+'\n')
 verify_adoption(folder,live=args.live,formal=not args.diagnostic_only);print('Native MDIOP representation acceptance verified; runtime key interpretation excluded')
