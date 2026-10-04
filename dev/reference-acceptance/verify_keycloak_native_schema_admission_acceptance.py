#!/usr/bin/env python3
"""One valid native schema counterexample; no general parser-absence or key-use conclusion."""
import argparse,base64,hashlib,importlib.util,json,pathlib,subprocess,sys,urllib.request,urllib.parse,xml.etree.ElementTree as ET
REPO=pathlib.Path(__file__).resolve().parents[2]
FOLDER='keycloak-native-schema-admission-v183-r1';CASE='IIP-MD05-b-idp-01'
spec=importlib.util.spec_from_file_location('kc_schema_runtime',REPO/'dev/reference-acceptance/verify_ssp_intersection_capability_acceptance.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
runtime.HELPER='VerifyKeycloakNativeSchemaAdmissionEvidence'
runtime.CLASSES=('com/samlscope/runner/cases/KeycloakNativeSchemaAdmissionEvidence.class',
 'com/samlscope/runner/cases/MetadataSchemaAdmissionConfigurationTestCase.class','com/samlscope/runner/cases/MetadataAlgorithmEvidence.class')
sha,load,require=runtime.sha,runtime.load,runtime.require
sys.path.insert(0,str(REPO/'dev/keycloak'))
from schema_admission_campaign import VARIANTS,JARS,reject_sensitive,ADMIN,CAMPAIGN
from mdiop_representation_campaign import runtime as product_runtime
from algorithm_preference_campaign import admin
MD='{urn:oasis:names:tc:SAML:2.0:metadata}';FOREIGN='{urn:samlscope:test:foreign}'
def api(path,body=None):
 q=urllib.request.Request('http://localhost:18080'+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(q,timeout=40) as r:return json.load(r)
def verify_adoption(root,live=False,formal=True):
 folder=pathlib.Path(root).resolve()
 if folder.name!=FOLDER:folder=folder/FOLDER
 created=load(folder/'created.json')['run'];run=created['id'];peer='http://localhost:18080/p/'+created['planId']
 target=(folder/'target-metadata.xml').read_bytes();receipt=load(folder/'qualified-receipt.json');target_hash=sha(target)
 require((receipt['schema'],receipt['adapter'],receipt['runId'],receipt['campaignId'],receipt['targetEntityId'],receipt['targetMetadataSha256'])==(
  'samlscope-keycloak-native-schema-admission-v1','keycloak-native-endpoint-parser-v1',run,CAMPAIGN,ET.fromstring(target).get('entityID'),target_hash),'Native receipt identity changed')
 entries=load(folder/'transcript.json');by_id={e['id']:e for e in entries}
 require(len(entries)==len(by_id) and all(e['runId']==run for e in entries),'Foreign or duplicate history')
 originals={}
 for row in load(folder/'decoded-manifest.json'):
  path=(folder/row['file']).resolve();raw=path.read_bytes()
  require(path.parent==(folder/'decoded').resolve() and row['id'] not in originals and sha(raw)==row['sha256'] and len(raw)==by_id[row['id']]['decodedSamlBytes'],'Original scope/hash/length changed')
  originals[row['id']]=raw
 def original(ref):
  raw=originals[ref['reference']];require(sha(raw)==ref['sha256'],'Native original reference changed');value=json.loads(raw)
  require(value['runId']==run and value['campaignId']==CAMPAIGN and value['targetMetadataSha256']==target_hash,'Native original identity changed')
  return value
 def response(value,method,url,status):
  native=value['native'];require((native['method'],native['url'],native['status'])==(method,url,status),'Native HTTP route/status changed')
  raw=base64.b64decode(native['response_base64']);require(sha(raw)==native['response_sha256'],'Native response bytes changed');parsed=json.loads(raw);reject_sensitive(parsed);return parsed
 before,after=original(receipt['before']),original(receipt['after'])
 require(before['runtime']==after['runtime'] and before['globalPolicy']==after['globalPolicy'] and before['nativeJars']==after['nativeJars']==load(folder/'native-runtime/pins.json'),'Native scope/restoration changed')
 require(before['runtime']==load(folder/'native-runtime-before.json'),'Captured native image scope changed')
 for name in JARS:require(sha((folder/'native-runtime'/name).read_bytes())==before['nativeJars'][name],'Native source binary changed')
 lookup=ADMIN+'/clients?clientId='+urllib.parse.quote(peer,safe='')
 for scope in [before,after]:require(scope['peerEntityId']==peer and response(scope,'GET',lookup,200)==[],'Native original/final client inventory changed')
 require(load(folder/'restoration.json')==dict(restored=True,recovery_client_removals=0,remaining_clients=[]),'Native restoration incomplete')
 baseline_native=original(receipt['baselineClient'])['native']
 require(baseline_native['response_projection']=='native-client-public-readback-v1' and isinstance(baseline_native['redactions'],list) and len(baseline_native['redactions'])==len(set(baseline_native['redactions'])) and set(baseline_native['redactions'])<={'$.secret','$.registrationAccessToken'},'Public native readback projection changed')
 operations=load(folder/'operations.json');conversion_rows=[r for r in operations if r['path']=='/client-description-converter']
 require(len(conversion_rows)==len(VARIANTS),'Native conversion count changed')
 for index,variant in enumerate(VARIANTS):
  raw=(folder/variant/'fixture.xml').read_bytes();record=load(folder/variant/'native-conversion.json')
  require(record['variant']==variant and record['fixtureSha256']==sha(raw) and record['native']['request_sha256']==sha(raw)
   and base64.b64decode(record['native']['request_base64'])==raw and conversion_rows[index]['status']==record['native']['status'],'Native original converter/request changed')
  require(any(e['samlSummary'].get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==variant and originals.get(e['id'])==raw for e in entries),'Original fixture was not Suite prepared')
  reject_sensitive(json.loads(base64.b64decode(record['native']['response_base64'])))
 test,contrast=original(receipt['test']['conversion']),original(receipt['contrast']['conversion'])
 require(test==load(folder/'schema-sso-endpoint-set/native-conversion.json') and contrast==load(folder/'schema-sso-endpoint-without-foreign/native-conversion.json'),'Native counterpart files differ')
 require(response(test,'POST',ADMIN+'/client-description-converter',400)=={'error':'HTTP 400 Bad Request'},'Explicit native rejection changed')
 require(response(contrast,'POST',ADMIN+'/client-description-converter',200)['clientId']==peer,'Native contrast was not accepted')
 test_xml=ET.fromstring((folder/'schema-sso-endpoint-set/fixture.xml').read_bytes());contrast_xml=ET.fromstring((folder/'schema-sso-endpoint-without-foreign/fixture.xml').read_bytes())
 require(test_xml.findall('.//'+FOREIGN+'endpoint') and not contrast_xml.findall('.//'+FOREIGN+'endpoint'),'Endpoint extension contrast lost detection power')
 invalid=original(receipt['schemaInvalidControl']['conversion'])
 require(invalid==load(folder/'schema-invalid-endpoint-location/native-conversion.json'),'Schema-invalid native observation changed')
 invalid_status=invalid['native']['status'];require(invalid_status in [200,400,500],'Schema-invalid observation was an authentication/Suite failure')
 response(invalid,'POST',ADMIN+'/client-description-converter',invalid_status)
 counts=load(folder/'operation-counts.json');writes=[r for r in operations if r['product_setting_write']]
 require(len(writes)==2 and [r['method'] for r in writes]==['POST','DELETE'] and [r['status'] for r in writes]==[201,204],'Native setting operations changed')
 require(counts==dict(native_http_attempts=len(operations),native_conversion_attempts=len(VARIANTS),product_setting_write_attempts=2,product_setting_writes=2,
  protocol_flows_attempted=1,normal_protocol_success=True,product_restarts=0,human_operations=0,restored=True,verdict_adopted=False),'Native operation counts changed')
 require(load(folder/'control/flow.json')['correlated_success'] is True,'Normal protocol control incomplete')
 history=load(folder/'operation-history.json');require(history['schema']=='samlscope-keycloak-schema-admission-operation-history-v1' and history['credential_values_persisted'] is False,'Failed-attempt cost history unavailable')
 aggregate=dict(product_setting_write_attempts=0,product_setting_writes=0,native_conversion_attempts=2,protocol_flows_attempted=0,normal_protocol_success=0,run_creations=0,product_restarts=0,human_operations=0,all_product_states_restored=True)
 require(len(history['attempts'])==5 and history['initial_diagnostic']==dict(native_conversion_attempts=2,product_setting_writes=0,protocol_flows_attempted=0,adopted=False,reason='pre-signature-fix public diagnostic, not formal proof'),'Initial diagnostic/failed attempt inventory changed')
 for attempt in history['attempts']:
  attempt_folder=(folder.parent/attempt['folder']).resolve();require(attempt_folder.parent==folder.parent and not attempt_folder.is_symlink(),'Failed-attempt scope changed')
  for name,digest in attempt['files'].items():require('/' not in name and sha((attempt_folder/name).read_bytes())==digest,'Failed-attempt original changed')
  c=attempt['counts'];require(c['restored'] is True,'Failed attempt was not restored')
  if 'operation-counts.json' in attempt['files']:require(load(attempt_folder/'operation-counts.json')==c,'Failed-attempt counts changed')
  for key in ['product_setting_write_attempts','product_setting_writes','native_conversion_attempts','protocol_flows_attempted','normal_protocol_success']:aggregate[key]+=c[key]
  aggregate['run_creations']+=attempt['run_id'] is not None
 require(aggregate==history['totals']==dict(product_setting_write_attempts=8,product_setting_writes=8,native_conversion_attempts=14,protocol_flows_attempted=1,normal_protocol_success=1,run_creations=4,product_restarts=0,human_operations=0,all_product_states_restored=True),'Complete operation costs changed')
 recorded=load(folder/'native-reader-replay.json');require(runtime.replay(folder)==recorded,'Archived actual production replay differs')
 outcome=recorded['caseOutcome'];require(recorded['runId']==run and recorded['caseId']==CASE and outcome['outcome']=='VIOLATED'
  and outcome['reasonCode']=='metadata.schema.native-valid-endpoint-extension-rejected' and len(recorded['checks'])==34
  and recorded['checks']['native-valid-endpoint-counterexample']=='VIOLATED' and all(v=='NOT_VERIFIED' for k,v in recorded['checks'].items() if k!='native-valid-endpoint-counterexample')
  and recorded['privateKeyExported'] is False and recorded['runtimeKeyInterpretationProven'] is False and recorded['originalTranscriptUnchanged'] is True,'Production counterexample/controls changed')
 require(outcome['details']['schema_invalid_control']==('native-accepted' if invalid_status==200 else 'native-rejected' if invalid_status==400 else 'native-error'),'Invalid control was promoted into an extra obligation')
 if live:
  require(product_runtime()==before['runtime'] and admin('/clients?clientId='+urllib.parse.quote(peer,safe=''))==[],'Live product not restored')
  require({k:admin('/client-policies/'+k) for k in ['policies','profiles']}==before['globalPolicy'],'Live product global policy changed')
  require(api('/api/runs/'+run+'/transcript')==entries,'Live Run history changed')
 if not formal:return recorded
 evaluation=folder/'evaluation';result=load(evaluation/'result.json');cases={c['id']:c for r in result['requirements'] for c in r['cases']};case=cases[CASE]
 require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+target_hash,'Formal Run/target changed')
 require((case['outcome'],case['verdict'],case['reason_code'],case['attested'],case['evidence_class'])==('VIOLATED','FAIL',outcome['reasonCode'],False,'OPERATOR_ASSISTED'),'Formal schema provenance/verdict changed')
 require(load(evaluation/'transcript-before.json')==load(evaluation/'transcript.json')==entries,'Formal re-evaluation changed original history')
 require(load(evaluation/'receipt-readback.json')['sha256']==sha((folder/'qualified-receipt.json').read_bytes()),'Installed receipt readback changed')
 execution=load(evaluation/'case-execution.json');observed=execution['outcome'];details=dict(observed['details'])
 previous=details.pop('previous_recorded_evidence_result',None);details.pop('configuration_confirmed',None)
 require(execution['runId']==run and execution['caseId']==CASE and execution['status']=='FINISHED' and details==outcome['details']
  and observed['outcome']==outcome['outcome'] and observed['reasonCode']==outcome['reasonCode'] and observed['evidence']==case['evidence']==outcome['evidence'],'Formal full stored outcome changed')
 if previous is not None:
  old=next(c for q in load(folder/'result-before.json')['requirements'] for c in q['cases'] if c['id']==CASE)
  require(previous['outcome']==old['outcome']=='NOT_VERIFIED' and previous['reason_code']==old['reason_code'],'Previous outcome audit changed')
 return evaluation/'result.json',{CASE:case}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--live',action='store_true');p.add_argument('--diagnostic-only',action='store_true')
 args=p.parse_args();folder=args.root.resolve()
 if folder.name!=FOLDER:folder=folder/FOLDER
 if args.capture_runtime:runtime.capture_runtime(folder)
 if args.record_replay:
  require(not(folder/'native-reader-replay.json').exists(),'Immutable replay exists');(folder/'native-reader-replay.json').write_text(json.dumps(runtime.replay(folder),indent=2)+'\n')
 verify_adoption(folder,live=args.live,formal=not args.diagnostic_only);print('Native schema counterexample adoption verified; one case only')
