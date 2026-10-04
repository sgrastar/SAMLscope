#!/usr/bin/env python3
"""Replay original native POST error Responses; no additional product operations.

SSO03.b has one applicable IdP error-producer variant. The SP-receiver variant
is outside this target role; no two-trigger threshold is present in its source.
A normal signed Success remains mandatory, and a GET-error mutant must fail.
"""
import argparse, hashlib, importlib.util, json, pathlib, shutil, sys, urllib.request, xml.etree.ElementTree as ET
REPO=pathlib.Path(__file__).resolve().parents[2]
CASE='IIP-SSO03-b-idp-01'
SOURCE={'keycloak':'reference-20260929/browser-chain-keycloak-full-v116-retry1',
        'simplesamlphp':'reference-20260918/ssp-browser-chain-v2'}
FOLDERS={p:'post-error-binding-'+p+'-v173' for p in SOURCE}
RUNS={'keycloak':'run_EJYK4M640FX4PJAWT2YQW6STER','simplesamlphp':'run_DQBEG87V5F2GDW83JXDW40STPV'}
CASE_DIGEST='sha256:fbfce2000bd2c63133890b630547c6efb0fec385ea297c2adf068656dd232391'
spec=importlib.util.spec_from_file_location('post_error_archived_runtime',REPO/'dev/reference-acceptance/verify_ssp_intersection_capability_acceptance.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
runtime.HELPER='VerifyPostErrorBindingEvidence'
runtime.CLASSES=('com/samlscope/runner/cases/NormalFlowBrowserObservation.class','com/samlscope/runner/cases/AutoBrowserEvidenceTestCase.class')
sha,load,require=runtime.sha,runtime.load,runtime.require
P='{urn:oasis:names:tc:SAML:2.0:protocol}';S='{urn:oasis:names:tc:SAML:2.0:assertion}'

_history_spec=importlib.util.spec_from_file_location('post_error_history_runtime',REPO/'dev/reference-acceptance/verify_ssp_intersection_capability_acceptance.py')
history_runtime=importlib.util.module_from_spec(_history_spec);_history_spec.loader.exec_module(history_runtime)
history_runtime.HELPER='VerifyPostErrorBindingHistoryEvidence'
history_runtime.CLASSES=runtime.CLASSES

def capture_history(folder):
 strict=folder/'history-v175';strict.mkdir(exist_ok=False)
 for name in ['created.json','transcript.json','decoded-manifest.json','target-metadata.xml']:shutil.copy2(folder/name,strict/name)
 shutil.copytree(folder/'decoded',strict/'decoded');shutil.copy2(folder/'native-reader-replay.json',strict/'baseline-reader-replay.json')
 history_runtime.capture_runtime(strict)
 (strict/'native-reader-replay.json').write_text(json.dumps(history_runtime.replay(strict),indent=2)+'\n')
 return strict

def verify_history(folder,baseline):
 strict=folder/'history-v175'
 for name in ['created.json','transcript.json','decoded-manifest.json','target-metadata.xml']:require((strict/name).read_bytes()==(folder/name).read_bytes(),'Strict history originals differ')
 require(load(strict/'baseline-reader-replay.json')==baseline,'Strict replay baseline changed')
 observed=history_runtime.replay(strict);require(observed==load(strict/'native-reader-replay.json'),'Archived strict Auto wrapper replay differs')
 require(observed['runId']==baseline['runId'] and observed['caseId']==CASE and observed['configurationWrites']==0 and observed['privateKeyExported'] is False,'Strict replay scope differs')
 require(observed['checks']=={'native-original-full-outcome-unchanged':'SATISFIED','foreign-run-history':'NOT_VERIFIED','duplicate-recorder-id':'NOT_VERIFIED'},'Strict history negative controls failed')
 outcome=observed['nativeOutcome']
 require(all(outcome[k]==baseline[k] for k in ['outcome','reasonCode','details','evidence']),'Strict wrapper changed adopted full outcome')
 return observed

def api(path,body=None):
 q=urllib.request.Request('http://localhost:18080'+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(q,timeout=60) as r:return json.load(r)

def capture_evidence(root,product):
 folder=pathlib.Path(root).resolve()/FOLDERS[product];folder.mkdir(exist_ok=False)
 source=REPO/'build/acceptance'/SOURCE[product]
 names=['created.json','plan.json','transcript.json','decoded-manifest.json','target-metadata.xml','restoration.json','operations.json','initial-login.json','preflight.json','tests-start.json','steps.json']
 names+=['import.json','suite-sp-metadata.xml'] if product=='keycloak' else ['operation-counts.json','fixture.xml']
 pins={}
 for name in names:
  shutil.copy2(source/name,folder/name);pins[name]=sha((source/name).read_bytes())
 shutil.copytree(source/'decoded',folder/'decoded')
 (folder/'source.json').write_text(json.dumps(dict(schema='samlscope-native-post-error-replay-v1',product=product,sourceFolder=SOURCE[product],sourceFiles=pins,approvedCaseDigest=CASE_DIGEST),indent=2)+'\n')
 shutil.copy2(source/'result.json',folder/'result-before.json')
 (folder/'operation-counts-current-batch.json').write_text(json.dumps(dict(product_setting_writes=0,product_restarts=0,protocol_sends=0,run_creations=0,human_operations=0,source_campaign_operations='operations.json'),indent=2)+'\n')
 return folder

def verify_adoption(root,product,live=False,formal=True):
 require(product in FOLDERS,'Unknown product')
 folder=pathlib.Path(root).resolve()
 if folder.name!=FOLDERS[product]:folder=folder/FOLDERS[product]
 source=load(folder/'source.json');require(source['schema']=='samlscope-native-post-error-replay-v1' and source['product']==product and source['sourceFolder']==SOURCE[product] and source['approvedCaseDigest']==CASE_DIGEST,'Native source/case scope differs')
 for name,digest in source['sourceFiles'].items():
  require(pathlib.Path(name).name==name and sha((folder/name).read_bytes())==digest,'Captured source changed')
 created=load(folder/'created.json')['run'];run,plan=created['id'],created['planId'];require(run==RUNS[product],'Wrong Run')
 entries=load(folder/'transcript.json');byid={e['id']:e for e in entries};require(len(byid)==len(entries) and all(e['runId']==run for e in entries),'Foreign/duplicate transcript')
 originals={}
 for row in load(folder/'decoded-manifest.json'):
  path=(folder/row['file']).resolve();raw=path.read_bytes();e=byid[row['id']]
  require(path.parent==(folder/'decoded').resolve() and sha(raw)==row['sha256'] and len(raw)==e['decodedSamlBytes'] and row['id'] not in originals,'Original path/hash/length differs');originals[row['id']]=raw
 restoration=load(folder/'restoration.json');require(restoration['restored'],'Source product not restored')
 if product=='keycloak':
  imported=load(folder/'import.json');fixture=(folder/'suite-sp-metadata.xml').read_bytes()
  require(imported['status']=='success' and imported['fixture']['sha256']==sha(fixture) and imported['import']['save_clicked'] and imported['import']['ui_status']=='client-settings-page','Native console import not verified')
  require(restoration['import_ok'] and restoration['cleanup']['delete_status']==204 and restoration['cleanup']['read_back_absent'],'Native client deletion not read back')
  require(load(folder/'operations.json')==[{'operation':'delete-imported-client','attempted':True,'delete_status':204,'read_back_absent':True}],'Source restoration operations changed')
 else:
  require(restoration['failures']==[] and restoration['original_sha256']==restoration['final_sha256']=='a04e059f24cda81aff7ecd8e77eb71c18df12477cd5086269eae29adc4c1a56b','Source native configuration restoration differs')
  counts=load(folder/'operation-counts.json');require(counts['restored'] and counts['human_operations']==0,'Source operation/restoration counts differ')
 require(load(folder/'operation-counts-current-batch.json')==dict(product_setting_writes=0,product_restarts=0,protocol_sends=0,run_creations=0,human_operations=0,source_campaign_operations='operations.json'),'Replay caused unrecorded product operations')
 replay=runtime.replay(folder);recorded=load(folder/'native-reader-replay.json');require(replay==recorded,'Archived production Reader replay differs')
 require(recorded['runId']==run and recorded['caseId']==CASE and recorded['outcome']=='SATISFIED' and recorded['reasonCode']=='browser.normal-flow.error-responses-use-post','Production reader result differs')
 require(recorded['checks']=={'native-normal-and-post-error':'SATISFIED','get-error-mutant':'VIOLATED','error-only':'NOT_VERIFIED','success-only':'NOT_VERIFIED','uncorrelated-error':'NOT_VERIFIED','missing-error-status':'NOT_VERIFIED'},'Approved controls failed')
 require(recorded['configurationWrites']==0 and recorded['privateKeyExported'] is False,'Replay changed reference settings or exported keys')
 requests={}
 for e in entries:
  if e['id'] not in originals or e['direction']!='OUTBOUND':continue
  try:node=ET.fromstring(originals[e['id']])
  except ET.ParseError:continue
  if node.tag==P+'AuthnRequest' and node.get('ID'):require(node.get('ID') not in requests,'Ambiguous request ID');requests[node.get('ID')]=(e,node)
 normal=errors=0
 for id,digest in recorded['verifiedNativeResponses'].items():
  require(sha(originals[id])==digest,'Signed native Response original changed')
  e=byid[id];node=ET.fromstring(originals[id]);req=requests.get(node.get('InResponseTo'));require(e['direction']=='INBOUND' and e['method']=='POST' and req is not None and req[0]['timestamp']<=e['timestamp'],'Native binding/operation correlation differs')
  status=node.find(P+'Status/'+P+'StatusCode');require(status is not None,'No native status')
  require(node.get('Destination')==req[1].get('AssertionConsumerServiceURL'),'Native response did not use registered requested ACS')
  if status.get('Value')=='urn:oasis:names:tc:SAML:2.0:status:Success':normal+=1
  else:require(req[1].get('IsPassive')=='true' and status.get('Value')=='urn:oasis:names:tc:SAML:2.0:status:Responder','Wrong error trigger/status');errors+=1
 require(normal==1 and errors>=1 and recorded['details']['error_kinds']==['is_passive'],'Native normal/error controls missing')
 if live:require(api('/api/runs/'+run+'/transcript')==entries,'Live original transcript changed')
 if not formal:return recorded
 verify_history(folder,recorded)
 result=load(folder/'evaluation/result.json');cases={c['id']:c for req in result['requirements'] for c in req['cases']};case=cases[CASE]
 require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+sha((folder/'target-metadata.xml').read_bytes()),'Formal Run/target differs')
 require((case['outcome'],case['verdict'],case['reason_code'],case['attested'])==('SATISFIED','PASS','browser.normal-flow.error-responses-use-post',False),'Formal result not proven')
 require({r['reference'] for r in case['evidence']}=={r['reference'] for r in recorded['evidence']},'Formal native evidence differs')
 require(load(folder/'evaluation/transcript-before.json')==load(folder/'evaluation/transcript.json')==entries,'Formal reevaluation altered transcript')
 return folder/'evaluation/result.json',{CASE:case}

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--product',required=True,choices=list(SOURCE));p.add_argument('--capture-evidence',action='store_true');p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--diagnostic-only',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args()
 folder=capture_evidence(a.root,a.product) if a.capture_evidence else (a.root if a.root.name==FOLDERS[a.product] else a.root/FOLDERS[a.product])
 if a.capture_runtime:runtime.capture_runtime(folder)
 if a.record_replay:require(not(folder/'native-reader-replay.json').exists(),'Immutable replay exists');(folder/'native-reader-replay.json').write_text(json.dumps(runtime.replay(folder),indent=2)+'\n')
 verify_adoption(folder,a.product,live=a.live,formal=not a.diagnostic_only);print(a.product+' native POST error binding acceptance verified')
