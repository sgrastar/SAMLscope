#!/usr/bin/env python3
"""Adopt native persistent NameID results with archived production replay and real producer control."""
import argparse,base64,hashlib,importlib.util,json,pathlib,re,subprocess,sys,urllib.parse,xml.etree.ElementTree as ET
REPO=pathlib.Path(__file__).resolve().parents[2]
FOLDER='keycloak-native-persistent-pairwise-v180-r4'
MUTANT='keycloak-native-persistent-pairwise-same-value-mutant-v180-r2'
CASES={'IIP-SSO05-a-idp-01','IIP-SSO05-a2-idp-01','IIP-SSO05-a3-idp-01'}
ADOPT={'IIP-SSO05-a3-idp-01'}
SERVICES='213c45bb357e0881ead8284f12308e3c9fd8e09e7f0b6ec816f95f8b0921bea9'
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
runtime=module('kc_pairwise_runtime',REPO/'dev/reference-acceptance/verify_ssp_intersection_capability_acceptance.py')
runtime.HELPER='VerifyKeycloakPersistentPairwiseEvidence'
runtime.CLASSES=tuple('com/samlscope/runner/cases/'+n+'.class' for n in ['KeycloakPersistentPairwiseEvidence','IdpExecutableBrowserFixtureScenarioTestCase','PersistentPairwiseQueuedTestCase','NormalFlowBrowserObservation','VerifiedResponseAssertion','ApprovedBrowserCaseRegistry'])
sha,load,require=runtime.sha,runtime.load,runtime.require
sys.path.insert(0,str(REPO/'dev/keycloak'))
SEMANTIC={'equal-persistent-values','wrong-name-qualifier','wrong-sp-name-qualifier','unexpected-sp-provided-id'}
UNPROVEN={'wrong-principal-attribute','foreign-history-run','duplicate-transcript-id','wrong-target','wrong-receipt-run','missing-peer','missing-original','wrong-request-hash','wrong-request-reference','wrong-decryption-key','wrong-restoration','late-before-readback','default-scope-mapper-changed','native-nameid-mapper-added','wrong-client-signature-policy','different-native-user','native-runtime-epoch-changed','wrong-native-converter-fixture','wrong-native-application','wrong-source-jar'}
def native(folder):
 receipt=load(folder/'qualified-receipt.json');target=sha((folder/'primary/target-metadata.xml').read_bytes());runs=set();fresh=None
 require(receipt['schema']=='samlscope-keycloak-persistent-pairwise-v1' and receipt['campaignId']=='native-persistent-pairwise' and receipt['targetMetadataSha256']==target and len(receipt['peers'])==2,'Native pairwise scope differs')
 for label,peer in zip(['primary','secondary'],receipt['peers']):
  child=folder/label;created=load(child/'created.json')['run'];run=created['id'];entity='http://localhost:18080/p/'+created['planId'];fixture=(child/'fixture.xml').read_bytes()
  require(peer['runId']==run and run not in runs and peer['entityId']==entity and peer['metadataSha256']==sha(fixture) and sha((child/'target-metadata.xml').read_bytes())==target,'Peer/native fixture differs');runs.add(run)
  entries=load(child/'transcript.json');by={e['id']:e for e in entries};require(len(by)==len(entries) and all(e['runId']==run for e in entries),'Foreign/duplicate native history');decoded={}
  for row in load(child/'decoded-manifest.json'):
   require(pathlib.Path(row['file']).parent==pathlib.Path('decoded') and row['id'] in by and row['id'] not in decoded,'Decoded reference escape');raw=(child/row['file']).read_bytes();require(sha(raw)==row['sha256'] and len(raw)==by[row['id']]['decodedSamlBytes'],'Native original changed');decoded[row['id']]=raw
  records={}
  for key,name,kind in [('initial','initial-inventory','initial-inventory'),('converter','converter','native-converter'),('application','application','native-client-application'),('before','before','operative-pairwise-state'),('after','after','operative-pairwise-state'),('restoration','restored','restoration')]:
   ref=peer[key];raw=decoded[ref['reference']];value=json.loads(raw);require(sha(raw)==ref['sha256'] and raw==(child/'native-originals'/(name+'.json')).read_bytes(),'Native original readback differs');require(value['schema']=='samlscope-keycloak-persistent-pairwise-original-v1' and value['runId']==run and value['peerEntityId']==entity and value['targetMetadataSha256']==target and value['kind']==kind,'Native original scope differs');records[key]=value
  user=records['initial']['userCreated'];require(user['username'].startswith('samlscope-pairwise-') and records['initial']['publicUserCreation']['credentialInputRetained'] is False and 'requestSha256' not in records['initial']['publicUserCreation']['native'],'Credential-bearing input retained')
  if fresh is None:fresh=user
  else:require(fresh==user,'Different native principal')
  require(records['initial']['clients']==records['initial']['usersBefore']['users']==[] and records['restoration']['clients']==records['restoration']['users']==[],'Native principals/peers not restored')
  c=records['converter']['native'];require(c['method']=='POST' and c['url']=='http://localhost:18180/admin/realms/samlscope/client-description-converter' and c['status']==200 and c['requestSha256']==sha(fixture),'Metadata did not reach native converter');raw=base64.b64decode(c['responseBase64']);require(sha(raw)==c['responseSha256'],'Native conversion output changed');converted=json.loads(raw)
  a=records['application'];recipe=dict(converted,protocolMappers=[dict(name='samlscope-native-principal-username',protocol='saml',protocolMapper='saml-user-property-mapper',consentRequired=False,config={'user.attribute':'username','attribute.name':'samlscope.native.username','attribute.nameformat':'Basic'})]);require(a['native']['status']==201 and a['native']['requestSha256']==sha(json.dumps(recipe,separators=(',',':')).encode()),'Suite changed native NameID/client policy')
  require(records['before']['client']==records['after']['client'] and records['before']['scope']==records['after']['scope'] and records['before']['user']==records['after']['user'] and records['before']['user']['id']==fresh['id'],'Native identity/policy changed during measurement')
  for key in ['baseline','persistent']:
   ex=peer[key];require(ex==load(child/(key+'-exchange.json')) and ex['success'] is True and len(ex['transcript_ids'])==2,'Normal/persistent control absent');req,res=[by[id] for id in ex['transcript_ids']];require(req['direction']=='OUTBOUND' and res['direction']=='INBOUND' and sha(decoded[req['id']])==ex['requestSha256'] and ET.fromstring(decoded[req['id']]).get('ID')==ex['requestId']==res['samlSummary']['inResponseTo'],'Request/response binding differs')
 require(load(folder/'restoration.json')['restored'] is True and load(folder/'scope-before.json')==load(folder/'scope-after.json'),'Global restoration incomplete')
 for phase in ['before','after']:require(sha((folder/f'native-source/{phase}-services.jar').read_bytes())==SERVICES,'Native source pin differs')
 return receipt

def operations(folder):
 history=load(folder/'operation-history.json');require(len(history['trials'])==6,'Failed trials/control operation costs absent');total={k:0 for k in ['nativeWriteAttempts','successfulNativeWrites','actualSuccessfulSamlFlows','suiteOnlyPreparedAuthnRequests','flowAttempts','runCreations']}
 for row in history['trials']:
  require(re.fullmatch(r'keycloak-native-persistent-pairwise-(?:same-value-mutant-)?v180-r[1-4]',row['folder']),'Invalid operation source');trial=folder.parent/row['folder'];require(set(row['files'])=={'operations.json','operation-counts.json','restoration.json'} and all(sha((trial/name).read_bytes())==digest for name,digest in row['files'].items()),'Operation originals changed');ops=load(trial/'operations.json');counts=load(trial/'operation-counts.json');require(load(trial/'restoration.json')['restored'] is True and counts['restored'] is True and counts['humanOperations']==counts['productRestarts']==0,'Prior native trial un-restored')
  writes=[o for o in ops if o['kind'] not in ['native-baseline-flow','native-persistent-flow']];actual=prepared=0
  for label in ['primary','secondary']:
   child=trial/label
   if not (child/'transcript.json').exists():continue
   tx=load(child/'transcript.json');decoded={m['id']:(child/m['file']).read_bytes() for m in load(child/'decoded-manifest.json')};responses={e['samlSummary']['inResponseTo'] for e in tx if e['direction']=='INBOUND' and e['samlSummary'].get('type')=='Response' and (e['samlSummary'].get('normalFlowAccepted') is True or e['samlSummary'].get('activeProbeAccepted') is True)}
   for e in tx:
    if e['direction']!='OUTBOUND' or e['samlSummary'].get('type')!='AuthnRequest':continue
    try:id=ET.fromstring(decoded[e['id']]).get('ID')
    except(KeyError,ET.ParseError):continue
    if id in responses:actual+=1
    else:prepared+=1
  require(row['nativeWriteAttempts']==len(writes)==counts['nativeConfigurationWriteAttempts'] and row['successfulNativeWrites']==sum(o['status'] in [200,201,204] for o in writes) and row['flowAttempts']==counts['normalFlowsAttempted']==sum(o['kind'] in ['native-baseline-flow','native-persistent-flow'] for o in ops) and row['actualSuccessfulSamlFlows']==actual and row['suiteOnlyPreparedAuthnRequests']==prepared and row['runCreations']==counts['runCreations'],'Operation cost derivation differs')
  for k in total:total[k]+=row[k]
 require(all(history[k]==v for k,v in total.items()) and history['humanOperations']==history['productRestarts']==0,'Cumulative operation costs differ')

def verify_adoption(root,live=False,formal=True):
 folder=pathlib.Path(root).resolve()
 if folder.name!=FOLDER:folder=folder/FOLDER
 receipt=native(folder);mutant=folder.parent/MUTANT;native(mutant);operations(folder)
 require(not(folder/'runtime/candidate-only.json').exists() and not(mutant/'runtime/candidate-only.json').exists(),'Candidate-only runtime cannot be adopted');report=runtime.replay(folder);require(report==load(folder/'native-reader-replay.json'),'Pinned actual production replay differs');checks=report['checks'];require(set(checks)==SEMANTIC|UNPROVEN|{'native-positive','signed-semantic-baseline'} and checks['native-positive']==checks['signed-semantic-baseline']=='SATISFIED' and all(checks[c]=='VIOLATED' for c in SEMANTIC) and all(checks[c]=='NOT_VERIFIED' for c in UNPROVEN),'Native semantic/original controls incomplete')
 negative=runtime.replay(mutant);require(negative==load(mutant/'native-reader-replay.json') and negative['nativeProducerControl'] is True and negative['outcome']['outcome']=='VIOLATED' and negative['normalCases']['IIP-SSO05-a2-idp-01']['outcome']=='VIOLATED' and negative['normalCases']['IIP-SSO05-a-idp-01']['outcome']=='SATISFIED','Native same-value/257-character producer not detected');require(report['privateKeyExported']==negative['privateKeyExported'] is False and all(r[k]==0 for r in [report,negative] for k in ['productConfigurationWrites','samlRequests']),'Replay changed native configuration/traffic')
 if live:
  from metadata_supersession_campaign import read
  from mdiop_representation_campaign import runtime as product_runtime
  initial=load(folder/'scope-before.json');require(product_runtime()==initial['runtime'] and read('/users/profile')==initial['userProfile'] and {k:read('/client-policies/'+k) for k in ['policies','profiles']}==initial['policies'],'Live native runtime/policy/profile not restored')
  for campaign in [folder,mutant]:
   for peer in load(campaign/'qualified-receipt.json')['peers']:require(read('/clients?clientId='+urllib.parse.quote(peer['entityId'],safe=''))==[],'Temporary native client remains')
   user=load(campaign/'user-created.json');require(read('/users?username='+urllib.parse.quote(user['username'],safe='')+'&exact=true')==[],'Temporary native user remains')
  pins=load(folder/'runtime/pins.json');require(all(sha(subprocess.check_output(['docker','exec','samlscope-reference-suite','cat','/opt/samlscope/lib/'+name+'-0.1.0.jar']))==digest for name,digest in pins['jars'].items()),'Live production runtime differs')
  installation=load(folder/'receipt-install.json');require(installation['runId']==receipt['runId'] and len(installation['files'])==4 and installation['productConfigurationWrites']==installation['samlRequests']==0,'Public proof installation differs')
  for row in installation['files']:
   require(row['path'].startswith('/data/persistent-nameid-evidence/'+receipt['runId']+'.keycloak-pairwise') and sha((folder/row['file']).read_bytes())==row['sha256'],'Receipt source differs');require(subprocess.check_output(['docker','exec','samlscope-reference-suite','sha256sum',row['path']],text=True).split()[0]==row['sha256'],'Receipt native readback differs')
 if not formal:return report
 negative_evaluation=mutant/'evaluation';negative_result=load(negative_evaluation/'result.json');negative_receipt=load(mutant/'qualified-receipt.json');require(negative_result['run']['id']==negative_receipt['runId'] and load(negative_evaluation/'transcript-before.json')==load(negative_evaluation/'transcript.json')==load(mutant/'primary/transcript.json'),'Native producer formal evaluation changed originals');negative_actual={c['id']:c for q in negative_result['requirements'] for c in q['cases']};negative_expected=dict(negative['normalCases'],**{'IIP-SSO05-a3-idp-01':negative['outcome']})
 for id in CASES:
  observed=negative_actual[id];proof=negative_expected[id];require((observed['outcome'],observed['verdict'],observed['reason_code'],observed['attested'],observed['evidence_class'])==(proof['outcome'],'PASS' if proof['outcome']=='SATISFIED' else 'FAIL',proof['reasonCode'],False,'PROTOCOL_OBSERVED') and observed['evidence']==proof['evidence'],'Native control formal outcome differs '+id);execution=load(negative_evaluation/(id+'.case-execution.json'));details=dict(execution['outcome']['details'])
  if id.endswith('a3-idp-01'):require(details.pop('previous_recorded_evidence_result')['outcome']=='NOT_VERIFIED','Native control prior result audit differs')
  require(execution['runId']==negative_receipt['runId'] and execution['caseId']==id and execution['status']=='FINISHED' and details==proof['details'] and execution['outcome']['evidence']==proof['evidence'],'Stored native control CaseOutcome differs '+id)
 evaluation=folder/'evaluation' ;result=load(evaluation/'result.json');require(result['run']['id']==receipt['runId'] and load(evaluation/'transcript-before.json')==load(evaluation/'transcript.json')==load(folder/'primary/transcript.json'),'Formal evaluation changed originals');actual={c['id']:c for q in result['requirements'] for c in q['cases']};expected=dict(report['normalCases'],**{'IIP-SSO05-a3-idp-01':report['outcome']});selected={}
 for id in CASES:
  case=actual[id];proven=expected[id];require((case['outcome'],case['verdict'],case['reason_code'],case['attested'],case['evidence_class'])==('SATISFIED','PASS',proven['reasonCode'],False,'PROTOCOL_OBSERVED') and case['evidence']==proven['evidence'],'Formal native NameID outcome/provenance differs '+id);
  if id in ADOPT:selected[id]=case
  execution=load(evaluation/(id+'.case-execution.json'));observed=execution['outcome'];details=dict(observed['details'])
  if id.endswith('a3-idp-01'):
   previous=details.pop('previous_recorded_evidence_result');old=next(c for q in load(folder/'primary/result.json')['requirements'] for c in q['cases'] if c['id']==id);require(previous['outcome']==old['outcome']=='NOT_VERIFIED' and previous['reason_code']==old['reason_code'],'Prior partial result audit differs')
  require(execution['runId']==receipt['runId'] and execution['caseId']==id and execution['status']=='FINISHED' and details==proven['details'] and observed['evidence']==proven['evidence'],'Formal stored CaseOutcome differs '+id)
 return evaluation/'result.json',selected
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--diagnostic-only',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=a.root.resolve()
 if folder.name!=FOLDER:folder=folder/FOLDER
 if a.capture_runtime:
  for f in [folder,folder.parent/MUTANT]:runtime.capture_runtime(f)
 if a.record_replay:
  for f in [folder,folder.parent/MUTANT]:require(not(f/'native-reader-replay.json').exists(),'Immutable replay exists');(f/'native-reader-replay.json').write_text(json.dumps(runtime.replay(f),indent=2)+'\n')
 verify_adoption(folder,live=a.live,formal=not a.diagnostic_only);print('Native Keycloak persistent NameID acceptance verified')
