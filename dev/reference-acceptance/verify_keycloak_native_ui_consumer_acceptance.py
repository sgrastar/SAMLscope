#!/usr/bin/env python3
"""Adopt request-bound native Keycloak logo fallback and policy URL consumer originals."""
import argparse,base64,importlib.util,json,pathlib,re,subprocess,sys,urllib.parse,zipfile
REPO=pathlib.Path(__file__).resolve().parents[2]
FOLDER='keycloak-native-ui-consumer-v178-r1';CASES={'IIP-MD05-f9-idp-01','IIP-MD05-fh-idp-01'}
VARIANTS=['control','ui-consumer-logo-localized','ui-consumer-logo-fallback']+['ui-url-'+element+'-'+scheme for element in ['logo','information','privacy'] for scheme in ['http','https','data','javascript','file']]
SERVICES='213c45bb357e0881ead8284f12308e3c9fd8e09e7f0b6ec816f95f8b0921bea9';THEMES='a89cbd82fa30951224262aaf5326f6239e1217224678d69cfac3d3fd1b493407'
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
runtime=module('kc_ui_runtime',REPO/'dev/reference-acceptance/verify_ssp_intersection_capability_acceptance.py');runtime.HELPER='VerifyKeycloakNativeUiConsumerEvidence'
runtime.CLASSES=tuple('com/samlscope/runner/cases/'+name+'.class' for name in ['KeycloakNativeUiConsumerEvidence','UiLogoComparison','UiLogoBrowserEvidenceTestCase','UiUrlBrowserEvidenceTestCase','ApprovedBrowserCaseRegistry'])
sha,load,require=runtime.sha,runtime.load,runtime.require
sys.path.insert(0,str(REPO/'dev/keycloak'))
def verify_adoption(root,live=False,formal=True):
 folder=pathlib.Path(root).resolve()
 if folder.name!=FOLDER:folder=folder/FOLDER
 receipt=load(folder/'qualified-receipt.json');created=load(folder/'created.json')['run'];run=created['id'];peer='http://localhost:18080/p/'+created['planId'];target=sha((folder/'target-metadata.xml').read_bytes())
 require(receipt['schema']=='samlscope-keycloak-native-ui-consumer-v1' and receipt['runId']==run and receipt['targetEntityId']=='http://localhost:18180/realms/samlscope' and receipt['targetMetadataSha256']==target and receipt['peerEntityId']==peer and receipt['campaignId']=='native-ui-consumer-matrix','Native UI original scope differs')
 entries=load(folder/'transcript.json');by={e['id']:e for e in entries};require(len(entries)==154 and len(by)==len(entries) and all(e['runId']==run for e in entries),'UI history foreign or ambiguous')
 decoded={}
 for row in load(folder/'decoded-manifest.json'):
  require(pathlib.Path(row['file']).parent==pathlib.Path('decoded') and row['id'] in by and row['id'] not in decoded,'Decoded original reference escape')
  raw=(folder/row['file']).read_bytes();require(sha(raw)==row['sha256'] and len(raw)==by[row['id']]['decodedSamlBytes'],'Decoded original hash/length differs');decoded[row['id']]=raw
 def original(ref,kind):
  raw=decoded[ref['reference']];require(sha(raw)==ref['sha256'],'Original reference binding differs');v=json.loads(raw);require(v['schema']=='samlscope-keycloak-native-ui-original-v1' and v['runId']==run and v['peerEntityId']==peer and v['targetMetadataSha256']==target and v['kind']==kind,'Native original identity differs');return v
 restoration=receipt['restoration'];require(restoration==load(folder/'restoration.json') and restoration['restored'] is True,'Native restoration absent')
 before,after=[original(restoration[key],'client-inventory') for key in ['before','after']];require(before['clients']==after['clients']==[],'Target client restoration incomplete')
 scope_before,scope_after=[original(restoration[key],'native-scope') for key in ['scopeBefore','scopeAfter']]
 require({k:v for k,v in scope_before.items() if k not in {'recordedAt'}}=={k:v for k,v in scope_after.items() if k not in {'recordedAt'}},'Native runtime/theme/policy changed')
 for phase in ['before','after']:
  for name,digest in [('services',SERVICES),('themes',THEMES)]:require(sha((folder/f'native-source/{phase}-{name}.jar').read_bytes())==digest==scope_before['sourceJarSha256'][name],'Native original source differs')
 require([m['variant'] for m in receipt['members']]==VARIANTS,'Full native fixture admission matrix absent')
 accepted=0;refused=[]
 for member in receipt['members']:
  variant=member['variant'];prepared=[e for e in entries if e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==variant];require(len(prepared)==1,'Fixture preparation ambiguous');raw=(folder/variant/'fixture.xml').read_bytes();require(raw==decoded[prepared[0]['id']] and sha(raw)==member['fixtureSha256']==prepared[0]['samlSummary']['metadataSha256'],'Native XML import does not match original prepared bytes')
  converter=original(member['converter'],'converter');native=converter['native'];require(native['requestSha256']==sha(raw) and native['status']==200 and native['url'].endswith('/client-description-converter'),'Native converter endpoint/input differs');recipe=json.loads(base64.b64decode(native['responseBase64']));require(sha(base64.b64decode(native['responseBase64']))==native['responseSha256'],'Native converter output hash differs')
  application=original(member['application'],'ui-prerequisite-application');require(application['converterSha256']==sha(json.dumps(recipe,separators=(',',':')).encode()) and application['consentRequired'] is True and application['native']['requestSha256']==sha(json.dumps(dict(recipe,consentRequired=True),separators=(',',':')).encode()),'Suite created UI attributes instead of native conversion')
  restored=original(member['restoration'],'client-inventory');require(restored['variant']==variant and restored['clients']==[],'Member client restored incorrectly')
  if member['nativeAdmission']=='accepted':
   accepted+=1;require(application['native']['status']==201,'Native successful creation absent');saved=original(member['persisted'],'operative-client');require(saved['client']==load(folder/variant/'client-readback.json') and saved['client']['consentRequired'] is True,'Saved native client differs');browser=original(member['browser'],'native-browser-ui');require(browser['observation']==load(folder/variant/'browser.json')['observation'] and browser['exchange']==load(folder/variant/'exchange.json'),'Native browser correlation differs');html=(folder/variant/'native-consent-public.html').read_bytes();require(html==base64.b64decode(browser['publicHtmlBase64']) and sha(html)==browser['observation']['consent']['publicHtmlSha256'] and len(html)==browser['observation']['consent']['publicHtmlBytes'],'Public consent HTML original differs');require(browser['observation']['credentialsPersisted'] is False and browser['observation']['externalRequestsPermitted'] is False,'Browser secret/network scope differs')
  else:
   refused.append(variant);require(member['nativeAdmission']=='rejected' and application['native']['status']==400 and member['rejection']==json.loads(base64.b64decode(application['native']['responseBase64'])) and member.get('orchestrationOnlyContinue') is True and 'browser' not in member and 'persisted' not in member,'Native validation refusal fabricated as browser/SAML result')
 require(accepted==15 and refused==['ui-url-logo-javascript','ui-url-privacy-data','ui-url-privacy-javascript'],'Unexpected native admission matrix')
 operations=load(folder/'operations.json');counts=load(folder/'operation-counts.json');require(counts==dict(product_configuration_write_attempts=33,product_restarts=0,human_operations=0,browser_saml_flows=15,metadata_fixture_count=18,restored=True),'Native operation counts differ')
 require(len(operations)==48 and sum(o['kind']=='native-client-create-attempt' for o in operations)==18 and sum(o['kind']=='native-client-delete' and o['status']==204 for o in operations)==15 and sum(o['kind']=='native-browser-saml-flow' and o['browserStatus'] is True for o in operations)==15,'Operation ledger incomplete')
 history=load(folder/'operation-history.json');require(history['successfulNativeConfigurationWrites']==36 and history['nativeWriteAttempts']==39 and history['samlFlows']==17 and history['runCreations']==3 and history['productRestarts']==history['humanOperations']==0 and len(history['trials'])==3,'All failed/diagnostic campaign operation costs absent')
 for row in history['trials']:
  source=folder.parent/row['folder'];require(re.fullmatch(r'keycloak-native-ui-consumer-v178-[a-z0-9-]+',row['folder']),'Operation source path invalid')
  for name,digest in row['files'].items():require(name in {'operations.json','restoration.json','operation-counts.json','created.json'} and sha((source/name).read_bytes())==digest,'Trial operation original changed')
  require(load(source/'restoration.json')['restored'] is True,'Prior failed/diagnostic trial not restored');trial_operations=load(source/'operations.json');writes=[o for o in trial_operations if o['kind'] in {'native-client-create-attempt','native-client-delete','native-recovery-delete'}];actual_requests=[e for e in load(source/'transcript.json') if e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='AuthnRequest'];require(row['nativeWriteAttempts']==len(writes) and row['successfulNativeWrites']==sum(o['status'] in {201,204} for o in writes) and row['browserFlowAttempts']==sum(o['kind']=='native-browser-saml-flow' for o in trial_operations) and row['actualSamlFlows']==len(actual_requests),'Trial operation counts not derived from originals')
 require(sum(r['nativeWriteAttempts'] for r in history['trials'])==history['nativeWriteAttempts'] and sum(r['successfulNativeWrites'] for r in history['trials'])==history['successfulNativeConfigurationWrites'] and sum(r['actualSamlFlows'] for r in history['trials'])==history['samlFlows'] and sum(r['browserFlowAttempts'] for r in history['trials'])==history['browserFlowAttempts']==18,'Cumulative operation costs differ');require(not(folder/'runtime/candidate-only.json').exists(),'Candidate runtime cannot be adopted');report=runtime.replay(folder);require(report==load(folder/'native-reader-replay.json'),'Actual archived production UI replay differs');require(report['runId']==run and report['privateKeyExported'] is False and report['productConfigurationWrites']==report['samlRequests']==0,'Production replay added target action')
 require(len(report['checks'])==32 and report['checks']['native-logo-known-preferred-default-fallback']=='SATISFIED' and report['checks']['native-policy-file-link-used']=='VIOLATED' and all(v==dict(logo='NOT_VERIFIED',url='NOT_VERIFIED') for k,v in report['checks'].items() if k not in {'native-logo-known-preferred-default-fallback','native-policy-file-link-used'}),'Altered native original accepted')
 proven=report['cases'];require(set(proven)==CASES and proven['IIP-MD05-f9-idp-01']['outcome']=='SATISFIED' and proven['IIP-MD05-fh-idp-01']['outcome']=='VIOLATED' and proven['IIP-MD05-fh-idp-01']['details']['disallowed_scheme_uses']==['privacy-file'],'Native UI outcome differs')
 if live:
  from metadata_supersession_campaign import read
  from mdiop_representation_campaign import runtime as product_runtime
  require(read('/clients?clientId='+urllib.parse.quote(peer,safe=''))==[] and product_runtime()==scope_before['runtime'],'Live target configuration/runtime not restored');realm=read('');require({k:realm.get(k) for k in scope_before['realm']}==scope_before['realm'] and {k:read('/client-policies/'+k) for k in ['policies','profiles']}==scope_before['clientPolicies'],'Live theme/policy state differs')
  installation=load(folder/'receipt-install.json');require(installation['runId']==run and installation['productConfigurationWrites']==installation['samlRequests']==0 and len(installation['files'])==3,'Public proof installation differs')
  for row in installation['files']:
   require(row['path'].startswith('/data/ui-native-feature-absence/'+run+'.keycloak-ui-consumer') and sha((folder/row['file']).read_bytes())==row['sha256'],'Installed receipt source differs');actual=subprocess.check_output(['docker','exec','samlscope-reference-suite','sha256sum',row['path']],text=True).split()[0];require(actual==row['sha256'],'Live public proof differs')
 if not formal:return report
 evaluation=folder/'evaluation';result=load(evaluation/'result.json');actual={c['id']:c for q in result['requirements'] for c in q['cases']};require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+target,'Formal UI result scope differs');require(load(evaluation/'transcript-before.json')==load(evaluation/'transcript.json')==entries,'Formal UI evaluation changed original history')
 selected={}
 for id in CASES:
  case=actual[id];expected=proven[id];require((case['outcome'],case['verdict'],case['reason_code'],case['attested'],case['evidence_class'])==(expected['outcome'],'PASS' if id.endswith('f9-idp-01') else 'WARNING',expected['reasonCode'],False,'PROTOCOL_OBSERVED'),'Formal native UI outcome/provenance differs');require(case['evidence']==expected['evidence'],'Formal native UI references differ');execution=load(evaluation/(id+'.case-execution.json'));observed=execution['outcome'];details=dict(observed['details']);previous=details.pop('previous_recorded_evidence_result');old=next(c for q in load(folder/'result.json')['requirements'] for c in q['cases'] if c['id']==id);require(execution['runId']==run and execution['caseId']==id and execution['status']=='FINISHED' and previous['outcome']==old['outcome']=='NOT_VERIFIED' and previous['reason_code']==old['reason_code'],'Previous UI result audit differs');require(details==expected['details'] and observed['evidence']==expected['evidence'] and observed['reasonCode']==expected['reasonCode'],'Production UI wrapper differs');selected[id]=case
 return evaluation/'result.json',selected
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--diagnostic-only',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=a.root.resolve()
 if folder.name!=FOLDER:folder=folder/FOLDER
 if a.capture_runtime:runtime.capture_runtime(folder)
 if a.record_replay:require(not(folder/'native-reader-replay.json').exists(),'Immutable replay exists');(folder/'native-reader-replay.json').write_text(json.dumps(runtime.replay(folder),indent=2)+'\n')
 verify_adoption(folder,live=a.live,formal=not a.diagnostic_only);print('Native Keycloak UI consumer verified')
