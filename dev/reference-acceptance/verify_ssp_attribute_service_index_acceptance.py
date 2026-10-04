#!/usr/bin/env python3
"""Verify native accepted metadata, fixed release policy, signed selectors and central formal FAIL."""
import argparse,importlib.util,json,subprocess,tempfile,urllib.request,sys
from pathlib import Path
from export_ssp_attribute_service_index import export
from ssp_ui_stored_outcome import compare_stored
FOLDER='ssp-attribute-service-index-v184-r1';REPO=Path(__file__).resolve().parents[2]
CASES=('IIP-IDP04-b-idp-01',);RUNTIME='runtime-v185'
spec=importlib.util.spec_from_file_location('ssp_index_runtime',Path(__file__).with_name('verify_ssp_consent_ui_acceptance.py'));runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
runtime.HELPER='VerifySimpleSamlPhpAttributeServiceIndex';runtime.RUNTIME=RUNTIME;runtime.CLASSES=('SimpleSamlPhpAttributeServiceIndexEvidence','AttributePolicyConfigurationTestCase','SimpleSamlPhpTransientAllowCreateEvidence','ApprovedConfigCaseRegistry')
sha,read,require=runtime.sha,runtime.read,runtime.require
def locate(root):
 root=Path(root).resolve();return root if root.name==FOLDER else root/FOLDER
def rows(result):return {c['id']:c for q in result['requirements'] for c in q['cases'] if c['id'] in CASES}
def native_parser_replay(folder):
 file=folder/'independent-native-parser-replay.json';require(not file.exists(),'Parser replay immutable');entity='http://localhost:18080/p/'+read(folder/'created.json')['run']['planId'];records=[]
 for fixtureName,stdoutName,stderrName in [('control/fixture.xml','control/parser.stdout','control/parser.stderr'),('index-0/fixture.xml','index-0/parser.stdout','index-0/parser.stderr')]:
  fixture=(folder/fixtureName).read_bytes();r=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',(folder/'native-parser-command.php').read_text(),entity,'default'],input=fixture,capture_output=True,timeout=30)
  require(r.returncode==0 and r.stdout==(folder/stdoutName).read_bytes() and r.stderr==(folder/stderrName).read_bytes(),'Independent native parser output differs');records.append(dict(fixture=fixtureName,fixtureSha256=sha(fixture),parserSha256=sha(r.stdout)))
 file.write_text(json.dumps(dict(records=records,nativeParserInvocations=2,productConfigurationWrites=0,protocolSends=0,humanOperations=0),indent=2)+'\n')
def verify(root,live=False):
 folder=locate(root);manifest=read(folder/'originals/manifest.json');run=read(folder/'created.json')['run']['id'];require(manifest['runId']==run,'Run mismatch')
 with tempfile.TemporaryDirectory(prefix='ssp-index-export-') as name:
  regenerated=Path(name)/'originals';export(folder,regenerated);require({p.name for p in regenerated.iterdir()}=={p.name for p in (folder/'originals').iterdir()},'Full regenerated original set differs')
  for p in regenerated.iterdir():require(p.read_bytes()==(folder/'originals'/p.name).read_bytes(),'Regenerated original differs')
 for name,digest in manifest['files'].items():require(sha((folder/'originals'/name).read_bytes())==digest,'Original manifest hash differs')
 restore=read(folder/'restoration.json')
 for label in ['remote','hosted','override']:
  baseline=(folder/(label+'-original.php')).read_bytes();require(baseline==(folder/(label+'-final.php')).read_bytes() and restore[label]['restored'] and restore[label]['original_sha256']==restore[label]['final_sha256']==sha(baseline),'Native restoration incomplete')
 require(read(folder/'identity-before.json')==read(folder/'identity-after.json'),'Native runtime changed')
 for p in folder.glob('native-*.php'):
  if '-after.' not in p.name and not p.name.endswith('-command.php'):require(p.read_bytes()==(folder/p.name.replace('.php','-after.php')).read_bytes(),'Native executable source changed')
 sys.path.insert(0,str(REPO/'dev/simplesamlphp'));from native_ui_privacy import contains_state_secret
 require(all(not contains_state_secret(p.read_text()) for p in folder.rglob('*.html')),'Native authentication state persisted')
 proof=read(folder/'production-reader-replay.json');require(runtime.replay(folder)==proof,'Actual archived production Reader replay differs')
 require(proof['production_outcome']['outcome']=='VIOLATED' and len(proof['negative_controls'])==53 and set(proof['negative_controls'].values())=={'NOT_VERIFIED'} and proof['required_selector_conditions']==3 and proof['configuration_precondition_supplied'] and proof['shared_native_scenario_lifecycle'],'Complete selection/altered-original controls unproven')
 require(proof['recorded_wrapper_outcome']==proof['production_outcome'],'Recorded wrapper changed native outcome')
 require(read(folder/'independent-native-parser-replay.json')['nativeParserInvocations']==2,'Independent native parser replay missing')
 history=read(folder/'attempt-history.json');require(history['formalEvaluationsBeforeDeployment']==0 and history['newProductProtocolSendsForReaderFix']==0 and history['newProductConfigurationWritesForReaderFix']==0 and history['candidateReplayAttempts']==4 and history['candidateReplayFailures']==3,'Incomplete failed-attempt history')
 for name,digest in history['files'].items():require(sha((folder/name).read_bytes())==digest,'Preserved candidate diagnostic changed')
 batch=read(folder/'batch-summary.json');require(batch['nativeParserInvocations']==4 and batch['nativeProducerInvocations']==3 and batch['productConfigurationWriteAttempts']==3 and batch['protocolOperationsAttempted']==5 and batch['credentialPosts']==1 and batch['humanOperations']==batch['productRestarts']==0,'Combined native/replay attempt counts differ')
 installed=read(folder/'receipt-installation.json');require(installed['readBackVerified'] and installed['path']=='/data/attribute-service-index-evidence/'+run and {r['file']:r['sha256'] for r in installed['records']}==manifest['files']|{'manifest.json':sha((folder/'originals/manifest.json').read_bytes())},'Actual native receipt placement/readback differs')
 evaluation=folder/'evaluation';result=read(evaluation/'result.json');actual=rows(result);require(set(actual)==set(CASES),'Formal case inventory differs')
 case=CASES[0];outcome=proof['production_outcome'];require(outcome['reasonCode']=='browser.attribute-index.selection-ignored' and outcome['details']['configuration_confirmed'] is True and outcome['details']['configuration_restored'] is True and outcome['details']['attested'] is False,'Native accepted selection scope unproven')
 stored=compare_stored(folder,RUNTIME,case,outcome,'evaluation/stored-before-index.json','evaluation/stored-after-index.json');row=actual[case]
 require((row['outcome'],row['verdict'],row['reason_code'],row['attested'])==('VIOLATED','FAIL','browser.attribute-index.selection-ignored',False) and stored['verdict']==row['verdict'],'Formal central nonattested FAIL differs')
 require({e['reference'] for e in row['evidence']}=={e['reference'] for e in outcome['evidence']},'Formal evidence differs')
 require(read(evaluation/'transcript-before.json')==read(evaluation/'transcript.json')==read(folder/'transcript.json'),'Formal evaluation changed transcript')
 counts=read(folder/'operation-counts.json');expected=dict(productConfigurationWriteAttempts=3,configurationApplyWrites=2,restorationWrites=1,nativeParserInvocations=2,protocolOperationsAttempted=5,runCreations=1,credentialPosts=1,nativeSessionReadbacks=7,productRestarts=0,humanOperations=0,restored=True)
 require(all(counts.get(k)==v for k,v in expected.items()),'Native campaign attempt counts differ')
 producer=read(folder/'producer-controls/manifest.json');require(producer['nativeProducerInvocations']==3 and producer['productConfigurationWrites']==producer['protocolSends']==producer['humanOperations']==0,'Native semantic control counts missing')
 require(read(evaluation/'operation-counts.json')['configurationConfirmations']==read(evaluation/'operation-counts.json')['attestations']==read(evaluation/'operation-counts.json')['protocolSends']==0,'Adoption introduced declaration/protocol operations')
 if live:
  SOURCES={'idp-saml2':'modules/saml/src/IdP/SAML2.php','idp':'src/SimpleSAML/IdP.php','auth-processing':'src/SimpleSAML/Auth/ProcessingChain.php','auth-source':'src/SimpleSAML/Auth/Source.php','userpass':'modules/exampleauth/src/Auth/Source/UserPass.php','userpass-base':'modules/core/src/Auth/UserPassBase.php','language-adaptor':'modules/core/src/Auth/Process/LanguageAdaptor.php','attribute-limit':'modules/core/src/Auth/Process/AttributeLimit.php','assertion':'vendor/simplesamlphp/saml2-legacy/src/SAML2/Assertion.php','subject-confirmation':'vendor/simplesamlphp/saml2-legacy/src/SAML2/XML/saml/SubjectConfirmation.php','subject-confirmation-data':'vendor/simplesamlphp/saml2-legacy/src/SAML2/XML/saml/SubjectConfirmationData.php','response':'vendor/simplesamlphp/saml2-legacy/src/SAML2/Response.php','xml-signer':'vendor/simplesamlphp/saml2-legacy/src/SAML2/Utils.php','message':'modules/saml/src/Message.php','web-browser-sso':'modules/saml/src/Controller/WebBrowserSingleSignOn.php','login-controller':'modules/core/src/Controller/Login.php','auth-state':'src/SimpleSAML/Auth/State.php','configuration':'src/SimpleSAML/Configuration.php','parser':'src/SimpleSAML/Metadata/SAMLParser.php','session':'src/SimpleSAML/Session.php','random':'src/SimpleSAML/Utils/Random.php','transient-filter':'modules/saml/src/Auth/Process/TransientNameID.php','nameid-generator':'modules/saml/src/BaseNameIDGenerator.php','attribute-add':'modules/core/src/Auth/Process/AttributeAdd.php','attribute-map':'modules/core/src/Auth/Process/AttributeMap.php','name2oid-map':'attributemap/name2oid.php'}
  for label,path in [('remote','metadata/saml20-sp-remote.php'),('hosted','metadata/saml20-idp-hosted.php'),('override','config/config-override.php')]:require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path])==(folder/(label+'-original.php')).read_bytes(),'Live native restoration differs')
  for name,path in SOURCES.items():require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path])==(folder/('native-'+name+'.php')).read_bytes(),'Live native source differs')
  policy=read(folder/'index-0-before/policy.json')
  for name,field in [('config.php','configSha256'),('authsources.php','authsourceSha256')]:require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','sha256sum','/var/simplesamlphp/config/'+name]).decode().split()[0]==policy[field],'Live native global/authsource file hash differs')
  for suffix in ['result.json','transcript']:
   with urllib.request.urlopen('http://localhost:18080/api/runs/'+run+'/'+suffix,timeout=30) as r:value=json.load(r)
   require(rows(value)==actual if suffix=='result.json' else value==read(folder/'transcript.json'),'Live formal proof differs')
 return evaluation/'result.json',actual
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--native-parser-replay',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=locate(a.root)
 if a.capture_runtime:runtime.capture_runtime(folder)
 if a.native_parser_replay:native_parser_replay(folder)
 if a.record_replay:
  file=folder/'production-reader-replay.json';require(not file.exists(),'Actual production replay immutable');file.write_text(json.dumps(runtime.replay(folder),indent=2)+'\n')
 if not any([a.capture_runtime,a.record_replay,a.native_parser_replay]):
  path,accepted=verify(folder,a.live);print(json.dumps(dict(result=str(path),cases={k:v['verdict'] for k,v in accepted.items()},verified=True),indent=2))
