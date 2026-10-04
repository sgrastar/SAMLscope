#!/usr/bin/env python3
"""Verify stock native no-opportunity scope, full semantic controls and actual formal outcomes."""
import argparse,importlib.util,json,subprocess,tempfile,urllib.request,sys
from pathlib import Path
from export_ssp_subject_confirmation import export
from ssp_ui_stored_outcome import compare_stored
FOLDER='ssp-subject-confirmation-native-v178-r1';REPO=Path(__file__).resolve().parents[2]
CASES=('IIP-SSO01-fr-idp-01','IIP-SSO01-gd-idp-01');RUNTIME='runtime-v180'
spec=importlib.util.spec_from_file_location('ssp_attester_runtime',Path(__file__).with_name('verify_ssp_consent_ui_acceptance.py'));runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
runtime.HELPER='VerifySimpleSamlPhpSubjectConfirmation';runtime.RUNTIME=RUNTIME;runtime.CLASSES=('SimpleSamlPhpSubjectConfirmationEvidence','SubjectConfirmationConfigurationTestCase','ApprovedConfigCaseRegistry','SuiteRunProfileLookup')
sha,read,require=runtime.sha,runtime.read,runtime.require
def locate(root):
 root=Path(root).resolve();return root if root.name==FOLDER else root/FOLDER
def rows(result):return {c['id']:c for q in result['requirements'] for c in q['cases'] if c['id'] in CASES}
def native_parser_replay(folder):
 file=folder/'independent-native-parser-replay.json';require(not file.exists(),'Parser replay immutable');entity='http://localhost:18080/p/'+read(folder/'created.json')['run']['planId'];fixture=(folder/'control/fixture.xml').read_bytes();r=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',(folder/'native-parser-command.php').read_text(),entity,'default'],input=fixture,capture_output=True,timeout=30)
 require(r.returncode==0 and r.stdout==(folder/'control/parser.stdout').read_bytes() and r.stderr==(folder/'control/parser.stderr').read_bytes(),'Independent native parser output differs');file.write_text(json.dumps(dict(fixtureSha256=sha(fixture),parserSha256=sha(r.stdout),nativeParserInvocations=1,productConfigurationWrites=0,protocolSends=0,humanOperations=0),indent=2)+'\n')
def verify(root,live=False):
 folder=locate(root);manifest=read(folder/'originals/manifest.json');run=read(folder/'created.json')['run']['id'];require(manifest['runId']==run,'Run mismatch')
 with tempfile.TemporaryDirectory(prefix='ssp-attester-export-') as name:
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
 require(set(proof['production_outcomes'])==set(CASES) and len(proof['negative_controls'])==28 and set(proof['negative_controls'].values())=={'NOT_VERIFIED'} and proof['native_signed_semantic_controls']==4 and proof['shared_native_config_lifecycle'],'Complete semantic/altered-original controls unproven')
 require(read(folder/'independent-native-parser-replay.json')['nativeParserInvocations']==1,'Independent native parser replay missing')
 installed=read(folder/'receipt-installation.json');require(installed['readBackVerified'] and installed['path']=='/data/subject-confirmation-evidence/'+run and {r['file']:r['sha256'] for r in installed['records']}==manifest['files']|{'manifest.json':sha((folder/'originals/manifest.json').read_bytes())},'Actual native receipt placement/readback differs')
 evaluation=folder/'evaluation';result=read(evaluation/'result.json');actual=rows(result);require(set(actual)==set(CASES),'Formal case inventory differs')
 for case in CASES:
  outcome=proof['production_outcomes'][case];require(outcome['outcome']=='SATISFIED_WITH_NOTE' and outcome['reasonCode']=='browser.subject-confirmation.native-no-opportunity' and outcome['details']['scope']=='this-run-stock-native-responder-and-effective-configuration' and outcome['details']['custom_php_capability_asserted'] is False,'Native closed scope unproven')
  short=case.split('-')[2];stored=compare_stored(folder,RUNTIME,case,outcome,'evaluation/stored-before-'+short+'.json','evaluation/stored-after-'+short+'.json');row=actual[case]
  require((row['outcome'],row['verdict'],row['reason_code'],row['attested'])==('SATISFIED_WITH_NOTE','WARNING','browser.subject-confirmation.native-no-opportunity',False) and stored['verdict']==row['verdict'],'Formal nonattested NOTE differs')
  require({e['reference'] for e in row['evidence']}=={e['reference'] for e in outcome['evidence']},'Formal evidence differs')
 require(read(evaluation/'transcript-before.json')==read(evaluation/'transcript.json')==read(folder/'transcript.json'),'Formal evaluation changed transcript')
 expected=dict(productConfigurationWriteAttempts=2,configurationApplyWrites=1,restorationWrites=1,nativeParserInvocations=1,protocolOperationsAttempted=2,nativeSignedProducerInvocations=4,runCreations=1,credentialPosts=1,productRestarts=0,humanOperations=0,restored=True);require(read(folder/'operation-counts.json')==expected,'Native campaign attempt counts differ')
 require(read(evaluation/'operation-counts.json')['configurationConfirmations']==read(evaluation/'operation-counts.json')['attestations']==read(evaluation/'operation-counts.json')['protocolSends']==0,'Adoption introduced declaration/protocol operations')
 if live:
  from subject_confirmation_campaign import SOURCES
  for label,path in [('remote','metadata/saml20-sp-remote.php'),('hosted','metadata/saml20-idp-hosted.php'),('override','config/config-override.php')]:require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path])==(folder/(label+'-original.php')).read_bytes(),'Live native restoration differs')
  for name,path in SOURCES.items():require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path])==(folder/('native-'+name+'.php')).read_bytes(),'Live native source differs')
  policy=read(folder/'before/policy.json')
  for name,field in [('config.php','configSha256'),('authsources.php','authsourceSha256')]:
   digest=subprocess.check_output(['docker','exec','samlscope-reference-ssp','sha256sum','/var/simplesamlphp/config/'+name]).decode().split()[0];require(digest==policy[field],'Live native global/authsource file hash differs')
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
