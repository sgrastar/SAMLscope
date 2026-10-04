#!/usr/bin/env python3
"""Verify stock native no-opportunity scope, full semantic controls and actual formal outcomes."""
import argparse,importlib.util,json,subprocess,tempfile,urllib.request,sys
from pathlib import Path
from export_ssp_consent_uri import export,VARIANTS
from ssp_ui_stored_outcome import compare_stored
FOLDER='ssp-native-consent-uri-v181-r2';REPO=Path(__file__).resolve().parents[2]
CASES=('IIP-MD05-fh-idp-01','IIP-MD05-fb-idp-01');RUNTIME='runtime-v182'
spec=importlib.util.spec_from_file_location('ssp_attester_runtime',Path(__file__).with_name('verify_ssp_consent_ui_acceptance.py'));runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
runtime.HELPER='VerifySimpleSamlPhpConsentUri';runtime.RUNTIME=RUNTIME;runtime.CLASSES=('SimpleSamlPhpConsentUriEvidence','UiUrlBrowserEvidenceTestCase','NativeUiFeatureAbsenceTestCase','UiUrlComparison','UiDisplayEvidenceFile','ApprovedBrowserCaseRegistry')
sha,read,require=runtime.sha,runtime.read,runtime.require
def locate(root):
 root=Path(root).resolve();return root if root.name==FOLDER else root/FOLDER
def rows(result):return {c['id']:c for q in result['requirements'] for c in q['cases'] if c['id'] in CASES}
def native_parser_replay(folder):
 file=folder/'independent-native-parser-replay.json';require(not file.exists(),'Parser replay immutable');entity='http://localhost:18080/p/'+read(folder/'created.json')['run']['planId'];records=[]
 for variant in ['control']+VARIANTS:
  raw=(folder/variant/'fixture.xml').read_bytes();r=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',(folder/'native-parser-command.php').read_text(),entity,'default'],input=raw,capture_output=True,timeout=30)
  require(r.returncode==0 and r.stdout==(folder/variant/'parser.stdout').read_bytes() and r.stderr==(folder/variant/'parser.stderr').read_bytes(),'Independent full native parser differs');records.append(dict(variant=variant,fixtureSha256=sha(raw),parserSha256=sha(r.stdout),bytesIdentical=True))
 file.write_text(json.dumps(dict(records=records,nativeParserInvocations=16,productConfigurationWrites=0,protocolSends=0,humanOperations=0),indent=2)+'\n')
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
 for p in folder.glob('native-*.txt'):
  if '-after.' not in p.name :require(p.read_bytes()==(folder/p.name.replace('.txt','-after.txt')).read_bytes(),'Native executable source changed')
 sys.path.insert(0,str(REPO/'dev/simplesamlphp'));from native_ui_privacy import contains_state_secret
 require(all(not contains_state_secret(p.read_text()) for p in folder.rglob('*.html')),'Native authentication state persisted')
 proof=read(folder/'production-reader-replay.json');require(runtime.replay(folder)==proof,'Actual archived production Reader replay differs')
 require(set(proof['production_outcomes'])==set(CASES) and proof['shared_native_ui_lifecycle'] and len(proof['negative_controls'])==23 and set(proof['negative_controls'].values())=={'NOT_VERIFIED'} and len(proof['uri_use_controls'])==7 and set(proof['uri_use_controls'].values())=={'NOT_VERIFIED'} and len(proof['discovery_controls'])==5 and set(proof['discovery_controls'].values())=={'NOT_VERIFIED'},'Complete altered-original/native-use controls unproven')
 require(read(folder/'independent-native-parser-replay.json')['nativeParserInvocations']==16,'Independent full native parser replay missing')
 history=read(folder/'failed-runtime-v181-diagnostic.json');require(history['outcome']=='NOT_VERIFIED' and not history['verdictAdopted'] and not history['formalEvaluationAttempted'] and history['stage']=='native-consent-browser-ui-url-privacy-http','Historical production observation gap hidden')
 for name,digest in history['records'].items():require(sha((folder/name).read_bytes())==digest,'Historical failed production runtime archive changed')
 installed=read(folder/'receipt-installation.json');require(installed['readBackVerified'] and installed['path']=='/data/ui-consent-uri-evidence/'+run and {r['file']:r['sha256'] for r in installed['records']}==manifest['files']|{'manifest.json':sha((folder/'originals/manifest.json').read_bytes())},'Actual native receipt placement/readback differs')
 evaluation=folder/'evaluation';result=read(evaluation/'result.json');actual=rows(result);require(set(actual)==set(CASES),'Formal case inventory differs')
 for case in CASES:
  outcome=proof['production_outcomes'][case];expected=('VIOLATED','browser.ui-url.disallowed-scheme-used') if case.endswith('fh-idp-01') else ('SATISFIED_WITH_NOTE','browser.ui-native-feature.no-discovery-ui');require((outcome['outcome'],outcome['reasonCode'])==expected,'Native full URL/discovery outcome differs')
  if case.endswith('fh-idp-01'):require(outcome['details']['missing_conditions']==[] and outcome['details']['evidence_issues']==[] and set(outcome['details']['disallowed_scheme_uses'])=={'information-javascript','information-file','privacy-javascript','privacy-file'} and outcome['details']['verified_nonuse_conditions']==5,'Full15 scheme observations unproven')
  else:require(outcome['details']['scope']=='this-run-stock-native-password-authsource-and-effective-configuration' and outcome['details']['custom_php_capability_asserted'] is False and outcome['details']['native_password_authentication'],'Stock native no-discovery scope unproven')
  short=case.split('-')[2];stored=compare_stored(folder,RUNTIME,case,outcome,'evaluation/stored-before-'+short+'.json','evaluation/stored-after-'+short+'.json');row=actual[case]
  require((row['outcome'],row['verdict'],row['reason_code'],row['attested'])==(expected[0],'WARNING',expected[1],False) and stored['verdict']==row['verdict'],'Formal nonattested outcome differs')
  require({e['reference'] for e in row['evidence']}=={e['reference'] for e in outcome['evidence']},'Formal evidence differs')
 require(read(evaluation/'transcript-before.json')==read(evaluation/'transcript.json')==read(folder/'transcript.json'),'Formal evaluation changed transcript')
 attempts=[]
 for index in [1,2]:
  attempt=folder.parent/('ssp-native-consent-uri-v180-r1' if index==1 else FOLDER);counts=read(attempt/'operation-counts.json');expected=dict(productConfigurationWriteAttempts=20 if index==1 else 21,configurationApplyWrites=17 if index==1 else 18,restorationWrites=3,nativeParserInvocations=16,protocolOperationsAttempted=30 if index==1 else 32,runCreations=1,productRestarts=0,humanOperations=0,restored=True,credentialPosts=1,chromeLaunches=1,browserObservationAttempts=15 if index==1 else 16,browserObservations=15 if index==1 else 16);require(counts==expected,'All attempted native operations differ')
  require(all(v['restored'] and v['original_sha256']==v['final_sha256'] for v in read(attempt/'restoration.json').values()),'Historical attempt not restored');attempts.append(counts)
 summary=read(folder/'batch-summary.json')
 for key in attempts[0]:
  if isinstance(attempts[0][key],int) and not isinstance(attempts[0][key],bool):require(summary[key]==sum(row[key] for row in attempts)+(16 if key=='nativeParserInvocations' else 0),'Batch attempted operation counts differ')
 require(summary['historicalAttemptNotAdopted']=='r1-native-logo-opaque-javascript-rejection-and-missing-data-popup-original','Historical partial observation hidden')
 require(read(evaluation/'operation-counts.json')['protocolSends']==0 and read(evaluation/'operation-counts.json')['humanOperations']==0,'Adoption introduced product/protocol operations')
 if live:
  from consent_ui_grouped_campaign import SOURCES
  from subject_confirmation_campaign import SOURCES as AUTH_SOURCES
  SOURCES={**SOURCES,**AUTH_SOURCES}
  for label,path in [('remote','metadata/saml20-sp-remote.php'),('hosted','metadata/saml20-idp-hosted.php'),('override','config/config-override.php')]:require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path])==(folder/(label+'-original.php')).read_bytes(),'Live native restoration differs')
  for name,path in SOURCES.items():require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path])==(folder/('native-'+name+'.txt')).read_bytes(),'Live native source differs')
  policy=read(folder/'control/before/authentication-policy.json')
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
