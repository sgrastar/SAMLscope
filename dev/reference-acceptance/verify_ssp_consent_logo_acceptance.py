#!/usr/bin/env python3
"""Verify full native no-logo policy, actual deployed Reader, all attempts and formal result."""
import argparse,importlib.util,json,subprocess,tempfile,urllib.request,sys
from pathlib import Path
from export_ssp_consent_logo import export,VARIANTS
from ssp_ui_stored_outcome import compare_stored
FOLDER='ssp-native-consent-logo-v176-r2';CASE='IIP-MD05-f9-idp-01';REPO=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ssp_logo_runtime',Path(__file__).with_name('verify_ssp_consent_ui_acceptance.py'));runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
runtime.HELPER='VerifySimpleSamlPhpConsentLogo';runtime.RUNTIME='runtime-v178';runtime.CLASSES=('SimpleSamlPhpConsentLogoEvidence','UiLogoComparison','UiLogoBrowserEvidenceTestCase','UiDisplayEvidenceFile','ApprovedBrowserCaseRegistry')
sha,read,require=runtime.sha,runtime.read,runtime.require
def locate(root):
 root=Path(root).resolve();return root if root.name==FOLDER else root/FOLDER
def case(result):return next(c for q in result['requirements'] for c in q['cases'] if c['id']==CASE)
def native_parser_replay(folder):
 file=folder/'independent-native-parser-replay.json';require(not file.exists(),'Refusing parser replay overwrite');command=(folder/'native-parser-command.php').read_text();entity='http://localhost:18080/p/'+read(folder/'created.json')['run']['planId'];rows=[]
 for variant in ['control']+VARIANTS:
  raw=(folder/variant/'fixture.xml').read_bytes();result=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',command,entity,'default'],input=raw,capture_output=True,timeout=30)
  require(result.returncode==0 and result.stdout==(folder/variant/'parser.stdout').read_bytes() and result.stderr==(folder/variant/'parser.stderr').read_bytes(),'Independent native parser changed');rows.append(dict(variant=variant,fixtureSha256=sha(raw),parserSha256=sha(result.stdout),bytesIdentical=True))
 file.write_text(json.dumps(dict(records=rows,nativeParserInvocations=3,productConfigurationWrites=0,protocolSends=0,humanOperations=0),indent=2)+'\n')
def verify(root,live=False):
 folder=locate(root);manifest=read(folder/'originals/manifest.json');run=read(folder/'created.json')['run']['id'];require(manifest['runId']==run,'Run differs')
 with tempfile.TemporaryDirectory(prefix='ssp-native-logo-export-') as name:
  regenerated=Path(name)/'originals';export(folder,regenerated);require({p.name for p in regenerated.iterdir()}=={p.name for p in (folder/'originals').iterdir()},'Regenerated original set differs')
  for p in regenerated.iterdir():require(p.read_bytes()==(folder/'originals'/p.name).read_bytes(),'Regenerated original differs')
 for name,digest in manifest['files'].items():require(sha((folder/'originals'/name).read_bytes())==digest,'Original hash differs')
 restore=read(folder/'restoration.json')
 for label in ['remote','hosted','override']:
  before=(folder/(label+'-original.php')).read_bytes();require(before==(folder/(label+'-final.php')).read_bytes() and restore[label]['restored'] and restore[label]['original_sha256']==restore[label]['final_sha256']==sha(before),'Native exact restoration incomplete')
 require(read(folder/'identity-before.json')==read(folder/'identity-after.json'),'Native runtime identity changed')
 for p in folder.glob('native-*.txt'):
  if '-after.' not in p.name:require(p.read_bytes()==(folder/p.name.replace('.txt','-after.txt')).read_bytes(),'Native executable/render source changed')
 sys.path.insert(0,str(REPO/'dev/simplesamlphp'));from native_ui_privacy import contains_state_secret
 require(all(not contains_state_secret(p.read_text()) for p in folder.rglob('*.html')),'Native state identifier retained')
 recorded=read(folder/'production-reader-replay.json');require(runtime.replay(folder)==recorded,'Actual archived Reader replay differs')
 history=read(folder/'failed-v177-replay/history.json');require(history['adopted'] is False and history['actualRuntime']=='runtime'
  and all(sha((folder/name).read_bytes())==digest for name,digest in history['archiveFiles'].items()),'Historical v177 failed replay not preserved')
 proof=recorded['production_outcome'];require(proof['outcome']=='SATISFIED_WITH_NOTE' and proof['reasonCode']=='browser.ui-logo.native-consumer-not-used' and proof['details']['native_closed_render_policy'] is True and len(recorded['negative_controls'])==23 and set(recorded['negative_controls'].values())=={'NOT_VERIFIED'},'Native no-logo waiver or complete controls unproven')
 require(read(folder/'independent-native-parser-replay.json')['nativeParserInvocations']==3,'Independent full native parser replay missing')
 installed=read(folder/'receipt-installation.json');require(installed['readBackVerified'] and {r['file']:r['sha256'] for r in installed['records']}==manifest['files']|{'manifest.json':sha((folder/'originals/manifest.json').read_bytes())},'Native runtime placement readback incomplete')
 stored=compare_stored(folder,'runtime-v178',CASE,proof)
 evaluation=folder/'evaluation';result=read(evaluation/'result.json');actual=case(result);require((actual['outcome'],actual['verdict'],actual['reason_code'],actual['attested'])==('SATISFIED_WITH_NOTE','WARNING','browser.ui-logo.native-consumer-not-used',False),'Formal outcome differs');require(stored['verdict']==actual['verdict'],'Central stored Evaluator differs')
 require({e['reference'] for e in actual['evidence']}=={e['reference'] for e in proof['evidence']},'Formal evidence references differ')
 entries=read(folder/'transcript.json');require(read(evaluation/'transcript-before.json')==read(evaluation/'transcript.json')==entries,'Formal evaluation modified transcript')
 attempts=[]
 for index in [1,2]:
  attempt=folder.parent/('ssp-native-consent-logo-v176-r'+str(index));counts=read(attempt/'operation-counts.json');require(counts==dict(productConfigurationWriteAttempts=8,configurationApplyWrites=5,restorationWrites=3,nativeParserInvocations=3,protocolOperationsAttempted=6,runCreations=1,productRestarts=0,humanOperations=0,restored=True,credentialPosts=1,chromeLaunches=1,browserObservationAttempts=3,browserObservations=3),'Attempt counts differ')
  require(all(v['restored'] and v['original_sha256']==v['final_sha256'] for v in read(attempt/'restoration.json').values()),'Historical attempt not restored');attempts.append(counts)
 summary=read(folder/'batch-summary.json')
 for field in ['productConfigurationWriteAttempts','configurationApplyWrites','restorationWrites','protocolOperationsAttempted','runCreations','credentialPosts','chromeLaunches','browserObservationAttempts','browserObservations']:require(summary[field]==sum(a[field] for a in attempts),'Batch counts differ')
 require(summary['nativeParserInvocations']==9 and summary['humanOperations']==summary['productRestarts']==0 and summary['historicalAttemptNotAdopted']=='r1-missing-noconsent-template-loader-image-originals','Historical baseline gap not accounted')
 if live:
  from consent_ui_grouped_campaign import SOURCES
  for label,path in [('remote','metadata/saml20-sp-remote.php'),('hosted','metadata/saml20-idp-hosted.php'),('override','config/config-override.php')]:require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path])==(folder/(label+'-original.php')).read_bytes(),'Live native restoration differs')
  # Newer collector families may capture additional security sources. Replay the
  # immutable source closure actually required by this campaign's production Reader.
  for name,path in SOURCES.items():
   original=folder/('native-'+name+'.txt')
   if original.exists():require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path])==original.read_bytes(),'Live native render source differs')
  for suffix in ['result.json','transcript']:
   with urllib.request.urlopen('http://localhost:18080/api/runs/'+run+'/'+suffix,timeout=30) as r:value=json.load(r)
   require(case(value)==actual if suffix=='result.json' else value==entries,'Live formal result/transcript differs')
 return evaluation/'result.json',{CASE:actual}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--native-parser-replay',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=locate(a.root)
 if a.capture_runtime:runtime.capture_runtime(folder)
 if a.native_parser_replay:native_parser_replay(folder)
 if a.record_replay:
  file=folder/'production-reader-replay.json';require(not file.exists(),'Replay is immutable');file.write_text(json.dumps(runtime.replay(folder),indent=2)+'\n')
 if not any([a.capture_runtime,a.record_replay,a.native_parser_replay]):
  path,outcomes=verify(folder,a.live);print(json.dumps(dict(result=str(path),cases={k:v['verdict'] for k,v in outcomes.items()},verified=True),indent=2))
