#!/usr/bin/env python3
"""Strict actual-Reader native encrypted SLO verification; Suite key stays in its existing store.

Replay is read-only but requires the existing Suite container/keystore. No private
key is exported to host, archived with evidence, or printed by helper.
"""
import argparse,importlib.util,json,subprocess,tempfile,urllib.request,sys,zipfile,shutil
from pathlib import Path
from export_ssp_encrypted_logout import export
from ssp_ui_stored_outcome import compare_stored
REPO=Path(__file__).resolve().parents[2];FOLDER='ssp-encrypted-logout-native-v186-r7';RUNTIME='runtime-v187';CASE='IIP-IDP19-c-idp-01';HELPER='VerifySimpleSamlPhpEncryptedLogout'
spec=importlib.util.spec_from_file_location('ssp_encrypted_runtime',Path(__file__).with_name('verify_ssp_consent_ui_acceptance.py'));runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime);runtime.HELPER=HELPER;runtime.RUNTIME=RUNTIME;runtime.CLASSES=('SimpleSamlPhpEncryptedLogoutEvidence','EncryptedLogoutNativeTestCase','IdpBasicLogoutScenarioTestCase','ApprovedBrowserCaseRegistry')
read,require,sha=runtime.read,runtime.require,runtime.sha
def locate(root):
 root=Path(root).resolve();return root if root.name==FOLDER else root/FOLDER
def rows(result):return {c['id']:c for q in result['requirements'] for c in q['cases'] if c['id']==CASE}
def replay(folder):
 archive=folder/RUNTIME;pins=read(archive/'pins.json');require(set(pins['jars'])==set(runtime.JARS),'Runtime JAR set differs')
 for name,digest in pins['jars'].items():require(sha((archive/(name+'.jar')).read_bytes())==digest,'Archived JAR changed')
 with zipfile.ZipFile(archive/'runner.jar') as z:require(pins['classes']=={n:sha(z.read('com/samlscope/runner/cases/'+n+'.class')) for n in runtime.CLASSES},'Actual reader class differs')
 require(sha((archive/(HELPER+'.java')).read_bytes())==pins['helperSha256'],'Archived helper differs')
 cp=':'.join(str((archive/(n+'.jar')).resolve()) for n in runtime.JARS)+':'+Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip()
 with tempfile.TemporaryDirectory(prefix='ssp-encrypted-replay-') as name:
  temporary=Path(name);classes=temporary/'classes';result=subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(archive/(HELPER+'.java'))],capture_output=True,text=True);require(result.returncode==0,'Helper compile failed: '+result.stderr[-1500:]);require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')),'Helper shadows runtime production class')
  public=temporary/'source';public.mkdir()
  for file in ['created.json','transcript.json','decoded-manifest.json','target-metadata.xml']:shutil.copyfile(folder/file,public/file)
  shutil.copytree(folder/'originals',public/'originals')
  for row in read(folder/'decoded-manifest.json'):
   destination=public/row['file'];destination.parent.mkdir(exist_ok=True,parents=True);shutil.copyfile(folder/row['file'],destination)
  copied=temporary/'runtime';copied.mkdir()
  for n in runtime.JARS:shutil.copyfile(archive/(n+'.jar'),copied/(n+'.jar'))
  remote='/tmp/'+temporary.name;subprocess.run(['docker','exec','samlscope-reference-suite','mkdir','-p',remote],check=True,capture_output=True)
  try:
   for local in [classes,public,copied]:subprocess.run(['docker','cp',str(local),'samlscope-reference-suite:'+remote+'/'+local.name],check=True,capture_output=True)
   classpath=remote+'/classes:'+':'.join(remote+'/runtime/'+n+'.jar' for n in runtime.JARS)+':/opt/samlscope/lib/*';result=subprocess.run(['docker','exec','samlscope-reference-suite','java','-cp',classpath,'com.samlscope.runner.cases.'+HELPER,remote+'/source',remote+'/report.json','/data'],capture_output=True,text=True,timeout=90);require(result.returncode==0,'Actual production Reader replay failed: '+result.stderr[-1600:]);raw=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',remote+'/report.json']);return json.loads(raw)
  finally:subprocess.run(['docker','exec','--user','0','samlscope-reference-suite','rm','-rf',remote],check=True,capture_output=True)
def verify(root,live=False):
 folder=locate(root);manifest=read(folder/'originals/manifest.json');run=manifest['runId']
 with tempfile.TemporaryDirectory(prefix='ssp-encrypted-export-') as name:
  regenerated=Path(name)/'originals';export(folder,regenerated);require({p.name for p in regenerated.iterdir()}=={p.name for p in (folder/'originals').iterdir()},'Exporter inventory differs')
  for p in regenerated.iterdir():require(p.read_bytes()==(folder/'originals'/p.name).read_bytes(),'Exporter original differs')
 for name,digest in manifest['files'].items():require(sha((folder/'originals'/name).read_bytes())==digest,'Manifest original differs')
 for label,state in read(folder/'restoration.json').items():
  require(state['restored'] and state['original_sha256']==state['final_sha256']==sha((folder/(label+'-original.php')).read_bytes()) and (folder/(label+'-original.php')).read_bytes()==(folder/(label+'-final.php')).read_bytes(),'Native restoration differs')
 require(read(folder/'identity-before.json')==read(folder/'identity-after.json'),'Native runtime changed')
 history=read(folder/'formal-attempt-history.json');require(not history['productionVerdictAdopted'] and history['nativeOperationsAdded']==history['configurationChangesAdded']==0 and history['oldNativeSessionAndSamlOriginalsRetained'],'Historical failure not preserved')
 for name,digest in history['protectedFiles'].items():require(sha((folder/name).read_bytes())==digest,'Historical production failure original changed')
 require(read(folder/'runtime-v186/failed-reader-replay.json')['status']=='failure','Historical Reader failure disappeared')
 proof=read(folder/'production-reader-replay.json');require(replay(folder)==proof,'Actual archived Reader differs');require(proof['production_outcome']['outcome']=='VIOLATED' and proof['shared_native_scenario_lifecycle'] and proof['suitePrivateKeyReadOnlyInMemory'] and not proof['privateCredentialsExported'] and len(proof['negative_controls'])==38 and proof['nativeStderrDiagnosticVariationOutcomeIdentical'] and set(proof['negative_controls'].values())=={'NOT_VERIFIED'},'Calibrated native counterexample/controls unproven')
 installation=read(folder/'receipt-installation.json');require(installation['path']=='/data/encrypted-logout-evidence/'+run and installation['readBackVerified'] and {r['file']:r['sha256'] for r in installation['records']}==manifest['files']|{'manifest.json':sha((folder/'originals/manifest.json').read_bytes())},'Formal receipt readback differs')
 actual=rows(read(folder/'evaluation/result.json'));require(set(actual)=={CASE},'Formal case differs');row=actual[CASE];outcome=proof['production_outcome'];stored=compare_stored(folder,RUNTIME,CASE,outcome,'evaluation/stored-before-encrypted.json','evaluation/stored-after-encrypted.json');require((row['outcome'],row['verdict'],row['reason_code'],row['attested'])==('VIOLATED','FAIL','slo.encrypted-id.multiple-keys.unknown-key-accepted',False) and row['verdict']==stored['verdict'],'Formal central FAIL differs');require({e['reference'] for e in row['evidence']}=={e['reference'] for e in outcome['evidence']},'Formal references differ');require(read(folder/'evaluation/transcript-before.json')==read(folder/'evaluation/transcript.json')==read(folder/'transcript.json'),'Formal replay altered transcript')
 attempts=[]
 for i in range(1,8):
  attempt=folder if i==7 else folder.parent/('ssp-encrypted-logout-native-v185-r'+str(i));counts=read(attempt/'operation-counts.json');require(counts['restored'] and counts['productRestarts']==counts['humanOperations']==0,'Attempt restoration/counts absent');correction=attempt/'observed-operation-counts-correction.json'
  if correction.exists():
   correction=read(correction);require(correction['originalCounterSha256']==sha((attempt/'operation-counts.json').read_bytes()) and correction['originalTranscriptSha256']==sha((attempt/'transcript.json').read_bytes()),'Historical count correction differs');counts['protocolOperationsAttempted']=correction['correctedProtocolOperationsAttempted']
  for label,state in read(attempt/'restoration.json').items():
   original=(attempt/(label+'-original.php')).read_bytes();final=(attempt/(label+'-final.php')).read_bytes();require(state['restored'] and original==final and state['original_sha256']==state['final_sha256']==sha(original),'Historical native attempt restoration differs')
  cleanup=read(attempt/'ephemeral-key-cleanup.json');require(cleanup['created'] and cleanup['removed'] and not cleanup['privateMaterialArchived'],'Historical ephemeral key not removed')
  attempts.append(counts)
 batch=read(folder/'batch-summary.json')
 for key in ['productConfigurationWriteAttempts','configurationApplyWrites','restorationWrites','nativeParserInvocations','nativeDecryptInvocations','nativeVerificationInvocations','protocolOperationsAttempted','credentialPosts','runCreations','nativeEphemeralKeyCreations','nativeEphemeralFileWrites','nativeEphemeralFileRemovals']:require(batch[key]==sum(c.get(key,0) if key=='nativeVerificationInvocations' else c[key] for c in attempts),'Full attempt batch counts differ: '+key)
 require(batch['humanOperations']==batch['productRestarts']==0,'Uncounted interaction/restart')
 if live:
  for label,path in [('remote','metadata/saml20-sp-remote.php'),('hosted','metadata/saml20-idp-hosted.php'),('override','config/config-override.php')]:require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path])==(folder/(label+'-original.php')).read_bytes(),'Live configuration not restored')
  for path in ['key.pem','cert.pem']:require(subprocess.run(['docker','exec','samlscope-reference-ssp','test','!','-e','/tmp/samlscope-encrypted-logout-'+path],capture_output=True).returncode==0,'Ephemeral native file remains')
  for suffix in ['result.json','transcript']:
   with urllib.request.urlopen('http://localhost:18080/api/runs/'+run+'/'+suffix,timeout=30) as response:value=json.load(response)
   require(rows(value)==actual if suffix=='result.json' else value==read(folder/'transcript.json'),'Live formal result differs')
 return folder/'evaluation/result.json',actual
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=locate(a.root)
 if a.capture_runtime:runtime.capture_runtime(folder)
 if a.record_replay:
  file=folder/'production-reader-replay.json';require(not file.exists(),'Replay immutable');file.write_text(json.dumps(replay(folder),indent=2)+'\n')
 if not a.capture_runtime and not a.record_replay:
  result,cases=verify(folder,a.live);print(json.dumps(dict(result=str(result),cases={k:v['verdict'] for k,v in cases.items()},verified=True),indent=2))
