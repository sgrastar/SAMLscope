#!/usr/bin/env python3
"""Strict reference-only native ambient-auth exclusion proof; no credentials or declarations.

The remote SAML/login actions are reusable by the ordinary Suite browser path.
The reference proof adapter additionally needs local Docker access to read native
source/effective configuration and temporarily register the Suite SP; it is not
available to an arbitrary remote operator without those administration rights.
"""
import argparse,importlib.util,json,tempfile,subprocess,urllib.request,sys
from pathlib import Path
from export_ssp_authentication_identity import export
from ssp_ui_stored_outcome import compare_stored
FOLDER='ssp-authentication-identity-v187-r1';RUNTIME='runtime-v188';CASE='IIP-SSO01-ae-idp-01';REPO=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ssp_identity_runtime',Path(__file__).with_name('verify_ssp_consent_ui_acceptance.py'));runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime);runtime.HELPER='VerifySimpleSamlPhpAuthenticationIdentity';runtime.RUNTIME=RUNTIME;runtime.CLASSES=('SimpleSamlPhpAuthenticationIdentityEvidence','AuthenticationIdentityConfigurationTestCase','ShibbolethAuthenticationIdentityEvidenceFile','ApprovedConfigCaseRegistry')
read,require,sha=runtime.read,runtime.require,runtime.sha
def locate(root):
 root=Path(root).resolve();return root if root.name==FOLDER else root/FOLDER
def rows(result):return {c['id']:c for q in result['requirements'] for c in q['cases'] if c['id']==CASE}
def verify(root,live=False):
 folder=locate(root);manifest=read(folder/'originals/manifest.json');run=manifest['runId']
 with tempfile.TemporaryDirectory(prefix='ssp-identity-export-') as name:
  regenerated=Path(name)/'originals';export(folder,regenerated);require({p.name for p in regenerated.iterdir()}=={p.name for p in (folder/'originals').iterdir()},'Regenerated inventory differs')
  for p in regenerated.iterdir():require(p.read_bytes()==(folder/'originals'/p.name).read_bytes(),'Regenerated original differs')
 for name,digest in manifest['files'].items():require(sha((folder/'originals'/name).read_bytes())==digest,'Original manifest differs')
 for label,state in read(folder/'restoration.json').items():
  raw=(folder/(label+'-original.php')).read_bytes();require(raw==(folder/(label+'-final.php')).read_bytes() and state['restored'] and state['original_sha256']==state['final_sha256']==sha(raw),'Native restoration differs')
 require(read(folder/'identity-before.json')==read(folder/'identity-after.json'),'Native runtime changed')
 proof=read(folder/'production-reader-replay.json');require(runtime.replay(folder)==proof,'Actual archived Reader differs');require(proof['production_outcome']['outcome']=='SATISFIED' and len(proof['negative_controls'])==28 and set(proof['negative_controls'].values())=={'NOT_VERIFIED'} and proof['shared_native_lifecycle'] and proof['native_signed_semantic_controls']==2 and not proof['privateMaterialExported'],'Native scoped identity proof/control unproven')
 counts=read(folder/'operation-counts.json');require(all(counts[k]==v for k,v in dict(productConfigurationWriteAttempts=3,configurationApplyWrites=2,restorationWrites=1,nativeParserInvocations=2,protocolOperationsAttempted=3,credentialPosts=1,nativeSignedProducerInvocations=0,humanOperations=0,productRestarts=0,restored=True).items()),'Full native attempt counts differ')
 completion=read(folder/'read-only-producer-completion.json');require(completion['originalCountsSha256']==sha((folder/'operation-counts.json').read_bytes()) and completion['nativeSignedProducerInvocations']==2 and completion['nativeRuntimeUnchanged'] and completion['protocolSends']==completion['productConfigurationWrites']==completion['productRestarts']==completion['humanOperations']==0,'Separate read-only producer completion unproven');require(read(folder/'campaign-error.json')['adopted'] is False,'Original collector failure hidden')
 installation=read(folder/'receipt-installation.json');require(installation['path']=='/data/simplesamlphp-authentication-identity-evidence/'+run and installation['readBackVerified'] and {r['file']:r['sha256'] for r in installation['records']}==manifest['files']|{'manifest.json':sha((folder/'originals/manifest.json').read_bytes())},'Runtime receipt readback differs')
 result=rows(read(folder/'evaluation/result.json'));require(set(result)=={CASE},'Formal case differs');outcome=proof['production_outcome'];stored=compare_stored(folder,RUNTIME,CASE,outcome,'evaluation/stored-before-identity.json','evaluation/stored-after-identity.json');row=result[CASE];require((row['outcome'],row['verdict'],row['reason_code'],row['attested'])==('SATISFIED','PASS','browser.authentication-identity.native-observed',False) and row['verdict']==stored['verdict'],'Formal central PASS differs');require({e['reference'] for e in row['evidence']}=={e['reference'] for e in outcome['evidence']},'Formal references differ');require(read(folder/'evaluation/transcript-before.json')==read(folder/'evaluation/transcript.json')==read(folder/'transcript.json'),'Formal evaluation changed transcript')
 sys.path.insert(0,str(REPO/'dev/simplesamlphp'));from native_ui_privacy import contains_state_secret
 require(all(not contains_state_secret(p.read_text()) for p in folder.rglob('*.html')),'Native auth state secret remains')
 if live:
  for label,path in [('remote','metadata/saml20-sp-remote.php'),('hosted','metadata/saml20-idp-hosted.php'),('override','config/config-override.php')]:require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/'+path])==(folder/(label+'-original.php')).read_bytes(),'Live native configuration not restored')
  for name,field in [('config.php','configSha256'),('authsources.php','authsourceSha256')]:require(subprocess.check_output(['docker','exec','samlscope-reference-ssp','sha256sum','/var/simplesamlphp/config/'+name]).decode().split()[0]==read(folder/'control-before/policy.json')[field],'Live auth/global config differs')
  for suffix in ['result.json','transcript']:
   with urllib.request.urlopen('http://localhost:18080/api/runs/'+run+'/'+suffix,timeout=30) as r:value=json.load(r)
   require(rows(value)==result if suffix=='result.json' else value==read(folder/'transcript.json'),'Live formal result differs')
 return folder/'evaluation/result.json',result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=locate(a.root)
 if a.capture_runtime:runtime.capture_runtime(folder)
 if a.record_replay:
  file=folder/'production-reader-replay.json';require(not file.exists(),'Replay immutable');file.write_text(json.dumps(runtime.replay(folder),indent=2)+'\n')
 if not a.capture_runtime and not a.record_replay:
  result,cases=verify(folder,a.live);print(json.dumps(dict(result=str(result),cases={k:v['verdict'] for k,v in cases.items()},verified=True),indent=2))
