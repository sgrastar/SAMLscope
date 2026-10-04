#!/usr/bin/env python3
"""Adopt one original-backed accepted-certificate runtime observation; calibration never substitutes product data."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,tempfile,urllib.request,sys
REPO=pathlib.Path(__file__).resolve().parents[2];FOLDER='simplesamlphp-certificate-runtime-r2';SUITE='samlscope-reference-suite';HELPER='VerifySimpleSamlPhpCertificateRuntime';JARS=('runner','core','saml','store');CASE='IIP-MD06-a6-idp-01';ADAPTER='simplesamlphp-native-certificate-runtime-v1';RUNTIME='runtime-v200';EVALUATION='evaluation-v200';REPLAY='native-reader-replay-v200.json'
PINS={'runner': '1310f37a83e26135b9d4db8f360c597c89474d9500234ef36ba13338105745d4', 'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'saml': '43b2cc47bd142956e7f35bd1d906950f64d3f952374db72a2df84f5e3617bec7', 'store': 'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece', 'helper': '96c22a00cb956f4e7c87c4fd639c00e292baf766fec83ceed679060d21c0277f'} # Actual deployed v200, independently fixed before adoption.
sha=lambda b:hashlib.sha256(b).hexdigest();load=lambda p:json.loads(p.read_bytes())
def require(b,message):
 if not b:raise ValueError(message)
def locate(root):
 root=pathlib.Path(root).absolute();require(not any(x.is_symlink() for x in [root,*root.parents]),'Unsafe adoption root');root=root.resolve();return root if (root/'receipt/manifest.json').exists() else root/FOLDER
def api(path,body=None):
 from urllib.request import Request,urlopen
 req=Request('http://localhost:18080'+path,data=None if body is None else json.dumps(body).encode(),headers={} if body is None else {'Content-Type':'application/json'})
 with urlopen(req,timeout=60) as response:return json.load(response)
def capture_runtime(folder):
 space=os.statvfs(REPO);require(space.f_bavail*space.f_frsize>=32*1024*1024,'Insufficient host space before runtime archive')
 dest=folder/RUNTIME;dest.mkdir(exist_ok=False);actual={};placements={}
 for name in JARS:
  files=list((REPO/'api/build/install/samlscope/lib').glob(name+'-*.jar'));require(len(files)==1,'Ambiguous production jar');host=files[0];remote='/opt/samlscope/lib/'+host.name;digest=subprocess.check_output(['docker','exec',SUITE,'sha256sum',remote],timeout=40).decode().split()[0];require(sha(host.read_bytes())==digest,'Host differs from actual deployed runtime')
  # Only completed evidence archives can be link sources; the mutable distribution cannot.
  candidates=[]
  for pattern in ('*/runtime*/'+name+'.jar','*/reader-v*/'+name+'.jar'):
   candidates.extend(folder.parent.glob(pattern))
  original=next((p for p in sorted(candidates) if p.parent!=dest and p.is_file() and not p.is_symlink() and sha(p.read_bytes())==digest),None)
  target=dest/(name+'.jar')
  if original is not None:
   try:os.link(original,target);placements[name]=dict(mode='immutable-archive-hardlink',source=str(original.relative_to(folder.parent)))
   except OSError:shutil.copyfile(host,target);placements[name]=dict(mode='copy',source='verified-distribution')
  else:shutil.copyfile(host,target);placements[name]=dict(mode='copy',source='verified-distribution')
  actual[name]=digest
 source=pathlib.Path(__file__).with_name(HELPER+'.java');(dest/source.name).write_bytes(source.read_bytes());actual['helper']=sha(source.read_bytes());(dest/'pins.json').write_text(json.dumps(actual,indent=2)+'\n');(dest/'archive-placement.json').write_text(json.dumps(dict(jars=placements,mutableDistributionLinked=False,actualDeployedHashesVerified=True),indent=2)+'\n');return actual
def replay(folder):
 runtime=folder/RUNTIME;pins=load(runtime/'pins.json');require(PINS and pins==PINS,'Runtime not independently pinned')
 for name in JARS:require(sha((runtime/(name+'.jar')).read_bytes())==pins[name],'Archived runtime modified')
 require(sha((runtime/(HELPER+'.java')).read_bytes())==pins['helper'],'Helper modified');cp=':'.join(str((runtime/(n+'.jar')).resolve()) for n in JARS)+':'+pathlib.Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip()
 with tempfile.TemporaryDirectory(prefix='kc-registered-signer-replay-') as name:
  tmp=pathlib.Path(name);classes=tmp/'classes';subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(runtime/(HELPER+'.java'))],check=True,capture_output=True,timeout=60);require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')),'Helper shadows production')
  remote='/tmp/'+tmp.name;subprocess.run(['docker','exec',SUITE,'mkdir','-p',remote],check=True,capture_output=True,timeout=40)
  try:
   for local,target in [(classes,'classes'),(folder/'receipt','receipt'),(runtime,'runtime'),(folder/'calibration','calibration')]:subprocess.run(['docker','cp',str(local),SUITE+':'+remote+'/'+target],check=True,capture_output=True,timeout=90)
   cp=':'.join(remote+'/runtime/'+n+'.jar' for n in JARS)+':/opt/samlscope/lib/*:'+remote+'/classes'
   result=subprocess.run(['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.'+HELPER,remote+'/receipt','/data',remote+'/replay.json',remote+'/calibration'],capture_output=True,text=True,timeout=120);require(result.returncode==0,'Production replay failed: '+result.stderr[-1800:]);subprocess.run(['docker','cp',SUITE+':'+remote+'/replay.json',str(tmp/'replay.json')],check=True,capture_output=True,timeout=40);return load(tmp/'replay.json')
  finally:subprocess.run(['docker','exec','--user','0',SUITE,'rm','-rf',remote],check=True,capture_output=True,timeout=60)
def stored_helpers():
 # Capture/verification functions keep their globals in this dedicated module instance.
 # Other product adopters retain the shared module's original helper selection.
 import importlib.util
 source=pathlib.Path(__file__).with_name('keycloak_registered_signer_stored_outcome.py')
 spec=importlib.util.spec_from_file_location('_ssp_certificate_stored_outcome',source)
 isolated=importlib.util.module_from_spec(spec);spec.loader.exec_module(isolated)
 isolated.HELPER="ReadSimpleSamlPhpCertificateStoredConclusions"
 return isolated
def install(folder):
 capture=stored_helpers().capture
 m=load(folder/'receipt/manifest.json');run=m['runId'];ev=folder/EVALUATION;ev.mkdir(exist_ok=True)
 if (ev/'stored-before.json').exists():
  stored_helpers().verify(folder,RUNTIME,EVALUATION+'/stored-before.json',run,CASE)
  require((ev/'result-before.json').is_file() and (ev/'transcript-before.json').is_file(),'Interrupted placement lacks complete unchanged before originals')
 elif (folder/'evaluation-actual/stored-before.json').exists():
  source=folder/'evaluation-actual';lineage={}
  for name in ['stored-before.json','stored-before.source.java','stored-before.provenance.json','result-before.json','transcript-before.json']:
   raw=(source/name).read_bytes();(ev/name).write_bytes(raw);lineage[name]=dict(source='evaluation-actual/'+name,sha256=sha(raw))
  (ev/'prior-before-lineage.json').write_text(json.dumps(dict(capturedBeforeOriginalReceiptPlacement=True,recaptured=False,stateRewritten=False,originals=lineage),indent=2)+'\n')
  stored_helpers().verify(folder,RUNTIME,EVALUATION+'/stored-before.json',run,CASE)
 else:
  capture(folder,RUNTIME,EVALUATION+'/stored-before.json',run,CASE)
  (ev/'result-before.json').write_text(json.dumps(api('/api/runs/'+run+'/result.json'),indent=2)+'\n');(ev/'transcript-before.json').write_text(json.dumps(api('/api/runs/'+run+'/transcript'),indent=2)+'\n')
 dest='/data/metadata-certificate-runtime-evidence-simplesamlphp/'+run;x=subprocess.run(['docker','exec',SUITE,'test','-e',dest+'/manifest.json'],capture_output=True,timeout=40)
 require(x.returncode in (0,1),'Receipt ownership test failed')
 if x.returncode==0:
  prior=load(folder/'receipt-installation.json');require(prior['path']==dest and prior['readBackVerified'] and prior['records']==m['files']|{'manifest.json':sha((folder/'receipt/manifest.json').read_bytes())},'Existing receipt not previously verified against this immutable original')
 else:
  subprocess.run(['docker','exec',SUITE,'mkdir','-p',dest],check=True,capture_output=True,timeout=40);subprocess.run(['docker','cp',str(folder/'receipt')+'/.',SUITE+':'+dest],check=True,capture_output=True,timeout=90)
 with tempfile.TemporaryDirectory(prefix='kc-signer-readback-') as name:
  readback=pathlib.Path(name)/'receipt';subprocess.run(['docker','cp',SUITE+':'+dest,str(readback)],check=True,capture_output=True,timeout=90);expected=m['files']|{'manifest.json':sha((folder/'receipt/manifest.json').read_bytes())};actual={str(p.relative_to(readback)):sha(p.read_bytes()) for p in readback.rglob('*') if p.is_file()};require(expected==actual,'Receipt readback differs')
 (folder/'receipt-installation.json').write_text(json.dumps(dict(path=dest,readBackVerified=True,records=expected,productOperations=0),indent=2)+'\n')
def formal_preflight(run,ev):
 """Persist the actual future API observation; do not manufacture past readiness proof."""
 status=api('/api/runs/'+run+'/protocol-evidence')
 with (ev/'protocol-evidence-preflight.json').open('x') as output:output.write(json.dumps(status,indent=2)+'\n')
 require(isinstance(status,dict) and isinstance(status.get('cases'),list),'Suite path gap: invalid protocol evidence status; evaluation POST skipped')
 selected=[c for c in status['cases'] if isinstance(c,dict) and c.get('caseId')==CASE]
 require(len(selected)<=1,'Suite path gap: ambiguous native case; evaluation POST skipped')
 if selected:
  require(selected[0].get('ready') is True,'Suite path gap: native certificate case not ready; evaluation POST skipped')
  return
 result=api('/api/runs/'+run+'/result.json')
 with (ev/'protocol-evidence-preflight-existing-result.json').open('x') as output:output.write(json.dumps(result,indent=2)+'\n')
 require(isinstance(result,dict) and result.get('run',{}).get('id')==run and isinstance(result.get('requirements'),list),'Suite path gap: native case missing and result unavailable; evaluation POST skipped')
 cases=[c for q in result['requirements'] if isinstance(q,dict) for c in q.get('cases',[]) if isinstance(c,dict) and c.get('id')==CASE]
 require(len(cases)==1 and cases[0].get('outcome') in {'SATISFIED','SATISFIED_WITH_NOTE','VIOLATED'},'Suite path gap: native case missing without an existing conclusive result; evaluation POST skipped')
def formal(folder):
 capture=stored_helpers().capture
 m=load(folder/'receipt/manifest.json');run=m['runId'];ev=folder/EVALUATION;require((ev/'stored-before.json').is_file(),'Old stored outcome must be captured before receipt placement')
 require(not (ev/'evaluate.json').exists() and not (ev/'stored-after.json').exists(),'Formal evaluation originals already exist; completed history will not be re-evaluated')
 formal_preflight(run,ev)
 (ev/'evaluate.json').write_text(json.dumps(api('/api/runs/'+run+'/protocol-evidence/evaluate',{}),indent=2)+'\n');(ev/'result.json').write_text(json.dumps(api('/api/runs/'+run+'/result.json'),indent=2)+'\n');(ev/'transcript.json').write_text(json.dumps(api('/api/runs/'+run+'/transcript'),indent=2)+'\n');capture(folder,RUNTIME,EVALUATION+'/stored-after.json',run,CASE)
def verify_cumulative_operations(folder):
 audit=load(folder/'cumulative-operation-audit.json');old=folder.parent/'simplesamlphp-certificate-runtime-r1'
 expected={}
 for name,path in {'failedCounts':'receipt/operation-counts.json','failedRestoration':'restoration.json','failedTranscript':'receipt/transcript.json','failedCollector':'collector-source.py','failedLog':'../cross-cluster-audit/ssp-certificate-runtime-r1-collector.log','qualifiedCounts':'receipt/operation-counts.json','qualifiedRestoration':'restoration.json','qualifiedCollector':'collector-source.py'}.items():
  source=(folder if name.startswith('qualified') else old)/path;expected[name]=dict(path=str(source.relative_to(folder.parent)),sha256=sha(source.read_bytes()))
 require(audit['originals']==expected,'Failed/qualified original lineage changed')
 failed=load(old/'receipt/operation-counts.json');qualified=load(folder/'receipt/operation-counts.json');restored=load(old/'restoration.json');require(failed['restored'] and restored['restored'] and restored['original_sha256']==restored['final_sha256'] and failed['protocolSubmissions']==6 and failed['credentialPosts']==1 and failed['nativeConfigurationWrites']==7 and failed['restorationWrites']==1,'Failed-attempt costs/restoration not proven')
 sums={k:failed[k]+qualified[k] for k in ['protocolSubmissions','credentialPosts','credentialPostAttempts','nativeConfigurationWrites','restorationWrites','personOperations','productRestarts']}
 require(audit['cumulative']==sums==dict(protocolSubmissions=13,credentialPosts=2,credentialPostAttempts=2,nativeConfigurationWrites=14,restorationWrites=2,personOperations=0,productRestarts=0) and audit['separateMemorySessions'] is True and audit['failedAttemptAdopted'] is False,'Cumulative operation accounting differs')
 require('ModuleNotFoundError: No module named' in (old.parent/'cross-cluster-audit/ssp-certificate-runtime-r1-collector.log').read_text(),'Interrupted host preparation cause original missing')
 return audit
def verify_adoption(root,live=False):
 folder=locate(root);verify_cumulative_operations(folder);receipt=folder/'receipt';m=load(receipt/'manifest.json');run=m['runId']
 require(m['schema']=='samlscope-simplesamlphp-certificate-runtime-v1' and m['adapter']==ADAPTER and m['campaignId']=='native-metadata-certificate-runtime','Native scope differs')
 require(run==load(folder/'created.json')['run']['id'] and m['targetMetadataSha256']==sha((folder/'target-metadata.xml').read_bytes()),'Run/target differs')
 require({str(p.relative_to(receipt)) for p in receipt.rglob('*') if p.is_file()}==set(m['files'])|{'manifest.json'},'Native inventory differs')
 for name,digest in m['files'].items():
  p=receipt/name;require(p.resolve().is_relative_to(receipt) and p.is_file() and not any(x.is_symlink() for x in [p,*p.parents]) and sha(p.read_bytes())==digest,'Original modified')
 require(not any('counterfactual' in name or 'producer-stdout' in name or 'calibration' in name for name in m['files']),'Diagnostic cause installed into product receipt')
 require([e['variant'] for e in m['epochs']]==['control','certificate-critical-extension','certificate-unknown-ca','certificate-revoked','certificate-revocation-unreachable'] and all('nativeCertificateCheckOriginal' not in p for e in m['epochs'] for p in e['probes']),'Actual product observations mixed with diagnostic findings')
 entries=load(receipt/'transcript.json');by={e['id']:e for e in entries};require(len(by)==len(entries) and all(e['runId']==run for e in entries),'Foreign/duplicate history');decoded={}
 for row in load(receipt/'decoded-manifest.json'):
  p=receipt/row['file'];e=by[row['id']];raw=p.read_bytes();require(p.parent==receipt/'decoded' and row['id'] not in decoded and e['decodedSamlRef']=='transcripts/'+run+'/'+row['id']+'.saml.xml' and sha(raw)==row['sha256'] and len(raw)==e['decodedSamlBytes'],'Foreign/modified decoded original');decoded[row['id']]=raw
 require(set(decoded)=={e['id'] for e in entries if e['decodedSamlRef']},'Decoded inventory incomplete')
 for row in load(receipt/'browser-originals-manifest.json'):
  e=by[row['id']];p=receipt/row['file'];require(p.parent==receipt/'browser-originals' and e['bodyRef']==row['reference']=='transcripts/'+run+'/'+row['id']+'.body' and e['bodyBytes']==row['bytes']==len(p.read_bytes()) and sha(p.read_bytes())==row['sha256'],'Native browser original differs')
 observed=load(folder/REPLAY);require(replay(folder)==observed and observed['privateMaterialExported'] is False and observed['additionalProductOperations']==0 and observed['controlsAdopted'] is False and observed['productionProviderAliasesOnly'] is True and observed['providerPrimaryAliasRejected'] is True,'Actual archived replay differs')
 require(len(observed['negativeControls'])==33 and set(observed['negativeControls'].values())=={'NOT_VERIFIED'} and observed['approvedMutants']=={'mut-iip-md06-a6-idp':'VIOLATED'} and observed['additionalRevokedControl']=='VIOLATED' and observed['counterfactualCalibrationOnly'] is True,'Detection controls incomplete')
 require(observed['wrapperLifecycle']==dict(start=True,ConfigConfirmed=True,TranscriptReady=True,Aborted=True,TimedOut=True,**{'status-ready':True,'recorded-not-verified':True,'recorded-conclusive':False,'incomplete-history':'NOT_VERIFIED'}),'Actual lifecycle differs')
 diagnostic=load(folder/'calibration/native-openssl-calibration.json');require(diagnostic['counterfactualCalibrationOnly'] is True and diagnostic['controlsAdopted'] is False and diagnostic['actualProductFinding'] is False and diagnostic['inputManifestSha256']==sha((receipt/'manifest.json').read_bytes()),'Native diagnostics not isolated')
 counts=load(receipt/'operation-counts.json');require(counts['restored'] is True and counts['nativeConfigurationWrites']==7 and counts['restorationWrites']==1 and counts['initialBaselineSubmissions']==1 and counts['actualOutboxTargetAttempts']==counts['selectedProbeAttempts']==6 and counts['protocolSubmissions']==counts['nativePostAttempts']+counts['nativeRedirectAttempts']==7 and counts['credentialPosts']==counts['credentialPostAttempts']==1 and counts['personOperations']==counts['productRestarts']==0,'Actual operation accounting differs')
 restored=load(folder/'restoration.json');require(restored['restored'] and restored['original_sha256']==restored['final_sha256']==sha((receipt/'original-configuration.php').read_bytes())==sha((receipt/'final-configuration.php').read_bytes()),'Exact restoration differs')
 installed=load(folder/'receipt-installation.json');require(installed['readBackVerified'] and installed['records']==m['files']|{'manifest.json':sha((receipt/'manifest.json').read_bytes())},'Installed receipt differs')
 ev=folder/EVALUATION;lineage=load(ev/'prior-before-lineage.json');require(lineage['capturedBeforeOriginalReceiptPlacement'] and not lineage['recaptured'] and not lineage['stateRewritten'],'Before lineage not disclosed')
 for name,record in lineage['originals'].items():require((ev/name).read_bytes()==(folder/record['source']).read_bytes() and sha((ev/name).read_bytes())==record['sha256'],'Prior before original rewritten')
 require(load(ev/'transcript-before.json')==load(ev/'transcript.json')==entries,'Formal changed original transcript');result=load(ev/'result.json');by={c['id']:c for req in result['requirements'] for c in req['cases']};proof=observed['outcome'];require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+m['targetMetadataSha256'],'Formal target differs')
 stored=stored_helpers().compare_stored(folder,RUNTIME,CASE,proof,before_name=EVALUATION+'/stored-before.json',after_name=EVALUATION+'/stored-after.json');case=by[CASE]
 require((case['outcome'],case['verdict'],case['reason_code'],case['attested'],case['evidence_class'])==('SATISFIED','PASS','metadata.certificate.runtime-no-pkix-observed',False,'OPERATOR_ASSISTED') and case['evidence']==proof['evidence'] and stored['verdict']=='PASS' and stored['outboxCount']==6,'Full central outcome/provenance differs')
 if live:
  raw=subprocess.check_output(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/metadata/saml20-sp-remote.php'],timeout=40);require(raw==(receipt/'original-configuration.php').read_bytes(),'Live restoration differs');require(api('/api/runs/'+run+'/transcript')==entries,'Live history differs');require(next(c for q in api('/api/runs/'+run+'/result.json')['requirements'] for c in q['cases'] if c['id']==CASE)==case,'Live formal differs')
 return ev/'result.json',{CASE:case}

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--install',action='store_true');p.add_argument('--formal',action='store_true');p.add_argument('--live',action='store_true');args=p.parse_args();folder=locate(args.root)
 if args.capture_runtime:print(capture_runtime(folder))
 if args.record_replay:
  path=folder/REPLAY;require(not path.exists(),'Replay immutable');path.write_text(json.dumps(replay(folder),indent=2)+'\n')
 if args.install:install(folder)
 if args.formal:formal(folder)
 if not any([args.capture_runtime,args.record_replay,args.install,args.formal]):verify_adoption(folder,args.live);print('SimpleSAMLphp certificate runtime adoption verified: one observation')
