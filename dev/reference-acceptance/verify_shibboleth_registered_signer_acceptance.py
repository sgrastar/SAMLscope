#!/usr/bin/env python3
"""Adopt one original-backed signer restriction observation; calibration never substitutes product data."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,tempfile,urllib.request,sys
REPO=pathlib.Path(__file__).resolve().parents[2];FOLDER='shibboleth-registered-signer-r1';SUITE='samlscope-reference-suite';HELPER='VerifyShibbolethRegisteredSignerEvidence';JARS=('runner','core','saml','store');CASE='IIP-SSO01-al-idp-01';ADAPTER='shibboleth-native-issuer-key-locator-v1';RUNTIME='runtime-actual-v2';EVALUATION='evaluation-actual'
PINS={'runner': '9449ba0fd13dcad6ad296d31dbb7811564bf21e732ea522e56aa2d341827c85d', 'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'saml': '43b2cc47bd142956e7f35bd1d906950f64d3f952374db72a2df84f5e3617bec7', 'store': 'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece', 'helper': 'b31edda467b4854c806106805e3155df2babac3dd17bf3c8a1e23f0d8ada49e8'}
DEPLOYED_PINS={'runner':'9449ba0fd13dcad6ad296d31dbb7811564bf21e732ea522e56aa2d341827c85d','core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe','saml':'43b2cc47bd142956e7f35bd1d906950f64d3f952374db72a2df84f5e3617bec7','store':'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'}
CONTROLS={'wrong-run','wrong-adapter','wrong-target','wrong-campaign','foreign-plan','missing-normal','foreign-history','duplicate-history','foreign-decoded-ref','foreign-primary-key','unrelated-native-http','native-request-hash-mismatch','native-body-hash-mismatch','native-runtime-epoch-changed','missing-native-peer','missing-restoration','restoration-configuration-changed','cost-omits-credential','private-native-readback','generic-native-http400','foreign-native-issuer','wrong-native-error-code','outside-native-clock','trust-engine-override','foreign-native-query','foreign-nameid-policy-same-native400','invalid-signature-accepted','any-trusted-signer-accepted'}
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
 dest=folder/RUNTIME
 if dest.exists():require(dest.is_dir() and not dest.is_symlink() and not any(dest.iterdir()),'Existing archive is immutable')
 else:dest.mkdir()
 actual={};placements={}
 for name in JARS:
  files=list((REPO/'api/build/install/samlscope/lib').glob(name+'-*.jar'));require(len(files)==1,'Ambiguous production jar');host=files[0];remote='/opt/samlscope/lib/'+host.name;digest=subprocess.check_output(['docker','exec',SUITE,'sha256sum',remote],timeout=40).decode().split()[0];require(DEPLOYED_PINS[name]==digest,'Actual deployed runtime differs from reviewed v202')
  # Only completed evidence archives can be link sources; the mutable distribution cannot.
  candidates=[]
  for pattern in ('*/runtime*/'+name+'.jar','*/reader-v*/'+name+'.jar'):
   candidates.extend(folder.parent.glob(pattern));candidates.extend((REPO/'build/acceptance/reference-20261002').glob(pattern))
  original=next((p for p in sorted(candidates) if p.parent!=dest and p.is_file() and not p.is_symlink() and sha(p.read_bytes())==digest),None)
  target=dest/(name+'.jar')
  if original is not None:
   try:os.link(original,target);placements[name]=dict(mode='immutable-archive-hardlink',source=str(original.relative_to(REPO)))
   except OSError:subprocess.run(['docker','cp',SUITE+':'+remote,str(target)],check=True,capture_output=True,timeout=60);placements[name]=dict(mode='copy',source='actual-deployed-runtime')
  else:subprocess.run(['docker','cp',SUITE+':'+remote,str(target)],check=True,capture_output=True,timeout=60);placements[name]=dict(mode='copy',source='actual-deployed-runtime')
  require(sha(target.read_bytes())==digest==subprocess.check_output(['docker','exec',SUITE,'sha256sum',remote],timeout=40).decode().split()[0],'Runtime changed during archive')
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
   for local,target in [(classes,'classes'),(folder/'receipt','receipt'),(runtime,'runtime')]:subprocess.run(['docker','cp',str(local),SUITE+':'+remote+'/'+target],check=True,capture_output=True,timeout=90)
   # docker cp preserves older archive owners/modes. Only these public temporary copies are made readable.
   subprocess.run(['docker','exec','--user','0',SUITE,'chmod','-R','a+rX',remote+'/receipt',remote+'/runtime'],check=True,capture_output=True,timeout=40)
   cp=':'.join(remote+'/runtime/'+n+'.jar' for n in JARS)+':/opt/samlscope/lib/*:'+remote+'/classes'
   result=subprocess.run(['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.'+HELPER,remote+'/receipt','/data',remote+'/replay.json'],capture_output=True,text=True,timeout=120);require(result.returncode==0,'Production replay failed: '+result.stderr[-1800:]);subprocess.run(['docker','cp',SUITE+':'+remote+'/replay.json',str(tmp/'replay.json')],check=True,capture_output=True,timeout=40);return load(tmp/'replay.json')
  finally:subprocess.run(['docker','exec','--user','0',SUITE,'rm','-rf',remote],check=True,capture_output=True,timeout=60)
def install(folder):
 from keycloak_registered_signer_stored_outcome import capture
 m=load(folder/'receipt/manifest.json');run=m['runId'];ev=folder/EVALUATION;ev.mkdir(exist_ok=False)
 capture(folder,RUNTIME,EVALUATION+'/stored-before.json',run,CASE)
 (ev/'result-before.json').write_text(json.dumps(api('/api/runs/'+run+'/result.json'),indent=2)+'\n');(ev/'transcript-before.json').write_text(json.dumps(api('/api/runs/'+run+'/transcript'),indent=2)+'\n')
 dest='/data/registered-signer-evidence-shibboleth/'+run;x=subprocess.run(['docker','exec',SUITE,'test','-e',dest+'/manifest.json'],capture_output=True,timeout=40);require(x.returncode==1,'Final native proof already owned');subprocess.run(['docker','cp',str(folder/'receipt')+'/.',SUITE+':'+dest],check=True,capture_output=True,timeout=90)
 subprocess.run(['docker','exec','--user','0',SUITE,'chmod','-R','a+rX',dest],check=True,capture_output=True,timeout=40)
 with tempfile.TemporaryDirectory(prefix='kc-signer-readback-') as name:
  readback=pathlib.Path(name)/'receipt';subprocess.run(['docker','cp',SUITE+':'+dest,str(readback)],check=True,capture_output=True,timeout=90);expected=m['files']|{'manifest.json':sha((folder/'receipt/manifest.json').read_bytes())};actual={str(p.relative_to(readback)):sha(p.read_bytes()) for p in readback.rglob('*') if p.is_file()};require(expected==actual,'Receipt readback differs')
 (folder/'receipt-installation.json').write_text(json.dumps(dict(path=dest,readBackVerified=True,records=expected,productOperations=0),indent=2)+'\n')
def formal(folder):
 from keycloak_registered_signer_stored_outcome import capture
 m=load(folder/'receipt/manifest.json');run=m['runId'];ev=folder/EVALUATION;require((ev/'stored-before.json').is_file(),'Old stored outcome must be captured before receipt placement')
 (ev/'evaluate.json').write_text(json.dumps(api('/api/runs/'+run+'/protocol-evidence/evaluate',{}),indent=2)+'\n');(ev/'result.json').write_text(json.dumps(api('/api/runs/'+run+'/result.json'),indent=2)+'\n');(ev/'transcript.json').write_text(json.dumps(api('/api/runs/'+run+'/transcript'),indent=2)+'\n');capture(folder,RUNTIME,EVALUATION+'/stored-after.json',run,CASE)
def verify_adoption(root,live=False):
 folder=locate(root);receipt=folder/'receipt';m=load(receipt/'manifest.json');run=m['runId']
 require(m['schema']=='samlscope-shibboleth-registered-signer-v1' and m['adapter']==ADAPTER and m['campaignId']=='native-registered-signer','Native scope differs')
 require(run==load(folder/'created.json')['run']['id'] and m['targetMetadataSha256']==sha((folder/'target-metadata.xml').read_bytes()),'Run/target differs')
 require(m['peers'][0]['runId']==run and m['peers'][0]['label']=='primary' and m['peers'][1]['label']=='secondary','Aggregate owner differs')
 require({str(p.relative_to(receipt)) for p in receipt.rglob('*') if p.is_file()}==set(m['files'])|{'manifest.json'},'Native inventory differs')
 for name,digest in m['files'].items():
  p=receipt/name;require(p.resolve().is_relative_to(receipt) and p.is_file() and not any(x.is_symlink() for x in [p,*p.parents]) and sha(p.read_bytes())==digest,'Original modified')
 for peer in m['peers']:
  child=receipt/peer['label'];entries=load(child/'transcript.json');by={e['id']:e for e in entries};require(len(by)==len(entries) and all(e['runId']==peer['runId'] for e in entries),'Foreign/duplicate history')
  decoded={}
  for row in load(child/'decoded-manifest.json'):
   p=child/row['file'];e=by[row['id']];raw=p.read_bytes();require(p.parent==child/'decoded' and row['id'] not in decoded and e['decodedSamlRef']=='transcripts/'+peer['runId']+'/'+row['id']+'.saml.xml' and sha(raw)==row['sha256'] and len(raw)==e['decodedSamlBytes'],'Foreign/modified decoded original');decoded[row['id']]=raw
  require(set(decoded)=={e['id'] for e in entries if e['decodedSamlRef']},'Decoded inventory incomplete')
  for row in load(child/'browser-originals-manifest.json'):
   e=by[row['id']];p=child/row['file'];require(p.parent==child/'browser-originals' and e['bodyRef']==row['reference']=='transcripts/'+peer['runId']+'/'+row['id']+'.body' and e['bodyBytes']==row['bytes']==len(p.read_bytes()) and sha(p.read_bytes())==row['sha256'],'Native browser original differs')
 observed=load(folder/'native-reader-replay.json');require(replay(folder)==observed and observed['shared_native_lifecycle'] and observed['privateMaterialExported'] is False and observed['additionalProductOperations']==0 and set(observed['checks'])==CONTROLS,'Actual archived calibration differs')
 for name,value in observed['checks'].items():require((value['outcome'],value['centralVerdict'])==(('VIOLATED','WARNING') if name=='any-trusted-signer-accepted' else ('NOT_VERIFIED','NOT_VERIFIED')),'Detection power missing')
 counts=load(receipt/'operation-counts.json');changed=(receipt/'original-audit.xml').read_bytes()!=(receipt/'configured-audit.xml').read_bytes()
 require(counts['restored'] is True and counts['nativeConfigurationWrites']==(6 if changed else 4) and counts['restorationWrites']==(2 if changed else 1) and counts['initialBaselineSubmissions']==2 and counts['outboxProtocolSubmissions']==counts['actualOutboxTargetAttempts']==counts['selectedProbeAttempts']==6 and counts['protocolSubmissions']==counts['nativePostAttempts']+counts['nativeRedirectAttempts']==8 and counts['nativePostAttempts']==6 and counts['nativeRedirectAttempts']==2 and counts['credentialPosts']==counts['credentialPostAttempts']==1 and counts['personOperations']==0 and counts['productRestarts']==(2 if changed else 0) and counts['metadataReloads']==(0 if changed else 2),'Actual operation accounting differs')
 restored=load(folder/'restoration.json');require(restored['restored'] and restored['original']==restored['final'] and restored['errors']==[], 'Exact native restoration differs')
 for kind,native in [('providers','/opt/reference-idp/conf/metadata-providers.xml'),('audit','/opt/reference-idp/conf/audit.xml')]:require(restored['original'][native]==sha((receipt/('original-'+kind+'.xml')).read_bytes())==sha((receipt/('final-'+kind+'.xml')).read_bytes()),'Original/final config differs')
 require(len(restored['temporarySourcesRemoved'])==2 and {row['path'] for row in restored['temporarySourcesRemoved']}=={peer['sourcePath'] for peer in m['peers']} and all(row['absent'] is True for row in restored['temporarySourcesRemoved']),'Fresh native source removal missing')
 audit=load(folder/'collector-operation-audit.json');require(audit['targetProtocolSubmissions']==8 and audit['credentialPosts']==1 and audit['personOperations']==0 and audit['finalReceiptInstalled'] is False and audit['oldStoredOutcomeRequiredBeforeFinalInstallation'] is True,'Collector boundary differs')
 installed=load(folder/'receipt-installation.json');require(installed['readBackVerified'] and installed['records']==m['files']|{'manifest.json':sha((receipt/'manifest.json').read_bytes())},'Installed receipt original differs')
 ev=folder/EVALUATION;require(load(ev/'transcript-before.json')==load(ev/'transcript.json')==load(receipt/'primary/transcript.json'),'Formal changed original transcript')
 result=load(ev/'result.json');by={c['id']:c for req in result['requirements'] for c in req['cases']};proof=observed['production_outcome'];require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+m['targetMetadataSha256'],'Formal target differs')
 from keycloak_registered_signer_stored_outcome import compare_stored
 stored=compare_stored(folder,RUNTIME,CASE,proof,before_name=EVALUATION+'/stored-before.json',after_name=EVALUATION+'/stored-after.json');case=by[CASE]
 require((case['outcome'],case['verdict'],case['reason_code'],case['attested'],case['evidence_class'])==('SATISFIED','PASS','signature.signer.issuer-key-restriction-observed',False,'OPERATOR_ASSISTED') and case['evidence']==proof['evidence'] and stored['verdict']=='PASS' and stored['outboxCount']==3,'Full central outcome/provenance differs')
 if live:
  for kind,native in [('providers','/opt/reference-idp/conf/metadata-providers.xml'),('audit','/opt/reference-idp/conf/audit.xml')]:
   raw=subprocess.check_output(['docker','exec','samlscope-reference-shibboleth','cat',native],timeout=40);require(raw==(receipt/('original-'+kind+'.xml')).read_bytes(),'Live native restoration differs')
  for peer in m['peers']:
   path=peer['sourcePath'];require(path=='/opt/reference-idp/metadata/registered-signer-'+peer['runId']+'.xml','Foreign removal path')
   removed=subprocess.run(['docker','exec','samlscope-reference-shibboleth','test','-e',path],capture_output=True,timeout=40);require(removed.returncode==1,'Fresh native source remains')
   require(api('/api/runs/'+peer['runId']+'/transcript')==load(receipt/peer['label']/'transcript.json'),'Live history differs')
  fmt='{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}},"mounts":{{json .Mounts}}}'
  actual=json.loads(subprocess.check_output(['docker','inspect','--format',fmt,'samlscope-reference-shibboleth'],timeout=40));record=load(receipt/'native-originals/restoration.json')['runtime'];require(actual==record,'Live post-restoration runtime differs')
  require(next(c for q in api('/api/runs/'+run+'/result.json')['requirements'] for c in q['cases'] if c['id']==CASE)==case,'Live formal differs')
 return ev/'result.json',{CASE:case}

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--install',action='store_true');p.add_argument('--formal',action='store_true');p.add_argument('--live',action='store_true');args=p.parse_args();folder=locate(args.root)
 if args.capture_runtime:print(capture_runtime(folder))
 if args.record_replay:
  path=folder/'native-reader-replay.json';require(not path.exists(),'Replay immutable');path.write_text(json.dumps(replay(folder),indent=2)+'\n')
 if args.install:install(folder)
 if args.formal:formal(folder)
 if not any([args.capture_runtime,args.record_replay,args.install,args.formal]):verify_adoption(folder,args.live);print('Shibboleth registered signer adoption verified: one observation')
