#!/usr/bin/env python3
"""Adopt one original-backed signer restriction observation; calibration never substitutes product data."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,tempfile,urllib.request,sys
REPO=pathlib.Path(__file__).resolve().parents[2];FOLDER='keycloak-registered-signer-r1';SUITE='samlscope-reference-suite';HELPER='VerifyKeycloakRegisteredSignerEvidence';JARS=('runner','core','saml','store');CASE='IIP-SSO01-al-idp-01';ADAPTER='keycloak-native-issuer-key-locator-v1';RUNTIME='runtime-actual';EVALUATION='evaluation-actual'
PINS={'runner':'85f0335c57bef0b8061644ba9c78bab37392ee56e3d677bcdf289db1d3542d5e','core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe','saml':'43b2cc47bd142956e7f35bd1d906950f64d3f952374db72a2df84f5e3617bec7','store':'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece','helper':'5605d6335a439d839283b10f7521150d3515247712245f564f93c92437a7270f'}
CONTROLS={'wrong-run','wrong-adapter','wrong-target','wrong-campaign','foreign-plan','foreign-lookup','missing-normal','foreign-history','duplicate-history','foreign-decoded-ref','foreign-primary-key','unrelated-native-http','native-request-hash-mismatch','native-body-hash-mismatch','native-signature-setting-disabled','native-metadata-url-active','converter-not-posted','native-readback-key-changed','native-runtime-epoch-changed','missing-native-client','restoration-client-remains','cost-omits-credential','foreign-nameid-policy-same-native-400','invalid-signature-accepted','any-trusted-signer-accepted'}
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
 dest=folder/RUNTIME;dest.mkdir(exist_ok=False);actual={}
 for name in JARS:
  files=list((REPO/'api/build/install/samlscope/lib').glob(name+'-*.jar'));require(len(files)==1,'Ambiguous production jar');host=files[0];remote='/opt/samlscope/lib/'+host.name;digest=subprocess.check_output(['docker','exec',SUITE,'sha256sum',remote],timeout=40).decode().split()[0];require(sha(host.read_bytes())==digest,'Host differs from actual deployed runtime');shutil.copyfile(host,dest/(name+'.jar'));actual[name]=digest
 source=pathlib.Path(__file__).with_name(HELPER+'.java');(dest/source.name).write_bytes(source.read_bytes());actual['helper']=sha(source.read_bytes());(dest/'pins.json').write_text(json.dumps(actual,indent=2)+'\n');return actual
def replay(folder):
 runtime=folder/RUNTIME;pins=load(runtime/'pins.json');require(PINS and pins==PINS,'Runtime not independently pinned')
 for name in JARS:require(sha((runtime/(name+'.jar')).read_bytes())==pins[name],'Archived runtime modified')
 require(sha((runtime/(HELPER+'.java')).read_bytes())==pins['helper'],'Helper modified');cp=':'.join(str((runtime/(n+'.jar')).resolve()) for n in JARS)+':'+pathlib.Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip()
 with tempfile.TemporaryDirectory(prefix='kc-registered-signer-replay-') as name:
  tmp=pathlib.Path(name);classes=tmp/'classes';subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(runtime/(HELPER+'.java'))],check=True,capture_output=True,timeout=60);require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')),'Helper shadows production')
  remote='/tmp/'+tmp.name;subprocess.run(['docker','exec',SUITE,'mkdir','-p',remote],check=True,capture_output=True,timeout=40)
  try:
   for local,target in [(classes,'classes'),(folder/'receipt','receipt'),(runtime,'runtime')]:subprocess.run(['docker','cp',str(local),SUITE+':'+remote+'/'+target],check=True,capture_output=True,timeout=90)
   cp=':'.join(remote+'/runtime/'+n+'.jar' for n in JARS)+':/opt/samlscope/lib/*:'+remote+'/classes'
   result=subprocess.run(['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.'+HELPER,remote+'/receipt','/data',remote+'/replay.json'],capture_output=True,text=True,timeout=120);require(result.returncode==0,'Production replay failed: '+result.stderr[-1800:]);subprocess.run(['docker','cp',SUITE+':'+remote+'/replay.json',str(tmp/'replay.json')],check=True,capture_output=True,timeout=40);return load(tmp/'replay.json')
  finally:subprocess.run(['docker','exec','--user','0',SUITE,'rm','-rf',remote],check=True,capture_output=True,timeout=60)
def install(folder):
 from keycloak_registered_signer_stored_outcome import capture
 m=load(folder/'receipt/manifest.json');run=m['runId'];ev=folder/EVALUATION;ev.mkdir(exist_ok=False)
 capture(folder,RUNTIME,EVALUATION+'/stored-before.json',run,CASE)
 (ev/'result-before.json').write_text(json.dumps(api('/api/runs/'+run+'/result.json'),indent=2)+'\n');(ev/'transcript-before.json').write_text(json.dumps(api('/api/runs/'+run+'/transcript'),indent=2)+'\n')
 dest='/data/keycloak-registered-signer-evidence/'+run;x=subprocess.run(['docker','exec',SUITE,'test','-e',dest+'/manifest.json'],capture_output=True,timeout=40);require(x.returncode==1,'Final native proof already owned');subprocess.run(['docker','cp',str(folder/'receipt')+'/.',SUITE+':'+dest],check=True,capture_output=True,timeout=90)
 with tempfile.TemporaryDirectory(prefix='kc-signer-readback-') as name:
  readback=pathlib.Path(name)/'receipt';subprocess.run(['docker','cp',SUITE+':'+dest,str(readback)],check=True,capture_output=True,timeout=90);expected=m['files']|{'manifest.json':sha((folder/'receipt/manifest.json').read_bytes())};actual={str(p.relative_to(readback)):sha(p.read_bytes()) for p in readback.rglob('*') if p.is_file()};require(expected==actual,'Receipt readback differs')
 (folder/'receipt-installation.json').write_text(json.dumps(dict(path=dest,readBackVerified=True,records=expected,productOperations=0),indent=2)+'\n')
def formal(folder):
 from keycloak_registered_signer_stored_outcome import capture
 m=load(folder/'receipt/manifest.json');run=m['runId'];ev=folder/EVALUATION;require((ev/'stored-before.json').is_file(),'Old stored outcome must be captured before receipt placement')
 (ev/'evaluate.json').write_text(json.dumps(api('/api/runs/'+run+'/protocol-evidence/evaluate',{}),indent=2)+'\n');(ev/'result.json').write_text(json.dumps(api('/api/runs/'+run+'/result.json'),indent=2)+'\n');(ev/'transcript.json').write_text(json.dumps(api('/api/runs/'+run+'/transcript'),indent=2)+'\n');capture(folder,RUNTIME,EVALUATION+'/stored-after.json',run,CASE)
def verify_adoption(root,live=False):
 folder=locate(root);r=folder/'receipt';m=load(r/'manifest.json');require(m['adapter']==ADAPTER and m['schema']=='samlscope-keycloak-registered-signer-v1' and m['campaignId']=='native-registered-signer','Native scope differs');run=m['runId'];require(run==load(folder/'created.json')['run']['id'] and m['targetMetadataSha256']==sha((folder/'target-metadata.xml').read_bytes()),'Native target/Run differs')
 for name,digest in m['files'].items():
  p=r/name;require(p.resolve().is_relative_to(r) and p.is_file() and not any(x.is_symlink() for x in [p,*p.parents]) and sha(p.read_bytes())==digest,'Original modified')
 for peer in m['peers']:
  child=r/peer['label'];entries=load(child/'transcript.json');by={e['id']:e for e in entries};require(len(by)==len(entries) and all(e['runId']==peer['runId'] for e in entries),'Foreign/duplicate history');decoded={}
  for row in load(child/'decoded-manifest.json'):
   p=child/row['file'];e=by[row['id']];require(p.parent==child/'decoded' and row['id'] not in decoded and e['decodedSamlRef']=='transcripts/'+peer['runId']+'/'+row['id']+'.saml.xml','Foreign decoded original');raw=p.read_bytes();require(sha(raw)==row['sha256'] and len(raw)==e['decodedSamlBytes'],'Decoded original modified');decoded[row['id']]=raw
  require(set(decoded)=={e['id'] for e in entries if e['decodedSamlRef']},'Original inventory incomplete')
  for row in load(child/'browser-originals-manifest.json'):
   e=by[row['id']];p=child/row['file'];require(p.parent==child/'browser-originals' and e['bodyRef']=='transcripts/'+peer['runId']+'/'+row['id']+'.body' and e['bodyBytes']==row['bytes']==len(p.read_bytes()) and sha(p.read_bytes())==row['sha256'],'Native browser original modified')
 observed=load(folder/'native-reader-replay.json');require(replay(folder)==observed and observed['shared_native_lifecycle'] and observed['privateMaterialExported'] is False and observed['additionalProductOperations']==0 and set(observed['checks'])==CONTROLS,'Actual archived replay/calibration differs')
 for name,value in observed['checks'].items():require((value['outcome'],value['centralVerdict'])==(('VIOLATED','WARNING') if name=='any-trusted-signer-accepted' else ('NOT_VERIFIED','NOT_VERIFIED')),'Calibration detection power missing')
 costs=load(folder/'operation-counts.json');ops=load(folder/'operations.json');writes=[o for o in ops if o['productSettingWrite']];conversions=[o for o in ops if o['url'].endswith('/client-description-converter')];require(len(ops)==costs['nativeHttpAttempts'] and costs['nativeConfigurationWriteAttempts']==len(writes) and [(o['method'],o['status']) for o in writes if 200<=o['status']<300]==[('POST',201),('POST',201),('DELETE',204),('DELETE',204)] and all(o['status']==401 or 200<=o['status']<300 for o in writes),'Native writes/restoration accounting differs');require(costs['nativeConverterAttempts']==len(conversions) and sum(o['status']==200 for o in conversions)==2 and all(o['status'] in {200,401} for o in conversions) and costs['nativeConfigurationWrites']==4 and costs['restorationWrites']==2 and costs['protocolSubmissions']==8 and costs['baselineProtocolSubmissions']==2 and costs['selectedOutboxProtocolSubmissions']==6 and costs['normalFlowsAttempted']==2 and costs['credentialPosts']==1 and costs['sharedAuthenticatedClients']==1 and costs['freshSessionBoundaries']==1 and costs['personOperations']==costs['productRestarts']==0 and costs['restored'] is True,'User/campaign costs differ')
 restored=load(folder/'restoration.json');require(restored['restored'] and restored['before_runtime']==restored['after_runtime'] and restored['before_policy']==restored['after_policy'],'Restoration scope differs')
 if live:
  sys.path.insert(0,str(REPO/'dev/keycloak'));from attribute_policy_capability_absence import product_token
  from mdiop_representation_campaign import runtime
  token=product_token()
  def admin(path):
   req=urllib.request.Request('http://localhost:18180/admin/realms/samlscope'+path,headers={'Authorization':'Bearer '+token})
   with urllib.request.urlopen(req,timeout=40) as response:return json.load(response)
  for peer in m['peers']:require(admin(peer['lookup'])==[] and api('/api/runs/'+peer['runId']+'/transcript')==load(r/peer['label']/'transcript.json'),'Live restoration/history differs')
  from keycloak_registered_signer_runtime_recovery import runtime_recovery_proof
  recovery=runtime_recovery_proof(folder,restored['after_runtime'],runtime())
  require({k:admin('/client-policies/'+k) for k in ['policies','profiles']}==restored['after_policy'],'Live native policy scope differs')
  if recovery is not None:
   audit=folder/'post-recovery-native-runtime-verification.json'
   if audit.exists():require(load(audit)==recovery,'Post-recovery native original changed')
   else:audit.write_text(json.dumps(recovery,indent=2)+'\n')
 install=load(folder/'receipt-installation.json');require(install['readBackVerified'] and install['records']==m['files']|{'manifest.json':sha((r/'manifest.json').read_bytes())},'Installed original readback differs');ev=folder/EVALUATION;require(load(ev/'transcript-before.json')==load(ev/'transcript.json')==load(r/'primary/transcript.json'),'Formal changed wire history');result=load(ev/'result.json');by={c['id']:c for req in result['requirements'] for c in req['cases']};proof=observed['production_outcome'];require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+m['targetMetadataSha256'],'Formal target differs');from keycloak_registered_signer_stored_outcome import compare_stored
 stored=compare_stored(folder,RUNTIME,CASE,proof,before_name=EVALUATION+'/stored-before.json',after_name=EVALUATION+'/stored-after.json');case=by[CASE];require((case['outcome'],case['verdict'],case['reason_code'],case['attested'],case['evidence_class'])==('SATISFIED','PASS','signature.signer.issuer-key-restriction-observed',False,'OPERATOR_ASSISTED') and case['evidence']==proof['evidence'] and stored['verdict']=='PASS' and stored['outboxCount']==3,'Full central result/provenance differs')
 if live:require(next(c for q in api('/api/runs/'+run+'/result.json')['requirements'] for c in q['cases'] if c['id']==CASE)==case,'Live formal differs')
 return ev/'result.json',{CASE:case}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('root',type=pathlib.Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--install',action='store_true');p.add_argument('--formal',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=locate(a.root)
 if a.capture_runtime:print(capture_runtime(folder))
 if a.record_replay:
  out=folder/'native-reader-replay.json';require(not out.exists(),'Replay immutable');out.write_text(json.dumps(replay(folder),indent=2)+'\n')
 if a.install:install(folder)
 if a.formal:formal(folder)
 if not any([a.capture_runtime,a.record_replay,a.install,a.formal]):verify_adoption(folder,a.live);print('Keycloak registered signer adoption verified: one observation')
