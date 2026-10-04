#!/usr/bin/env python3
"""Adopt two identity obligations from one restored, two-peer native registration campaign."""
import argparse,base64,hashlib,json,pathlib,subprocess,sys,tempfile,urllib.parse,urllib.request,zipfile
REPO=pathlib.Path(__file__).resolve().parents[2];FOLDER='keycloak-metadata-entity-identity-r1';SUITE='samlscope-reference-suite';HELPER='VerifyKeycloakMetadataEntityIdentityEvidence';JARS=('runner','core','saml','store');CLASSES=('KeycloakMetadataEntityIdentityEvidence','MetadataEntityIdentityConfigurationTestCase','KeycloakSubjectConfirmationEvidence','MetadataAlgorithmEvidence');CASES=('IIP-MD05-a1-idp-01','IIP-MD05-a2-idp-01');ADAPTER='keycloak-native-simultaneous-entity-registration-v1';CONTROLS={'wrong-run','wrong-adapter','wrong-target','wrong-campaign','unknown-secondary','foreign-native-lookup','duplicate-history','foreign-history','foreign-decoded-ref','wrong-native-method','wrong-native-conflict-message','explicit-replacement-not-simultaneous','converter-output-not-posted','missing-normal','wrong-secondary-key','fixture-not-original','native-redaction-removes-keys','readback-before-normal-incomplete','native-policy-change','restore-client-remains','cost-omits-credential','duplicate-identity-overwrite'}
sha=lambda b:hashlib.sha256(b).hexdigest();load=lambda p:json.loads(p.read_bytes())
def require(b,m):
 if not b:raise ValueError(m)
def api(path,body=None):
 q=urllib.request.Request('http://localhost:18080'+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(q,timeout=45) as r:return json.load(r)
def locate(root):
 r=pathlib.Path(root).resolve();return r if r.name==FOLDER else r/FOLDER
def capture_runtime(folder):
 out=folder/'runtime-v194-exact';out.mkdir(exist_ok=False);pins={'jars':{},'classes':{}}
 for n in JARS:
  dest=out/(n+'.jar');subprocess.run(['docker','cp',SUITE+':/opt/samlscope/lib/'+n+'-0.1.0.jar',str(dest)],check=True,capture_output=True,timeout=90);pins['jars'][n]=sha(dest.read_bytes())
 raw=(REPO/'dev/reference-acceptance'/(HELPER+'.java')).read_bytes();(out/(HELPER+'.java')).write_bytes(raw);pins['helperSha256']=sha(raw)
 with zipfile.ZipFile(out/'runner.jar') as z:pins['classes']={n:sha(z.read('com/samlscope/runner/cases/'+n+'.class')) for n in CLASSES}
 (out/'pins.json').write_text(json.dumps(pins,indent=2)+'\n')
def replay(folder):
 runtime=folder/'runtime-v194-exact';pins=load(runtime/'pins.json');require(set(pins['jars'])==set(JARS),'Runtime inventory mismatch')
 for n in JARS:require(sha((runtime/(n+'.jar')).read_bytes())==pins['jars'][n],'Archived runtime changed')
 require(sha((runtime/(HELPER+'.java')).read_bytes())==pins['helperSha256'],'Archived helper changed')
 with zipfile.ZipFile(runtime/'runner.jar') as z:require(pins['classes']=={n:sha(z.read('com/samlscope/runner/cases/'+n+'.class')) for n in CLASSES},'Actual reader changed')
 dependencies=pathlib.Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip();cp=':'.join(str((runtime/(n+'.jar')).resolve()) for n in JARS)+':'+dependencies
 with tempfile.TemporaryDirectory(prefix='kc-entity-replay-') as name:
  tmp=pathlib.Path(name);classes=tmp/'classes';subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(runtime/(HELPER+'.java'))],check=True,capture_output=True,timeout=60)
  require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')),'Helper shadows production');remote='/tmp/'+tmp.name
  subprocess.run(['docker','exec',SUITE,'mkdir','-p',remote],check=True,capture_output=True,timeout=40)
  try:
   for local,target in [(classes,'classes'),(folder/'receipt','receipt'),(runtime,'runtime')]:subprocess.run(['docker','cp',str(local),SUITE+':'+remote+'/'+target],check=True,capture_output=True,timeout=90)
   pinned=':'.join(remote+'/runtime/'+n+'.jar' for n in JARS)+':/opt/samlscope/lib/*:'+remote+'/classes'
   x=subprocess.run(['docker','exec',SUITE,'java','-cp',pinned,'com.samlscope.runner.cases.'+HELPER,remote+'/receipt','/data',remote+'/replay.json'],capture_output=True,text=True,timeout=90)
   require(x.returncode==0,'Actual archived Reader failed '+x.stderr[-1600:]);subprocess.run(['docker','cp',SUITE+':'+remote+'/replay.json',str(tmp/'replay.json')],check=True,capture_output=True,timeout=40);return load(tmp/'replay.json')
  finally:subprocess.run(['docker','exec','--user','0',SUITE,'rm','-rf',remote],check=True,capture_output=True,timeout=60)
def install(folder):
 m=load(folder/'receipt/manifest.json');run=m['runId'];dest='/data/keycloak-metadata-entity-identity-evidence/'+run
 from keycloak_entity_identity_stored_outcome import capture
 ev=folder/'evaluation-v194';ev.mkdir(exist_ok=False)
 for case in CASES:capture(folder,'runtime-v194-exact','evaluation-v194/stored-before-'+case+'.json',run,case)
 (ev/'result-before.json').write_text(json.dumps(api('/api/runs/'+run+'/result.json'),indent=2)+'\n');(ev/'transcript-before.json').write_text(json.dumps(api('/api/runs/'+run+'/transcript'),indent=2)+'\n')
 x=subprocess.run(['docker','exec',SUITE,'test','-e',dest],capture_output=True,timeout=40);require(x.returncode==1,'Native directory already owned')
 subprocess.run(['docker','exec',SUITE,'mkdir','-p','/data/keycloak-metadata-entity-identity-evidence'],check=True,capture_output=True,timeout=40);subprocess.run(['docker','cp',str(folder/'receipt'),SUITE+':'+dest],check=True,capture_output=True,timeout=90)
 with tempfile.TemporaryDirectory(prefix='kc-entity-readback-') as name:
  readback=pathlib.Path(name)/'receipt';subprocess.run(['docker','cp',SUITE+':'+dest,str(readback)],check=True,capture_output=True,timeout=90)
  expected=m['files']|{'manifest.json':sha((folder/'receipt/manifest.json').read_bytes())};actual={str(p.relative_to(readback)):sha(p.read_bytes()) for p in readback.rglob('*') if p.is_file()};require(expected==actual,'Installed original readback mismatch')
 (folder/'receipt-installation-v194.json').write_text(json.dumps(dict(path=dest,readBackVerified=True,records=expected,productOperations=0),indent=2)+'\n')
def formal(folder):
 from keycloak_entity_identity_stored_outcome import capture
 run=load(folder/'created.json')['run']['id'];ev=folder/'evaluation-v194';require(ev.is_dir() and all((ev/('stored-before-'+case+'.json')).is_file() for case in CASES),'Before originals must precede receipt installation')
 (ev/'evaluate.json').write_text(json.dumps(api('/api/runs/'+run+'/protocol-evidence/evaluate',{}),indent=2)+'\n');(ev/'result.json').write_text(json.dumps(api('/api/runs/'+run+'/result.json'),indent=2)+'\n');(ev/'transcript.json').write_text(json.dumps(api('/api/runs/'+run+'/transcript'),indent=2)+'\n')
 for case in CASES:capture(folder,'runtime-v194-exact','evaluation-v194/stored-after-'+case+'.json',run,case)
def verify_adoption(root,live=False,formal_result=True):
 folder=locate(root);r=folder/'receipt';m=load(r/'manifest.json');run=load(folder/'created.json')['run']['id'];require(m['runId']==run and m['adapter']==ADAPTER and m['targetMetadataSha256']==sha((folder/'target-metadata.xml').read_bytes()),'Manifest identity differs')
 for name,digest in m['files'].items():
  p=r/name;require(p.resolve().is_relative_to(r) and not any(x.is_symlink() for x in [p,*p.parents]) and p.is_file() and sha(p.read_bytes())==digest,'Original changed')
 for peer in m['peers']:
  child=r/peer['label'];entries=load(child/'transcript.json');by={e['id']:e for e in entries};require(len(by)==len(entries) and all(e['runId']==peer['runId'] for e in entries),'Foreign/duplicate original Run')
  decoded={}
  for row in load(child/'decoded-manifest.json'):
   path=child/row['file'];require(path.parent==child/'decoded' and row['id'] in by and row['id'] not in decoded and by[row['id']]['decodedSamlRef']=='transcripts/'+peer['runId']+'/'+row['id']+'.saml.xml','Decoded foreign original');b=path.read_bytes();require(sha(b)==row['sha256'] and len(b)==by[row['id']]['decodedSamlBytes'],'Decoded bytes changed');decoded[row['id']]=b
  require(set(decoded)=={e['id'] for e in entries if e['decodedSamlRef']},'Original inventory incomplete')
 observed=load(folder/'native-reader-replay-v194-exact.json');require(replay(folder)==observed,'Archived actual replay differs');require(observed['shared_native_lifecycle'] and observed['privateMaterialExported'] is False and observed['additionalProductOperations']==0 and set(observed['checks'])==CONTROLS,'Replay scope differs')
 for name,cases in observed['checks'].items():
  require(set(cases)==set(CASES),'Calibration cases differ');require(all(c['outcome']==('VIOLATED' if name=='duplicate-identity-overwrite' else 'NOT_VERIFIED') for c in cases.values()),'Calibration detection power missing')
 counts=load(folder/'operation-counts.json');ops=load(folder/'operations.json');require(len(ops)==counts['nativeHttpAttempts']==33 and [(o['method'],o['status']) for o in ops if o['productSettingWrite']]==[('POST',201),('POST',201),('POST',409),('DELETE',204),('DELETE',204)],'Native operation accounting differs')
 require(counts['nativeConfigurationWriteAttempts']==5 and counts['nativeConfigurationWrites']==4 and counts['restorationWrites']==2 and counts['nativeConverterAttempts']==3 and counts['credentialPosts']==1 and counts['protocolSubmissions']==2 and counts['normalFlowsAttempted']==2 and counts['personOperations']==counts['productRestarts']==0 and counts['restored'] is True,'User/configuration costs differ')
 q=load(folder/'read-only-completion/qualification.json');require(q['originalCollectorExitCode']==1 and q['nativeCredentialValuesPersisted'] is False and q['productConfigurationWrites']==q['protocolSubmissions']==q['credentialPosts']==q['personOperations']==0 and q['originalOperationCountsSha256']==sha((folder/'operation-counts.json').read_bytes()),'Failed attempt/read-only recovery hidden')
 if live:
  sys.path.insert(0,str(REPO/'dev/keycloak'));from attribute_policy_capability_absence import product_token
  from mdiop_representation_campaign import runtime
  token=product_token()
  def admin(path):
   req=urllib.request.Request('http://localhost:18180/admin/realms/samlscope'+path,headers={'Authorization':'Bearer '+token})
   with urllib.request.urlopen(req,timeout=40) as response:return json.load(response)
  for peer in m['peers']:require(admin(peer['lookup'])==[],'Live owned native client remains');require(api('/api/runs/'+peer['runId']+'/transcript')==load(r/peer['label']/'transcript.json'),'Live shared original history changed')
  restore=load(r/'native-originals/restoration.json');require(runtime()==restore['runtimeAfter'] and {kind:admin('/client-policies/'+kind) for kind in ['policies','profiles']}==restore['policiesAfter'],'Live runtime/policy scope changed')
 if not formal_result:return observed
 from keycloak_entity_identity_stored_outcome import compare_stored
 install=load(folder/'receipt-installation-v194.json');require(install['path']=='/data/keycloak-metadata-entity-identity-evidence/'+run and install['readBackVerified'] and install['records']==m['files']|{'manifest.json':sha((r/'manifest.json').read_bytes())},'Receipt installation differs')
 ev=folder/'evaluation-v194';require(load(ev/'transcript-before.json')==load(ev/'transcript.json')==load(r/'primary/transcript.json'),'Formal changed wire originals');result=load(ev/'result.json');by={c['id']:c for req in result['requirements'] for c in req['cases']};require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+m['targetMetadataSha256'],'Formal target differs')
 for case in CASES:
  proof=observed['production_outcomes'][case];require(proof['outcome']=='SATISFIED' and proof['details']['evidence_adapter']==ADAPTER and proof['details']['native_run_id']==run,'Native positive scope differs');stored=compare_stored(folder,'runtime-v194-exact',case,proof,before_name='evaluation-v194/stored-before-'+case+'.json',after_name='evaluation-v194/stored-after-'+case+'.json');c=by[case]
  require((c['outcome'],c['verdict'],c['reason_code'],c['attested'],c['evidence_class'])==('SATISFIED','PASS',proof['reasonCode'],False,'OPERATOR_ASSISTED') and c['evidence']==proof['evidence'] and stored['verdict']=='PASS','Central verdict/provenance differs')
 if live:
  latest={c['id']:c for req in api('/api/runs/'+run+'/result.json')['requirements'] for c in req['cases']};require(all(latest[case]==by[case] for case in CASES),'Live central result differs')
 return ev/'result.json',{case:by[case] for case in CASES}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--install',action='store_true');p.add_argument('--formal',action='store_true');p.add_argument('--diagnostic-only',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=locate(a.root)
 if a.capture_runtime:capture_runtime(folder)
 if a.record_replay:
  dest=folder/'native-reader-replay-v194-exact.json';require(not dest.exists(),'Replay immutable');dest.write_text(json.dumps(replay(folder),indent=2)+'\n')
 if a.install:install(folder)
 if a.formal:formal(folder)
 if not any([a.capture_runtime,a.record_replay,a.install,a.formal]):verify_adoption(folder,a.live,not a.diagnostic_only);print('Keycloak metadata identity adoption verified: two observations')
