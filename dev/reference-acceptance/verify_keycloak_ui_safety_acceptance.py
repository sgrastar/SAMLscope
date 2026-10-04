#!/usr/bin/env python3
"""Adopt the complete original-backed native Keycloak UI safety observation.

An isolated renderer is a diagnostic only. Installation contains the stock
receipt and fixed native JARs; no counterfactual renderer is installed.
"""
import argparse,base64,hashlib,importlib.util,json,os,pathlib,shutil,subprocess,sys,tempfile,urllib.parse,urllib.request,zipfile
REPO=pathlib.Path(__file__).resolve().parents[2]
FOLDER='keycloak-ui-safety-r1';CASE='IIP-MD05-fg-idp-01';SUITE='samlscope-reference-suite'
HELPER='VerifyKeycloakUiSafetyEvidence';RUNTIME='runtime-v204';EVALUATION='evaluation-v204';JARS=('runner','core','saml','store')
PINS={'runner': 'c94981f1baf1202d07934715ae18ee853d2f4e2d5794a5f581f5ae299a386a61', 'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'saml': '1bf3b5913095e86f432a864b87bcc9087a3441358ad8cdfcc46ae6c226cf00e0', 'store': 'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece', 'helper': '2ba6a87d991a63d01b722b8115dbc62dccae1598a2822d688a0fb19234fa9688'} # Actual v204; fixed after independent deployment hash verification.
sha=lambda raw:hashlib.sha256(raw).hexdigest()
load=lambda p:json.loads(p.read_bytes())
def require(ok,message):
 if not ok:raise ValueError(message)
def locate(root):
 p=pathlib.Path(root).absolute();require(not any(x.is_symlink() for x in [p,*p.parents]),'Unsafe evidence root');p=p.resolve();return p if p.name==FOLDER else p/FOLDER
def save(path,value):
 with path.open('x') as output:output.write(json.dumps(value,indent=2)+'\n')
def api(path,body=None):
 q=urllib.request.Request('http://localhost:18080'+path,data=None if body is None else json.dumps(body).encode(),headers={} if body is None else {'Content-Type':'application/json'})
 with urllib.request.urlopen(q,timeout=45) as response:return json.load(response)
def rows(result):return {c['id']:c for r in result['requirements'] for c in r['cases']}
def stored_helpers():
 spec=importlib.util.spec_from_file_location('_keycloak_ui_safety_stored',pathlib.Path(__file__).with_name('keycloak_registered_signer_stored_outcome.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.HELPER='ReadKeycloakUiSafetyStoredConclusions';return m
def capture_runtime(folder):
 require(os.statvfs(REPO).f_bavail*os.statvfs(REPO).f_frsize>32*1024*1024,'Insufficient archive capacity');dest=folder/RUNTIME;dest.mkdir();pins={}
 for name in JARS:
  candidates=list((REPO/'api/build/install/samlscope/lib').glob(name+'-*.jar'));require(len(candidates)==1,'Ambiguous distribution');source=candidates[0];digest=subprocess.check_output(['docker','exec',SUITE,'sha256sum','/opt/samlscope/lib/'+source.name],timeout=40).decode().split()[0];require(sha(source.read_bytes())==digest,'Distribution differs from deployed runtime');shutil.copyfile(source,dest/(name+'.jar'));pins[name]=digest
 source=pathlib.Path(__file__).with_name(HELPER+'.java');(dest/source.name).write_bytes(source.read_bytes());pins['helper']=sha(source.read_bytes());save(dest/'pins.json',pins)
 with zipfile.ZipFile(dest/'runner.jar') as jar:save(dest/'reader-class-pins.json',{n:sha(jar.read('com/samlscope/runner/cases/'+n+'.class')) for n in ['KeycloakUiSafetyEvidence','NativeUiSafetyTestCase','ApprovedBrowserCaseRegistry']})
 cp=pathlib.Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip();files=[pathlib.Path(x) for x in cp.split(':') if pathlib.Path(x).name not in [n+'-0.1.0.jar' for n in ['runner','core','saml','store','api','peer']]];require(all(p.is_file() for p in files),'Dependency classpath must contain original files');save(dest/'dependency-pins.json',[dict(path=str(p),sha256=sha(p.read_bytes())) for p in files]);save(dest/'archive-placement.json',dict(mutableDistributionLinked=False,actualDeployedHashesVerified=True));return pins
def classpath(folder):
 runtime=folder/RUNTIME;actual=load(runtime/'pins.json');require(PINS and actual==PINS,'Actual runtime is not independently pinned')
 for name in JARS:require(sha((runtime/(name+'.jar')).read_bytes())==actual[name],'Archived production JAR changed')
 require(sha((runtime/(HELPER+'.java')).read_bytes())==actual['helper'],'Archived helper changed');deps=load(runtime/'dependency-pins.json')
 for row in deps:require(sha(pathlib.Path(row['path']).read_bytes())==row['sha256'],'Archived dependency reference changed')
 with zipfile.ZipFile(runtime/'runner.jar') as jar:require(load(runtime/'reader-class-pins.json')=={n:sha(jar.read('com/samlscope/runner/cases/'+n+'.class')) for n in ['KeycloakUiSafetyEvidence','NativeUiSafetyTestCase','ApprovedBrowserCaseRegistry']},'Production class changed')
 return ':'.join(str((runtime/(n+'.jar')).resolve()) for n in JARS)+':'+':'.join(r['path'] for r in deps)
def replay(folder):
 cp=classpath(folder)
 with tempfile.TemporaryDirectory(prefix='kc-ui-safety-replay-') as name:
  tmp=pathlib.Path(name);classes=tmp/'classes';subprocess.run(['javac','-sourcepath','','-cp',cp,'-d',str(classes),str(folder/RUNTIME/(HELPER+'.java'))],check=True,capture_output=True,timeout=60);require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')),'Helper shadows production');output=tmp/'replay.json';result=subprocess.run(['java','-cp',cp+':'+str(classes),'com.samlscope.runner.cases.'+HELPER,str(folder),'/data',str(output)],capture_output=True,text=True,timeout=90);require(result.returncode==0,'Actual production replay failed: '+result.stderr[-1400:]);return load(output)
def bind_originals(folder):
 selected=[]
 for name in ['qualified-receipt.json','created.json','plan.json','target-metadata.xml','transcript.json','decoded-manifest.json','operations.json','operation-counts.json','restoration.json','case-slot-preflight.json','planned-scope-preflight.json','scope-result-before.json','privacy-qualification.json','preflight-only-reuse.json','native-http-operation-counts.json']:
  selected.append(folder/name)
 for name in ['decoded','native-originals','native-source','control','ui-safety-logo-data','ui-safety-information-javascript','ui-safety-privacy-javascript','calibration-with-native-csp','preflight-native-inventory-failed','preflight-native-mount-failed','calibration']:
  selected.extend(p for p in (folder/name).rglob('*') if p.is_file())
 save(folder/'acceptance-originals.json',dict(schema='samlscope-keycloak-ui-safety-original-bindings-v1',files={str(p.relative_to(folder)):sha(p.read_bytes()) for p in sorted(set(selected))},productOriginalsRewritten=False,counterfactualAssetsInstalled=False))
def verify_originals(folder):
 bindings=load(folder/'acceptance-originals.json');require(bindings['productOriginalsRewritten'] is False and bindings['counterfactualAssetsInstalled'] is False,'Original or diagnostic ownership differs')
 for name,digest in bindings['files'].items():
  p=folder/name;require(p.resolve().is_relative_to(folder) and not any(x.is_symlink() for x in [p,*p.parents]) and sha(p.read_bytes())==digest,'Immutable original changed')
 m=load(folder/'qualified-receipt.json');run=load(folder/'created.json')['run']['id'];target=sha((folder/'target-metadata.xml').read_bytes());require(m['schema']=='samlscope-keycloak-ui-safety-v1' and m['runId']==run and m['targetMetadataSha256']==target and m['counterfactualCalibrationOnly'] is False and 'isolatedCalibration' not in m,'Stock receipt identity or permission differs');require(load(folder/'case-slot-preflight.json')['scope_ready'] is True,'Actual formal slot was not established')
 counts=load(folder/'operation-counts.json');require(counts==dict(configurationWriteAttempts=7,successfulConfigurationWrites=6,productRestarts=0,humanOperations=0,browserAttempts=3,actualSamlSubmissions=3,metadataFixtureCount=4,credentialSubmissions=1,browserContexts=1,isolatedDetectorContexts=1,restored=True),'Qualified operation counts differ');ops=load(folder/'operations.json');require(sum(x['kind']=='native-client-create-attempt' for x in ops)==4 and sum(x['kind']=='native-client-delete' and x['status']==204 for x in ops)==3,'Failed native admission or cleanup costs missing');require(load(folder/'restoration.json')['restored'] is True,'Native restoration incomplete');http=load(folder/'native-http-operation-counts.json');require(http['adminTokenGrants']==1 and http['nativeHttpAttempts']==len(http['operations'])==34 and http['credentialsPersisted'] is False and sum(x['method']=='POST' and x['path']=='/clients' for x in http['operations'])==4 and sum(x['method']=='DELETE' and x['status']==204 for x in http['operations'])==3,'Native administrative costs or failed admission missing')
 history=load(folder/'operation-history.json');require(history['qualifiedCampaignCounts']==counts and history['qualifiedNativeAdminHttp']==dict(attempts=34,tokenGrants=1) and history['allProductSettingAttempts']==7 and history['allProductSettingSuccesses']==6 and history['allSamlSubmissions']==3 and history['allCredentialSubmissions']==1 and history['productRestarts']==history['humanOperations']==0 and history['prototypeCspOmittedAdopted'] is False and history['qualifiedNativeCspPreserved'] is True,'Cumulative operation history differs')
 for trial in history['failedPreflightTrials']:
  require(trial['productConfigurationWrites']==trial['samlRequests']==trial['credentialPosts']==0 and trial['priorNativeReadAttemptsExact']=='not-recorded','Failed preflight costs misrepresented')
  for name,digest in trial['originals'].items():require(sha((folder/name).read_bytes())==digest,'Failed preflight original changed')
 require([x['variant'] for x in m['members']]==['control','ui-safety-logo-data','ui-safety-information-javascript','ui-safety-privacy-javascript'],'Approved native matrix incomplete');entries=load(folder/'transcript.json');require(len(entries)==36 and len({x['id'] for x in entries})==len(entries) and all(x['runId']==run for x in entries),'Foreign or ambiguous history');by={x['id']:x for x in entries}
 for row in load(folder/'decoded-manifest.json'):
  p=folder/row['file'];e=by[row['id']];raw=p.read_bytes();require(p.parent==folder/'decoded' and e['decodedSamlRef']=='transcripts/'+run+'/'+e['id']+'.saml.xml' and len(raw)==e['decodedSamlBytes'] and sha(raw)==row['sha256'],'Original raw evidence scope differs')
 privacy=load(folder/'privacy-qualification.json');require(privacy['valuesDisclosed'] is False and privacy['publicProjectionIsTransformation'] is True and all(not any(x['findings'].values()) for x in privacy['checks']),'Public credential redaction failed');return m,run,target,entries
def install(folder):
 m,run,target,entries=verify_originals(folder);ev=folder/EVALUATION;ev.mkdir();stored_helpers().capture(folder,RUNTIME,EVALUATION+'/stored-before.json',run,CASE);save(ev/'result-before.json',api('/api/runs/'+run+'/result.json'));save(ev/'transcript-before.json',api('/api/runs/'+run+'/transcript'));require(load(ev/'transcript-before.json')==entries,'History changed before receipt placement')
 base='/data/ui-native-feature-absence/'+run+'.keycloak-ui-safety';files={'qualified-receipt.json':base+'.json','native-source/before-services.jar':base+'/native-services.jar','native-source/before-themes.jar':base+'/native-themes.jar'};test=subprocess.run(['docker','exec',SUITE,'test','-e',base+'.json'],capture_output=True,timeout=30);require(test.returncode==1,'Unexpected existing receipt ownership');subprocess.run(['docker','exec',SUITE,'mkdir','-p',base],check=True,capture_output=True,timeout=30);records=[]
 for source,dest in files.items():
  subprocess.run(['docker','cp',str(folder/source),SUITE+':'+dest],check=True,capture_output=True,timeout=45);digest=subprocess.check_output(['docker','exec',SUITE,'sha256sum',dest],timeout=30).decode().split()[0];require(digest==sha((folder/source).read_bytes()),'Receipt readback differs');records.append(dict(file=source,path=dest,sha256=digest))
 save(folder/'receipt-installation.json',dict(runId=run,files=records,readBackVerified=True,counterfactualAssetsInstalled=False,productConfigurationWrites=0,samlRequests=0,credentialPosts=0))
def formal_preflight(folder,run):
 ev=folder/EVALUATION;status=api('/api/runs/'+run+'/protocol-evidence');save(ev/'protocol-evidence-preflight.json',status);require(isinstance(status.get('cases'),list),'Suite path gap: no valid readiness status; POST skipped');selected=[x for x in status['cases'] if x.get('caseId')==CASE];require(len(selected)<=1,'Suite path gap: ambiguous readiness; POST skipped')
 if selected:require(selected[0].get('ready') is True,'Suite path gap: native UI evidence not ready; POST skipped');return
 result=api('/api/runs/'+run+'/result.json');save(ev/'protocol-evidence-preflight-existing-result.json',result);require(result['run']['id']==run and rows(result).get(CASE,{}).get('outcome') in ['SATISFIED','SATISFIED_WITH_NOTE','VIOLATED'],'Suite path gap: no ready or conclusive native UI case; POST skipped')
def formal(folder):
 ev=folder/EVALUATION;run=load(folder/'created.json')['run']['id'];require((ev/'stored-before.json').is_file() and not (ev/'evaluate.json').exists(),'Formal evaluation history or before ordering differs');formal_preflight(folder,run);save(ev/'evaluate.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}));save(ev/'result.json',api('/api/runs/'+run+'/result.json'));save(ev/'transcript.json',api('/api/runs/'+run+'/transcript'));stored_helpers().capture(folder,RUNTIME,EVALUATION+'/stored-after.json',run,CASE)
def verify_adoption(root,live=False):
 folder=locate(root);m,run,target,entries=verify_originals(folder);report=load(folder/'native-reader-replay.json');require(replay(folder)==report,'Archived actual production replay differs');checks=report['checks'];require(checks['stock-native-image-sink-and-unused-urls']=='SATISFIED_WITH_NOTE' and checks['offline-approved-unsanitized-information-consumer']=='VIOLATED' and len(checks)==41 and all(v=='NOT_VERIFIED' for k,v in checks.items() if k not in ['stock-native-image-sink-and-unused-urls','offline-approved-unsanitized-information-consumer']),'Detection controls incomplete');require(report['privateKeyExported'] is False and report['productConfigurationWrites']==report['samlRequests']==0,'Replay changed target state')
 proof=report['cases'][CASE];require(proof['outcome']=='SATISFIED_WITH_NOTE' and proof['details']['counterfactual_calibration_only'] is False,'Diagnostic finding adopted');ev=folder/EVALUATION;result=load(ev/'result.json');case=rows(result)[CASE];require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+target and load(ev/'transcript-before.json')==load(ev/'transcript.json')==entries,'Formal scope/history differs');stored=stored_helpers().compare_stored(folder,RUNTIME,CASE,proof,before_name=EVALUATION+'/stored-before.json',after_name=EVALUATION+'/stored-after.json');require((case['outcome'],case['verdict'],case['reason_code'],case['attested'],case['evidence_class'])==('SATISFIED_WITH_NOTE','WARNING',proof['reasonCode'],False,'PROTOCOL_OBSERVED') and case['evidence']==proof['evidence'] and stored['verdict']=='WARNING','Formal outcome, provenance or central verdict differs')
 installation=load(folder/'receipt-installation.json');require(installation['runId']==run and installation['readBackVerified'] and installation['counterfactualAssetsInstalled'] is False and len(installation['files'])==3,'Stock installation inventory differs')
 for x in installation['files']:require(sha((folder/x['file']).read_bytes())==x['sha256'] and 'isolated' not in x['path'],'Installed source changed')
 if live:
  sys.path.insert(0,str(REPO/'dev/keycloak'));from metadata_supersession_campaign import read
  require(read('/clients?clientId='+urllib.parse.quote(m['peerEntityId'],safe=''))==[],'Live peer not restored');require(api('/api/runs/'+run+'/transcript')==entries and rows(api('/api/runs/'+run+'/result.json'))[CASE]==case,'Live result/history differs')
  for x in installation['files']:require(subprocess.check_output(['docker','exec',SUITE,'sha256sum',x['path']],timeout=30).decode().split()[0]==x['sha256'],'Installed proof changed')
 return ev/'result.json',{CASE:case}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--capture-runtime',action='store_true');p.add_argument('--bind-originals',action='store_true');p.add_argument('--record-replay',action='store_true');p.add_argument('--install',action='store_true');p.add_argument('--formal',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=locate(a.root)
 if a.capture_runtime:print(capture_runtime(folder))
 if a.bind_originals:bind_originals(folder)
 if a.record_replay:save(folder/'native-reader-replay.json',replay(folder))
 if a.install:install(folder)
 if a.formal:formal(folder)
 if not any([a.capture_runtime,a.bind_originals,a.record_replay,a.install,a.formal]):verify_adoption(folder,a.live);print('Native Keycloak UI safety adopted: one observation')
