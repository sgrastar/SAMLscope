#!/usr/bin/env python3
"""Archived actual Reader + raw native ALG08 originals; no live product operations by default."""
import argparse,hashlib,importlib.util,json,pathlib,re,secrets,subprocess,tempfile,os,shutil,zipfile
REPO=pathlib.Path(__file__).resolve().parents[2];SUITE='samlscope-reference-suite';NATIVE='samlscope-reference-shibboleth';CASE='IIP-ALG08-c-idp-01';ARCHIVE='reader-v217';FOLDER='shibboleth-default-algorithm-r7'
JARS={'runner':'29405b429e4e6443be170c9de14584916481613496dccd9e09346fcf0b744310','core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe','saml':'d8ea9ebf6048f82ba9773850d8302cca00b19751fa0aac4eca675506c8c737ca','store':'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'}
DEPENDENCY_SOURCE_SHA256='ea05e271134512911900c380f813f92453284cc78a97cecb90ae9ea07f3c6d90'
HELPERS={'replay-helper.java':('VerifyShibbolethDefaultAlgorithms','5b41393bf8c5ed57295f24acb0ad601778639f84e909bc5221755fc929fb4406'),'stored-helper.java':('ReadDefaultAlgorithmStoredConclusion','4bacf7156446497c9ec19f46f3a8be5894c17e888486231dbb4fb372b9b125aa'),'outbox-helper.java':('ReadDefaultAlgorithmOutbox','f3a4009d4df17e11c7662389786e2203f2b2de1df8ba1094c97e3932e8393f4e')}
SHA=lambda b:hashlib.sha256(b).hexdigest();READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
def require(value,why):
 if not value:raise ValueError(why)
def command(argv,timeout=90):return subprocess.run(argv,capture_output=True,check=True,timeout=timeout)
def immutable(path,raw):require(not path.exists() and not path.is_symlink(),'Immutable archive already exists');path.write_bytes(raw)
def save(path,value):immutable(path,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode())
def dependency_classpath(archive,seed=False):
 """Bind this new archive to the actual v215 third-party bytes and explicit priority."""
 archive=pathlib.Path(archive);original=archive/'verification-dependencies.json'
 if not original.exists():
  require(seed,'Archived verification dependencies missing')
  source=REPO/'build/acceptance/reference-20261004/deployment-v215/isolated-test-overlay.json'
  require(SHA(source.read_bytes())==DEPENDENCY_SOURCE_SHA256,'Actual v215 dependency source changed')
  installed=REPO/'api/build/install/samlscope/lib';excluded={name+'-0.1.0.jar' for name in ['api','core','peer','runner','saml','store','auth']}
  rows=[]
  for path,digest in READ(source)['dependencySha256'].items():
   p=pathlib.Path(path)
   if p.parent!=installed or p.name in excluded:continue
   require(p.is_file() and not p.is_symlink() and p.suffix=='.jar' and SHA(p.read_bytes())==digest,'Actual dependency bytes missing')
   rows.append(dict(path=str(p),name=p.name,sha256=digest))
  require(rows and len({r['name'] for r in rows})==len(rows),'Actual dependency names ambiguous')
  # Both host and remote replays use this order; no implicit wildcard priority remains.
  providers={}
  for row in rows:
   with zipfile.ZipFile(row['path']) as jar:
    for name in jar.namelist():
     if name.endswith('.class') and not name.startswith('META-INF/') and name!='module-info.class':providers.setdefault(name,[]).append(row['name'])
  save(original,rows)
  raw=command(['docker','exec',SUITE,'sha256sum',*['/opt/samlscope/lib/'+r['name'] for r in rows]]).stdout
  actual={line.split()[1].rsplit('/',1)[-1]:line.split()[0] for line in raw.decode().splitlines()}
  require(actual=={r['name']:r['sha256'] for r in rows},'Live third-party bytes differ from actual archive source')
  save(archive/'dependency-priority.json',dict(schema='samlscope-actual-v215-dependency-priority-v1',sourceSha256=DEPENDENCY_SOURCE_SHA256,inventorySha256=SHA(original.read_bytes()),projectArchivesFirst=['suite-'+name+'-0.1.0.jar' for name in JARS],thirdPartyOrder=[r['name'] for r in rows],duplicateClasses={name:names for name,names in providers.items() if len(names)>1},liveThirdPartySha256=actual,liveReadbackSha256=SHA(raw)))
 rows=READ(original);priority=READ(archive/'dependency-priority.json')
 require(priority['sourceSha256']==DEPENDENCY_SOURCE_SHA256 and priority['inventorySha256']==SHA(original.read_bytes())
         and priority['thirdPartyOrder']==[r['name'] for r in rows] and priority['projectArchivesFirst']==['suite-'+name+'-0.1.0.jar' for name in JARS],'Archived classpath priority changed')
 require(rows and len({r['name'] for r in rows})==len(rows),'Dependency inventory ambiguous')
 for row in rows:require(pathlib.Path(row['path']).name==row['name'] and SHA(pathlib.Path(row['path']).read_bytes())==row['sha256']==priority['liveThirdPartySha256'][row['name']],'Actual dependency changed')
 return ':'.join(row['path'] for row in rows)
def archive(folder):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;a.mkdir(exist_ok=False);pins={}
 for name,digest in JARS.items():
  file='suite-'+name+'-0.1.0.jar';command(['docker','cp',SUITE+':/opt/samlscope/lib/'+name+'-0.1.0.jar',str(a/file)])
  require(SHA((a/file).read_bytes())==digest and (a/file).stat().st_nlink==1,'Actual JAR mismatch or unsafe hardlink');pins[name]=dict(file=file,sha256=digest)
 for file,(klass,digest) in HELPERS.items():
  source=REPO/'dev/reference-acceptance'/(klass+'.java');require(SHA(source.read_bytes())==digest,'Replay source changed');immutable(a/file,source.read_bytes())
 dependency_classpath(a,True);save(a/'pins.json',dict(jars=pins,helpers={file:value[1] for file,value in HELPERS.items()},dependenciesSha256=SHA((a/'verification-dependencies.json').read_bytes()),dependencyPrioritySha256=SHA((a/'dependency-priority.json').read_bytes())))
 return a
def project(a):
 pins=READ(a/'pins.json');require(pins['helpers']=={file:value[1] for file,value in HELPERS.items()},'Helper pins changed');require(SHA((a/'verification-dependencies.json').read_bytes())==pins['dependenciesSha256'] and SHA((a/'dependency-priority.json').read_bytes())==pins['dependencyPrioritySha256'],'Dependency original changed');out=[]
 for name,digest in JARS.items():
  row=pins['jars'][name];path=a/row['file'];require(row['sha256']==digest==SHA(path.read_bytes()) and path.stat().st_nlink==1,'Archived production bytes changed');out.append(path)
 for file,(_,digest) in HELPERS.items():require(SHA((a/file).read_bytes())==digest,'Archived helper changed')
 return out
def remote_classes(folder,names):
 a=pathlib.Path(folder)/ARCHIVE;jars=project(a);temporary=tempfile.TemporaryDirectory(prefix='default-native-reader-');tmp=pathlib.Path(temporary.name);classes=tmp/'classes';classes.mkdir(mode=0o755);sources=[]
 for file in names:
  klass=HELPERS[file][0];source=tmp/(klass+'.java');source.write_bytes((a/file).read_bytes());sources.append(source)
 cp=':'.join(map(str,jars))+':'+dependency_classpath(a);javac=str(pathlib.Path(os.environ.get('JAVA_HOME','/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home'))/'bin/javac');command([javac,'-cp',cp,'-d',str(classes),*map(str,sources)])
 require(all(any(p.name.startswith(HELPERS[f][0]) for f in names) for p in classes.rglob('*.class')),'Helper shadows production class');remote='/tmp/default-native-reader-'+secrets.token_hex(6);command(['docker','exec','-u','0',SUITE,'mkdir',remote]);command(['docker','cp',str(classes),SUITE+':'+remote+'/classes'])
 for j in jars:command(['docker','cp',str(j),SUITE+':'+remote+'/'+j.name])
 command(['docker','exec','-u','0',SUITE,'chmod','-R','a+rX',remote]);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote])
 dependencies=READ(a/'verification-dependencies.json')
 return temporary,tmp,remote,':'.join(remote+'/'+j.name for j in jars)+':'+remote+'/classes:'+':'.join('/opt/samlscope/lib/'+row['name'] for row in dependencies)
def cleanup(temporary,remote):
 try:command(['docker','exec','-u','0',SUITE,'rm','-rf','--',remote])
 finally:temporary.cleanup()
def replay(folder,retain=False,positive=False):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;temporary,tmp,remote,cp=remote_classes(folder,['replay-helper.java'])
 try:
  for name in ['receipt','created.json','target-metadata.xml','finalized-originals']+([] if positive else ['calibration']):command(['docker','cp',str(folder/name),SUITE+':'+remote+'/'+name])
  command(['docker','exec','-u','0',SUITE,'chmod','-R','a+rX',remote]);argv=['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.VerifyShibbolethDefaultAlgorithms',remote,remote+'/report.json']
  if positive:argv.append('positive-only')
  result=subprocess.run(argv,capture_output=True,timeout=100);require(result.returncode==0,'Archived reader replay failed: '+result.stderr.decode(errors='replace')[-5000:]);command(['docker','cp',SUITE+':'+remote+'/report.json',str(tmp/'report.json')]);raw=(tmp/'report.json').read_bytes()
 finally:cleanup(temporary,remote)
 path=a/('positive-preverification.json' if positive else 'production-replay.json')
 if retain:immutable(path,raw)
 else:require(path.read_bytes()==raw,'Archived actual replay differs')
 n=json.loads(raw);require(n['outcome']['outcome'] in {'SATISFIED','VIOLATED'} and n['outcome']['details']['counterfactual_calibration_only'] is False,'Not genuine native proof')
 if not positive:require(len(n['negativeControls'])==46 and set(n['negativeControls'].values())=={'NOT_VERIFIED'} and n['approvedMutant']=='VIOLATED' and n['productionDiagnostic']==n['relabeledDiagnosticProductionAndOffline']=='NOT_VERIFIED' and n['controlsAdopted'] is False,'Approved detector/default boundary incomplete')
 return n
def selected(folder,phase,retain=False):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;temporary,tmp,remote,cp=remote_classes(folder,['stored-helper.java','outbox-helper.java']);run=READ(folder/'created.json')['run']['id'];out={}
 try:
  for label,file,args in [('stored','stored-helper.java',['capture',run]),('outbox','outbox-helper.java',[run])]:
   raw=command(['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.'+HELPERS[file][0],*args]).stdout;path=a/(label+'-'+phase+'.json')
   if retain:immutable(path,raw)
   else:require(path.read_bytes()==raw,'Selected stored result changed')
   out[label]=json.loads(raw)
 finally:cleanup(temporary,remote)
 return out
def carry_before(folder):
 """Preserve and recheck the actual pre-install v215 state; never fabricate prior history."""
 folder=pathlib.Path(folder);a=folder/ARCHIVE;project(a);prior=folder/'reader-v215';pins=READ(prior/'pins.json')
 require(pins['jars']['runner']['sha256']=='c95c580bc1f268038f10ae7926bac51ed94d99248230174934be016b78c7b9a4','Prior runtime changed')
 for row in pins['jars'].values():
  p=prior/row['file'];require(p.is_file() and not p.is_symlink() and p.stat().st_nlink==1 and SHA(p.read_bytes())==row['sha256'],'Prior actual archive changed')
 run=READ(folder/'created.json')['run']['id'];hashes={}
 for label in ['stored','outbox']:
  source=prior/(label+'-before.json');require(source.is_file() and not source.is_symlink() and 0<source.stat().st_size<8_388_608,'Prior execution original unavailable')
  raw=source.read_bytes();require(json.loads(raw)['runId']==run,'Prior execution belongs to another Run');immutable(a/source.name,raw);hashes[source.name]=SHA(raw)
 require(READ(a/'stored-before.json')['cases'][CASE]['status']=='FINISHED' and READ(a/'stored-before.json')['cases'][CASE]['outcome']['outcome']=='NOT_VERIFIED','Original pre-install state is not pending native proof')
 selected(folder,'before',False)
 save(a/'stored-before-source-binding.json',dict(runId=run,sourceArchive='reader-v215',sourceRunnerSha256=pins['jars']['runner']['sha256'],files=hashes,currentDatabaseFullOriginalsEqual=True,productSettings=0,protocolSubmissions=0,credentialPosts=0))
def central_offline(folder):
 a=pathlib.Path(folder)/ARCHIVE;jars=project(a)
 with tempfile.TemporaryDirectory(prefix='default-central-reader-') as temp:
  p=pathlib.Path(temp);s=p/'ReadDefaultAlgorithmStoredConclusion.java';s.write_bytes((a/'stored-helper.java').read_bytes());cp=':'.join(map(str,jars))+':'+dependency_classpath(a);java=pathlib.Path(os.environ.get('JAVA_HOME','/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home'))/'bin';command([str(java/'javac'),'-cp',cp,'-d',str(p),str(s)]);raw=command([str(java/'java'),'-cp',cp+':'+str(p),'com.samlscope.runner.cases.ReadDefaultAlgorithmStoredConclusion','offline',str((a/'stored-final.json').resolve())]).stdout;require(raw==(a/'stored-final.json').read_bytes(),'Archived central Evaluator differs')
def public_install_assets(receipt,m):
 """Copy hashed public originals plus only invocation-bound empty SDK auxiliaries."""
 receipt=pathlib.Path(receipt).absolute();files=m.get('files');require(isinstance(files,dict) and files,'Public file manifest missing');assets={}
 def read(name,allow_empty=False):
  require(isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,160}',name),'Unsafe public file');p=receipt/name
  require(not any(parent.is_symlink() for parent in [p,*p.parents]),'Public original has a symlink parent')
  require(p.is_file() and (allow_empty or p.stat().st_size>0) and p.stat().st_size<=8_388_608,'Missing or unbounded public original');return p.read_bytes()
 assets['manifest.json']=read('manifest.json')
 require(json.loads(assets['manifest.json'])==m,'Manifest original differs')
 for name,digest in files.items():
  require(name!='manifest.json' and isinstance(digest,str) and re.fullmatch(r'[0-9a-f]{64}',digest),'Invalid original digest');b=read(name);require(SHA(b)==digest,'Original file changed');assets[name]=b
 early=[]
 for row in m['observations']:
  name=row['fixtureId']+'-native-use.json';require(name in assets,'Native use original missing');use=json.loads(assets[name])
  require(use.get('counterfactualCalibrationOnly',False) is False and use.get('diagnosticOnly',False) is False and not any(k in use for k in ['calibrationOutputReference','calibrationOutputSha256','calibrationInvocationFile','stockCalibrationOutputFile']),'Counterfactual consumer proof cannot be installed')
  if use.get('auditMode')=='pre-audit-decoder-rejection':
   require(row['fixtureId']=='rsa-md5','SDK auxiliary outside early RSA-MD5 consumer');early.append(use)
 require(len(early)<=1,'Duplicate decoder proof')
 if early:
  use=early[0];name=use.get('unmarshallerInvocationFile');require(name=='stock-unmarshaller-invocation.json' and name in assets,'SDK invocation original missing');call=json.loads(assets[name])
  require(call.get('schema')=='samlscope-shibboleth-stock-unmarshaller-invocation-v1' and call.get('runId')==m['runId'] and type(call.get('exitCode')) is int and call['exitCode']==0 and call.get('stderrFile')=='stock-unmarshaller.stderr','Invalid SDK auxiliary invocation')
  name=call.get('compileInvocationFile');require(name=='stock-unmarshaller-compile-invocation.json' and name in assets,'SDK compile original missing');compiled=json.loads(assets[name]);require(type(compiled.get('exitCode')) is int and compiled['exitCode']==0,'SDK compile not successful')
  auxiliary={'stock-unmarshaller.stderr':call.get('stderrSha256'),'stock-unmarshaller-compile.stdout':compiled.get('stdoutSha256'),'stock-unmarshaller-compile.stderr':compiled.get('stderrSha256')}
  for name,digest in auxiliary.items():
   b=assets.get(name)
   if b is None:
    b=read(name,True);require(b==b'' and digest==SHA(b''),'Unlisted SDK auxiliary must be an actual bound empty original');assets[name]=b
   else:require(SHA(b)==digest,'SDK auxiliary hash differs')
 return dict(sorted(assets.items()))
def install(folder):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;project(a);m=READ(folder/'receipt/manifest.json');run=m['runId'];require(m['counterfactualCalibrationOnly'] is False and (a/'stored-before.json').is_file() and (a/'outbox-before.json').is_file(),'Only stock final proof after stored-before may be installed')
 verified=READ(a/'production-replay.json');require(verified['runId']==run and verified['manifestSha256']==SHA((folder/'receipt/manifest.json').read_bytes()) and verified['outcome']['outcome'] in {'SATISFIED','VIOLATED'} and verified['outcome']['details']['counterfactual_calibration_only'] is False and verified['productionDiagnostic']=='NOT_VERIFIED','Full actual reader/control replay must precede installation')
 assets=public_install_assets(folder/'receipt',m)
 destination='/data/default-algorithm-evidence/'+run
 require(command(['docker','exec',SUITE,'sh','-c','test -e '+destination+' && echo exists || true']).stdout.strip()==b'','Never replace existing evidence')
 with tempfile.TemporaryDirectory(prefix='default-public-install-') as tmp:
  copied=pathlib.Path(tmp)/run;copied.mkdir(mode=0o755)
  for file,b in assets.items():
   p=copied/file;p.write_bytes(b);p.chmod(0o644)
  command(['docker','exec',SUITE,'mkdir','-p','/data/default-algorithm-evidence']);command(['docker','cp',str(copied),SUITE+':/data/default-algorithm-evidence/'+run])
  installed_files={p.name:SHA(p.read_bytes()) for p in copied.iterdir()}
  for file,digest in installed_files.items():
   require(command(['docker','exec',SUITE,'sha256sum',destination+'/'+file]).stdout.decode().split()[0]==digest,'Suite user public-file readback failed')
   require(command(['docker','exec',SUITE,'stat','-c','%s',destination+'/'+file]).stdout.strip()==str(len(assets[file])).encode(),'Suite user public-file size readback failed')
 save(a/'installation.json',dict(runId=run,manifestSha256=SHA((folder/'receipt/manifest.json').read_bytes()),counterfactualCalibrationOnly=False,files=installed_files,sizes={name:len(b) for name,b in assets.items()},emptyAuxiliaryFiles=[name for name,b in assets.items() if not b],productSettings=0,protocolSubmissions=0,credentialPosts=0))
def formal(folder):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;run=READ(folder/'created.json')['run']['id'];spec=importlib.util.spec_from_file_location('default_formal_api',REPO/'dev/keycloak/import_metadata_batch.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);f=a/'formal';f.mkdir(exist_ok=False)
 save(f/'transcript-before.json',mod.api('/api/runs/'+run+'/transcript'));save(f/'status-before.json',mod.api('/api/runs/'+run+'/protocol-evidence'));save(f/'evaluation.json',mod.api('/api/runs/'+run+'/protocol-evidence/evaluate',{}));save(f/'result.json',mod.api('/api/runs/'+run+'/result.json'));save(f/'transcript.json',mod.api('/api/runs/'+run+'/transcript'));selected(folder,'final',True)
def seal(folder):
 folder=pathlib.Path(folder).resolve();a=folder/ARCHIVE;project(a)
 require((a/'stored-final.json').is_file() and (a/'production-replay.json').is_file() and (a/'formal/result.json').is_file(),'Final actual replay/stored/formal originals must precede sealing')
 paths=sorted(folder.rglob('*'));files={}
 for path in paths:
  require(not path.is_symlink(),'Accepted original cannot be a symlink')
  if path.is_file() and path.name!='acceptance-originals.json':files[path.relative_to(folder).as_posix()]=SHA(path.read_bytes())
 require(files and all(not name.startswith('/') and '..' not in pathlib.PurePosixPath(name).parts for name in files),'Unsafe accepted originals')
 save(folder/'acceptance-originals.json',files);return dict(runId=READ(folder/'created.json')['run']['id'],originalFiles=len(files),productSettings=0,protocolSubmissions=0,credentialPosts=0)
def verify(root):
 folder=pathlib.Path(root)/FOLDER;a=folder/ARCHIVE;require(all(SHA((folder/f).read_bytes())==h for f,h in READ(folder/'acceptance-originals.json').items()),'Accepted originals changed');n=replay(folder);run=n['runId'];before=READ(a/'stored-before.json')['cases'][CASE];after=READ(a/'stored-final.json')['cases'][CASE];outcome=dict(after['outcome']);details=dict(outcome['details']);old=details.pop('previous_recorded_evidence_result',None);outcome['details']=details;verdict='PASS' if n['outcome']['outcome']=='SATISFIED' else 'WARNING'
 carried=READ(a/'stored-before-source-binding.json');require(carried['runId']==run and carried['sourceArchive']=='reader-v215' and carried['sourceRunnerSha256']=='c95c580bc1f268038f10ae7926bac51ed94d99248230174934be016b78c7b9a4' and carried['currentDatabaseFullOriginalsEqual'] is True and carried['files']=={name:SHA((a/name).read_bytes()) for name in ['stored-before.json','outbox-before.json']} and all((a/name).read_bytes()==(folder/'reader-v215'/name).read_bytes() for name in carried['files']),'Actual previous runtime/execution source binding differs')
 require(after['status']=='FINISHED' and after['verdict']==verdict and outcome==n['outcome'],'Full saved outcome differs');require(before['outcome'] is not None and before['outcome']['outcome']=='NOT_VERIFIED' and old is not None and set(old)=={'revision','updated_at','outcome','not_verified_reason','reason_code','reason_message_key','evidence','details'} and old['revision']==before['revision'] and old['updated_at']==before['updatedAt'] and after['revision']==before['revision']+1,'Prior execution not bound')
 require(all(old[x]==before['outcome'][y] for x,y in [('outcome','outcome'),('not_verified_reason','notVerifiedReason'),('reason_code','reasonCode'),('reason_message_key','reasonMessageKey'),('evidence','evidence'),('details','details')]),'Previous full result changed')
 require(READ(a/'outbox-before.json')==READ(a/'outbox-final.json'),'Formal evaluation issued or modified requests');original=READ(folder/'finalized-originals/transcript.json');require(original==READ(a/'formal/transcript-before.json')==READ(a/'formal/transcript.json'),'Formal modified transcript')
 from verify_terminal_http_acceptance import find_case
 result=READ(a/'formal/result.json');case=find_case(result,CASE);require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+n['targetMetadataSha256'] and case['mode']=='ATTESTED' and case['outcome']==n['outcome']['outcome'] and case['verdict']==verdict and case['attested'] is False and case['evidence_class']=='OPERATOR_ASSISTED' and case['evidence']==n['outcome']['evidence'] and case['reason_code']==n['outcome']['reasonCode'],'Formal central/provenance differs')
 require(READ(folder/'restoration.json')['restored'] is True and READ(folder/'operation-counts.json')['credentialPosts']==1 and READ(folder/'operation-counts.json')['protocolSubmissions']==7 and READ(folder/'calibration/diagnostic-operations.json')['nativeJavaCalls']==2,'Restoration/burden/diagnostic count changed')
 finalization=READ(folder/'finalized-manifest-binding.json');require(finalization['runId']==run and finalization['manifestSha256']==n['manifestSha256'] and finalization['nativeCompilerCalls']==2 and finalization['nativeJavaCalls']==3 and finalization['stockDecoderCompilerCalls']==finalization['stockDecoderJavaCalls']==1,'SDK/cipher diagnostic operations not bound')
 assets=public_install_assets(folder/'receipt',READ(folder/'receipt/manifest.json'));installed=READ(a/'installation.json');require(installed['runId']==run and installed['manifestSha256']==n['manifestSha256'] and installed['counterfactualCalibrationOnly'] is False and installed['files']=={name:SHA(raw) for name,raw in assets.items()} and installed['sizes']=={name:len(raw) for name,raw in assets.items()} and installed['emptyAuxiliaryFiles']==[name for name,raw in assets.items() if not raw],'Installed public originals or empty SDK auxiliary binding differ');central_offline(folder);return a/'formal/result.json',{CASE:case}
def live(folder):
 folder=pathlib.Path(folder)
 for name,path in [('providers','metadata-providers'),('audit','audit'),('logback','logback')]:require(command(['docker','exec',NATIVE,'cat','/opt/reference-idp/conf/'+path+'.xml']).stdout==(folder/'receipt'/('original-'+name+'.xml')).read_bytes()==(folder/'receipt'/('final-'+name+'.xml')).read_bytes(),'Native exact restore changed')
 run=READ(folder/'created.json')['run']['id'];require(command(['docker','exec',NATIVE,'sh','-c','test -e /opt/reference-idp/metadata/default-algorithm-'+run+'.xml && echo exists || true']).stdout.strip()==b'','Temporary native source still exists');return dict(restored=True,productSettings=0,protocolSubmissions=0,credentialPosts=0)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--archive',action='store_true');p.add_argument('--retain-replay',action='store_true');p.add_argument('--positive-only',action='store_true');p.add_argument('--capture-before',action='store_true');p.add_argument('--carry-before',action='store_true');p.add_argument('--capture-after',action='store_true');p.add_argument('--install',action='store_true');p.add_argument('--formal',action='store_true');p.add_argument('--live',action='store_true');p.add_argument('--seal',action='store_true');a=p.parse_args();folder=a.root/FOLDER
 if a.archive:print(archive(folder))
 elif a.retain_replay:print(replay(folder,True,a.positive_only)['runId'])
 elif a.capture_before or a.capture_after:print(selected(folder,'before' if a.capture_before else 'final',True)['stored']['runId'])
 elif a.carry_before:carry_before(folder);print('Original v215 stored-before preserved and current full state rechecked')
 elif a.install:install(folder);print('Stock public originals installed/read back')
 elif a.formal:formal(folder);print('Formal recorded-evidence evaluation saved')
 elif a.seal:print(seal(folder))
 elif a.live:print(live(folder))
 else:print(verify(a.root))
