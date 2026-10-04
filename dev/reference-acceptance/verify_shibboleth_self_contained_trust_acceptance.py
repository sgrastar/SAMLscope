#!/usr/bin/env python3
"""Archived deployed Reader replays same-Run Shibboleth role/trust evidence. No product settings or protocol operations."""
import argparse,hashlib,json,pathlib,subprocess,secrets,tempfile,os
from verify_shibboleth_native_ui_acceptance import dependency_classpath
REPO=pathlib.Path(__file__).resolve().parents[2];SUITE='samlscope-reference-suite';CASE='IIP-MD06-c-idp-01';ARCHIVE='reader-v204';FOLDER='shibboleth-role-self-contained-trust-r2/trust-proof'
SOURCE=REPO/'dev/reference-acceptance/VerifyShibbolethSelfContainedTrustEvidence.java';COMMON=REPO/'dev/reference-acceptance/VerifyNativeRoleKeyConsumption.java';STORED=REPO/'dev/reference-acceptance/ReadSelfContainedMetadataTrustStoredConclusion.java';OUTBOX=REPO/'dev/reference-acceptance/ReadSelfContainedMetadataTrustOutboxState.java';SHA=lambda b:hashlib.sha256(b).hexdigest();READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
RUNNER='c94981f1baf1202d07934715ae18ee853d2f4e2d5794a5f581f5ae299a386a61'
JAR_PINS={'runner':RUNNER,'core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe','saml':'1bf3b5913095e86f432a864b87bcc9087a3441358ad8cdfcc46ae6c226cf00e0','store':'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'}
HELPER_PINS={'replay-helper.java': 'b9487ce9adc490a5fe22e0411d5ead461dfe25ecfa294901832b562eb2755718', 'common-helper.java': 'fbcaaa5e541b17286348e1bfce9a3785db64e59d457b8476c8ff981d2d5c615e', 'stored-helper.java': '9d9d1a1dbc026d86dce15f8e41deb96462522601fffbf6cb5e1e04989309d222', 'outbox-helper.java': '9b7256b045e16dbd87783eb25139628b44c86aa98093794e0923e84926db573e'}
PRODUCER='a2e49b1980fa80b576db0156ddb0a91fe2b44d7dcdb5793f77e75f78f00cdc0a'
def require(b,s):
 if not b:raise ValueError(s)
def command(args):return subprocess.run(args,check=True,capture_output=True,timeout=90)
def archive(folder):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;a.mkdir(exist_ok=False);fmt='{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}}}';native=command(['docker','inspect','--format',fmt,SUITE]).stdout;(a/'suite-native-inspect.json').write_bytes(native);runtime=READ(a/'suite-native-inspect.json');require(runtime['running'] is True,'Suite not running');jars={}
 for name in ['runner','core','saml','store']:
  file='suite-'+name+'-0.1.0.jar';command(['docker','cp',SUITE+':/opt/samlscope/lib/'+name+'-0.1.0.jar',str(a/file)]);jars[name]=dict(file=file,sha256=SHA((a/file).read_bytes()))
 require(jars['runner']['sha256']==RUNNER,'Wrong deployed Runner');(a/'jars.json').write_text(json.dumps(jars,indent=2)+'\n');(a/'replay-helper.java').write_bytes(SOURCE.read_bytes());(a/'common-helper.java').write_bytes(COMMON.read_bytes());(a/'stored-helper.java').write_bytes(STORED.read_bytes());(a/'outbox-helper.java').write_bytes(OUTBOX.read_bytes());dependency_classpath(a,True);pins=dict(runtime=runtime,jars=jars,helpers={file:SHA((a/file).read_bytes()) for file in ['replay-helper.java','common-helper.java','stored-helper.java','outbox-helper.java']},dependenciesSha256=SHA((a/'verification-dependencies.json').read_bytes()));(a/'pins.json').write_text(json.dumps(pins,indent=2)+'\n');return a

def project(a):
 p=READ(a/'pins.json');require(p['jars']==READ(a/'jars.json') and p['jars']['runner']['sha256']==RUNNER,'Archive pins differ');require(SHA((a/'verification-dependencies.json').read_bytes())==p['dependenciesSha256'],'Dependency inventory changed');result=[]
 for name in ['runner','core','saml','store']:
  n=p['jars'][name];file=a/n['file'];require(SHA(file.read_bytes())==n['sha256']==JAR_PINS[name],'Archived actual JAR changed');result.append(file)
 for f,h in p['helpers'].items():require(SHA((a/f).read_bytes())==h==HELPER_PINS[f],'Archived helper changed')
 return result

def remote_classes(folder,names):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;jars=project(a);temporary=tempfile.TemporaryDirectory(prefix='native-role-proof-');tmp=pathlib.Path(temporary.name);classes=tmp/'classes';classes.mkdir();sources=[]
 for name,file in names:
  s=tmp/(name+'.java');s.write_bytes((a/file).read_bytes());sources.append(s)
 cp=':'.join(map(str,jars))+':'+dependency_classpath(a);command(['javac','-cp',cp,'-d',str(classes),*map(str,sources)]);require(all(any(f.name.startswith(n) for n,_ in names) for f in classes.rglob('*.class')),'Helper shadows production');remote='/tmp/native-role-proof-'+secrets.token_hex(6);command(['docker','exec','-u','0',SUITE,'mkdir',remote]);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();command(['docker','cp',str(classes),SUITE+':'+remote+'/classes'])
 for j in jars:command(['docker','cp',str(j),SUITE+':'+remote+'/'+j.name])
 cp=':'.join(remote+'/'+j.name for j in jars)+':'+remote+'/classes:/opt/samlscope/lib/*';return temporary,tmp,remote,uid,cp

def cleanup(temporary,remote):
 try:command(['docker','exec','-u','0',SUITE,'rm','-rf',remote])
 finally:temporary.cleanup()

def replay(folder,retain=False,positive_only=False):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;temporary,tmp,remote,uid,cp=remote_classes(folder,[('VerifyShibbolethSelfContainedTrustEvidence','replay-helper.java'),('VerifyNativeRoleKeyConsumption','common-helper.java')])
 try:
  for name in ['source-role','receipt','decoded','created.json','target-metadata.xml','transcript.json','decoded-manifest.json','trust-receipt.json']:command(['docker','cp',str(folder/name),SUITE+':'+remote+'/'+name])
  command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote]);cmd=['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.VerifyShibbolethSelfContainedTrustEvidence',remote,'/data',remote+'/report.json']
  require(not positive_only,'Full detector replay is mandatory')
  result=subprocess.run(cmd,capture_output=True,timeout=90);require(result.returncode==0,'Production replay failed: '+result.stderr.decode(errors='replace')[-3500:]);command(['docker','cp',SUITE+':'+remote+'/report.json',str(tmp/'report.json')]);raw=(tmp/'report.json').read_bytes()
 finally:cleanup(temporary,remote)
 path=a/('positive-preverification.json' if positive_only else 'production-replay.json')
 if retain:require(not path.exists(),'Refusing to overwrite original replay');path.write_bytes(raw)
 else:require(path.read_bytes()==raw,'Archived actual replay differs')
 n=json.loads(raw);require(n['outcome']['outcome']=='SATISFIED' and n['outcome']['reasonCode']=='metadata.trust.self-contained-native-observed' and n['outcome']['details']['counterfactual_calibration_only'] is False,'Native role scope not proven')
 require(len(n['negativeControls'])==33 and set(n['negativeControls'].values())=={'NOT_VERIFIED'} and n['approvedMutant']['outcome']=='VIOLATED' and n['approvedMutant']['details']['counterfactual_calibration_only'] is True and n['productionMutantOutcome']['outcome']=='NOT_VERIFIED' and n['sameReaderPredicateAndExplicitOfflineWrapper'] is True and n['counterfactualAdoptedAsProductFinding'] is False and n['privateKeyExported'] is False and n['plaintextPersisted'] is False and all(n[k]==0 for k in ['productConfigurationWrites','protocolOperations','credentialPosts']),'Controls or offline boundary incomplete')
 return n

def selected(folder,phase,retain=False):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;temporary,tmp,remote,uid,cp=remote_classes(folder,[('ReadSelfContainedMetadataTrustStoredConclusion','stored-helper.java'),('ReadSelfContainedMetadataTrustOutboxState','outbox-helper.java')]);run=READ(folder/'created.json')['run']['id'];value={}
 try:
  command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote])
  for label,klass,args in [('stored','ReadSelfContainedMetadataTrustStoredConclusion',['capture',run]),('outbox','ReadSelfContainedMetadataTrustOutboxState',[run])]:
   raw=command(['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.'+klass,*args]).stdout;path=a/(label+'-'+phase+'.json')
   if retain:require(not path.exists(),'Refusing to overwrite stored original');path.write_bytes(raw)
   else:require(path.read_bytes()==raw,'Current stored/outbox differs')
   value[label]=json.loads(raw)
 finally:cleanup(temporary,remote)
 return value

def central_readback_offline(folder):
 a=pathlib.Path(folder)/ARCHIVE;jars=project(a)
 with tempfile.TemporaryDirectory(prefix='role-central-readback-') as temporary:
  tmp=pathlib.Path(temporary);source=tmp/'ReadSelfContainedMetadataTrustStoredConclusion.java';source.write_bytes((a/'stored-helper.java').read_bytes());cp=':'.join(map(str,jars))+':'+dependency_classpath(a);command(['javac','-cp',cp,'-d',str(tmp),str(source)]);raw=command(['java','-cp',cp+':'+str(tmp),'com.samlscope.runner.cases.ReadSelfContainedMetadataTrustStoredConclusion','offline',str((a/'stored-final.json').resolve())]).stdout;require(raw==(a/'stored-final.json').read_bytes(),'Archived central Evaluator disagrees')

def stock_files(m):
 return {m[k+'File'] for k in ['producer','input','nativeOutput','stockInput','stockOutput','operations','nativeJarBefore','nativeJarAfter','nativeSecurityJar']}

def install(folder):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;project(a);m=READ(folder/'trust-receipt.json');run=m['runId'];require((a/'stored-before.json').is_file() and (a/'outbox-before.json').is_file(),'Capture old result before placement');require(m['selectedPath']=='stock-native-signature-encryption' and m['counterfactualCalibrationOnly'] is False,'Never install calibration as product evidence')
 native=READ(folder/'receipt'/m['nativeOutputFile']);require(native['selectedPath']==m['selectedPath'] and native['counterfactualCalibrationOnly'] is False and all(row['selectedConsumer']['accepted'] is True and 'mutant' not in row for row in native['records']),'Not stock-selected originals');roleRemote='/data/metadata-role-key-evidence/'+run;command(['docker','exec','-u','0',SUITE,'mkdir','-p',roleRemote]);roleFiles={}
 for file in sorted((folder/'source-role/receipt').iterdir()):
  require(file.is_file() and not file.is_symlink(),'Unsafe role original');command(['docker','cp',str(file),SUITE+':'+roleRemote+'/'+file.name]);require(command(['docker','exec','-u','0',SUITE,'cat',roleRemote+'/'+file.name]).stdout==file.read_bytes(),'Placed role original differs');roleFiles[file.name]=SHA(file.read_bytes())
 require(command(['docker','exec','-u','0',SUITE,'cat',roleRemote+'/manifest.json']).stdout==(folder/'source-role/receipt/manifest.json').read_bytes(),'Runtime source role proof differs')
 base='/data/metadata-trust-evidence';remote=base+'/'+run+'.shibboleth-trust';command(['docker','exec','-u','0',SUITE,'mkdir','-p',base,remote]);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();files={}
 command(['docker','cp',str(folder/'trust-receipt.json'),SUITE+':'+base+'/'+run+'.shibboleth-trust.json']);files[run+'.shibboleth-trust.json']=SHA((folder/'trust-receipt.json').read_bytes())
 for name in sorted(stock_files(m)):
  file=folder/'receipt'/name;
  require(file.is_file() and not file.is_symlink(),'Unsafe public file');command(['docker','cp',str(file),SUITE+':'+remote+'/'+file.name]);require(command(['docker','exec','-u','0',SUITE,'cat',remote+'/'+file.name]).stdout==file.read_bytes(),'Placed original differs');files[run+'.shibboleth-trust/'+file.name]=SHA(file.read_bytes())
 require(command(['docker','exec','-u','0',SUITE,'cat',base+'/'+run+'.shibboleth-trust.json']).stdout==(folder/'trust-receipt.json').read_bytes(),'Receipt placement differs');command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,base,'/data/metadata-role-key-evidence/'+run]);original=folder/'installation.json';require(not original.exists(),'Refusing to overwrite installation');original.write_text(json.dumps(dict(runId=run,stockOnly=True,counterfactualInstalled=False,readBackMatched=True,files=files,roleFiles=roleFiles,productSettings=0,protocol=0,credentialPosts=0),indent=2)+'\n')

def formal(folder):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;require((a/'stored-before.json').is_file() and (a/'outbox-before.json').is_file(),'Stored-before must precede receipt placement');formal=a/'formal';formal.mkdir(exist_ok=False)
 import importlib.util
 spec=importlib.util.spec_from_file_location('suite_native_trust_api',REPO/'dev/keycloak/import_metadata_batch.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);run=READ(folder/'created.json')['run']['id']
 for name,path in [('result-before.json','result.json'),('transcript-before.json','transcript')]:
  require((a/name).is_file(),'Capture API originals before installation');(formal/name).write_bytes((a/name).read_bytes())
 (formal/'evaluation.json').write_text(json.dumps(module.api('/api/runs/'+run+'/protocol-evidence/evaluate',{}),indent=2)+'\n')
 for name,path in [('result.json','result.json'),('transcript.json','transcript')]: (formal/name).write_text(json.dumps(module.api('/api/runs/'+run+'/'+path),indent=2)+'\n')
 selected(folder,'final',True)
 return formal

def capture_before(folder):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;selected(folder,'before',True)
 import importlib.util
 spec=importlib.util.spec_from_file_location('suite_native_trust_api',REPO/'dev/keycloak/import_metadata_batch.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);run=READ(folder/'created.json')['run']['id']
 for name,path in [('result-before.json','result.json'),('transcript-before.json','transcript')]:require(not (a/name).exists(),'Before original immutable');(a/name).write_text(json.dumps(module.api('/api/runs/'+run+'/'+path),indent=2)+'\n')
 return run

def seal(folder):
 folder=pathlib.Path(folder);path=folder/'acceptance-originals.json';require(not path.exists(),'Acceptance manifest immutable');files={str(p.relative_to(folder)):SHA(p.read_bytes()) for p in folder.rglob('*') if p.is_file()};path.write_text(json.dumps(files,sort_keys=True,indent=2)+'\n')

def verify(root):
 root=pathlib.Path(root);folder=root/FOLDER;a=folder/ARCHIVE;require(all(SHA((folder/f).read_bytes())==h for f,h in READ(folder/'acceptance-originals.json').items()),'Accepted original changed');n=replay(folder);m=READ(folder/'trust-receipt.json');run=READ(folder/'created.json')['run']['id'];require(n['runId']==run==m['runId'],'Foreign replay');require(m['selectedPath']=='stock-native-signature-encryption' and m['counterfactualCalibrationOnly'] is False,'Counterfactual proof cannot be adopted')
 native=READ(folder/'receipt'/m['nativeOutputFile']);require(native['selectedPath']==m['selectedPath'] and native['counterfactualCalibrationOnly'] is False and all(row['selectedConsumer']['accepted'] is True and 'mutant' not in row for row in native['records']),'Stock-selected consumer not proven');require(READ(folder/'source-binding.json')['sourceOperationsReusedNotNew'] is True and m['roleReceiptSha256']==SHA((folder/'source-role/receipt/manifest.json').read_bytes())==SHA((root/'shibboleth-role-self-contained-trust-r2/receipt/manifest.json').read_bytes()),'Reused actual proof differs')
 item=READ(a/'stored-final.json')['cases'][CASE];before=READ(a/'stored-before.json')['cases'][CASE];outcome=dict(item['outcome']);details=dict(outcome['details']);history=details.pop('previous_recorded_evidence_result',None);outcome['details']=details
 require(item['status']=='FINISHED' and item['verdict']=='PASS' and outcome==n['outcome'],'Full stored outcome differs')
 if before['outcome'] is not None and before['outcome']['outcome']=='NOT_VERIFIED':
  require(history is not None and set(history)=={'revision','updated_at','outcome','not_verified_reason','reason_code','reason_message_key','evidence','details'} and history['revision']==before['revision'] and __import__('keycloak_registered_signer_stored_outcome')._same_stored_update_timestamp(before,history['updated_at']) and all(history[x]==before['outcome'][y] for x,y in [('outcome','outcome'),('not_verified_reason','notVerifiedReason'),('reason_code','reasonCode'),('reason_message_key','reasonMessageKey'),('evidence','evidence'),('details','details')]) and item['revision']==before['revision']+1,'Old recorded evidence envelope differs')
 else:require(history is None and before['outcome'] is None and item['revision']==before['revision']+1,'Unexpected old lifecycle')
 require(READ(a/'outbox-before.json')==READ(a/'outbox-final.json') and READ(a/'outbox-final.json')['count']==len(READ(a/'outbox-final.json')['rows']) and not any(row['case_id']==CASE for row in READ(a/'outbox-final.json')['rows']),'Formal evaluation issued or modified requests');require(READ(a/'formal/transcript-before.json')==READ(a/'formal/transcript.json')==READ(folder/'transcript.json'),'Transcript changed');result=READ(a/'formal/result.json')
 from verify_terminal_http_acceptance import find_case
 case=find_case(result,CASE);require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+m['targetMetadataSha256'] and case['outcome']=='SATISFIED' and case['verdict']=='PASS' and case['mode']=='ATTESTED' and case['attested'] is False and case['evidence_class']=='PROTOCOL_OBSERVED' and case['reason_code']==n['outcome']['reasonCode'] and case['evidence']==n['outcome']['evidence'],'Central result/provenance differs');central_readback_offline(folder)
 installation=READ(folder/'installation.json');expected={run+'.shibboleth-trust.json':SHA((folder/'trust-receipt.json').read_bytes())}|{run+'.shibboleth-trust/'+name:SHA((folder/'receipt'/name).read_bytes()) for name in stock_files(m)};require(installation['files']==expected and installation['stockOnly'] is True and installation['counterfactualInstalled'] is False and installation['readBackMatched'] is True,'Public stock evidence placement differs');verify_operations(root,folder);require(installation['roleFiles']=={p.name:SHA(p.read_bytes()) for p in (folder/'source-role/receipt').iterdir()},'Common role placement inventory changed');return a/'formal/result.json',{CASE:case}

def verify_operations(root,folder):
 source=root/'shibboleth-role-self-contained-trust-r2';failed=root/'shibboleth-role-self-contained-trust-r1';audit=READ(folder/'cumulative-operation-audit.json');require(audit['runId']==READ(folder/'created.json')['run']['id'] and audit['originalsOverwritten'] is False and audit['credentialValuesPersisted'] is False,'Operation qualification missing')
 for key,path in [('countsSha256','operation-counts.json'),('cumulativeCountsSha256','cumulative-operation-counts.json'),('baselineReconciledCountsSha256','initial-baseline/operation-counts-reconciled.json'),('transcriptSha256','transcript.json'),('manifestSha256','receipt/manifest.json')]:require(audit['actualAttempt'][key]==SHA((source/path).read_bytes()),'Qualified actual count original changed')
 for key,path in [('countsSha256','operation-counts.json'),('restorationSha256','restoration.json')]:require(audit['failedAttempt'][key]==SHA((failed/path).read_bytes()),'Failed attempt count changed')
 failedCounts=READ(failed/'operation-counts.json');require(failedCounts['restored'] is True and all(failedCounts[k]==0 for k in ['productWrites','protocolSubmissions','credentialPosts','productRestarts']),'Suite-only failed preflight concealed target operation')
 counts=READ(source/'cumulative-operation-counts.json');require(counts['protocolSubmissions']==11 and counts['credentialPosts']==1 and counts['nativeConfigurationWrites']==11 and counts['restorationWrites']==3 and counts['metadataReloads']==6 and counts['productRestarts']==2 and counts['personOperations']==0,'Actual setup/restoration count mismatch')
 tx={e['id']:e for e in READ(folder/'transcript.json')};baseline=audit['ordinaryBaseline'];role=READ(source/'receipt/manifest.json');requests=[e['requestReference'] for epoch in role['observations'] for e in epoch['exchanges']];require(requests==audit['roleOutboxRequestReferences'] and len(set(requests))==11 and all(tx[r]['method']=='POST' for r in requests),'Role request count mismatch')
 require(tx[baseline['requestReference']]['method']=='GET' and tx[baseline['responseReference']]['samlSummary']['inResponseTo']==tx[baseline['requestReference']]['samlSummary']['id'] and baseline['nativeAttempts']==1 and audit['qualifiedProtocolSubmissions']==12 and audit['qualifiedCredentialPosts']==1,'Baseline Redirect qualification mismatch')
 operations=READ(folder/'receipt/operations.json');require(operations['nativeCompilerCalls']==1 and operations['nativePublicJavaCalls']==2 and operations['temporarySourceRemoved'] is True and all(operations[k]==0 for k in ['productSettings','protocol','credentialPosts','productRestarts','personOperations']),'Public calibration count mixed with actual campaign')
 require(READ(source/'restoration.json')['restored'] is True and READ(source/'initial-baseline/restoration.json')['restored'] is True,'Restoration not established')

def verify_adoption(root,live=False):
 result=verify(root)
 if live:globals()['live'](pathlib.Path(root)/FOLDER)
 return result

def live(folder):
 folder=pathlib.Path(folder);source=folder.parent;receipt=folder/'source-role/receipt';native='samlscope-reference-shibboleth'
 for kind,path in [('providers','/opt/reference-idp/conf/metadata-providers.xml'),('audit','/opt/reference-idp/conf/audit.xml')]:require(command(['docker','exec',native,'cat',path]).stdout==(receipt/('original-'+kind+'.xml')).read_bytes()==(receipt/('final-'+kind+'.xml')).read_bytes(),'Native restoration differs')
 role=READ(receipt/'manifest.json');paths=[role['sourcePath'],'/opt/reference-idp/metadata/validity-baseline-'+role['runId']+'.xml']
 for path in paths:require(command(['docker','exec',native,'sh','-c','test ! -e "$1"','guard',path]).returncode==0,'Temporary native source remains')
 for row in READ(receipt/'other-provider-inventory.json'):require(SHA(command(['docker','exec',native,'cat',row['path']]).stdout)==row['sha256'],'Existing native provider source changed')
 fmt='{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}},"mounts":{{json .Mounts}}}';runtime=json.loads(command(['docker','inspect','--format',fmt,native]).stdout);historical=READ(receipt/'trust-runtime-final.json');require(runtime==historical,'Historical restored runtime epoch changed')
 return dict(restored=True,productSettings=0,protocol=0,credentialPosts=0)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--archive',action='store_true');p.add_argument('--retain-replay',action='store_true');p.add_argument('--capture-before',action='store_true');p.add_argument('--capture-after',action='store_true');p.add_argument('--install',action='store_true');p.add_argument('--formal',action='store_true');p.add_argument('--seal',action='store_true');p.add_argument('--live',action='store_true');args=p.parse_args();folder=args.root/FOLDER
 if args.archive:print(archive(folder))
 elif args.retain_replay:print(replay(folder,True)['runId'],'archived actual replay retained')
 elif args.capture_before:print(capture_before(folder))
 elif args.capture_after:print(selected(folder,'final',True)['stored']['runId'])
 elif args.install:print(install(folder))
 elif args.formal:print(formal(folder))
 elif args.seal:print(seal(folder))
 elif args.live:print(verify(args.root));print(live(folder))
 else:print(verify(args.root))
