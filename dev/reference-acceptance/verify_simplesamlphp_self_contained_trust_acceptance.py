#!/usr/bin/env python3
"""Archived deployed Reader replays native full-role evidence. No product settings or protocol operations."""
import argparse,hashlib,json,pathlib,subprocess,secrets,tempfile,os
from verify_shibboleth_native_ui_acceptance import dependency_classpath
REPO=pathlib.Path(__file__).resolve().parents[2];SUITE='samlscope-reference-suite';CASE='IIP-MD06-c-idp-01';ARCHIVE='reader-v203';FOLDER='simplesamlphp-self-contained-trust-r3'
SOURCE=REPO/'dev/reference-acceptance/VerifySimpleSamlPhpSelfContainedTrust.java';COMMON=REPO/'dev/reference-acceptance/VerifyNativeRoleKeyConsumption.java';STORED=REPO/'dev/reference-acceptance/ReadSelfContainedMetadataTrustStoredConclusion.java';OUTBOX=REPO/'dev/reference-acceptance/ReadSelfContainedMetadataTrustOutboxState.java';SHA=lambda b:hashlib.sha256(b).hexdigest();READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
RUNNER='aee67ef5729a5696986e09050a6b1c38658d525428c2b77eb52d6a2a44e02127'
JAR_PINS={'runner':RUNNER,'core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe','saml':'43b2cc47bd142956e7f35bd1d906950f64d3f952374db72a2df84f5e3617bec7','store':'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'}
HELPER_PINS={'replay-helper.java': 'f67e8c275d67c3feed14ea7f3d11d69a644f93203c9e03c572cbb0b12a0c7b91', 'common-helper.java': 'fbcaaa5e541b17286348e1bfce9a3785db64e59d457b8476c8ff981d2d5c615e', 'stored-helper.java': '9d9d1a1dbc026d86dce15f8e41deb96462522601fffbf6cb5e1e04989309d222', 'outbox-helper.java': '9b7256b045e16dbd87783eb25139628b44c86aa98093794e0923e84926db573e'}
PRODUCER='6dfbf7c49d2135de2d0079352fab3c1153ffeaad05a4c323b45c03319dbc9ec7'
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
 folder=pathlib.Path(folder);a=folder/ARCHIVE;temporary,tmp,remote,uid,cp=remote_classes(folder,[('VerifySimpleSamlPhpSelfContainedTrust','replay-helper.java'),('VerifyNativeRoleKeyConsumption','common-helper.java')])
 try:
  for name in ['source-role','receipt','created.json','target-metadata.xml','transcript.json','decoded-manifest.json','trust-receipt.json']:command(['docker','cp',str(folder/name),SUITE+':'+remote+'/'+name])
  command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote]);cmd=['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.VerifySimpleSamlPhpSelfContainedTrust',remote,remote+'/report.json']
  require(not positive_only,'Full detector replay is mandatory')
  result=subprocess.run(cmd,capture_output=True,timeout=90);require(result.returncode==0,'Production replay failed: '+result.stderr.decode(errors='replace')[-3500:]);command(['docker','cp',SUITE+':'+remote+'/report.json',str(tmp/'report.json')]);raw=(tmp/'report.json').read_bytes()
 finally:cleanup(temporary,remote)
 path=a/('positive-preverification.json' if positive_only else 'production-replay.json')
 if retain:require(not path.exists(),'Refusing to overwrite original replay');path.write_bytes(raw)
 else:require(path.read_bytes()==raw,'Archived actual replay differs')
 n=json.loads(raw);require(n['outcome']['outcome']=='SATISFIED' and n['outcome']['reasonCode']=='metadata.trust.self-contained-native-observed' and n['outcome']['details']['counterfactual_calibration_only'] is False,'Native role scope not proven')
 require(len(n['negativeControls'])==37 and set(n['negativeControls'].values())=={'NOT_VERIFIED'} and n['approvedMutant']['outcome']=='VIOLATED' and n['approvedMutant']['details']['counterfactual_calibration_only'] is True and n['productionMutantOutcome']['outcome']=='NOT_VERIFIED' and n['sameReaderPredicateAndExplicitOfflineWrapper'] is True and n['counterfactualAdoptedAsProductFinding'] is False and n['privateKeyExported'] is False and n['plaintextPersisted'] is False and all(n[k]==0 for k in ['productConfigurationWrites','protocolOperations','credentialPosts']),'Controls or offline boundary incomplete')
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

def install(folder):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;project(a);m=READ(folder/'trust-receipt.json');run=m['runId'];require((a/'stored-before.json').is_file() and (a/'outbox-before.json').is_file(),'Capture old result before placement');require(m['selectedPath']=='stock-native-signature-encryption' and m['counterfactualCalibrationOnly'] is False,'Never install calibration as product evidence')
 native=READ(folder/'receipt'/m['nativeOutputFile']);require(native['selectedPath']==m['selectedPath'] and native['counterfactualCalibrationOnly'] is False and all(row['selectedConsumer']['accepted'] is True and 'mutant' not in row for row in native['records']),'Not stock-selected originals');require(command(['docker','exec',SUITE,'cat','/data/metadata-role-key-evidence/'+run+'/manifest.json']).stdout==(folder/'source-role/receipt/manifest.json').read_bytes(),'Runtime source role proof differs')
 base='/data/metadata-trust-evidence';remote=base+'/'+run+'.simplesamlphp-trust';command(['docker','exec','-u','0',SUITE,'mkdir','-p',base,remote]);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();files={}
 command(['docker','cp',str(folder/'trust-receipt.json'),SUITE+':'+base+'/'+run+'.simplesamlphp-trust.json']);files[run+'.simplesamlphp-trust.json']=SHA((folder/'trust-receipt.json').read_bytes())
 for name in sorted({m[k] for k in ['producerFile','inputFile','nativeOutputFile','operationsFile']}):
  file=folder/'receipt'/name;
  require(file.is_file() and not file.is_symlink(),'Unsafe public file');command(['docker','cp',str(file),SUITE+':'+remote+'/'+file.name]);require(command(['docker','exec','-u','0',SUITE,'cat',remote+'/'+file.name]).stdout==file.read_bytes(),'Placed original differs');files[run+'.simplesamlphp-trust/'+file.name]=SHA(file.read_bytes())
 require(command(['docker','exec','-u','0',SUITE,'cat',base+'/'+run+'.simplesamlphp-trust.json']).stdout==(folder/'trust-receipt.json').read_bytes(),'Receipt placement differs');command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,base]);original=folder/'installation.json';require(not original.exists(),'Refusing to overwrite installation');original.write_text(json.dumps(dict(runId=run,stockOnly=True,counterfactualInstalled=False,readBackMatched=True,files=files,productSettings=0,protocol=0,credentialPosts=0),indent=2)+'\n')

def verify(root):
 root=pathlib.Path(root);folder=root/FOLDER;a=folder/ARCHIVE;require(all(SHA((folder/f).read_bytes())==h for f,h in READ(folder/'acceptance-originals.json').items()),'Accepted original changed');n=replay(folder);m=READ(folder/'trust-receipt.json');run=READ(folder/'created.json')['run']['id'];require(n['runId']==run==m['runId'],'Foreign replay');require(m['selectedPath']=='stock-native-signature-encryption' and m['counterfactualCalibrationOnly'] is False,'Counterfactual proof cannot be adopted')
 native=READ(folder/'receipt'/m['nativeOutputFile']);require(native['selectedPath']==m['selectedPath'] and native['counterfactualCalibrationOnly'] is False and all(row['selectedConsumer']['accepted'] is True and 'mutant' not in row for row in native['records']),'Stock-selected consumer not proven');require(READ(folder/'source-binding.json')['sourceOperationsReusedNotNew'] is True and m['roleReceiptSha256']==SHA((folder/'source-role/receipt/manifest.json').read_bytes())==SHA((root/'simplesamlphp-role-keys-r1/receipt/manifest.json').read_bytes()),'Reused actual proof differs')
 item=READ(a/'stored-final.json')['cases'][CASE];before=READ(a/'stored-before.json')['cases'][CASE];outcome=dict(item['outcome']);details=dict(outcome['details']);history=details.pop('previous_recorded_evidence_result',None);outcome['details']=details
 require(item['status']=='FINISHED' and item['verdict']=='PASS' and outcome==n['outcome'],'Full stored outcome differs')
 if before['outcome'] is not None and before['outcome']['outcome']=='NOT_VERIFIED':
  require(history is not None and set(history)=={'revision','updated_at','outcome','not_verified_reason','reason_code','reason_message_key','evidence','details'} and history['revision']==before['revision'] and history['updated_at']==before['updatedAt'] and all(history[x]==before['outcome'][y] for x,y in [('outcome','outcome'),('not_verified_reason','notVerifiedReason'),('reason_code','reasonCode'),('reason_message_key','reasonMessageKey'),('evidence','evidence'),('details','details')]) and item['revision']==before['revision']+1,'Old recorded evidence envelope differs')
 else:require(history is None and before['outcome'] is None and item['revision']==before['revision']+1,'Unexpected old lifecycle')
 require(READ(a/'outbox-before.json')==READ(a/'outbox-final.json') and READ(a/'outbox-final.json')['count']==len(READ(a/'outbox-final.json')['rows']) and not any(row['case_id']==CASE for row in READ(a/'outbox-final.json')['rows']),'Formal evaluation issued or modified requests');require(READ(a/'formal/transcript-before.json')==READ(a/'formal/transcript.json')==READ(folder/'transcript.json'),'Transcript changed');result=READ(a/'formal/result.json')
 from verify_terminal_http_acceptance import find_case
 case=find_case(result,CASE);require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+m['targetMetadataSha256'] and case['outcome']=='SATISFIED' and case['verdict']=='PASS' and case['mode']=='ATTESTED' and case['attested'] is False and case['evidence_class']=='PROTOCOL_OBSERVED' and case['reason_code']==n['outcome']['reasonCode'] and case['evidence']==n['outcome']['evidence'],'Central result/provenance differs');central_readback_offline(folder)
 installation=READ(folder/'installation.json');expected={run+'.simplesamlphp-trust.json':SHA((folder/'trust-receipt.json').read_bytes())}|{run+'.simplesamlphp-trust/'+name:SHA((folder/'receipt'/name).read_bytes()) for name in {m[k] for k in ['producerFile','inputFile','nativeOutputFile','operationsFile']}};require(installation['files']==expected and installation['stockOnly'] is True and installation['counterfactualInstalled'] is False and installation['readBackMatched'] is True,'Public stock evidence placement differs');costs=READ(folder/'cumulative-diagnostic-counts.json');require(costs['qualifiedNativePhpCalls']==2 and costs['cumulativeNativePhpCalls']==5 and all(costs[k]==0 for k in ['newProductSettings','newProtocol','newCredentialPosts','newProductRestarts','newPersonOperations']),'Reused costs confused with new operations');return a/'formal/result.json',{CASE:case}

def live(folder):
 folder=pathlib.Path(folder);require(command(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/metadata/saml20-sp-remote.php']).stdout==(folder/'source-role/receipt/original-configuration.php').read_bytes()==(folder/'source-role/receipt/final-configuration.php').read_bytes(),'Native restore differs');return dict(restored=True,productSettings=0,protocol=0,credentialPosts=0)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--archive',action='store_true');p.add_argument('--retain-replay',action='store_true');p.add_argument('--capture-before',action='store_true');p.add_argument('--capture-after',action='store_true');p.add_argument('--install',action='store_true');p.add_argument('--live',action='store_true');args=p.parse_args();folder=args.root/FOLDER
 if args.archive:print(archive(folder))
 elif args.retain_replay:print(replay(folder,True)['runId'],'archived actual replay retained')
 elif args.capture_before or args.capture_after:print(selected(folder,'before' if args.capture_before else 'final',True)['stored']['runId'])
 elif args.install:print(install(folder))
 elif args.live:print(live(folder))
 else:print(verify(args.root))
