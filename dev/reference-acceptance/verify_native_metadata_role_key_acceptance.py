#!/usr/bin/env python3
"""Archived deployed Reader replays native full-role evidence. No product settings or protocol operations."""
import argparse,hashlib,json,pathlib,subprocess,secrets,tempfile,os
from verify_shibboleth_native_ui_acceptance import dependency_classpath
REPO=pathlib.Path(__file__).resolve().parents[2];SUITE='samlscope-reference-suite';CASE='IIP-MD06-a2-idp-01';ARCHIVE='reader-v202';FOLDERS={'simplesamlphp':'simplesamlphp-role-keys-r1','keycloak':'keycloak-role-keys-r1'}
SOURCE=REPO/'dev/reference-acceptance/VerifyNativeRoleKeyConsumption.java';STORED=REPO/'dev/reference-acceptance/ReadMetadataRoleKeyStoredConclusion.java';OUTBOX=REPO/'dev/reference-acceptance/ReadMetadataRoleKeyOutboxState.java';SHA=lambda b:hashlib.sha256(b).hexdigest();READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
RUNNER='9449ba0fd13dcad6ad296d31dbb7811564bf21e732ea522e56aa2d341827c85d'
JAR_PINS={'runner':RUNNER,'core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe','saml':'43b2cc47bd142956e7f35bd1d906950f64d3f952374db72a2df84f5e3617bec7','store':'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'}
HELPER_PINS={'replay-helper.java':'fbcaaa5e541b17286348e1bfce9a3785db64e59d457b8476c8ff981d2d5c615e','stored-helper.java':'e3bc134617ac0c8a786d89d1adcef000a72e8593d4c66aa63f0ff0fbfc60b674','outbox-helper.java':'0d3ea08cc8a44b94c1a142d0116e42a51b210600cc74b487b7f30fbf4d9b5126'}
PRODUCER='074ce6e4c58db49630820e41d3ac7c4ec9a027d3a5e90c766c54cd06923fe4ce'
def require(b,s):
 if not b:raise ValueError(s)
def command(args):return subprocess.run(args,check=True,capture_output=True,timeout=90)
def archive(folder):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;a.mkdir(exist_ok=False);fmt='{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}}}';native=command(['docker','inspect','--format',fmt,SUITE]).stdout;(a/'suite-native-inspect.json').write_bytes(native);runtime=READ(a/'suite-native-inspect.json');require(runtime['running'] is True,'Suite not running');jars={}
 for name in ['runner','core','saml','store']:
  file='suite-'+name+'-0.1.0.jar';command(['docker','cp',SUITE+':/opt/samlscope/lib/'+name+'-0.1.0.jar',str(a/file)]);jars[name]=dict(file=file,sha256=SHA((a/file).read_bytes()))
 require(jars['runner']['sha256']==RUNNER,'Wrong deployed Runner');(a/'jars.json').write_text(json.dumps(jars,indent=2)+'\n');(a/'replay-helper.java').write_bytes(SOURCE.read_bytes());(a/'stored-helper.java').write_bytes(STORED.read_bytes());(a/'outbox-helper.java').write_bytes(OUTBOX.read_bytes());dependency_classpath(a,True);pins=dict(runtime=runtime,jars=jars,helpers={file:SHA((a/file).read_bytes()) for file in ['replay-helper.java','stored-helper.java','outbox-helper.java']},dependenciesSha256=SHA((a/'verification-dependencies.json').read_bytes()));(a/'pins.json').write_text(json.dumps(pins,indent=2)+'\n');return a

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
 folder=pathlib.Path(folder);a=folder/ARCHIVE;temporary,tmp,remote,uid,cp=remote_classes(folder,[('VerifyNativeRoleKeyConsumption','replay-helper.java')])
 try:
  for name in ['receipt','created.json','target-metadata.xml','transcript.json','decoded-manifest.json','decoded','calibration']:command(['docker','cp',str(folder/name),SUITE+':'+remote+'/'+name])
  command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote]);cmd=['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.VerifyNativeRoleKeyConsumption',remote,remote+'/report.json']
  if positive_only:cmd.append('positive-only')
  result=subprocess.run(cmd,capture_output=True,timeout=90);require(result.returncode==0,'Production replay failed: '+result.stderr.decode(errors='replace')[-3500:]);command(['docker','cp',SUITE+':'+remote+'/report.json',str(tmp/'report.json')]);raw=(tmp/'report.json').read_bytes()
 finally:cleanup(temporary,remote)
 path=a/('positive-preverification.json' if positive_only else 'production-replay.json')
 if retain:require(not path.exists(),'Refusing to overwrite original replay');path.write_bytes(raw)
 else:require(path.read_bytes()==raw,'Archived actual replay differs')
 n=json.loads(raw);require(n['outcome']['outcome']=='SATISFIED' and n['outcome']['reasonCode']=='metadata.role-keys.scoped-use-observed','Native role scope not proven')
 if not positive_only:require(len(n['negativeControls'])==25 and set(n['negativeControls'].values())=={'NOT_VERIFIED'} and len(n['approvedMutants'])==4 and set(n['approvedMutants'].values())=={'VIOLATED'} and n['purposeAcceptanceControls']=={'explicit-a-encryption-key':'NOT_VERIFIED','explicit-b-encryption-key':'NOT_VERIFIED'} and n['privateCredentialsPersisted'] is False and n['productOperations']==0,'Controls incomplete')
 return n

def selected(folder,phase,retain=False):
 folder=pathlib.Path(folder);a=folder/ARCHIVE;temporary,tmp,remote,uid,cp=remote_classes(folder,[('ReadMetadataRoleKeyStoredConclusion','stored-helper.java'),('ReadMetadataRoleKeyOutboxState','outbox-helper.java')]);run=READ(folder/'created.json')['run']['id'];value={}
 try:
  command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote])
  for label,klass,args in [('stored','ReadMetadataRoleKeyStoredConclusion',['capture',run]),('outbox','ReadMetadataRoleKeyOutboxState',[run])]:
   raw=command(['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.'+klass,*args]).stdout;path=a/(label+'-'+phase+'.json')
   if retain:require(not path.exists(),'Refusing to overwrite stored original');path.write_bytes(raw)
   else:require(path.read_bytes()==raw,'Current stored/outbox differs')
   value[label]=json.loads(raw)
 finally:cleanup(temporary,remote)
 return value

def central_readback_offline(folder):
 a=pathlib.Path(folder)/ARCHIVE;jars=project(a)
 with tempfile.TemporaryDirectory(prefix='role-central-readback-') as temporary:
  tmp=pathlib.Path(temporary);source=tmp/'ReadMetadataRoleKeyStoredConclusion.java';source.write_bytes((a/'stored-helper.java').read_bytes());cp=':'.join(map(str,jars))+':'+dependency_classpath(a);command(['javac','-cp',cp,'-d',str(tmp),str(source)]);raw=command(['java','-cp',cp+':'+str(tmp),'com.samlscope.runner.cases.ReadMetadataRoleKeyStoredConclusion','offline',str((a/'stored-final.json').resolve())]).stdout;require(raw==(a/'stored-final.json').read_bytes(),'Archived central Evaluator disagrees')
def verify(root,product='simplesamlphp'):
 folder=pathlib.Path(root)/FOLDERS[product];a=folder/ARCHIVE;require(all(SHA((folder/f).read_bytes())==h for f,h in READ(folder/'acceptance-originals.json').items()),'Accepted originals changed');n=replay(folder);run=READ(folder/'created.json')['run']['id'];require(n['runId']==run,'Foreign replay');item=READ(a/'stored-final.json')['cases'][CASE];before=READ(a/'stored-before.json')['cases'][CASE];outcome=dict(item['outcome']);details=dict(outcome['details']);history=details.pop('previous_recorded_evidence_result',None);outcome['details']=details
 require(item['status']=='FINISHED' and item['verdict']=='PASS' and outcome==n['outcome'],'Full stored conclusion differs')
 if before['outcome'] is not None and before['outcome']['outcome']=='NOT_VERIFIED':
  require(history is not None and set(history)=={'revision','updated_at','outcome','not_verified_reason','reason_code','reason_message_key','evidence','details'} and history['revision']==before['revision'] and history['updated_at']==before['updatedAt'] and all(history[x]==before['outcome'][y] for x,y in [('outcome','outcome'),('not_verified_reason','notVerifiedReason'),('reason_code','reasonCode'),('reason_message_key','reasonMessageKey'),('evidence','evidence'),('details','details')]) and item['revision']==before['revision']+1,'Complete old recorded result differs')
 else:require(history is None and before['outcome'] is None and item['revision']==before['revision']+1,'Unexpected prior lifecycle')
 require(READ(a/'outbox-before.json')==READ(a/'outbox-final.json') and READ(a/'outbox-final.json')['count']==11,'Formal evaluation changed outbox');before_tx=READ(a/'formal/transcript-before.json');require(before_tx==READ(a/'formal/transcript.json')==READ(folder/'transcript.json'),'Formal changed transcript');result=READ(a/'formal/result.json');cases=[x for group in result.get('groups',[]) for x in group.get('cases',[]) if x.get('case_id')==CASE]
 if not cases:
  from verify_terminal_http_acceptance import find_case
  cases=[find_case(result,CASE)]
 case=cases[0];require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+n['targetMetadataSha256'] and case['outcome']=='SATISFIED' and case['verdict']=='PASS' and case['attested'] is False and case['evidence_class']=='OPERATOR_ASSISTED' and case['reason_code']==n['outcome']['reasonCode'] and case['evidence']==n['outcome']['evidence'],'Central formal verdict differs');require(READ(folder/'receipt/restoration.json')['restored'] is True and READ(folder/'calibration/producer.json')['controlsAdopted'] is False,'Native restoration/calibration differs');producer=READ(folder/'calibration/producer.json');native=READ(folder/'calibration/native-producer-output.json');require(SHA((folder/'calibration/metadata_role_key_calibration.php').read_bytes())==producer['sourceSha256']==native['sourceSha256']==PRODUCER and producer['nativeOutputSha256']==SHA((folder/'calibration/native-producer-output.json').read_bytes()) and producer['nativePhpProducerCalls']==1 and producer['nativeCompilerCalls']==0 and native['counterfactualCalibrationOnly'] is True and native['controlsAdopted'] is False and native['nativeUtilsSha256']=='5845e28158c7641d5ce1e6b9205e8005b6d9c090e1888ea46416abb8fdf0018d' and len(native['controls'])==len(producer['controls'])==6,'Native diagnostic originals differ');require(all(next(x for x in native['controls'] if x['fixtureId']==row['fixtureId'])['sha256']==row['sha256']==SHA((folder/'calibration'/row['file']).read_bytes()) for row in producer['controls']),'Native producer control hash differs');central_readback_offline(folder);return a/'formal/result.json',{CASE:case}

def live(folder):
 folder=pathlib.Path(folder);receipt=folder/'receipt';require(command(['docker','exec','samlscope-reference-ssp','cat','/var/simplesamlphp/metadata/saml20-sp-remote.php']).stdout==(receipt/'original-configuration.php').read_bytes()==(receipt/'final-configuration.php').read_bytes(),'Native restore changed');return dict(restored=True,productSettings=0,protocol=0,credentialPosts=0)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--product',choices=FOLDERS,default='simplesamlphp');p.add_argument('--archive',action='store_true');p.add_argument('--retain-replay',action='store_true');p.add_argument('--positive-only',action='store_true');p.add_argument('--capture-before',action='store_true');p.add_argument('--capture-after',action='store_true');p.add_argument('--live',action='store_true');args=p.parse_args();folder=args.root/FOLDERS[args.product]
 if args.archive:print(archive(folder))
 elif args.retain_replay:print(replay(folder,True,args.positive_only)['runId'],'actual deployed archived replay retained')
 elif args.capture_before or args.capture_after:print(selected(folder,'before' if args.capture_before else 'final',True)['stored']['runId'])
 elif args.live:print(live(folder))
 else:print(verify(args.root,args.product))
