#!/usr/bin/env python3
"""Adopt the complete three-epoch retained-metadata validity proof, using archived production code."""
import argparse,hashlib,json,pathlib,secrets,subprocess,tempfile
from verify_shibboleth_native_ui_acceptance import dependency_classpath
from verify_terminal_http_acceptance import _verify_target_runtime,_verify_suite_runtime,find_case
REPO=pathlib.Path(__file__).resolve().parents[2];FOLDER='shibboleth-metadata-validity-r2';CASE='IIP-MD05-ar-idp-01';SUITE='samlscope-reference-suite';ARCHIVE='reader-v193'
PINS={'image_id': 'sha256:b446b37ddf0884b10dee188abf64aa32c4400223859ec99e72941289381081b4', 'jars': {'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'runner': '5f6e92d264804680112ba17952876abfe330fc67bdbab475c7a676a8df91f548', 'saml': 'd5dd36a15d7df8c164d406de5ebac9d180e371061a36ad31e3184dc56964cdb7'}};STORE='c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece';HELPER='9565d8b2c1dbcfa7c12a56ff18ea2b45a4e2396a41f636d296df73ce7b55d440';STORED_HELPER='c23bffa4d711633c17602dd7986149272fc0a4262644e962c1008a006b39ba16'
SHA=lambda b:hashlib.sha256(b).hexdigest();READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
def require(value,message):
 if not value:raise ValueError(message)
def command(args):return subprocess.run(args,check=True,capture_output=True,timeout=90)
def jars(archive):
 require(PINS is not None,'Actual deployed validity Reader pins not finalized');runtime=READ(archive/'suite-runtime-terminal-http.json');paths=[]
 for name,digest in PINS['jars'].items():
  path=archive/runtime['jars'][name]['file'];require(SHA(path.read_bytes())==runtime['jars'][name]['sha256']==digest,'Archived production JAR differs');paths.append(path)
 path=archive/'suite-store-0.1.0.jar';require(SHA(path.read_bytes())==STORE,'Archived Store differs');return paths+[path]
def replay(folder,retain=False):
 folder=pathlib.Path(folder);archive=folder/ARCHIVE;project=jars(archive);source=archive/'replay-helper.java';require(HELPER is not None and SHA(source.read_bytes())==HELPER,'Archived validity helper changed')
 with tempfile.TemporaryDirectory(prefix='shib-validity-replay-') as tmp:
  tmp=pathlib.Path(tmp);classes=tmp/'classes';classes.mkdir();named=tmp/'VerifyShibbolethMetadataValidity.java';named.write_bytes(source.read_bytes());cp=':'.join(map(str,project))+':'+dependency_classpath(archive,retain);command(['javac','-cp',cp,'-d',str(classes),str(named)]);require(all(p.name.startswith('VerifyShibbolethMetadataValidity') for p in classes.rglob('*.class')),'Helper shadows production Reader')
  remote='/tmp/shib-validity-replay-'+secrets.token_hex(6);command(['docker','exec','-u','0',SUITE,'mkdir',remote]);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip()
  try:
   for local,name in [(folder/name,name) for name in ['receipt','created.json','target-metadata.xml','calibration-r3','baseline-recovery']]+[(archive/'full-run-originals'/name,name) for name in ['transcript.json','decoded-manifest.json','decoded']]+[(classes,'classes')]+[(p,p.name) for p in project]:command(['docker','cp',str(local),SUITE+':'+remote+'/'+name])
   command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote]);cp=':'.join(remote+'/'+p.name for p in project)+':'+remote+'/classes:/opt/samlscope/lib/*';result=subprocess.run(['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.VerifyShibbolethMetadataValidity',remote,remote+'/report.json'],capture_output=True,timeout=90);require(result.returncode==0,'Archived production replay failed: '+result.stderr.decode(errors='replace')[-1000:]);command(['docker','cp',SUITE+':'+remote+'/report.json',str(tmp/'report.json')]);raw=(tmp/'report.json').read_bytes()
  finally:command(['docker','exec','-u','0',SUITE,'rm','-rf',remote])
 saved=archive/'production-replay.json'
 if retain:require(not saved.exists(),'Refusing to overwrite actual replay');saved.write_bytes(raw)
 else:require(saved.read_bytes()==raw,'Actual archived Reader replay differs')
 value=json.loads(raw);require(value['outcome']['outcome']=='SATISFIED' and value['outcome']['reasonCode']=='metadata.validity.expiration-observed','Complete validity observation differs');require(len(value['negativeControls'])==33 and set(value['negativeControls'].values())=={'NOT_VERIFIED'},'Invalid originals accepted');require(value['approvedMutants']=={'ignore-root-deadline':'VIOLATED','ignore-earlier-parent':'VIOLATED','ignore-earlier-child':'VIOLATED'},'Expiry/ancestor mutant detection incomplete');require(value['wrapperLifecycle']=={'start':True,'ConfigConfirmed':True,'TranscriptReady':True,'Aborted':True,'TimedOut':True,'status-ready':True,'recorded-not-verified':True,'recorded-conclusive':False,'incomplete-history':'NOT_VERIFIED'},'Actual wrapper lifecycle differs');require(value['productOperations']==0 and value['privateCredentialsPersisted'] is False,'Replay performed product operations or persisted credentials');return value
def stored(folder,retain=False):
 folder=pathlib.Path(folder);archive=folder/ARCHIVE;project=jars(archive);source=archive/'stored-helper.java';require(STORED_HELPER is not None and SHA(source.read_bytes())==STORED_HELPER,'Stored helper differs')
 with tempfile.TemporaryDirectory(prefix='shib-validity-stored-') as tmp:
  tmp=pathlib.Path(tmp);classes=tmp/'classes';classes.mkdir();named=tmp/'ReadShibbolethMetadataValidityStoredConclusion.java';named.write_bytes(source.read_bytes());cp=':'.join(map(str,project))+':'+dependency_classpath(archive);command(['javac','-cp',cp,'-d',str(classes),str(named)])
  if retain:
   remote='/tmp/shib-validity-stored-'+secrets.token_hex(6);command(['docker','exec','-u','0',SUITE,'mkdir',remote]);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip()
   try:
    command(['docker','cp',str(classes),SUITE+':'+remote+'/classes']);command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote]);raw=command(['docker','exec',SUITE,'java','-cp',remote+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.ReadShibbolethMetadataValidityStoredConclusion','capture',READ(folder/'created.json')['run']['id']]).stdout
   finally:command(['docker','exec','-u','0',SUITE,'rm','-rf',remote])
   require(not (archive/'stored-conclusion.json').exists(),'Refusing to overwrite stored original');(archive/'stored-conclusion.json').write_bytes(raw)
  path=archive/'stored-conclusion.json';raw=command(['java','-cp',cp+':'+str(classes),'com.samlscope.runner.cases.ReadShibbolethMetadataValidityStoredConclusion','offline',str(path.resolve())]).stdout;require(raw==path.read_bytes(),'Archived central Evaluator differs');return json.loads(raw)
def verify(root):
 folder=pathlib.Path(root)/FOLDER;archive=folder/ARCHIVE;require(all(SHA((folder/name).read_bytes())==digest for name,digest in READ(folder/'acceptance-originals.json').items()),'Accepted original bytes changed');created=READ(folder/'created.json')['run'];run=created['id'];report=replay(folder);require(report['runId']==run,'Foreign replay');_verify_target_runtime(folder/'receipt','shibboleth',float(created['createdAt']))
 # Deployment followed evidence collection. The formal archive is pinned to its real capture;
 # no claim that the stricter Reader was running during the earlier protocol operation is made.
 _verify_suite_runtime(archive,run,float(READ(archive/'formal-lifecycle.json')['runtimeCapturedAtEpoch']),PINS)
 restored=READ(folder/'restoration.json');require(restored['restored'] is True and restored['errors']==[] and restored['original']==restored['final'],'Native settings not exactly restored');receipt=folder/'receipt'
 for kind in ['providers','audit']:require((receipt/('original-'+kind+'.xml')).read_bytes()==(receipt/('final-'+kind+'.xml')).read_bytes(),'Restoration bytes differ')
 ops=READ(folder/'operation-counts.json');require(ops==dict(restored=True,personOperations=0,credentialPosts=1,productWrites=7,restorationWrites=2,productRestarts=2,metadataReloads=4,protocolSubmissions=7,unconsumedSuiteRearms=3),'Expiry campaign operation counts differ');require(READ(receipt/'retrospective-log-range.json')['historicalBeforeOffsetCaptured'] is False,'Historical offsets were invented');require(READ(folder/'calibration-r3/producer.json')['controlsAdopted'] is False,'Synthetic controls were counted as product outcomes')
 path=archive/'evaluation-terminal-http-v1/result.json';result=READ(path);case=find_case(result,CASE);require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+report['targetMetadataSha256'],'Formal Run/target differs');require(case['outcome']=='SATISFIED' and case['verdict']=='PASS' and case['attested'] is False and case['evidence_class']=='OPERATOR_ASSISTED' and case['reason_code']==report['outcome']['reasonCode'] and case['evidence']==report['outcome']['evidence'],'Formal central result differs');require(READ(archive/'full-run-originals/transcript.json')==READ(archive/'evaluation-terminal-http-v1/transcript-before.json')==READ(archive/'evaluation-terminal-http-v1/transcript.json'),'Formal evaluation changed transcript');require(READ(folder/'baseline-recovery/transcript-before.json')==READ(folder/'transcript.json') and READ(folder/'baseline-recovery/transcript-after.json')==READ(archive/'full-run-originals/transcript.json'),'Baseline changed earlier expiry originals');baseline=folder/'baseline-recovery';require(READ(baseline/'restoration.json')['restored'] is True and (baseline/'original-providers.xml').read_bytes()==(baseline/'final-providers.xml').read_bytes(),'Baseline provider not restored');counts=READ(baseline/'operation-counts-reconciled.json');require(counts['credentialPosts']==1 and counts['actualProtocolSubmissions']==counts['actualNativeProtocolGets']==1 and counts['actualNativeProtocolPosts']==0 and counts['productConfigurationWrites']==3 and counts['metadataReloads']==2 and counts['productRestarts']==counts['personOperations']==0,'Baseline supplemental operation counts differ');value=stored(folder);item=value['cases'][CASE];require(value['runId']==run and item['status']=='FINISHED' and item['verdict']=='PASS' and item['outcome']==report['outcome'],'Stored CaseOutcome differs');return path,{CASE:case}

def live(folder):
 folder=pathlib.Path(folder);receipt=folder/'receipt';restored=READ(folder/'restoration.json')
 for path,digest in restored['original'].items():require(SHA(command(['docker','exec','samlscope-reference-shibboleth','cat',path]).stdout)==digest,'Live native settings differ from restored original')
 ranges=READ(receipt/'retrospective-log-range.json');inode=command(['docker','exec','samlscope-reference-shibboleth','stat','-c','%i',ranges['logPath']]).stdout.decode().strip();require(int(inode)==ranges['inode'],'Native retrospective log inode changed')
 for row in ranges['ranges']:
  raw=command(['docker','exec','samlscope-reference-shibboleth','dd','if='+ranges['logPath'],'bs=1','skip='+str(row['offsetStart']),'count='+str(row['offsetEnd']-row['offsetStart']),'status=none']).stdout;require(raw==(receipt/row['file']).read_bytes() and SHA(raw)==row['sha256'],'Actual native physical log range changed')
 return dict(nativeSettingsRestored=True,retrospectiveRangesReadBack=3,productOperations=0)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--retain-replay',action='store_true');p.add_argument('--capture-stored',action='store_true');p.add_argument('--live',action='store_true');a=p.parse_args();folder=a.root/FOLDER
 if a.live:print(live(folder))
 elif a.retain_replay:print(replay(folder,True)['runId'],'actual production replay retained')
 elif a.capture_stored:print(stored(folder,True)['runId'],'stored original retained')
 else:print(verify(a.root))
