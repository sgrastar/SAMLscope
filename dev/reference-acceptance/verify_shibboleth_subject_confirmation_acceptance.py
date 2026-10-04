#!/usr/bin/env python3
"""Adopt two native ordinary-bearer observations by regenerating archived production Reader outcomes."""
import argparse,hashlib,json,pathlib,secrets,subprocess,tempfile
import yaml
from verify_shibboleth_native_ui_acceptance import dependency_classpath
from verify_terminal_http_acceptance import _verify_suite_runtime,find_case,parsed_time
REPO=pathlib.Path(__file__).resolve().parents[2]
FOLDER='shibboleth-subject-confirmation-v184-r4';ARCHIVE='reader-v185';SUITE='samlscope-reference-suite'
CASES={'IIP-SSO01-fr-idp-01','IIP-SSO01-gd-idp-01'}
SCHEMA='samlscope-shibboleth-subject-confirmation-v1'
PINS={'image_id':'sha256:c9e32368a574f6de2d1838387e5b1faa1c32cbeaabaca163469a53ea96edda71','jars':{'core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe','runner':'83899c8cfe0dd901fcbf18c70441c0b95638447604b7640b84734ab2ad62e605','saml':'d8a4b81658187663fb8a31ed6da3c5fdbdde3d02def1c1a513634245c606cf03'}}
STORE='c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'
HELPER='eeb57b672ef00b8cf95ed5a2d03bb4e01c0035c4cf1abdd7f22af8425ee9b8a2'
STORED_HELPER='cdc34d5ffe5ba0ca661362e099c12142c4661c2dbd9ce76ee43b7dda6ce17fbb'
COVERAGE='2bee3db74c9be9908710bbe18935c73454f1ed4c5c0f06bdab1cf18deaef843c'
CONTROLS={'wrong-run','wrong-target','wrong-campaign','wrong-entity','native-factory-changed','stock-config-changed','unknown-source-override','unknown-classpath','provider-not-restored','restoration-false','native-profile-foreign-attester','native-profile-extra-setting','different-native-runtime','wrong-native-peer','profile-dump-wrong-peer','before-readback-late','after-readback-early','negative-http-unproven','native-signed-control-tampered','semantic-control-swapped','missing-original','symlink-original','wrong-profile','foreign-transcript-entry','duplicate-transcript-id','foreign-content-reference','wrong-response-correlation','tampered-request','tampered-response','wrong-decryption-key','missing-response','incomplete-history'}
SHA=lambda b:hashlib.sha256(b).hexdigest()
READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
def require(v,message):
 if not v:raise ValueError(message)
def command(args):return subprocess.run(args,check=True,capture_output=True)
def jars(archive):
 require(PINS is not None and HELPER is not None and STORED_HELPER is not None,'Actual deployed Reader pins not finalized');rt=READ(archive/'suite-runtime-terminal-http.json');paths=[]
 for name,digest in PINS['jars'].items():
  p=archive/rt['jars'][name]['file'];require(SHA(p.read_bytes())==rt['jars'][name]['sha256']==digest,'Archived production JAR differs');paths.append(p)
 store=READ(archive/'store-runtime.json');p=archive/store['file'];require(SHA(p.read_bytes())==store['sha256']==STORE,'Archived Store differs');return paths+[p]
def replay(folder,retain=False):
 folder=pathlib.Path(folder);archive=folder/ARCHIVE;project=jars(archive);helper=archive/'replay-helper.java';require(SHA(helper.read_bytes())==HELPER==READ(archive/'replay-helper.json')['sha256'],'Archived helper changed')
 marker=next(folder.glob('run_*.shibboleth-subject-confirmation.json'));run=READ(marker)['runId']
 with tempfile.TemporaryDirectory(prefix='shib-sc-adoption-') as tmp:
  tmp=pathlib.Path(tmp);classes=tmp/'classes';classes.mkdir();source=tmp/'VerifyShibbolethSubjectConfirmation.java';source.write_bytes(helper.read_bytes());cp=':'.join(map(str,project))+':'+dependency_classpath(archive,retain)
  command(['javac','-cp',cp,'-d',str(classes),str(source)]);require(all(p.name.startswith('VerifyShibbolethSubjectConfirmation') for p in classes.rglob('*.class')),'Helper shadows production')
  remote='/tmp/shib-sc-adoption-'+secrets.token_hex(6);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();command(['docker','exec','-u','0',SUITE,'mkdir',remote])
  try:
   for p,name in [(folder/'subject-confirmation-receipt','receipt'),(folder/'browser/created.json','created.json'),(folder/'browser/transcript.json','transcript.json'),(marker,marker.name),(classes,'classes')]:command(['docker','cp',str(p),SUITE+':'+remote+'/'+name])
   for jar in project:command(['docker','cp',str(jar),SUITE+':'+remote+'/'+jar.name])
   command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote]);cp=':'.join(remote+'/'+p.name for p in project)+':'+remote+'/classes:/opt/samlscope/lib/*'
   result=subprocess.run(['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.VerifyShibbolethSubjectConfirmation',remote+'/receipt',remote,remote+'/report.json'],capture_output=True)
   require(result.returncode==0,'Archived Reader replay failed: '+result.stderr.decode(errors='replace')[-1000:]);command(['docker','cp',SUITE+':'+remote+'/report.json',str(tmp/'report.json')]);raw=(tmp/'report.json').read_bytes()
  finally:command(['docker','exec','-u','0',SUITE,'rm','-rf',remote])
 saved=archive/'production-replay.json'
 if retain:require(not saved.exists(),'Refusing to overwrite replay');saved.write_bytes(raw)
 else:require(saved.read_bytes()==raw,'Archived production Reader replay differs')
 report=json.loads(raw);require(report['runId']==run and set(report['negativeControls'])==CONTROLS and set(report['negativeControls'].values())=={'NOT_VERIFIED'},'Altered evidence adopted')
 require(report['nativeSignedSemanticControls']==4 and report['productOperations']==0 and report['privateKeyPersisted'] is report['decryptedIdentifierPersisted'] is False,'Replay/privacy differs')
 expected=dict(startResume='SATISFIED_WITH_NOTE',recordedUpdate=True,existingConclusiveUnchanged=True,statusReady=True,protocolProvenance=True,incompleteHistory='NOT_VERIFIED',emptyKey='NOT_VERIFIED',wrongRunKey='NOT_VERIFIED',wrongVariantKey='NOT_VERIFIED')
 require(set(report['wrapperLifecycle'])==CASES and all(v==expected for v in report['wrapperLifecycle'].values()),'Actual wrapper lifecycle differs');return report
def stored(archive):
 source=archive/'stored-readback-source.java';original=archive/'stored-case-conclusions.json';provenance=READ(archive/'stored-readback-provenance.json')
 require(SHA(source.read_bytes())==STORED_HELPER==provenance['sourceSha256'] and SHA(original.read_bytes())==provenance['sha256'] and provenance['readonly'] is True and provenance['caseStateExported'] is provenance['privateCredentialsExported'] is False,'Stored public conclusion changed')
 coverage=(archive/'approved-coverage-original.yaml').read_bytes();require(SHA(coverage)==COVERAGE,'Approved coverage changed')
 def levels(n):
  if isinstance(n,dict):
   if 'key' in n and 'level' in n:yield n['key'],n['level']
   for v in n.values():yield from levels(v)
  elif isinstance(n,list):
   for v in n:yield from levels(v)
 require(all(dict(levels(yaml.safe_load(coverage)))[k]=='SHOULD' for k in ['IIP-SSO01.fr','IIP-SSO01.gd']),'Approved central levels differ')
 with tempfile.TemporaryDirectory(prefix='shib-sc-conclusion-') as tmp:
  tmp=pathlib.Path(tmp);file=tmp/'ReadShibbolethSubjectConfirmationStoredConclusion.java';file.write_bytes(source.read_bytes());classes=tmp/'classes';classes.mkdir();cp=':'.join(map(str,jars(archive)))+':'+dependency_classpath(archive)
  command(['javac','-cp',cp,'-d',str(classes),str(file)]);require(all(p.name.startswith('ReadShibbolethSubjectConfirmationStoredConclusion') for p in classes.rglob('*.class')),'Readback helper shadows production')
  raw=command(['java','-cp',cp+':'+str(classes),'com.samlscope.runner.cases.ReadShibbolethSubjectConfirmationStoredConclusion','offline',str(original.resolve())]).stdout;require(raw==original.read_bytes(),'Archived central Evaluator differs')
 return READ(original)
def verify(root):
 root=pathlib.Path(root);folder=root/FOLDER;archive=folder/ARCHIVE;receipt=folder/'subject-confirmation-receipt';marker=next(folder.glob('run_*.shibboleth-subject-confirmation.json'));m=READ(marker);run=m['runId'];installation=READ(folder/'receipt-installation.json')
 require({p.name:SHA(p.read_bytes()) for p in receipt.iterdir()}==m['files']==installation['files'] and installation['runId']==run and installation['readBack'] is True and installation['manifestSha256']==SHA(marker.read_bytes()) and installation['productConfigurationWrites']==installation['protocolOperations']==0,'Receipt originals/read-back changed')
 report=replay(folder);require(report['manifestSha256']==SHA(marker.read_bytes()) and report['originalDecodedSha256']=={r['id']:r['sha256'] for r in READ(folder/'browser/decoded-manifest.json')},'Replay original transcript differs')
 for phase in ['original','before-protocol','after-protocol','final']:
  native=READ(folder/phase/'observed.json');require(native['productConfigurationWrites']==0 and native['privateCredentialsExported'] is False,'Native source capture differs')
 restoration=READ(folder/'browser/restoration.json');ops=READ(folder/'browser/operation-counts.json');require(restoration['restored'] is restoration['temporary_file_removed'] is True and ops==dict(restored=True,human_operations=0,product_restarts=0,metadata_fixture_writes=1,provider_apply_writes=1,restoration_writes=1,reloads=2,protocol_roundtrips=1,verdict_adopted=False),'Native operations/restoration differ')
 formal=READ(archive/'formal.json');require(formal['runId']==run and formal['transcriptUnchanged'] is True and all(formal[k]==0 for k in ['productWrites','productRestarts','protocolSends','humanOperations','newRuns']),'Formal native operations occurred')
 _verify_suite_runtime(archive,run,parsed_time(formal['startedAt']),PINS);path=archive/'evaluation-terminal-http-v1/result.json';result=READ(path);require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+m['targetMetadataSha256'],'Formal Run/target differs')
 require(READ(archive/'evaluation-terminal-http-v1/transcript-before.json')==READ(archive/'evaluation-terminal-http-v1/transcript.json')==READ(folder/'browser/transcript.json'),'Formal transcript changed')
 conclusions=stored(archive);prior=READ(archive/'previous-stored-case-conclusions.json');require(conclusions['runId']==prior['runId']==run and set(conclusions['cases'])==set(prior['cases'])==CASES,'Stored scope differs');adopted={}
 for id in CASES:
  actual=report['outcomes'][id];case=find_case(result,id);require(formal['cases'][id]==case and actual['outcome']=='SATISFIED_WITH_NOTE' and actual['reasonCode']=='browser.subject-confirmation.native-no-opportunity','Native conclusion differs')
  require(case['outcome']=='SATISFIED_WITH_NOTE' and case['verdict']=='WARNING' and case['attested'] is False and case['evidence_class']=='PROTOCOL_OBSERVED' and case['reason_code']==actual['reasonCode'] and case['evidence']==actual['evidence'],'Formal central verdict/provenance differs')
  current=conclusions['cases'][id];old=prior['cases'][id];require(current['status']=='FINISHED' and current['revision']==old['revision']+1 and current['verdict']=='WARNING','Stored transition differs')
  observed=dict(current['outcome']);details=dict(observed['details']);history=details.pop('previous_recorded_evidence_result',None)
  if old['outcome'] is None:
   require(old['status']=='WAITING_CONFIG' and old['revision']==0 and old['verdict'] is None and history is None,'Initial configured conclusion audit differs')
  else:
   require(old['status']=='FINISHED' and old['outcome']['outcome']=='NOT_VERIFIED' and history is not None and history['revision']==old['revision'] and history['updated_at']==old['updatedAt'] and all(history[a]==old['outcome'][b] for a,b in [('outcome','outcome'),('not_verified_reason','notVerifiedReason'),('reason_code','reasonCode'),('reason_message_key','reasonMessageKey'),('evidence','evidence'),('details','details')]),'Previous conclusion audit differs')
  observed['details']=details;require(observed==actual,'Stored full CaseOutcome differs');adopted[id]=case
 return path,adopted
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--retain-replay',action='store_true');a=p.parse_args()
 if a.retain_replay:print(replay(a.root/FOLDER,True)['runId'],'production archived replay retained')
 else:
  path,cases=verify(a.root);print(path,{k:v['verdict'] for k,v in cases.items()})
