#!/usr/bin/env python3
"""Verify a native Subject-identifier counterexample using immutable G02 originals and archived Reader."""
import argparse,hashlib,json,pathlib,secrets,shutil,subprocess,tempfile
import yaml
from verify_shibboleth_native_ui_acceptance import dependency_classpath
from verify_terminal_http_acceptance import _verify_suite_runtime,find_case,parsed_time
from verify_shibboleth_g02_known_subject_acceptance import verify as verify_g02

REPO=pathlib.Path(__file__).resolve().parents[2]
FOLDER='shibboleth-g02-known-subject-v181-r1';ARCHIVE='subject-match-reader-v183';CASE='IIP-SSO07-b-idp-01';SUITE='samlscope-reference-suite'
PINS={'image_id': 'sha256:1fc16b6fb6924474f433ffaca295faba3f33c4422bdf5bf5b4436b6ab560c581', 'jars': {'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'runner': '39d6cb61b67678a4a9863f22552c5143d6a3e75f2e8755c2d32b7ed5d000664b', 'saml': 'd8a4b81658187663fb8a31ed6da3c5fdbdde3d02def1c1a513634245c606cf03'}}
STORE='c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'
HELPER='9450928b08b1fe4012d645d1719e908fedf25bc734f7953158c7ab8dee9b6a9b'
STORED_HELPER='bb106aef5a9e930c31a6bdd520936e71d5b62828d4ae7265bf00cb652c2687a3'
COVERAGE='2bee3db74c9be9908710bbe18935c73454f1ed4c5c0f06bdab1cf18deaef843c'
CONTROLS={'missing-normal-response','wrong-normal-signature','missing-original','wrong-native-source','missing-audit','wrong-audit-principal','wrong-audit-request','wrong-restoration','wrong-readback','late-before-readback','early-after-readback','disabled-transform','different-native-runtime','wrong-fixed-target','wrong-decryption-key','missing-response','wrong-correlation','tampered-request','tampered-response','foreign-run','duplicate-entry','foreign-original-reference','incomplete-history','different-format-policy-exception','equal-id-no-policy'}
SHA=lambda b:hashlib.sha256(b).hexdigest()
READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
def require(v,message):
 if not v:raise ValueError(message)
def command(args):return subprocess.run(args,check=True,capture_output=True)
def jars(archive):
 require(PINS is not None and all(v is not None for v in [STORE,HELPER,STORED_HELPER]),'Actual deployed Reader pins not finalized')
 rt=READ(archive/'suite-runtime-terminal-http.json');store=READ(archive/'store-runtime.json');result=[]
 for name,digest in PINS['jars'].items():
  file=archive/rt['jars'][name]['file'];require(SHA(file.read_bytes())==rt['jars'][name]['sha256']==digest,'Archived production JAR differs');result.append(file)
 file=archive/store['file'];require(SHA(file.read_bytes())==store['sha256']==STORE,'Archived Store JAR differs');return result+[file]
def replay(folder,retain=False):
 folder=pathlib.Path(folder);archive=folder/ARCHIVE;project=jars(archive);helper=archive/'replay-helper-v2.java'
 require(SHA(helper.read_bytes())==HELPER==READ(archive/'replay-helper-v2.json')['sha256'],'Archived helper changed')
 with tempfile.TemporaryDirectory(prefix='samlscope-subject-verify-') as temporary:
  temporary=pathlib.Path(temporary);classes=temporary/'classes';classes.mkdir();source=temporary/'VerifyShibbolethRequestedSubjectMatch.java';source.write_bytes(helper.read_bytes())
  cp=':'.join(map(str,project))+':'+dependency_classpath(archive,retain);command(['javac','-cp',cp,'-d',str(classes),str(source)])
  require(all(p.name.startswith('VerifyShibbolethRequestedSubjectMatch') for p in classes.rglob('*.class')),'Helper shadows production')
  remote='/tmp/samlscope-subject-verify-'+secrets.token_hex(6);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();command(['docker','exec','--user','0',SUITE,'mkdir',remote])
  try:
   for local,name in [(folder/'subject-match-receipt-v2','receipt'),(folder/'browser/created.json','created.json'),(folder/'browser/transcript.json','transcript.json'),(classes,'classes')]:command(['docker','cp',str(local),SUITE+':'+remote+'/'+name])
   for jar in project:command(['docker','cp',str(jar),SUITE+':'+remote+'/'+jar.name])
   command(['docker','exec','--user','0',SUITE,'chown','-R',uid+':'+uid,remote])
   # Original Reader JARs first. Private decryption key never leaves the Suite JVM.
   cp=':'.join(remote+'/'+jar.name for jar in project)+':'+remote+'/classes:/opt/samlscope/lib/*'
   result=subprocess.run(['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.VerifyShibbolethRequestedSubjectMatch',remote+'/receipt',remote,remote+'/report.json'],capture_output=True)
   require(result.returncode==0,'Archived subject replay failed: '+result.stderr.decode(errors='replace')[-1000:])
   command(['docker','cp',SUITE+':'+remote+'/report.json',str(temporary/'report.json')]);raw=(temporary/'report.json').read_bytes()
  finally:command(['docker','exec','--user','0',SUITE,'rm','-rf',remote])
 saved=archive/'production-replay-v2.json'
 if retain:require(not saved.exists(),'Refusing to overwrite archived replay');saved.write_bytes(raw)
 else:require(saved.read_bytes()==raw,'Archived Reader replay differs')
 report=json.loads(raw);require(set(report['controls'])==CONTROLS and set(report['controls'].values())=={'NOT_VERIFIED'},'Invalid counterexample adopted')
 require(report['wrapperLifecycle']==dict(start='VIOLATED',TranscriptReady='VIOLATED',Aborted='VIOLATED',TimedOut='VIOLATED',queued='VIOLATED',**{'recorded-not-verified':'VIOLATED','recorded-conclusive':False,'status-ready':True,'incomplete-history':'NOT_VERIFIED'}),'Wrapper lifecycle differs')
 require(report['productOperations']==0 and report['privateKeyPersisted'] is report['decryptedIdentifierPersisted'] is False and report['equalIdentifierStrongMatch'] is True
  and report['allAttributeChecks']==dict(Format=True,NameQualifier=True,SPNameQualifier=True,SPProvidedID=True),'Replay controls/privacy differ')
 return report
def stored(archive):
 source=archive/'stored-readback-source.java';original=archive/'stored-case-conclusions.json';provenance=READ(archive/'stored-readback-provenance.json')
 require(SHA(source.read_bytes())==STORED_HELPER==provenance['sourceSha256'] and SHA(original.read_bytes())==provenance['sha256']
  and provenance['readonly'] is True and provenance['caseStateExported'] is provenance['privateCredentialsExported'] is False,'Stored conclusion readback changed')
 coverage=(archive/'approved-coverage-original.yaml').read_bytes();require(SHA(coverage)==COVERAGE,'Approved source changed')
 def levels(n):
  if isinstance(n,dict):
   if 'key' in n and 'level' in n:yield n['key'],n['level']
   for v in n.values():yield from levels(v)
  elif isinstance(n,list):
   for v in n:yield from levels(v)
 require(dict(levels(yaml.safe_load(coverage)))['IIP-SSO07.b']=='REQUIRED','Central approved level differs')
 with tempfile.TemporaryDirectory(prefix='samlscope-subject-conclusion-') as temporary:
  temporary=pathlib.Path(temporary);file=temporary/'ReadShibbolethRequestedSubjectStoredConclusion.java';file.write_bytes(source.read_bytes());classes=temporary/'classes';classes.mkdir();cp=':'.join(map(str,jars(archive)))+':'+dependency_classpath(archive)
  command(['javac','-cp',cp,'-d',str(classes),str(file)]);require(all(p.name.startswith('ReadShibbolethRequestedSubjectStoredConclusion') for p in classes.rglob('*.class')),'Readback helper shadows production')
  raw=command(['java','-cp',cp+':'+str(classes),'com.samlscope.runner.cases.ReadShibbolethRequestedSubjectStoredConclusion','offline',str(original.resolve())]).stdout;require(raw==original.read_bytes(),'Archived central Evaluator differs')
 return READ(original)
def verify(root):
 root=pathlib.Path(root);folder=root/FOLDER;archive=folder/ARCHIVE;receipt=folder/'subject-match-receipt-v2';manifest=READ(receipt/'manifest.json');run=manifest['runId']
 # Native principal mapper/source/configuration/restoration is regenerated from archived originals.
 verify_g02(root)
 originals=READ(folder/'subject-match-receipt-originals-v2.json');require({p.name:SHA(p.read_bytes()) for p in receipt.iterdir() if p.is_file()}==originals,'Receipt originals changed')
 installation=READ(folder/'subject-match-receipt-installation-v2.json');require(installation['files']==originals and installation['readBackMatched'] is installation['priorDiagnosticRetained'] is True
  and all(installation[k]==0 for k in ['productOperations','protocolSends','humanOperations']),'Installed evidence readback differs')
 for file,digest in manifest['originals'].items():require(SHA((receipt/file).read_bytes())==digest,'Native original changed')
 report=replay(folder);require(report['runId']==run and report['originalDecodedSha256']=={r['id']:r['sha256'] for r in READ(folder/'browser/decoded-manifest.json')},'Replay protocol originals differ')
 actual=report['outcome'];require(actual['outcome']=='VIOLATED' and actual['reasonCode']=='idp.subject.native-identifier-mismatch' and actual['details']==dict(adapter='shibboleth-native-requested-subject-match',run_id=run,strong_match_counterexamples=2,known_principal_proven=True,different_format_policy_exception=False),'Actual counterexample details differ')
 formal=READ(archive/'formal.json');require(formal['runId']==run and formal['transcriptUnchanged'] is True and all(formal[k]==0 for k in ['productWrites','productRestarts','protocolSends','humanOperations','newRuns']),'Formal product operations occurred')
 _verify_suite_runtime(archive,run,parsed_time(formal['startedAt']),PINS)
 path=archive/'evaluation-terminal-http-v1/result.json';result=READ(path);case=find_case(result,CASE)
 require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+manifest['targetMetadataSha256'] and case==formal['case'],'Formal Run/target differs')
 require((case['outcome'],case['verdict'],case['attested'])==('VIOLATED','FAIL',False) and case['reason_code']==actual['reasonCode'] and case['evidence']==actual['evidence'],'Formal verdict/evidence differs')
 require(READ(archive/'evaluation-terminal-http-v1/transcript-before.json')==READ(archive/'evaluation-terminal-http-v1/transcript.json')==READ(folder/'browser/transcript.json'),'Formal changed original transcript')
 conclusion=stored(archive);require(conclusion['runId']==run and set(conclusion['cases'])=={CASE},'Stored case scope differs');current=conclusion['cases'][CASE];prior=READ(archive/'previous-stored-case-conclusions.json')['cases'][CASE]
 require(current['status']=='FINISHED' and current['verdict']=='FAIL' and current['revision']>prior['revision'] and prior['status']=='FINISHED' and prior['outcome']['outcome']=='NOT_VERIFIED','Stored transition differs')
 observed=dict(current['outcome']);details=dict(observed['details']);previous=details.pop('previous_recorded_evidence_result',None)
 require(previous is not None and previous['revision']==prior['revision'] and previous['updated_at']==prior['updatedAt'] and all(previous[a]==prior['outcome'][b] for a,b in [('outcome','outcome'),('not_verified_reason','notVerifiedReason'),('reason_code','reasonCode'),('reason_message_key','reasonMessageKey'),('evidence','evidence'),('details','details')]),'Previous conclusion audit differs')
 observed['details']=details;require(observed==actual,'Stored complete CaseOutcome differs')
 return path,{CASE:case}
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=pathlib.Path);parser.add_argument('--retain-replay',action='store_true');args=parser.parse_args()
 if args.retain_replay:print(replay(args.root/FOLDER,True)['runId'],'archived production replay retained')
 else:
  path,cases=verify(args.root);print(path,{k:v['verdict'] for k,v in cases.items()})
