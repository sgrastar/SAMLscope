#!/usr/bin/env python3
"""Replay archived genuine native instrumentation and actual Runner; no operator declaration.

This developer fixture proves selected stock Password-boundary capability, preserving the live
true+IsPassive NoPassive result. It does not claim a live true Password UI or change ATTESTED mode.
"""
import argparse,hashlib,json,pathlib,secrets,subprocess,tempfile,shutil
import yaml
from verify_shibboleth_native_ui_acceptance import dependency_classpath
from verify_terminal_http_acceptance import find_case
REPO=pathlib.Path(__file__).resolve().parents[2]
FOLDER='shibboleth-forceauthn-mechanism-v186-r1';ARCHIVE='reader-v188';SUITE='samlscope-reference-suite'
CASE='IIP-IDP06-b-idp-01';RUN='run_B7216J6NG10P449KERTB9WWV2T'
APPROVED_COVERAGE_SHA256='2bee3db74c9be9908710bbe18935c73454f1ed4c5c0f06bdab1cf18deaef843c'
APPROVED_CASES_SHA256='431d9aa863d5d882d37266667a8fd20547d1fe6d037274b8d59ff66347f5ecd4'
NATIVE_CLASSPATH_SHA256='53237205e9eaf6d719d6f8dc4257938880ee0e856b18cf0722014be458f57a18'
NATIVE_HELPER='0c4b156aca2f5ac3821ed181e9dee00015067e0165ee901e6103dfd71e97aae2'
HELPER='f468cef4f604351ac5f610bb8d3f62aaad908a27303c20c088291e13540973cd';STORED_HELPER='3fa9bcacaaf4add931ff614ccca95b2f4457b3ed4860558f8174e8a24548f21e';PINS={'image': 'sha256:ecd757653ce1e01dbc54f1f0d59e48fb0492066c5b08e81ff2b6650cf14ea41b', 'jars': {'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'runner': '3330e35f5e7b63921d7bd55313d9856c3688c9f9fb48a370d25b9e5ea442a547', 'saml': 'd8a4b81658187663fb8a31ed6da3c5fdbdde3d02def1c1a513634245c606cf03', 'store': 'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'}}
CONTROLS={'true-context-lost','false-flag-lost','native-initializer-lost','misbound-native-context','input-hash','request-id','issuer','missing-negative','duplicate-positive','unknown-mutant','native-class','native-expression','false-live-ui-claim','scope'}
SHA=lambda b:hashlib.sha256(b).hexdigest()
READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
def require(v,msg):
 if not v:raise ValueError(msg)
def command(args):return subprocess.run(args,check=True,capture_output=True)
def project_jars(archive):
 require(PINS is not None,'Actual deployed pins not finalized');rt=READ(archive/'suite-runtime-terminal-http.json');store=READ(archive/'store-runtime.json');paths=[]
 require(rt['container']['image_id']==PINS['image'],'Actual image changed')
 for name,digest in PINS['jars'].items():
  row=store if name=='store' else rt['jars'][name];p=archive/row['file'];require(SHA(p.read_bytes())==row['sha256']==digest,'Archived production jar changed');paths.append(p)
 return paths
def native_replay(folder):
 source=folder/'NativeForceAuthnMechanismProbe.java';require(SHA(source.read_bytes())==NATIVE_HELPER,'Native helper changed')
 require(SHA((folder/'native-classpath-before.json').read_bytes())==NATIVE_CLASSPATH_SHA256,'Accepted native whole-classpath original changed');rows=READ(folder/'native-classpath-before.json');require(rows==READ(folder/'native-classpath-after.json')==READ(folder/'native-classpath.json'),'Native classpath epoch differs')
 for name,digest in rows.items():require(SHA((folder/'native-libs'/name).read_bytes())==digest,'Archived native library changed')
 require(len(rows)==127,'Native classpath inventory differs')
 with tempfile.TemporaryDirectory(prefix='shib-forceauthn-native-') as temp:
  temp=pathlib.Path(temp);classes=temp/'classes';classes.mkdir();cp=str((folder/'native-libs').resolve())+'/*'
  command(['javac','-cp',cp,'-d',str(classes),str(source.resolve())]);require(all(p.name.startswith('NativeForceAuthnMechanismProbe') for p in classes.rglob('*.class')),'Native helper shadows target')
  logging=temp/'logback-off.xml';logging.write_text('<configuration><root level="OFF"/></configuration>');output=temp/'trace.json'
  command(['java','-Dlogback.configurationFile='+str(logging),'-cp',str(classes)+':'+cp,'NativeForceAuthnMechanismProbe',str((folder/'inputs/normal.xml').resolve()),str((folder/'inputs/forced-passive.xml').resolve()),str(output)])
  require(output.read_bytes()==(folder/'native-trace.json').read_bytes(),'Genuine archived native trace differs')
 trace=READ(folder/'native-trace.json');require([r['indicatorReachable'] for r in trace['traces']]==[True,True,False,False,False,False] and trace['trueLivePasswordUiExecutionClaimed'] is False,'Native mutants/scope differ');return trace
def replay(folder,baseline,retain=False):
 folder=pathlib.Path(folder);archive=folder/ARCHIVE;jars=project_jars(archive);helper=archive/'replay-helper.java';require(SHA(helper.read_bytes())==HELPER,'Archived Reader helper changed')
 with tempfile.TemporaryDirectory(prefix='shib-forceauthn-reader-') as temp:
  temp=pathlib.Path(temp);source=temp/'VerifyShibbolethForceAuthnMechanism.java';source.write_bytes(helper.read_bytes());classes=temp/'classes';classes.mkdir();cp=':'.join(map(str,jars))+':'+dependency_classpath(archive,retain)
  command(['javac','-cp',cp,'-d',str(classes),str(source)]);require(all(p.name.startswith('VerifyShibbolethForceAuthnMechanism') for p in classes.rglob('*.class')),'Helper shadows actual Reader')
  remote='/tmp/shib-forceauthn-adoption-'+secrets.token_hex(6);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();command(['docker','exec','-u','0',SUITE,'mkdir','-p',remote+'/force-authn-mechanism-evidence',remote+'/authentication-identity-evidence',remote+'/baseline'])
  try:
   marker=folder/(RUN+'.shibboleth-force-authn-mechanism.json')
   for path,name in [(folder, 'force-authn-mechanism-evidence/'+RUN+'.shibboleth-force-authn-mechanism'),(marker,'force-authn-mechanism-evidence/'+marker.name),(baseline/'receipt','authentication-identity-evidence/'+RUN),(baseline/'receipt','baseline/receipt'),(baseline/'browser','baseline/browser'),(baseline/'context-parameters.json','baseline/context-parameters.json'),(classes,'classes')]:command(['docker','cp',str(path),SUITE+':'+remote+'/'+name])
   for jar in jars:command(['docker','cp',str(jar),SUITE+':'+remote+'/'+jar.name])
   command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote]);cp=':'.join(remote+'/'+p.name for p in jars)+':'+remote+'/classes:/opt/samlscope/lib/*'
   command(['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.VerifyShibbolethForceAuthnMechanism',remote+'/force-authn-mechanism-evidence',remote+'/baseline',remote+'/report.json'])
   raw=command(['docker','exec',SUITE,'cat',remote+'/report.json']).stdout
  finally:command(['docker','exec','-u','0',SUITE,'rm','-rf',remote])
 saved=archive/'production-replay.json'
 if retain:
  require(not saved.exists(),'Refusing to overwrite archived replay');saved.write_bytes(raw)
 else:require(json.loads(raw)==READ(saved),'Actual archived CaseOutcome/details/evidence differ')
 report=json.loads(raw);require(report['runId']==RUN and set(report['negativeControls'])==CONTROLS and set(report['negativeControls'].values())=={'NOT_VERIFIED'},'Controls differ')
 require(report['productOperations']==0 and report['privateCredentialsPersisted'] is False and report['trueLiveNoPassiveRetained'] is True,'Operations/privacy/scope differ');return report
def stored(archive):
 source=archive/'stored-readback-source.java';require(SHA(source.read_bytes())==STORED_HELPER,'Stored helper changed');original=archive/'stored-case-conclusions.json'
 with tempfile.TemporaryDirectory(prefix='shib-forceauthn-central-') as temp:
  temp=pathlib.Path(temp);file=temp/'ReadShibbolethForceAuthnMechanismStoredConclusion.java';file.write_bytes(source.read_bytes());classes=temp/'classes';classes.mkdir();cp=':'.join(map(str,project_jars(archive)))+':'+dependency_classpath(archive)
  command(['javac','-cp',cp,'-d',str(classes),str(file)]);raw=command(['java','-cp',cp+':'+str(classes),'com.samlscope.runner.cases.ReadShibbolethForceAuthnMechanismStoredConclusion','offline',str(original.resolve())]).stdout
  require(raw==original.read_bytes(),'Archived central Evaluator differs')
 return READ(original)
def verify(root):
 root=pathlib.Path(root);folder=root/FOLDER;archive=folder/ARCHIVE;baseline=root.parent/'reference-20260930/shibboleth-identity-v170-r3'
 require(SHA((archive/'approved-coverage-original.yaml').read_bytes())==APPROVED_COVERAGE_SHA256 and SHA((archive/'approved-cases-original.yaml').read_bytes())==APPROVED_CASES_SHA256,'Approved source originals changed')
 def nodes(value):
  if isinstance(value,dict):
   yield value
   for child in value.values():yield from nodes(child)
  elif isinstance(value,list):
   for child in value:yield from nodes(child)
 coverage=list(nodes(yaml.safe_load((archive/'approved-coverage-original.yaml').read_bytes())));cases=list(nodes(yaml.safe_load((archive/'approved-cases-original.yaml').read_bytes())))
 require(any(x.get('key')=='IIP-IDP06.b' and x.get('level')=='MUST' and x.get('testability')=='ATTESTED' for x in coverage),'Approved owner meaning differs')
 require(any(x.get('id')==CASE and x.get('mode')=='ATTESTED' and x.get('obligation')=='IIP-IDP06.b' for x in cases),'Approved case mode differs')
 native_replay(folder);report=replay(folder,baseline);actual=report['outcome'];require(actual['outcome']=='SATISFIED' and actual['reasonCode']=='idp.force-authn.mechanism-reachability.native-proven','Candidate differs')
 marker=folder/(RUN+'.shibboleth-force-authn-mechanism.json');require(report['manifestSha256']==SHA(marker.read_bytes()),'Manifest differs')
 ops=READ(folder/'operation-counts.json');require(all(ops[k]==0 for k in ['newProductConfigurationWrites','productReloads','productRestarts','protocolSends','humanOperations','newRuns']) and ops['settingsUnchangedAndTemporaryHelpersRemoved'] is True and ops['productCredentialsPersisted'] is False,'Native operation/privacy counts differ');final=READ(folder/'final-state.json');require(final['productConfigurationUnchanged'] is True and final['nativeMetadataStatus']==200 and final['privateCredentialsExported'] is False and all(v['matchesBefore'] for v in final['sourceReadbacks'].values()),'Final reference state differs');before=READ(folder/'execution-readbacks.json');require(before['configurationUnchanged'] is before['runtimeUnchanged'] is before['nativeClasspathUnchanged'] is True,'Native epoch differs')
 formal=READ(archive/'formal.json');require(formal['runId']==RUN and formal['transcriptUnchanged'] is True and all(formal[k]==0 for k in ['productWrites','productRestarts','protocolSends','humanOperations','newRuns']),'Formal operations differ')
 path=archive/'evaluation-terminal-http-v1/result.json';result=READ(path);case=find_case(result,CASE);require(result['run']['id']==RUN and result['target']['metadata_digest']=='sha256:'+READ(marker)['targetMetadataSha256'],'Formal binding differs')
 require(case['verdict']=='PASS' and case['outcome']=='SATISFIED' and case['attested'] is False and case['evidence_class']=='PROTOCOL_OBSERVED' and case['reason_code']==actual['reasonCode'] and case['evidence']==actual['evidence'],'Formal verdict/provenance differs')
 require(READ(archive/'evaluation-terminal-http-v1/transcript-before.json')==READ(archive/'evaluation-terminal-http-v1/transcript.json')==READ(baseline/'browser/transcript.json'),'Original transcript changed')
 current=stored(archive)['cases'][CASE];prior=READ(archive/'previous-stored-case-conclusions.json')['cases'][CASE];require(current['status']=='FINISHED' and current['verdict']=='PASS' and current['revision']==prior['revision']+1,'Stored lifecycle differs')
 value=dict(current['outcome']);details=dict(value['details']);history=details.pop('previous_recorded_evidence_result',None)
 if prior['outcome'] is None:require(history is None,'Unexpected prior history')
 else:require(prior['outcome']['outcome']=='NOT_VERIFIED' and history is not None and history['revision']==prior['revision'] and history['updated_at']==prior['updatedAt'] and all(history[a]==prior['outcome'][b] for a,b in [('outcome','outcome'),('not_verified_reason','notVerifiedReason'),('reason_code','reasonCode'),('reason_message_key','reasonMessageKey'),('evidence','evidence'),('details','details')]),'Prior outcome audit differs')
 value['details']=details;require(value==actual,'Stored full conclusion differs');return path,{CASE:case}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=pathlib.Path);p.add_argument('--retain-replay',action='store_true');a=p.parse_args()
 if a.retain_replay:print(replay(a.root/FOLDER,a.root.parent/'reference-20260930/shibboleth-identity-v170-r3',True)['runId'])
 else:print(verify(a.root)[0])
