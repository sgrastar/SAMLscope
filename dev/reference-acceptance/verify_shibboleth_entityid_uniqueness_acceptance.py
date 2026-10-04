#!/usr/bin/env python3
"""Adopt native entityID conflict and distinct-peer originals with archived Runner replay."""
import argparse,hashlib,json,pathlib,secrets,shutil,subprocess,tempfile,datetime
import yaml
from verify_shibboleth_native_ui_acceptance import dependency_classpath
from verify_terminal_http_acceptance import _verify_target_runtime,_verify_suite_runtime,find_case,parsed_time
from capture_terminal_http_runtime import capture_suite

REPO=pathlib.Path(__file__).resolve().parents[2]
FOLDER='shibboleth-entityid-uniqueness-v180-r1';CASE='IIP-MD05-a1-idp-01';SUITE='samlscope-reference-suite'
PAIRWISE=REPO/'build/acceptance/reference-20260930/shibboleth-persistent-pairwise-v165-r1'
PINS={'image_id':'sha256:17d88e2272a995ef5543cb533475580cd7ec707221c0af93f15b3162e23d9099',
 'jars':{'core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe',
 'runner':'e63c0a44f36ed8bb5d83bcf40862f5718a78fc86a572f3d90ffbd09beb74a520',
 'saml':'cc23a92b38dc21b18c57004c59e90f795c9001b7e919b0ec67559b44d31f9441'}}
STORE='c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'
HELPER='94724e4665db20898a965d2da59239d67f56a62ed854a9c8ab2335c1f20d3ab0'
STORED_HELPER='dacc85fa52c35e5c90644a6a7e6b6249609da8f5b0f1c70e58cf1f3ba57a4928'
COVERAGE='2bee3db74c9be9908710bbe18935c73454f1ed4c5c0f06bdab1cf18deaef843c'
CONTROLS={'missing-conflict-log','wrong-conflict-run','wrong-conflict-entity','conflict-outside-epoch','conflict-on-normal-control',
 'wrong-native-class','wrong-native-jar','native-source-changed','wrong-native-image','different-native-image-epoch','wrong-provider-readback',
 'missing-epoch','late-before-readback','early-after-readback','wrong-restoration','missing-distinct-peer','same-distinct-entity',
 'wrong-distinct-restoration','missing-distinct-readback','wrong-distinct-request','missing-normal-response','wrong-normal-signature',
 'foreign-run-entry','duplicate-entry','foreign-decoded-reference','wrong-prepared-hash','prepared-after-native-reload','incomplete-history','wrong-fixed-target'}
SHA=lambda b:hashlib.sha256(b).hexdigest()
READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
SAVE=lambda p,v:pathlib.Path(p).write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def require(value,message):
 if not value:raise ValueError(message)
def command(args):return subprocess.run(args,check=True,capture_output=True)
def jars(archive):
 require(PINS is not None and STORE is not None,'Actual deployed Reader pins not finalized')
 rt=READ(archive/'suite-runtime-terminal-http.json');store=READ(archive/'store-runtime.json')
 result=[archive/rt['jars'][n]['file'] for n in ['runner','core','saml']]
 require(all(SHA((archive/rt['jars'][n]['file']).read_bytes())==digest for n,digest in PINS['jars'].items()),'Archived production JAR changed')
 require(SHA((archive/store['file']).read_bytes())==store['sha256']==STORE,'Archived Store JAR changed');return result+[archive/store['file']]
def replay(folder,retain=False):
 folder=pathlib.Path(folder);archive=folder/'reader-v181';project=jars(archive);helper=archive/'replay-helper.java'
 require(SHA(helper.read_bytes())==HELPER==READ(archive/'replay-helper.json')['sha256'],'Archived helper changed')
 with tempfile.TemporaryDirectory(prefix='samlscope-entityid-verify-') as temporary:
  temporary=pathlib.Path(temporary);classes=temporary/'classes';classes.mkdir();source=temporary/'VerifyShibbolethEntityIdUniqueness.java';source.write_bytes(helper.read_bytes())
  cp=':'.join(map(str,project))+':'+dependency_classpath(archive,retain)
  command(['javac','-cp',cp,'-d',str(classes),str(source)])
  require(all(p.name.startswith('VerifyShibbolethEntityIdUniqueness') for p in classes.rglob('*.class')),'Helper shadows production')
  remote='/tmp/samlscope-entityid-verify-'+secrets.token_hex(6);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip()
  command(['docker','exec','--user','0',SUITE,'mkdir',remote])
  try:
   for local,name in [(folder/'receipt','receipt'),(folder/'transcript.json','transcript.json'),(classes,'classes')]:command(['docker','cp',str(local),SUITE+':'+remote+'/'+name])
   for jar in project:command(['docker','cp',str(jar),SUITE+':'+remote+'/'+jar.name])
   command(['docker','exec','--user','0',SUITE,'chown','-R',uid+':'+uid,remote])
   # Archived project JARs first: current deployment never decides historical adoption.
   cp=':'.join(remote+'/'+jar.name for jar in project)+':'+remote+'/classes:/opt/samlscope/lib/*'
   result=subprocess.run(['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.VerifyShibbolethEntityIdUniqueness',remote+'/receipt',remote+'/transcript.json',remote+'/report.json'],capture_output=True)
   require(result.returncode==0,'Archived entityID replay failed: '+result.stderr.decode(errors='replace')[-1000:])
   command(['docker','cp',SUITE+':'+remote+'/report.json',str(temporary/'report.json')]);raw=(temporary/'report.json').read_bytes()
  finally:command(['docker','exec','--user','0',SUITE,'rm','-rf',remote])
 saved=archive/'production-replay.json'
 if retain:require(not saved.exists(),'Refusing to replace replay');saved.write_bytes(raw)
 else:require(saved.read_bytes()==raw,'Archived replay differs')
 report=json.loads(raw);require(set(report['controls'])==CONTROLS and set(report['controls'].values())=={'NOT_VERIFIED'},'Invalid controls accepted')
 expected={'start':'SATISFIED','ConfigConfirmed':'SATISFIED','TranscriptReady':'SATISFIED','Aborted':'SATISFIED','TimedOut':'SATISFIED',
  'recorded-not-verified':'SATISFIED','recorded-conclusive':False,'status-ready':True,'external-evidence':True,'copied-provenance':False}
 require(report['wrapperLifecycle']==expected and report['productOperations']==0 and report['privateCredentialsUsed'] is True and report['privateCredentialsPersisted'] is False,'Lifecycle/operation evidence differs')
 return report
def stored(archive):
 source=archive/'stored-readback-source.java';original=archive/'stored-case-conclusions.json';provenance=READ(archive/'stored-readback-provenance.json')
 require(SHA(source.read_bytes())==STORED_HELPER==provenance['sourceSha256'] and SHA(original.read_bytes())==provenance['sha256']
  and provenance['readonly'] is True and provenance['caseStateExported'] is provenance['privateCredentialsExported'] is False,'Stored readback changed')
 coverage=(archive/'approved-coverage-original.yaml').read_bytes();require(SHA(coverage)==COVERAGE,'Approved level source changed')
 def levels(node):
  if isinstance(node,dict):
   if 'key' in node and 'level' in node:yield node['key'],node['level']
   for value in node.values():yield from levels(value)
  elif isinstance(node,list):
   for value in node:yield from levels(value)
 require(dict(levels(yaml.safe_load(coverage)))['IIP-MD05.a1']=='MUST','Central level differs')
 with tempfile.TemporaryDirectory(prefix='samlscope-entityid-conclusion-') as temporary:
  temporary=pathlib.Path(temporary);file=temporary/'ReadShibbolethEntityIdStoredConclusion.java';file.write_bytes(source.read_bytes());classes=temporary/'classes';classes.mkdir()
  cp=':'.join(map(str,jars(archive)))+':'+dependency_classpath(archive)
  command(['javac','-cp',cp,'-d',str(classes),str(file)])
  require(all(p.name.startswith('ReadShibbolethEntityIdStoredConclusion') for p in classes.rglob('*.class')),'Stored exporter shadows production')
  raw=command(['java','-cp',cp+':'+str(classes),'com.samlscope.runner.cases.ReadShibbolethEntityIdStoredConclusion','offline',str(original.resolve())]).stdout
  require(raw==original.read_bytes(),'Archived central Evaluator differs')
 return READ(original)
def verify(root):
 root=pathlib.Path(root);folder=root/FOLDER;archive=folder/'reader-v181';receipt=folder/'receipt';manifest=READ(receipt/'manifest.json');run=manifest['runId']
 original=READ(folder/'receipt-originals.json');require({str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file()}==original,'Receipt originals changed')
 require(READ(folder/'receipt-installation.json')==dict(runId=run,readBackMatched=True,files=original),'Receipt readback changed')
 for file,digest in manifest['originals'].items():require(SHA((receipt/file).read_bytes())==digest,'Bound original changed')
 require((receipt/'original-providers.xml').read_bytes()==(receipt/'final-providers.xml').read_bytes(),'Configuration not restored')
 restoration=READ(folder/'restoration.json');require(restoration['restored'] is restoration['temporary_file_removed'] is True
  and restoration['original_sha256']==restoration['final_sha256']==SHA((receipt/'original-providers.xml').read_bytes()),'Restoration readback failed')
 operations=READ(folder/'native-operations.json');counts=READ(folder/'operation-counts.json')
 require(counts['product_restarts']==counts['human_operations']==0 and counts['restored'] is True
  and counts['metadata_fixture_writes']==sum(r['operation']=='write' and r['label'].startswith('fixture-') for r in operations)==2
  and counts['provider_apply_writes']==sum(r['operation']=='write' and r['label']=='provider-apply' for r in operations)==1
  and counts['restoration_writes']==sum(r['operation']=='write' and r['label']=='restore-provider' for r in operations)==1
  and counts['reloads']==sum(r['operation']=='reload' for r in operations)==3
  and all(r.get('read_back') is True for r in operations if r['operation']=='write'),'Native operation count/readback differs')
 _verify_target_runtime(folder,'shibboleth',float(READ(folder/'created.json')['run']['createdAt']))
 # Reuse the exact independently adopted two-SP originals, not a narrative success.
 distinct=manifest['distinctRunId'];proof=receipt/'distinct-proof'/distinct
 require({str(p.relative_to(proof)):SHA(p.read_bytes()) for p in proof.rglob('*') if p.is_file()}==
  {str(p.relative_to(PAIRWISE/'receipt-v1')):SHA(p.read_bytes()) for p in (PAIRWISE/'receipt-v1').rglob('*') if p.is_file()},'Distinct proof differs from adopted originals')
 pair=READ(proof/'manifest.json');require(pair['runId']==distinct and pair['targetMetadataSha256']==manifest['targetMetadataSha256'],'Distinct fixed metadata differs')
 expected_hashes={};all_ids=set()
 for source,expected in [(folder,run),*[(PAIRWISE/label,peer['runId']) for label,peer in zip(['primary','secondary'],pair['peers'])]]:
  transcript=READ(source/'transcript.json');byid={e['id']:e for e in transcript}
  require(len(byid)==len(transcript) and all(e['runId']==expected for e in transcript) and not all_ids.intersection(byid),'Foreign/duplicate Recorder history');all_ids.update(byid)
  for row in READ(source/'decoded-manifest.json'):
   raw=(source/row['file']).read_bytes();entry=byid[row['id']]
   require(entry['decodedSamlRef']=='transcripts/'+expected+'/'+entry['id']+'.saml.xml' and entry['decodedSamlBytes']==len(raw) and SHA(raw)==row['sha256'],'Decoded original differs');expected_hashes[row['id']]=row['sha256']
  if source!=folder:_verify_target_runtime(source,'shibboleth',float(READ(source/'created.json')['run']['createdAt']))
 for peer in pair['peers']:
  readback=READ(proof/peer['nativeMetadataReadFile']);require(readback['runId']==peer['runId'] and readback['entityId']==peer['entityId']
   and readback['exitCode']==0 and readback['command']==['/opt/reference-idp/bin/mdquery.sh','-u','http://localhost:8080/idp','-e',peer['entityId']]
   and readback['sha256']==peer['nativeMetadataSha256']==SHA((proof/peer['nativeMetadataFile']).read_bytes()),'Native effective distinct peer provenance differs')
 for row in pair['configurationFiles']:
  for phase in ['original','configured','final']:require(SHA((proof/row[phase+'File']).read_bytes())==row[phase+'Sha256'],'Distinct configuration original changed')
  require((proof/row['originalFile']).read_bytes()==(proof/row['finalFile']).read_bytes(),'Distinct configuration not restored')
  for read in row['readBacks']:require((proof/read['file']).read_bytes()==(proof/row['configuredFile']).read_bytes() and SHA((proof/read['file']).read_bytes())==read['sha256'],'Distinct native epoch changed')
 formal=READ(archive/'formal.json');require(formal['runId']==run and formal['transcriptUnchanged'] is True and all(formal[k]==0 for k in ['productWrites','productRestarts','protocolSends','humanOperations','newRuns']),'Formal performed product operations')
 _verify_suite_runtime(archive,run,parsed_time(formal['startedAt']),PINS)
 result_path=archive/'evaluation-terminal-http-v1/result.json';result=READ(result_path);case=find_case(result,CASE)
 require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+manifest['targetMetadataSha256'],'Formal Run/target differs')
 require(case==formal['case'] and (case['outcome'],case['verdict'],case['attested'])==('SATISFIED','PASS',False),'Formal verdict differs')
 require(READ(archive/'evaluation-terminal-http-v1/transcript-before.json')==READ(archive/'evaluation-terminal-http-v1/transcript.json')==READ(folder/'transcript.json'),'Formal changed transcript')
 report=replay(folder);require(report['runId']==run and report['caseId']==CASE and report['originalDecodedSha256']==expected_hashes,'Replay originals differ')
 actual=report['outcome'];require(actual['outcome']==case['outcome'] and actual['reasonCode']==case['reason_code'] and actual['evidence']==case['evidence'],'Formal differs from production Reader')
 conclusion=stored(archive);require(conclusion['runId']==run and set(conclusion['cases'])=={CASE},'Stored selected scope differs')
 current=conclusion['cases'][CASE];observed=dict(current['outcome']);details=dict(observed['details']);previous=details.pop('previous_recorded_evidence_result',None)
 prior=READ(archive/'previous-stored-case-conclusions.json')['cases'][CASE]
 require(current['status']=='FINISHED' and current['verdict']==case['verdict'] and current['revision']>prior['revision'],'Stored conclusion/revision differs')
 if prior['status']=='WAITING_CONFIG':require(prior['outcome'] is None and previous is None,'Fabricated prior conclusion')
 else:
  require(prior['status']=='FINISHED' and prior['outcome']['outcome']=='NOT_VERIFIED' and previous is not None
   and previous['revision']==prior['revision'] and previous['updated_at']==prior['updatedAt'],'Prior recorded audit differs')
  require(all(previous[a]==prior['outcome'][b] for a,b in [('outcome','outcome'),('not_verified_reason','notVerifiedReason'),('reason_code','reasonCode'),
   ('reason_message_key','reasonMessageKey'),('evidence','evidence'),('details','details')]),'Prior public CaseOutcome differs')
 observed['details']=details;require(observed==actual,'Stored full CaseOutcome differs')
 return result_path,{CASE:case}

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=pathlib.Path);parser.add_argument('--retain-replay',action='store_true');args=parser.parse_args()
 if args.retain_replay:print(replay(args.root/FOLDER,True)['runId'],'archived controls passed')
 else:
  path,cases=verify(args.root);print(path,{id:c['verdict'] for id,c in cases.items()})
