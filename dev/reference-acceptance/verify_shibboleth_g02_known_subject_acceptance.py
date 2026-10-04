#!/usr/bin/env python3
"""Verify all G02 original inputs, native known-principal scope and archived production replay."""
import argparse,ast,hashlib,json,pathlib,shutil,subprocess,tempfile,types,xml.etree.ElementTree as ET,zipfile
import yaml
from verify_shibboleth_native_ui_acceptance import dependency_classpath
from verify_terminal_http_acceptance import _verify_target_runtime,_verify_suite_runtime,find_case,parsed_time

REPO=pathlib.Path(__file__).resolve().parents[2];FOLDER='shibboleth-g02-known-subject-v181-r1';CASE='IIP-G02-a-idp-01'
SHA=lambda b:hashlib.sha256(b).hexdigest();READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
PINS={'image_id':'sha256:17d88e2272a995ef5543cb533475580cd7ec707221c0af93f15b3162e23d9099','jars':{
 'core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe',
 'runner':'e63c0a44f36ed8bb5d83bcf40862f5718a78fc86a572f3d90ffbd09beb74a520',
 'saml':'cc23a92b38dc21b18c57004c59e90f795c9001b7e919b0ec67559b44d31f9441'}}
STORE='c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'
HELPER='167b99fbb6cfec1b18cde61fffcb9a6002e53a3700cf1757d532ddf655a16746'
PREPARATION='b478e229ade238a7379e10a934e2a6b587f50a0d55fcf4d06336a4b2b59ac9fe'
STORED='3f3ea7952415b4f1658fe99feb211e69d14f37b0a3fe11d02fb9a10c89423d6d'
COVERAGE='2bee3db74c9be9908710bbe18935c73454f1ed4c5c0f06bdab1cf18deaef843c'
CONTROLS={'missing-response':'NOT_VERIFIED','wrong-correlation':'NOT_VERIFIED','unrecognized-status':'NOT_VERIFIED',
 'reject-256':'VIOLATED','missing-assertion':'NOT_VERIFIED','unrelated-long-subject-error':'NOT_VERIFIED'}
NATIVE_IMAGE='sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a'

def require(v,message):
 if not v:raise ValueError(message)
def command(args):return subprocess.run(args,check=True,capture_output=True)
def canonical(node):return node.tag,tuple(sorted(node.attrib.items())),(node.text or '').strip(),tuple(canonical(n) for n in node)
def timestamp(value):return float(value) if isinstance(value,(int,float)) else parsed_time(value)
def jars(archive):
 rt=READ(archive/'suite-runtime-terminal-http.json');result=[]
 for n,digest in PINS['jars'].items():
  file=archive/rt['jars'][n]['file'];require(SHA(file.read_bytes())==rt['jars'][n]['sha256']==digest,'Production project JAR changed');result.append(file)
 file=archive/'suite-store-0.1.0.jar';require(SHA(file.read_bytes())==STORE,'Production Store JAR changed');return result+[file]
def replay(folder,retain=False):
 folder=pathlib.Path(folder);archive=folder/'reader-v181-predeployment';helper=archive/'replay-helper.java';require(SHA(helper.read_bytes())==HELPER,'Archived helper changed')
 with tempfile.TemporaryDirectory(prefix='samlscope-g02-archived-') as temporary:
  temporary=pathlib.Path(temporary);source=temporary/'VerifyShibbolethG02KnownSubject.java';source.write_bytes(helper.read_bytes());classes=temporary/'classes';classes.mkdir()
  cp=':'.join(map(str,jars(archive)))+':'+dependency_classpath(archive,retain)
  command(['javac','-cp',cp,'-d',str(classes),str(source)])
  require(all(p.name.startswith('VerifyShibbolethG02KnownSubject') for p in classes.rglob('*.class')),'Replay helper shadows production')
  output=temporary/'report.json';command(['java','-cp',cp+':'+str(classes),'com.samlscope.runner.cases.VerifyShibbolethG02KnownSubject',str((folder/'browser').resolve()),str(output)])
  raw=output.read_bytes()
 saved=archive/'production-replay.json'
 if retain:require(not saved.exists(),'Refusing to overwrite replay');saved.write_bytes(raw)
 else:require(saved.read_bytes()==raw,'Actual archived production replay differs')
 report=json.loads(raw);require(report['controls']==CONTROLS and report['outcome']['outcome']=='SATISFIED'
  and len(report['exchanges'])==43 and len(report['unknownSubjectControls'])==25 and report['productOperations']==0
  and report['privateCredentialsPersisted'] is False,'Production fixture/controls differ')
 return report
def native(folder,report):
 archive=folder/'reader-v181-predeployment';child=folder/'browser';binding=READ(folder/'native-subject-binding.json');source=(archive/'native-preparation-source.py').read_bytes()
 require(SHA(source)==PREPARATION,'Native preparation source changed')
 # Regenerate the pure preparation from its archived source, without loading the live driver.
 definition=[n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='preparation'];require(len(definition)==1,'Native preparation definition missing')
 namespace=dict(ET=ET,BEANS='http://www.springframework.org/schema/beans',UTIL='http://www.springframework.org/schema/util',P='http://www.springframework.org/schema/p',
  VALUE='aZ09'*64,AUDIT='SAMLscope-G02-known-v1|%I|%SP|%u|%S|%b|%P',driver=types.SimpleNamespace(BASE='http://localhost:18080'))
 exec(compile(ast.Module(body=definition,type_ignores=[]),'<archived-native-preparation>','exec'),namespace)
 originals={k:(folder/('original-'+k+'.xml')).read_bytes() for k in ['c14n','audit']}
 configured=namespace['preparation'](originals,binding['suiteEntityId'],binding['principal'])
 require(binding['schema']=='samlscope-shibboleth-g02-known-subject-v1' and binding['inputValue']=='aZ09'*64 and binding['inputCodePoints']==256
  and binding['formats']==['persistent','transient'] and binding['preservationClaimed'] is False,'Known-principal prerequisite differs')
 plan=READ(child/'plan.json')['plan']['plan']['id'];require(binding['suiteEntityId']=='http://localhost:18080/p/'+plan,'Native SP scope differs')
 times={}
 for label in ['before-run','before-protocol','after-protocol']:
  record=READ(folder/(label+'-readback.json'));times[label]=parsed_time(record['recordedAt'])
  for k,row in record['files'].items():
   require(k in configured and (folder/row['file']).read_bytes()==(folder/('configured-'+k+'.xml')).read_bytes()
    and SHA((folder/row['file']).read_bytes())==row['sha256'],'Native configuration readback differs')
 for k in originals:
  require(canonical(ET.fromstring(configured[k]))==canonical(ET.fromstring((folder/('configured-'+k+'.xml')).read_bytes())),'Uncontrolled native configuration change')
  require(originals[k]==(folder/('final-'+k+'.xml')).read_bytes(),'Native configuration not restored')
 restoration=READ(folder/'restoration.json');require(restoration['restored'] is True and not restoration['errors']
  and restoration['original']==restoration['final']=={k:SHA(raw) for k,raw in originals.items()},'Native restoration original/hash mismatch')
 run=READ(child/'created.json')['run'];require(times['before-run']<=float(run['createdAt'])<=times['before-protocol']<times['after-protocol'],'Native configuration chronology differs')
 entries=READ(child/'transcript.json');byid={e['id']:e for e in entries};manifest={r['id']:r for r in READ(child/'decoded-manifest.json')}
 audit={};audits=(folder/'native-request-bound-audit.log').read_text().splitlines()
 for line in audits:
  fields=line.split('|');require(len(fields)==7 and fields[0]=='SAMLscope-G02-known-v1' and fields[1] not in audit,'Native principal audit ambiguous');audit[fields[1]]=fields
 for row in report['exchanges']+report['unknownSubjectControls']:
  request=byid[row['request']];response=byid[row['response']];raw=(child/manifest[request['id']]['file']).read_bytes();xml=ET.fromstring(raw);fields=audit.get(xml.get('ID'))
  require(fields is not None and fields[2]==binding['suiteEntityId'] and times['before-protocol']<=timestamp(request['timestamp'])<timestamp(response['timestamp'])<=times['after-protocol'],'Native audit/configuration/request scope differs')
  require(fields[5]=='POST' and fields[6]=='http://shibboleth.net/ns/profiles/saml2/sso/browser','Native binding/profile differs')
  if row in report['exchanges']:require(fields[3]==binding['principal'] and fields[4]=='Success','Native known-principal evidence missing')
  else:require(fields[3]=='' and fields[4]=='Requester','Unknown principal accepted')
 require(len(audits)==70,'Actual native operation inventory differs')
 source=READ(folder/'native-source.json');require(SHA((folder/'native-idp-conf-impl.jar').read_bytes())==source['sha256'],'Native source JAR changed')
 with zipfile.ZipFile(folder/'native-idp-conf-impl.jar') as jar:
  config=ET.fromstring(jar.read(source['subjectCanonicalizationResource']));beans='http://www.springframework.org/schema/beans';p='http://www.springframework.org/schema/p'
  found=[n for n in config if n.get('id')=='c14n/SAML2Transform'];require(len(found)==1 and found[0].get('class')=='net.shibboleth.idp.saml.nameid.impl.NameIDCanonicalization'
   and 'shibboleth.NameTransformPredicate' in found[0].get('{'+p+'}activationCondition','') and 'shibboleth.NameTransformFormats' in found[0].get('{'+p+'}formats',''),'Native configured decoder path unproven')
 _verify_target_runtime(child,'shibboleth',float(run['createdAt']))
 for label in ['start','end']:require(READ(child/('target-container-inspect-'+label+'.json'))[0]['Image']==NATIVE_IMAGE,'Native image changed')
 ops=READ(folder/'operations.json');counts=READ(folder/'operation-counts.json');childcounts=READ(child/'operation-counts.json')
 require(len(ops)==6 and sum(o['operation']=='product-config-write' for o in ops)==4 and sum(o['operation']=='product-restart' for o in ops)==2
  and all(o.get('readBack',o.get('completed')) is True for o in ops),'Native apply/restore operations incomplete')
 require(counts['product_configuration_writes']==4 and counts['restoration_writes']==2 and counts['product_restarts']==2 and counts['restored'] is True and counts['human_operations']==0,'Native operation counts differ')
 require(childcounts['configuration_write_attempts']==3 and childcounts['restoration_write_attempts']==1 and childcounts['reloads']==2
  and childcounts['target_submissions']==69 and childcounts['skipped_before_target_submission']==88 and childcounts['human_operations']==0
  and childcounts['product_restarts']==0 and childcounts['restored'] is True,'Browser/Suite-only skip operation counts differ')
 require((child/'original-providers.xml').read_bytes()==(child/'final-providers.xml').read_bytes() and READ(child/'restoration.json')['restored'] is True,'Native metadata source not restored')
def stored(archive):
 source=archive/'stored-readback-source.java';require(SHA(source.read_bytes())==STORED,'Stored helper changed')
 coverage=(archive/'approved-coverage-original.yaml').read_bytes();require(SHA(coverage)==COVERAGE,'Approved source changed')
 def levels(node):
  if isinstance(node,dict):
   if 'key' in node and 'level' in node:yield node['key'],node['level']
   for v in node.values():yield from levels(v)
  elif isinstance(node,list):
   for v in node:yield from levels(v)
 require(dict(levels(yaml.safe_load(coverage)))['IIP-G02.a']=='MUST','Central level differs')
 with tempfile.TemporaryDirectory(prefix='samlscope-g02-conclusion-') as temporary:
  temporary=pathlib.Path(temporary);file=temporary/'ReadShibbolethG02StoredConclusion.java';file.write_bytes(source.read_bytes());classes=temporary/'classes';classes.mkdir();cp=':'.join(map(str,jars(archive)))+':'+dependency_classpath(archive)
  command(['javac','-cp',cp,'-d',str(classes),str(file)]);raw=command(['java','-cp',cp+':'+str(classes),'com.samlscope.runner.cases.ReadShibbolethG02StoredConclusion','offline',str((archive/'stored-case-conclusions.json').resolve())]).stdout
  require(raw==(archive/'stored-case-conclusions.json').read_bytes(),'Archived central Evaluator differs')
 return json.loads(raw)
def verify(root):
 folder=pathlib.Path(root)/FOLDER;archive=folder/'reader-v181-predeployment';report=replay(folder);native(folder,report)
 originals=READ(folder/'acceptance-originals.json')
 require(all(SHA((folder/name).read_bytes())==digest for name,digest in originals.items()),'Adopted original bytes changed')
 run=READ(folder/'browser/created.json')['run']['id'];resultpath=archive/'evaluation-terminal-http-v1/result.json';result=READ(resultpath);case=find_case(result,CASE)
 require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+report['targetMetadataSha256'],'Formal Run/target differs')
 require((case['outcome'],case['verdict'],case['attested'])==('SATISFIED','PASS',False) and case['evidence']==report['outcome']['evidence'] and case['reason_code']==report['outcome']['reasonCode'],'Formal differs from archived production')
 before=READ(archive/'evaluation-terminal-http-v1/transcript-before.json');require(before==READ(archive/'evaluation-terminal-http-v1/transcript.json')==READ(archive/'transcript.json'),'v181 formal changed originals')
 final=READ(folder/'browser/transcript.json');require(final[:len(before)]==before,'v181 original history changed after continued controls')
 require(find_case(READ(folder/'reader-v182-final/evaluation-terminal-http-v1/result.json'),CASE)==case
  and READ(folder/'reader-v182-final/evaluation-terminal-http-v1/transcript-before.json')==final==READ(folder/'reader-v182-final/evaluation-terminal-http-v1/transcript.json'),'Final formal/originals differs')
 _verify_suite_runtime(archive,run,float(READ(folder/'browser/created.json')['run']['createdAt']),PINS)
 conclusion=stored(archive);require(conclusion['runId']==run and set(conclusion['cases'])=={CASE},'Selected public conclusion scope differs');item=conclusion['cases'][CASE]
 require(item['status']=='FINISHED' and item['verdict']=='PASS' and item['outcome']==report['outcome'],'Stored full CaseOutcome differs')
 # The interrupted deployment changed a UI caption leaf; actual G02 code stays byte-identical.
 with zipfile.ZipFile(archive/'suite-runner-0.1.0.jar') as old,zipfile.ZipFile(folder/'reader-v182-final/suite-runner-0.1.0.jar') as new:
  names=[n for n in old.namelist() if n.startswith(('com/samlscope/runner/cases/IdpExecutableBrowserFixtureScenarioTestCase','com/samlscope/runner/scenario/FixtureScenarioTestCase')) and n.endswith('.class')]
  require(names and all(old.read(n)==new.read(n) for n in names),'G02 production case changed during campaign')
 return resultpath,{CASE:case}

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=pathlib.Path);parser.add_argument('--retain-replay',action='store_true');args=parser.parse_args()
 if args.retain_replay:print(replay(args.root/FOLDER,True)['runId'],'production replay retained')
 else:print(verify(args.root))
