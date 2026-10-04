#!/usr/bin/env python3
"""Adopt only the complete signed four-fixture exact-context Shibboleth observation."""
import argparse,hashlib,json,pathlib,secrets,subprocess,tempfile
from verify_shibboleth_native_ui_acceptance import dependency_classpath
from verify_terminal_http_acceptance import _verify_suite_runtime,_verify_target_runtime,find_case
REPO=pathlib.Path(__file__).resolve().parents[2]
FOLDER='shibboleth-authn-exact-r1';CASE='IIP-IDP08-a-idp-01';SUITE='samlscope-reference-suite'
PINS={'image_id':'sha256:0a7eb01b2a2599b5d865981c1c6f232f73a31475a856e673664045e19e1442ef','jars':{
 'core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe',
 'runner':'45641e8a03772f3e2687ed475b10db50d6e4c43a4981bfe6c092a94dd3ec6de2',
 'saml':'d8a4b81658187663fb8a31ed6da3c5fdbdde3d02def1c1a513634245c606cf03'}}
STORE='c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'
HELPER='888cfa53c74822b6b4cc1c45828df6fdb06f4b4275da28304a16a9edde9fe2b5';STORED_HELPER='3a3bb8d35d87375e1f930c656a2e63e1e7b153051b621490eec1dc73609a2827'
SHA=lambda b:hashlib.sha256(b).hexdigest();READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
def require(value,message):
 if not value:raise ValueError(message)
def command(args):return subprocess.run(args,check=True,capture_output=True,timeout=90)
def jars(browser):
 r=READ(browser/'suite-runtime-terminal-http.json');paths=[]
 for name,digest in PINS['jars'].items():
  p=browser/r['jars'][name]['file'];require(SHA(p.read_bytes())==r['jars'][name]['sha256']==digest,'Actual project JAR differs');paths.append(p)
 p=browser/'suite-store-0.1.0.jar';require(SHA(p.read_bytes())==STORE,'Archived Store differs');return paths+[p]
def replay(folder,retain=False):
 folder=pathlib.Path(folder);browser=folder/'browser';project=jars(browser);source=folder/'archived-replay-helper.java';require(HELPER is not None and SHA(source.read_bytes())==HELPER,'Archived exact-context helper changed')
 with tempfile.TemporaryDirectory(prefix='shib-exact-replay-') as tmp:
  tmp=pathlib.Path(tmp);classes=tmp/'classes';classes.mkdir();named=tmp/'VerifyShibbolethExactAuthnContext.java';named.write_bytes(source.read_bytes());cp=':'.join(map(str,project))+':'+dependency_classpath(browser)
  command(['javac','-cp',cp,'-d',str(classes),str(named)]);require(all(p.name.startswith('VerifyShibbolethExactAuthnContext') for p in classes.rglob('*.class')),'Helper shadows production')
  remote='/tmp/shib-exact-replay-'+secrets.token_hex(6);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();command(['docker','exec','-u','0',SUITE,'mkdir',remote])
  try:
   inputs=['created.json','transcript.json','decoded-manifest.json','target-metadata.xml','suite-sp-metadata.xml','decoded']
   for p,name in [(browser/name,name) for name in inputs]+[(classes,'classes')]+[(p,p.name) for p in project]:command(['docker','cp',str(p),SUITE+':'+remote+'/'+name])
   command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote]);cp=':'.join(remote+'/'+p.name for p in project)+':'+remote+'/classes:/opt/samlscope/lib/*'
   executed=subprocess.run(['docker','exec',SUITE,'java','-cp',cp,'com.samlscope.runner.cases.VerifyShibbolethExactAuthnContext',remote,remote+'/report.json'],capture_output=True,timeout=90)
   require(executed.returncode==0,'Archived production replay failed: '+executed.stderr.decode(errors='replace')[-1200:]);command(['docker','cp',SUITE+':'+remote+'/report.json',str(tmp/'report.json')]);raw=(tmp/'report.json').read_bytes()
  finally:command(['docker','exec','-u','0',SUITE,'rm','-rf',remote])
 saved=folder/'production-replay.json'
 if retain:require(not saved.exists(),'Refusing to overwrite production replay');saved.write_bytes(raw)
 else:require(saved.read_bytes()==raw,'Actual archived production replay differs')
 report=json.loads(raw);require(report['outcome']['outcome']=='SATISFIED' and len(report['exchanges'])==4,'Complete production scenario differs')
 require(report['semanticControls']==dict(**{'missing-response':'NOT_VERIFIED','wrong-correlation':'NOT_VERIFIED','wrong-class':'VIOLATED','wrong-declaration':'VIOLATED','accept-unavailable':'VIOLATED','unsatisfiable-requester':'VIOLATED'}),'Semantic detection controls differ')
 require(report['bindingControls']=={key:'NOT_VERIFIED' for key in ['foreign-run','duplicate-entry','missing-response','tampered-request','tampered-response','wrong-decryption-key']},'Invalid originals adopted')
 require(report['productOperations']==0 and report['privateCredentialsPersisted'] is report['decryptedAssertionPersisted'] is False,'Replay performed product operations or persisted credentials');return report

def stored(folder,retain=False):
 browser=folder/'browser';source=folder/'archived-stored-helper.java';require(STORED_HELPER is not None and SHA(source.read_bytes())==STORED_HELPER,'Stored public helper changed')
 with tempfile.TemporaryDirectory(prefix='shib-exact-stored-') as tmp:
  tmp=pathlib.Path(tmp);classes=tmp/'classes';classes.mkdir();named=tmp/'ReadShibbolethExactAuthnContextStoredConclusion.java';named.write_bytes(source.read_bytes());cp=':'.join(map(str,jars(browser)))+':'+dependency_classpath(browser);command(['javac','-cp',cp,'-d',str(classes),str(named)])
  if retain:
   remote='/tmp/shib-exact-stored-'+secrets.token_hex(6);uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();command(['docker','exec','-u','0',SUITE,'mkdir',remote])
   try:
    command(['docker','cp',str(classes),SUITE+':'+remote+'/classes']);command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,remote]);raw=command(['docker','exec',SUITE,'java','-cp',remote+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.ReadShibbolethExactAuthnContextStoredConclusion','capture',READ(browser/'created.json')['run']['id']]).stdout
   finally:command(['docker','exec','-u','0',SUITE,'rm','-rf',remote])
   require(not (folder/'stored-case-conclusion.json').exists(),'Refusing to overwrite stored original');(folder/'stored-case-conclusion.json').write_bytes(raw)
  original=folder/'stored-case-conclusion.json';raw=command(['java','-cp',cp+':'+str(classes),'com.samlscope.runner.cases.ReadShibbolethExactAuthnContextStoredConclusion','offline',str(original.resolve())]).stdout;require(raw==original.read_bytes(),'Archived central Evaluator differs');return json.loads(raw)
def verify(root):
 folder=pathlib.Path(root)/FOLDER;browser=folder/'browser';originals=READ(folder/'acceptance-originals.json');require(all(SHA((folder/name).read_bytes())==digest for name,digest in originals.items()),'Accepted original bytes changed')
 created=READ(browser/'created.json')['run'];run=created['id'];report=replay(folder);require(report['runId']==run,'Foreign production replay');_verify_suite_runtime(browser,run,float(created['createdAt']),PINS);_verify_target_runtime(browser,'shibboleth',float(created['createdAt']))
 original=(folder/'original-authn.properties').read_bytes();configured=(folder/'configured-authn.properties').read_bytes();require(original==(folder/'final-authn.properties').read_bytes(),'Native authn setup not restored');require(configured==(folder/'configured-authn-readback.properties').read_bytes()==(folder/'after-authn-readback.properties').read_bytes(),'Native principal setup changed during protocol')
 suffix=b'\n# Temporary exact AuthnContext fixture; restored after collection.\nidp.authn.Password.supportedPrincipals = saml2/urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport, saml2/urn:oasis:names:tc:SAML:2.0:ac:classes:Password, saml1/urn:oasis:names:tc:SAML:1.0:am:password, saml2declref/urn:samlscope:fixture:authn-context-decl\n';require(configured==original+suffix,'Uncontrolled principal setup')
 restored=READ(folder/'restoration.json');require(restored['restored'] is True and restored['failures']==[] and restored['original_sha256']==restored['final_sha256']==SHA(original),'Authn restoration hash differs');require(READ(folder/'operation-counts.json')==dict(restored=True,person_operations=0,product_configuration_writes=2,restoration_writes=1,product_restarts=2),'Authn counts differ')
 require((browser/'original-providers.xml').read_bytes()==(browser/'final-providers.xml').read_bytes() and READ(browser/'restoration.json')['restored'] is True,'Native provider not restored');ops=READ(browser/'operation-counts.json');expected=dict(configuration_write_attempts=3,restoration_write_attempts=1,reloads=2,target_submissions=6,initial_baseline_submissions=1,prepared_actions=162,skipped_before_target_submission=156,login_submissions=1,fresh_session_boundaries=0,reused_authenticated_client_submissions=6,human_operations=0,product_restarts=0);require(all(ops[k]==v for k,v in expected.items()) and ops['restored'] is ops['authenticated_session_reuse_enabled'] is True,'Browser/user-operation counts differ')
 path=browser/'evaluation-terminal-http-v1/result.json';result=READ(path);case=find_case(result,CASE);require(result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+report['targetMetadataSha256'],'Formal Run/target differs');require(case['outcome']=='SATISFIED' and case['verdict']=='PASS' and case['attested'] is False and case['evidence_class']=='PROTOCOL_OBSERVED' and case['reason_code']==report['outcome']['reasonCode'] and case['evidence']==report['outcome']['evidence'],'Formal central result differs')
 require(READ(browser/'transcript.json')==READ(browser/'evaluation-terminal-http-v1/transcript-before.json')==READ(browser/'evaluation-terminal-http-v1/transcript.json'),'Formal replay changed transcript');conclusion=stored(folder);item=conclusion['cases'][CASE];require(conclusion['runId']==run and item['status']=='FINISHED' and item['verdict']=='PASS' and item['outcome']==report['outcome'],'Stored CaseOutcome differs')
 for unknown in ['IIP-IDP12-d-idp-01','IIP-IDP12-f-idp-01']:require(find_case(result,unknown)['outcome']=='NOT_VERIFIED','Unknown delivery was promoted')
 return path,{CASE:case}
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=pathlib.Path);parser.add_argument('--retain-replay',action='store_true');parser.add_argument('--capture-stored',action='store_true');args=parser.parse_args();folder=args.root/FOLDER
 if args.retain_replay:print(replay(folder,True)['runId'],'archived production replay retained')
 elif args.capture_stored:print(stored(folder,True)['runId'],'stored original retained')
 else:print(verify(args.root))
