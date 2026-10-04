#!/usr/bin/env python3
"""Two public-input native SDK detector calls. Never live product findings or SAML sends.

Only run after the genuine campaign restores the target. Both producer modes and exact
invocations are immutable. The default product reader rejects these diagnostic originals.
"""
import argparse,datetime,hashlib,json,pathlib,re,subprocess,zipfile,xml.etree.ElementTree as ET
REPO=pathlib.Path(__file__).resolve().parents[2]
SOURCE=REPO/'dev/shibboleth/ShibbolethDefaultAlgorithmCalibration.java'
SOURCE_SHA='027312995daaca8f7b91e4dc1978111abeec505daf73ed5b3cd4c33e94536000'
NATIVE='samlscope-reference-shibboleth'
SHA=lambda b:hashlib.sha256(b).hexdigest()
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
MODES=('stock-policy','developer-missing-default-prevention')
FIXTURES=('sha256-control','invalid-sha256-signature','md5-digest','rsa-md5')
def require(value,reason):
 if not value:raise ValueError(reason)
def raw(path,value):
 require(not path.exists() and not path.is_symlink(),'Immutable diagnostic output exists');path.write_bytes(value)
def save(path,value):raw(path,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode())
def command(argv,timeout=40,check=True):
 r=subprocess.run(argv,capture_output=True,timeout=timeout)
 if check:require(r.returncode==0,'Public diagnostic command failed: '+str(r.returncode))
 return r
def runtime():
 n=json.loads(command(['docker','inspect',NATIVE]).stdout)[0]
 r=dict(containerId=n['Id'],image=n['Image'],running=n['State']['Running'],startedAt=n['State']['StartedAt'],mounts=n['Mounts'])
 require(r['running'] is True and r['mounts']==[],'Unknown mutable runtime');return r
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--folder',required=True,type=pathlib.Path);p.add_argument('--signature-preflight-only',action='store_true');p.add_argument('--diagnostic-name',default='calibration-preflight');a=p.parse_args();parent=a.folder.resolve();receipt=parent/'receipt'
 if a.signature_preflight_only:
  run=json.loads((parent/'created.json').read_bytes())['run']['id'];m=json.loads((parent/(run+'.preparation.json')).read_bytes())
 else:m=json.loads((receipt/'manifest.json').read_bytes());run=m['runId']
 require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run),'Unsafe Run')
 require(m['counterfactualCalibrationOnly'] is False and json.loads((parent/'restoration.json').read_bytes())['restored'] is True,'Genuine restored campaign required')
 require(SHA(SOURCE.read_bytes())==SOURCE_SHA,'Frozen native producer changed')
 require(re.fullmatch(r'calibration-preflight(?:-r[0-9]+)?',a.diagnostic_name),'Unsafe diagnostic directory');out=parent/(a.diagnostic_name if a.signature_preflight_only else 'calibration');require(not out.exists(),'Diagnostic originals already exist');out.mkdir()
 temporary='/tmp/samlscope-default-calibration-'+run
 require(command(['docker','exec',NATIVE,'sh','-c','test -e '+temporary+' && echo exists || true']).stdout.strip()==b'','Fresh native directory required')
 snapshot=parent if a.signature_preflight_only else parent/'finalized-originals';decoded={r['id']:(snapshot/r['file'],r['sha256']) for r in json.loads((snapshot/'decoded-manifest.json').read_bytes())}
 records=[]
 if a.signature_preflight_only:
  by_fixture={};transcript=json.loads((parent/'transcript.json').read_bytes());http=json.loads((parent/'native-http.json').read_bytes())
  for fixture in FIXTURES:
   selected=[r for r in transcript if r.get('runId')==run and r.get('direction')=='OUTBOUND' and r.get('samlSummary',{}).get('scenario_case_id')=='IIP-ALG08-c-idp-01' and r.get('samlSummary',{}).get('fixture_id')==fixture and r.get('samlSummary',{}).get('type')=='AuthnRequest']
   require(len(selected)==1,'Exact same-Run selected signature original missing');entry=selected[0];require(entry['decodedSamlRef']=='transcripts/'+run+'/'+entry['id']+'.saml.xml','Foreign signature original path');path,digest=decoded[entry['id']];data=path.read_bytes();root=ET.fromstring(data)
   require(SHA(data)==digest and len(data)==entry['decodedSamlBytes'] and len([h for h in http if h.get('requestId')==root.get('ID') and h.get('requestSha256')==digest])==1,'Actual signature input hash/transport mismatch');by_fixture[fixture]=dict(requestReference=entry['id'],requestSha256=digest)
 else:by_fixture={r['fixtureId']:r for r in m['observations']}
 for fixture in FIXTURES:
  row=by_fixture[fixture];path,digest=decoded[row['requestReference']];data=path.read_bytes();require(SHA(data)==row['requestSha256']==digest,'Original request changed')
  name=fixture+'.request.xml';raw(out/name,data);records.append(dict(fixtureId=fixture,requestId=ET.fromstring(data).attrib['ID'],requestSha256=SHA(data),requestFile=temporary+'/'+name))
 suite=(receipt/m['registeredSuiteMetadataFile']).read_bytes();require(SHA(suite)==m['suiteMetadataSha256'],'Registered metadata changed');raw(out/'registered-suite-metadata.xml',suite)
 input_value=dict(runId=run,suiteMetadataFile=temporary+'/suite-metadata.xml',suiteMetadataSha256=SHA(suite),suiteEntityId=ET.fromstring(suite).attrib['entityID'],targetMetadataSha256=m['targetMetadataSha256'],targetEntityId=m['targetEntityId'],records=records)
 save(out/'calibration-input.json',input_value);raw(out/'calibration-producer.java',SOURCE.read_bytes())
 logback=b'<configuration><root level="OFF"/></configuration>\n';raw(out/'calibration-logback.xml',logback)
 ledger=dict(schema='samlscope-default-algorithm-diagnostic-operations-v1',runId=run,diagnosticOnly=True,controlsAdopted=False,signaturePreflightOnly=a.signature_preflight_only,productSettings=0,protocolSubmissions=0,credentialPosts=0,personOperations=0,nativeCompilerCalls=0,nativeJavaCalls=0,temporaryRemoved=False,attempts=[])
 command(['docker','exec',NATIVE,'mkdir','-p',temporary+'/classes']);before=runtime();save(out/'calibration-native-before.json',before)
 try:
  inputs={'ShibbolethDefaultAlgorithmCalibration.java':SOURCE,'input.json':out/'calibration-input.json','suite-metadata.xml':out/'registered-suite-metadata.xml','logback.xml':out/'calibration-logback.xml'}
  inputs.update({f+'.request.xml':out/(f+'.request.xml') for f in FIXTURES})
  for name,path in inputs.items():
   command(['docker','cp',str(path),NATIVE+':'+temporary+'/'+name]);require(command(['docker','exec',NATIVE,'cat',temporary+'/'+name]).stdout==path.read_bytes(),'Native input/source readback mismatch')
  argv=['javac','-cp','/usr/local/tomcat/webapps/idp/WEB-INF/lib/*','-d',temporary+'/classes',temporary+'/ShibbolethDefaultAlgorithmCalibration.java'];start=NOW();r=command(['docker','exec',NATIVE,*argv],timeout=60,check=False);ledger['nativeCompilerCalls']+=1
  save(out/'calibration-compile-invocation.json',dict(command=argv,startedAt=start,completedAt=NOW(),exitCode=r.returncode,sourceSha256=SOURCE_SHA,stdoutSha256=SHA(r.stdout),stderrSha256=SHA(r.stderr)));raw(out/'calibration-compile.stdout',r.stdout);raw(out/'calibration-compile.stderr',r.stderr);require(r.returncode==0,'Native diagnostic compile failed')
  class_selection=None
  for mode in MODES:
   argv=['java','-Dlogback.configurationFile='+temporary+'/logback.xml','-cp',temporary+'/classes:/usr/local/tomcat/webapps/idp/WEB-INF/lib/*','ShibbolethDefaultAlgorithmCalibration',mode,temporary+'/input.json',temporary+'/ShibbolethDefaultAlgorithmCalibration.java']
   start=NOW();r=command(['docker','exec',NATIVE,*argv],timeout=45,check=False);ledger['nativeJavaCalls']+=1
   call=dict(schema='samlscope-shibboleth-default-calibration-invocation-v1',runId=run,selectedPath=mode,command=argv,startedAt=start,completedAt=NOW(),exitCode=r.returncode,sourceFile='calibration-producer.java',sourceSha256=SOURCE_SHA,inputFile='calibration-input.json',inputSha256=SHA((out/'calibration-input.json').read_bytes()),stdoutFile=mode+'.stdout.json',stdoutSha256=SHA(r.stdout),stderrSha256=SHA(r.stderr),nativeBeforeFile='calibration-native-before.json',nativeAfterFile='calibration-native-after.json')
   ledger['attempts'].append(call);save(out/(mode+'.invocation.json'),call);raw(out/(mode+'.stdout.json'),r.stdout);raw(out/(mode+'.stderr'),r.stderr)
   require(r.returncode==0 and r.stderr==b'','Native diagnostic failed; no fabricated calibration')
   value=json.loads(r.stdout);require(value['runId']==run and value['selectedPath']==mode and value['producerSourceSha256']==SOURCE_SHA and value['inputSha256']==call['inputSha256'] and value['diagnosticOnly'] is True and value['productFinding'] is False and value['privateKeyExported'] is False,'Native selected producer not bound')
   require(value['selectedConsumer']=='native-SignatureAlgorithmValidator-fixture-only' and value['stockDecoderAcceptanceEvaluated'] is False,'Selected diagnostic consumer scope changed')
   if class_selection is None:class_selection=value['nativeClasses']
   else:require(class_selection==value['nativeClasses'],'Native selected classes changed between modes')
  require(set(class_selection)=={'org.opensaml.xmlsec.signature.support.impl.SignatureAlgorithmValidator','org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap'},'Unknown selected native validator')
  native_jar=receipt/'default-native-opensaml-xmlsec-impl.jar';bindings={}
  with zipfile.ZipFile(native_jar) as archive:
   for name,digest in class_selection.items():
    body=archive.read(name.replace('.','/')+'.class');require(SHA(body)==digest,'Actual selected native class differs from captured native JAR');filename=name.rsplit('.',1)[1]+'.class';raw(out/filename,body);bindings[name]=dict(classFile=filename,classSha256=digest,jarFile='../receipt/default-native-opensaml-xmlsec-impl.jar',jarSha256=SHA(native_jar.read_bytes()))
  save(out/'selected-native-class-originals.json',bindings)
  after=runtime();require(before==after,'Runtime changed during diagnostic');save(out/'calibration-native-after.json',after)
 finally:
  command(['docker','exec',NATIVE,'rm','-rf','--',temporary]);ledger['temporaryRemoved']=True;save(out/'diagnostic-operations.json',ledger)
 save(out/'originals.json',dict(runId=run,diagnosticOnly=True,controlsAdopted=False,files={p.name:SHA(p.read_bytes()) for p in out.iterdir() if p.is_file()}))
 print(run,'diagnostic native compiler1/Java2; product settings/SAML/login0',flush=True)
if __name__=='__main__':main()
