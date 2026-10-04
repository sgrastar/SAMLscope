#!/usr/bin/env python3
"""One public-only native stock decoder call, bound to actual same-Run request originals.

This SDK evidence supplements actual HTTP/process evidence. It cannot prove a product finding
on its own. No configuration, network/SAML, credentials, or private-key access is performed.
"""
import argparse,datetime,hashlib,json,pathlib,re,subprocess,zipfile,xml.etree.ElementTree as ET
REPO=pathlib.Path(__file__).resolve().parents[2]
SOURCE=REPO/'dev/shibboleth/ShibbolethStockUnmarshaller.java'
SOURCE_SHA='cce9485d6941837e143c5d7c62351ad4270997f895a8fb8cb07198824594a34d'
NATIVE='samlscope-reference-shibboleth'
SHA=lambda b:hashlib.sha256(b).hexdigest()
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
SCHEMA='samlscope-shibboleth-stock-unmarshaller-v1'
CLASSES={
 'org.opensaml.core.xml.util.XMLObjectSupport':('stock-native-opensaml-core-api.jar','stock-XMLObjectSupport.class'),
 'org.opensaml.xmlsec.signature.impl.SignatureUnmarshaller':('default-native-opensaml-xmlsec-impl.jar','stock-SignatureUnmarshaller.class'),
 'org.apache.xml.security.signature.XMLSignature':('stock-native-xmlsec.jar','stock-XMLSignature.class'),
 'org.apache.xml.security.algorithms.SignatureAlgorithm':('stock-native-xmlsec.jar','stock-SignatureAlgorithm.class')}
def require(value,reason):
 if not value:raise ValueError(reason)
def original(path,raw):
 require(not path.is_symlink(),'Public original is symlink')
 if path.exists():require(path.read_bytes()==raw,'Immutable public original differs')
 else:path.write_bytes(raw)
def save(path,value):original(path,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode())
def command(argv,timeout=30,check=True):
 r=subprocess.run(argv,capture_output=True,timeout=timeout)
 if check:require(r.returncode==0,'Public stock decoder command failed: '+str(r.returncode))
 return r
def runtime():
 n=json.loads(command(['docker','inspect',NATIVE]).stdout)[0]
 value=dict(containerId=n['Id'],image=n['Image'],running=n['State']['Running'],startedAt=n['State']['StartedAt'],mounts=n['Mounts'])
 require(value['running'] is True and value['mounts']==[],'Unknown mutable native runtime');return value
def actual_inputs(parent,run,observations):
 rows=json.loads((parent/'transcript.json').read_bytes());decoded=json.loads((parent/'decoded-manifest.json').read_bytes())
 paths={r['id']:(parent/r['file'],r['sha256']) for r in decoded};require(len(paths)==len(decoded),'Duplicate decoded originals')
 http=json.loads((parent/'native-http.json').read_bytes())
 by_fixture={r['fixtureId']:r for r in observations};selected=[]
 for fixture in ('sha256-control','rsa-md5'):
  expected=by_fixture.get(fixture)
  candidates=[r for r in rows if r.get('runId')==run and r.get('direction')=='OUTBOUND' and r.get('samlSummary',{}).get('fixture_id')==fixture
      and r.get('samlSummary',{}).get('scenario_case_id')=='IIP-ALG08-c-idp-01' and r.get('samlSummary',{}).get('active_probe') is True and r.get('samlSummary',{}).get('type')=='AuthnRequest']
  if expected:candidates=[r for r in candidates if r['id']==expected['requestReference']]
  require(len(candidates)==1,'Same-Run stock decoder request missing or ambiguous');entry=candidates[0]
  require(entry['id'] in paths and entry.get('decodedSamlRef')=='transcripts/'+run+'/'+entry['id']+'.saml.xml','Foreign original path')
  path,digest=paths[entry['id']];raw=path.read_bytes();require(len(raw)==entry['decodedSamlBytes'] and SHA(raw)==digest,'Original byte count/hash changed')
  if expected:require(SHA(raw)==expected['requestSha256'],'Original request hash changed')
  root=ET.fromstring(raw);require(root.tag=='{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest','Foreign native decoder input')
  matching=[h for h in http if h.get('requestId')==root.get('ID') and h.get('requestSha256')==digest and h.get('requestMethod')=='POST' and h.get('requestUrl')==root.get('Destination')]
  require(len(matching)==1,'Exact actual native HTTP input unavailable')
  selected.append((fixture,entry,raw,root))
 return selected
def capture(parent,manifest,observations,partial_diagnostic=False,diagnostic_name='stock-decoder-diagnostic'):
 require(re.fullmatch(r'stock-decoder-diagnostic(?:-r[0-9]+)?',diagnostic_name),'Unsafe diagnostic directory')
 parent=parent.resolve();source_folder=parent/'receipt';folder=parent/diagnostic_name if partial_diagnostic else source_folder
 if partial_diagnostic:folder.mkdir(exist_ok=False)
 run=manifest['runId'];require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run),'Unsafe Run')
 require(SHA(SOURCE.read_bytes())==SOURCE_SHA,'Frozen stock decoder producer changed')
 require(json.loads((parent/'restoration.json').read_bytes())['restored'] is True,'Restore before stock decoder diagnostic')
 temporary='/tmp/samlscope-stock-unmarshaller-'+run
 require(command(['docker','exec',NATIVE,'sh','-c','test -e '+temporary+' && echo exists || true']).stdout.strip()==b'','Fresh native public diagnostic directory required')
 selected=actual_inputs(parent,run,observations);records=[]
 for fixture,entry,raw,root in selected:
  name=fixture+'-unmarshaller-request.xml';original(folder/name,raw)
  records.append(dict(fixtureId=fixture,requestReference=entry['id'],originalPath=entry['decodedSamlRef'],requestId=root.get('ID'),requestSha256=SHA(raw),requestFile=temporary+'/'+name))
 suite=(source_folder/manifest['registeredSuiteMetadataFile']).read_bytes();target=(parent/'target-metadata.xml').read_bytes()
 require(SHA(suite)==manifest['suiteMetadataSha256'] and SHA(target)==manifest['targetMetadataSha256'],'Fixed metadata original changed')
 original(folder/'stock-unmarshaller-suite.xml',suite);original(folder/'stock-unmarshaller-target.xml',target);original(folder/'stock-unmarshaller-producer.java',SOURCE.read_bytes())
 input_value=dict(runId=run,suiteMetadataFile=temporary+'/stock-unmarshaller-suite.xml',suiteMetadataSha256=SHA(suite),suiteEntityId=ET.fromstring(suite).get('entityID'),
   targetMetadataFile=temporary+'/stock-unmarshaller-target.xml',targetMetadataSha256=SHA(target),targetEntityId=manifest['targetEntityId'],records=records)
 save(folder/'stock-unmarshaller-input.json',input_value)
 logback=b'<configuration><root level="OFF"/></configuration>\n';original(folder/'stock-unmarshaller-logback.xml',logback)
 ledger=dict(schema='samlscope-stock-unmarshaller-diagnostic-operations-v1',runId=run,sdkEvidenceOnly=True,productSettings=0,protocolSubmissions=0,credentialPosts=0,personOperations=0,privateKeyReads=0,nativeCompilerCalls=0,nativeJavaCalls=0,temporaryRemoved=False,attempts=[])
 before=runtime();save(folder/'stock-unmarshaller-native-before.json',before);command(['docker','exec',NATIVE,'mkdir','-p',temporary+'/classes'])
 try:
  inputs={'ShibbolethStockUnmarshaller.java':folder/'stock-unmarshaller-producer.java','stock-unmarshaller-input.json':folder/'stock-unmarshaller-input.json','stock-unmarshaller-logback.xml':folder/'stock-unmarshaller-logback.xml',
   'stock-unmarshaller-suite.xml':folder/'stock-unmarshaller-suite.xml','stock-unmarshaller-target.xml':folder/'stock-unmarshaller-target.xml'}
  inputs.update({f+'-unmarshaller-request.xml':folder/(f+'-unmarshaller-request.xml') for f in ('sha256-control','rsa-md5')})
  for name,path in inputs.items():
   command(['docker','cp',str(path),NATIVE+':'+temporary+'/'+name]);require(command(['docker','exec',NATIVE,'cat',temporary+'/'+name]).stdout==path.read_bytes(),'Native public input/source readback mismatch')
  argv=['javac','-cp','/usr/local/tomcat/webapps/idp/WEB-INF/lib/*','-d',temporary+'/classes',temporary+'/ShibbolethStockUnmarshaller.java'];started=NOW();ledger['nativeCompilerCalls']+=1;r=command(['docker','exec',NATIVE,*argv],timeout=60,check=False)
  save(folder/'stock-unmarshaller-compile-invocation.json',dict(command=argv,startedAt=started,completedAt=NOW(),exitCode=r.returncode,sourceSha256=SHA(SOURCE.read_bytes()),stdoutSha256=SHA(r.stdout),stderrSha256=SHA(r.stderr)))
  original(folder/'stock-unmarshaller-compile.stdout',r.stdout);original(folder/'stock-unmarshaller-compile.stderr',r.stderr);require(r.returncode==0,'Native stock decoder compilation failed')
  argv=['java','-Dlogback.configurationFile='+temporary+'/stock-unmarshaller-logback.xml','-cp',temporary+'/classes:/usr/local/tomcat/webapps/idp/WEB-INF/lib/*','ShibbolethStockUnmarshaller',temporary+'/stock-unmarshaller-input.json',temporary+'/ShibbolethStockUnmarshaller.java']
  started=NOW();ledger['nativeJavaCalls']+=1;r=command(['docker','exec',NATIVE,*argv],timeout=45,check=False)
  call=dict(schema='samlscope-shibboleth-stock-unmarshaller-invocation-v1',runId=run,command=argv,startedAt=started,completedAt=NOW(),exitCode=r.returncode,sourceFile='stock-unmarshaller-producer.java',sourceSha256=SHA(SOURCE.read_bytes()),inputFile='stock-unmarshaller-input.json',inputSha256=SHA((folder/'stock-unmarshaller-input.json').read_bytes()),stdoutFile='stock-unmarshaller.stdout.json',stdoutSha256=SHA(r.stdout),stderrFile='stock-unmarshaller.stderr',stderrSha256=SHA(r.stderr),nativeBeforeFile='stock-unmarshaller-native-before.json',nativeAfterFile='stock-unmarshaller-native-after.json',compileInvocationFile='stock-unmarshaller-compile-invocation.json',operationsFile='stock-unmarshaller-operations.json')
  ledger['attempts'].append(call);original(folder/call['stdoutFile'],r.stdout);original(folder/call['stderrFile'],r.stderr);require(r.returncode==0 and r.stderr==b'','Native stock decoder diagnostic failed')
  value=json.loads(r.stdout);require(value['schema']==SCHEMA and value['runId']==run and value['inputSha256']==call['inputSha256'] and value['producerSourceSha256']==call['sourceSha256'] and value['privateKeysRead'] is False and value['algorithmPolicyChanged'] is False,'Native stock decoder output not bound')
  require(set(value['nativeClasses'])==set(CLASSES),'Unexpected native decoder class selection');origins={}
  for name,(jar_file,class_file) in CLASSES.items():
   origin=value['nativeClasses'][name];native_path=origin['jarPath'];require(native_path.startswith('/usr/local/tomcat/webapps/idp/WEB-INF/lib/') and native_path.endswith('.jar'),'Unsafe native JAR path')
   data=command(['docker','exec',NATIVE,'cat',native_path]).stdout;require(SHA(data)==origin['jarSha256'],'Loaded native JAR changed');original(folder/jar_file,data)
   with zipfile.ZipFile(folder/jar_file) as archive:class_bytes=archive.read(name.replace('.','/')+'.class')
   require(SHA(class_bytes)==origin['classSha256'],'Loaded native class changed');original(folder/class_file,class_bytes);origins[name]=dict(jarFile=jar_file,classFile=class_file)
  call['classOriginals']=origins;save(folder/'stock-unmarshaller-invocation.json',call)
  after=runtime();require(before==after,'Native decoder runtime changed');save(folder/'stock-unmarshaller-native-after.json',after)
 finally:
  command(['docker','exec',NATIVE,'rm','-rf','--',temporary]);ledger['temporaryRemoved']=True;save(folder/'stock-unmarshaller-operations.json',ledger)
 return (folder/'stock-unmarshaller.stdout.json').read_bytes()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--folder',required=True,type=pathlib.Path);p.add_argument('--partial-diagnostic',action='store_true');p.add_argument('--diagnostic-name',default='stock-decoder-diagnostic');a=p.parse_args();parent=a.folder.resolve()
 if a.partial_diagnostic:
  m=json.loads((parent/(json.loads((parent/'created.json').read_bytes())['run']['id']+'.preparation.json')).read_bytes());observations=json.loads((parent/'observations-pending.json').read_bytes())
 else:m=json.loads((parent/'manifest-pending.json').read_bytes());observations=m['observations']
 capture(parent,m,observations,a.partial_diagnostic,a.diagnostic_name);print(m['runId'],'stock decoder compiler1/JVM1; settings/SAML/login/private reads0',flush=True)
if __name__=='__main__':main()
