#!/usr/bin/env python3
"""Reuse a restored same-Run role-key campaign; public native calibration only, no login or SAML."""
import argparse,base64,hashlib,json,os,pathlib,secrets,subprocess,datetime

REPO=pathlib.Path(__file__).resolve().parents[2]
SOURCE=pathlib.Path(__file__).with_name('ShibbolethSelfContainedTrustProducer.java')
CONTAINER='samlscope-reference-shibboleth'
SHA=lambda b:hashlib.sha256(b).hexdigest()
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def inspect():
 fmt='{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}},"mounts":{{json .Mounts}}}'
 return json.loads(run('docker','inspect','--format',fmt,CONTAINER).stdout)
LOAD=lambda p:json.loads(p.read_bytes())
def save(p,n):p.write_text(json.dumps(n,sort_keys=True,indent=2)+'\n')
def run(*a):return subprocess.run(a,check=True,capture_output=True,timeout=60)
def docker(*a):return run('docker','exec',CONTAINER,*a)
def capture(source,out):
 source=source.absolute();out=out.absolute()
 assert not any(p.is_symlink() for p in [source,out,*source.parents,*out.parents]);assert not out.exists()
 receipt=source/'receipt';m=LOAD(receipt/'manifest.json');assert m['schema']=='samlscope-metadata-role-key-consumption-v1' and m['adapter']=='shibboleth-native-filesystem-role-keys-v1'
 assert LOAD(source/'restoration.json')['restored'] is True and LOAD(source/'operation-counts.json')['restored'] is True
 preflight=LOAD(source/'case-slot-preflight.json');slots={c['id'] for row in preflight['requirements'] for c in row['cases']};assert preflight['run']['id']==m['runId'] and preflight['profile']['id']=='metadata-idp' and 'IIP-MD06-c-idp-01' in slots
 out.mkdir();payload=out/'receipt';payload.mkdir();shared=out/'source-role';shared.mkdir();sharedReceipt=shared/'receipt';sharedReceipt.mkdir()
 binding={}
 for p in sorted(receipt.rglob('*')):
  if p.is_file():
   assert not p.is_symlink();dest=sharedReceipt/p.relative_to(receipt);dest.parent.mkdir(parents=True,exist_ok=True);os.link(p,dest);binding[str(p.relative_to(receipt))]=SHA(p.read_bytes())
 for name in ['created.json','target-metadata.xml','transcript.json','decoded-manifest.json','case-slot-preflight.json','restoration.json','operation-counts.json','cumulative-operation-counts.json']:
  assert (source/name).is_file() and not (source/name).is_symlink();(out/name).write_bytes((source/name).read_bytes())
 (out/'decoded').mkdir()
 dm=LOAD(source/'decoded-manifest.json');by={r['id']:r for r in dm}
 for row in dm:
  raw=(source/row['file']).read_bytes();assert SHA(raw)==row['sha256'];destination=out/row['file'];assert destination.parent==out/'decoded';destination.write_bytes(raw)
 records=[]
 for epoch in m['observations']:
  normal=[r for r in epoch['exchanges'] if r['fixtureId'].endswith('-normal')];assert len(normal)==1;row=normal[0];request=by[row['requestReference']];raw=(source/request['file']).read_bytes();assert SHA(raw)==request['sha256']
  metadata=(receipt/(epoch['variant']+'-fixture.xml')).read_bytes()
  import xml.etree.ElementTree as E
  requestId=E.fromstring(raw).get('ID');assert requestId
  records.append(dict(variant=epoch['variant'],fixtureId=row['fixtureId'],peerEntityId=m['entityId'],requestReference=row['requestReference'],requestId=requestId,requestSha256=SHA(raw),metadataSha256=SHA(metadata),metadataBase64=base64.b64encode(metadata).decode(),requestBase64=base64.b64encode(raw).decode()))
 assert len(records)==4
 input=dict(schema='samlscope-shibboleth-self-contained-trust-input-v2',runId=m['runId'],selectedPath='stock-native-signature-encryption',records=records)
 save(payload/'input.json',input);save(payload/'calibration-input.json',dict(input,selectedPath='developer-instrumented-additional-anchor'));(payload/SOURCE.name).write_bytes(SOURCE.read_bytes());(payload/'logback.xml').write_bytes(b'<configuration><root level="OFF"/></configuration>\n')
 nativepaths=["/usr/local/tomcat/webapps/idp/WEB-INF/lib/"+n+'-5.2.3.jar' for n in ['opensaml-saml-impl','opensaml-xmlsec-impl','opensaml-security-impl']]
 before=docker('sha256sum',*nativepaths).stdout;(payload/'native-jars-before.sha256').write_bytes(before)
 temp='/tmp/shib-self-contained-trust-'+secrets.token_hex(6);commands=[];removed=False;compiler=0;calls=0;nativeBefore=inspect();invocation=None
 try:
  docker('mkdir',temp)
  for f in [SOURCE.name,'input.json','calibration-input.json','logback.xml']:run('docker','cp',str(payload/f),CONTAINER+':'+temp+'/'+f)
  compiler+=1;p=docker('javac','-cp','/usr/local/tomcat/webapps/idp/WEB-INF/lib/*','-d',temp,temp+'/'+SOURCE.name);(payload/'compile.stderr').write_bytes(p.stderr)
  for selectedPath,filename in [('stock-native-signature-encryption','native-output.json'),('developer-instrumented-additional-anchor','native-calibration-output.json')]:
   inputName='calibration-input.json' if selectedPath.startswith('developer-') else 'input.json'
   calls+=1;command=['docker','exec',CONTAINER,'java','-Dlogback.configurationFile='+temp+'/logback.xml','-cp',temp+':/usr/local/tomcat/webapps/idp/WEB-INF/lib/*','ShibbolethSelfContainedTrustProducer',temp+'/'+inputName,temp+'/'+SOURCE.name,selectedPath];started=NOW();p=run(*command);commands.append(dict(selectedPath=selectedPath,command=command,startedAt=started,completedAt=NOW(),exitCode=p.returncode,inputSha256=SHA((payload/inputName).read_bytes()),sourceSha256=SHA(SOURCE.read_bytes()),outputSha256=SHA(p.stdout)));(payload/filename).write_bytes(p.stdout);(payload/(filename+'.stderr')).write_bytes(p.stderr)
   n=LOAD(payload/filename);assert n['runId']==m['runId'] and n['inputSha256']==SHA((payload/inputName).read_bytes()) and n['producerSha256']==SHA(SOURCE.read_bytes()) and n['selectedPath']==selectedPath
  after=docker('sha256sum',*nativepaths).stdout;assert before==after;(payload/'native-jars-after.sha256').write_bytes(after)
  securityDigest=next(line.split()[0] for line in before.decode().splitlines() if 'opensaml-security-impl-' in line)
  # Copy a public immutable library only; its bytes are bound to contemporaneous native inventory.
  run('docker','cp',CONTAINER+':'+nativepaths[-1],str(payload/'native-opensaml-security-impl.jar'))
  assert SHA((payload/'native-opensaml-security-impl.jar').read_bytes())==securityDigest
 except subprocess.CalledProcessError as failure:
  (payload/'failed-command.stdout').write_bytes(failure.stdout or b'');(payload/'failed-command.stderr').write_bytes(failure.stderr or b'')
  save(payload/'failed-command.json',dict(command=list(failure.cmd),exitCode=failure.returncode,purpose='public-native-calibration-only',settings=0,protocol=0,credentials=0))
  raise
 finally:
  docker('rm','-rf',temp);removed=True
  save(payload/'operations.json',dict(invocations=commands,nativeContainerBefore=nativeBefore,nativeContainerAfter=inspect(),nativePublicJavaCalls=calls,nativeCompilerCalls=compiler,temporarySourceRemoved=removed,productSettings=0,protocol=0,credentialPosts=0,productRestarts=0,personOperations=0))
 value=dict(schema='samlscope-shibboleth-self-contained-trust-v2',adapter='shibboleth-native-self-contained-trust-v1',caseId='IIP-MD06-c-idp-01',runId=m['runId'],campaignId='native-metadata-trust',targetMetadataSha256=m['targetMetadataSha256'],targetEntityId=__import__('xml.etree.ElementTree',fromlist=['ElementTree']).fromstring((source/'target-metadata.xml').read_bytes()).get('entityID'),peerEntityId=m['entityId'],roleReceiptSha256=SHA((receipt/'manifest.json').read_bytes()),selectedPath='stock-native-signature-encryption',counterfactualCalibrationOnly=False)
 for field,file in [('producer',SOURCE.name),('input','input.json'),('stockInput','input.json'),('stockOutput','native-output.json'),('calibrationInput','calibration-input.json'),('nativeOutput','native-output.json'),('calibrationOutput','native-calibration-output.json'),('operations','operations.json'),('nativeJarBefore','native-jars-before.sha256'),('nativeJarAfter','native-jars-after.sha256'),('nativeSecurityJar','native-opensaml-security-impl.jar')]:value[field+'File']=file;value[field+'Sha256']=SHA((payload/file).read_bytes())
 save(out/'trust-receipt.json',value);save(out/'source-binding.json',dict(source=str(source),files=binding,sourceOperationsReusedNotNew=True,originalTranscriptChanged=False));return m['runId']
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();print(capture(a.source,a.output))
