#!/usr/bin/env python3
"""Two selected public native diagnostics. No target settings, SAML sends or logins."""
import argparse,base64,datetime,hashlib,json,pathlib,secrets,subprocess
REPO=pathlib.Path(__file__).resolve().parents[2]
PHP=pathlib.Path(__file__).with_suffix('.php')
SHA=lambda b:hashlib.sha256(b).hexdigest()
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def command(args,**kw):return subprocess.run(args,check=True,capture_output=True,timeout=45,**kw)
def identity():
 raw=command(['docker','inspect','samlscope-reference-ssp','--format','{{json .Id}} {{json .Image}} {{json .State.Running}}']).stdout.decode().split()
 return dict(Id=json.loads(raw[0]),Image=json.loads(raw[1]),State=dict(Running=json.loads(raw[2])))
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();src=a.input.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 m=json.loads((src/'receipt/manifest.json').read_bytes());created=json.loads((src/'created.json').read_bytes())['run'];assert m['runId']==created['id'] and m['adapter']=='simplesamlphp-native-role-key-consumption-v1'
 decoded={r['id']:r for r in json.loads((src/'decoded-manifest.json').read_bytes())};entries={r['id']:r for r in json.loads((src/'transcript.json').read_bytes())};rows=[]
 for epoch in m['observations']:
  normal=[x for x in epoch['exchanges'] if x['fixtureId'].endswith('-normal')];assert len(normal)==1;x=normal[0];e=entries[x['requestReference']];raw=(src/decoded[e['id']]['file']).read_bytes();fixture=(src/'receipt'/(epoch['variant']+'-fixture.xml')).read_bytes();assert SHA(raw)==decoded[e['id']]['sha256'] and e['runId']==created['id']
  rows.append(dict(fixtureId=x['fixtureId'],fixtureSha256=SHA(fixture),metadataBase64=base64.b64encode(fixture).decode(),requestReference=e['id'],requestSha256=SHA(raw),requestBase64=base64.b64encode(raw).decode()))
 value=dict(schema='samlscope-simplesamlphp-self-contained-trust-input-v1',runId=created['id'],peerEntityId=m['entityId'],targetMetadataSha256=m['targetMetadataSha256'],records=rows);producer=PHP.read_bytes();(out/PHP.name).write_bytes(producer);remote='/tmp/self-contained-trust-'+secrets.token_hex(6)+'.php';attempts=[];before=identity();after=None
 try:
  command(['docker','cp',str(PHP),'samlscope-reference-ssp:'+remote])
  for name,path in [('stock','stock-native-signature-encryption'),('mutant','developer-instrumented-additional-anchor')]:
   selected=value|dict(selectedPath=path);raw=json.dumps(selected,separators=(',',':'),sort_keys=True).encode();(out/(name+'-input.json')).write_bytes(raw);start=NOW();argv=['docker','exec','-i','samlscope-reference-ssp','php',remote];native=command(argv,input=raw);attempts.append(dict(operation='grouped-public-native-diagnostic',selectedPath=path,startedAt=start,completedAt=NOW(),exitCode=native.returncode,command=argv,inputSha256=SHA(raw),outputSha256=SHA(native.stdout),sourceSha256=SHA(producer)));(out/(name+'-native-output.json')).write_bytes(native.stdout);n=json.loads(native.stdout);assert n['runId']==created['id'] and n['inputSha256']==SHA(raw) and n['sourceSha256']==SHA(producer) and len(n['records'])==4 and n['nativePrivateKeyUsed'] is False and n['mutantControlsAdopted'] is False and n['selectedPath']==path and n['counterfactualCalibrationOnly'] is (name=='mutant') and n['selectedNativeClasses']==n['selectedNativeClassesAfter']
  after=identity();assert before==after and before['State']['Running'] is True
 finally:
  command(['docker','exec','samlscope-reference-ssp','rm','-f',remote]);(out/'operations.json').write_text(json.dumps(dict(nativePhpDiagnosticCalls=len(attempts),nativeCompilerCalls=0,nativeContainerReadCalls=2,nativeContainerBefore=before,nativeContainerAfter=after,productSettings=0,protocol=0,credentialPosts=0,productRestarts=0,personOperations=0,temporarySourceRemoved=True,attempts=attempts),indent=2)+'\n')
 print(created['id'],'stock signature/explicit anchor-dependency calibration complete')
if __name__=='__main__':main()
