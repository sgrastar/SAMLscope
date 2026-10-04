#!/usr/bin/env python3
"""One grouped installed-native signature producer for six diagnostic role-confusion responses."""
import argparse,base64,datetime,hashlib,json,pathlib,secrets,subprocess,xml.etree.ElementTree as E
CONTAINER='samlscope-reference-ssp';SOURCE=pathlib.Path(__file__).with_suffix('.php');SHA=lambda b:hashlib.sha256(b).hexdigest()
def capture(folder):
 folder=pathlib.Path(folder);out=folder/'calibration';out.mkdir(exist_ok=False);(out/SOURCE.name).write_bytes(SOURCE.read_bytes());controls=[]
 for row in json.loads((folder/'observations.json').read_bytes()):
  for x in row['exchanges']:
   if not x['fixtureId'].endswith(('peer-key','encryption-key')):continue
   raw=(folder/'decoded'/(x['requestReference']+'.xml')).read_bytes();req=E.fromstring(raw);controls.append(dict(fixtureId=x['fixtureId'],requestReference=x['requestReference'],issuer='http://localhost:18380/idp',entity=req.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer').text,requestId=req.get('ID'),recipient=req.get('AssertionConsumerServiceURL'),instant=x['nativeHttp'][0]['completedAt']))
 assert len(controls)==6;public=json.dumps(dict(controls=controls)).encode();(out/'producer-input.json').write_bytes(public);remote='/tmp/role-calibration-'+secrets.token_hex(6)+'.php'
 try:
  subprocess.run(['docker','cp',str(SOURCE),CONTAINER+':'+remote],check=True,capture_output=True,timeout=20);r=subprocess.run(['docker','exec','-i',CONTAINER,'php',remote],input=public,capture_output=True,timeout=30);(out/'producer.stderr.txt').write_bytes(r.stderr)
  if r.returncode:raise ValueError('Native diagnostic failed; no product result adopted')
  (out/'native-producer-output.json').write_bytes(r.stdout);n=json.loads(r.stdout);assert n['sourceSha256']==SHA(SOURCE.read_bytes()) and n['controlsAdopted'] is False and n['nativePrivateKeyExported'] is False;rows=[]
  for value in n['controls']:
   raw=base64.b64decode(value['responseBase64'],validate=True);assert SHA(raw)==value['sha256'];file=value['fixtureId']+'-synthetic-success.xml';(out/file).write_bytes(raw);original=next(x for x in controls if x['fixtureId']==value['fixtureId']);rows.append(dict(fixtureId=value['fixtureId'],requestReference=original['requestReference'],file=file,sha256=SHA(raw)))
  (out/'producer.json').write_text(json.dumps(dict(schema='samlscope-simplesamlphp-metadata-role-key-calibration-set-v1',controls=rows,sourceSha256=SHA(SOURCE.read_bytes()),nativeOutputSha256=SHA(r.stdout),nativePhpProducerCalls=1,nativeCompilerCalls=0,nativePrivateKeyExported=False,controlsAdopted=False,counterfactualCalibrationOnly=True,productConfigurationWrites=0,protocolOperations=0,productRestarts=0,humanOperations=0),indent=2)+'\n')
 finally:subprocess.run(['docker','exec',CONTAINER,'rm','-f',remote],check=True,capture_output=True,timeout=20)
 return len(rows)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=pathlib.Path);a=p.parse_args();print(capture(a.folder),'counterfactual native detector fixtures, not adopted')
