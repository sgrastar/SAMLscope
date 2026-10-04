#!/usr/bin/env python3
"""Native-key signed role-confusion detector fixtures only. No product settings or protocol sends."""
import argparse,datetime,hashlib,json,pathlib,secrets,subprocess,xml.etree.ElementTree as E
CONTAINER='samlscope-reference-shibboleth';SOURCE=pathlib.Path(__file__).with_name('ShibbolethMetadataRoleKeyProducer.java')
SHA=lambda b:hashlib.sha256(b).hexdigest()
def run(*args):return subprocess.run(args,check=True,capture_output=True,timeout=90)
def docker(*args):return run('docker','exec',CONTAINER,*args)
def capture(folder):
 folder=pathlib.Path(folder);out=folder/'calibration';out.mkdir(exist_ok=False);(out/SOURCE.name).write_bytes(SOURCE.read_bytes());(out/'logback.xml').write_bytes(b'<configuration><root level="OFF"/></configuration>\n')
 before=docker('sha256sum','/usr/local/tomcat/webapps/idp/WEB-INF/lib/opensaml-saml-impl-5.2.3.jar').stdout;temporary='/tmp/role-key-calibration-'+secrets.token_hex(6);docker('mkdir',temporary)
 try:
  run('docker','cp',str(SOURCE),CONTAINER+':'+temporary+'/'+SOURCE.name);run('docker','cp',str(out/'logback.xml'),CONTAINER+':'+temporary+'/logback.xml')
  compile=subprocess.run(['docker','exec',CONTAINER,'javac','-cp','/usr/local/tomcat/webapps/idp/WEB-INF/lib/*','-d',temporary,temporary+'/'+SOURCE.name],capture_output=True,timeout=90);(out/'compile.stderr').write_bytes(compile.stderr)
  if compile.returncode:raise ValueError('Native calibration compile failed; safe diagnostics retained')
  rows=[]
  for observation in json.loads((folder/'observations.json').read_bytes()):
   for exchange in observation['exchanges']:
    if not (exchange['fixtureId'].endswith('peer-key') or exchange['fixtureId'].endswith('encryption-key')):continue
    ref=exchange['requestReference'];request=E.fromstring((folder/'decoded'/(ref+'.xml')).read_bytes());at=datetime.datetime.fromisoformat(exchange['nativeEnd'])-datetime.timedelta(milliseconds=1)
    entity=request.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer').text;fixture=exchange['fixtureId'];output=temporary+'/'+fixture
    process=docker('java','-Dlogback.configurationFile='+temporary+'/logback.xml','-cp',temporary+':/usr/local/tomcat/webapps/idp/WEB-INF/lib/*','ShibbolethMetadataRoleKeyProducer',output,'http://localhost:18280/idp/shibboleth',entity,request.get('ID'),request.get('AssertionConsumerServiceURL'),'/opt/reference-idp/credentials/idp-signing.key','/opt/reference-idp/credentials/idp-signing.crt',at.isoformat().replace('+00:00','Z'))
    value=json.loads(process.stdout);raw=docker('cat',output+'/wrong-role-success.xml').stdout;assert SHA(raw)==value['files']['wrong-role-success'];name=fixture+'-synthetic-success.xml';(out/name).write_bytes(raw);rows.append(dict(fixtureId=fixture,file=name,sha256=SHA(raw),requestReference=ref,nativeProducer=value));(out/(fixture+'-stderr.txt')).write_bytes(process.stderr)
  after=docker('sha256sum','/usr/local/tomcat/webapps/idp/WEB-INF/lib/opensaml-saml-impl-5.2.3.jar').stdout;assert before==after
  (out/'producer.json').write_text(json.dumps(dict(schema='samlscope-shibboleth-metadata-role-key-calibration-set-v1',controls=rows,sourceSha256=SHA(SOURCE.read_bytes()),nativeJarReadBackBefore=before.decode().strip(),nativeJarReadBackAfter=after.decode().strip(),nativePrivateKeyExported=False,controlsAdopted=False,productConfigurationWrites=0,protocolOperations=0,productRestarts=0,humanOperations=0),indent=2)+'\n')
 finally:docker('rm','-rf',temporary)
 return len(rows)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=pathlib.Path);a=p.parse_args();print(capture(a.folder),'synthetic native signed expiry detector fixtures captured')
