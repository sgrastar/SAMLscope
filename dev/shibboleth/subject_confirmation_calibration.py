#!/usr/bin/env python3
"""Four signed detector controls; target credentials remain in native memory."""
import argparse,hashlib,json,pathlib,subprocess,xml.etree.ElementTree as E
REPO=pathlib.Path(__file__).resolve().parents[2]
CONTAINER='samlscope-reference-shibboleth'
SOURCE=pathlib.Path(__file__).with_name('ShibbolethSubjectConfirmationProducer.java')
SHA=lambda b:hashlib.sha256(b).hexdigest()
def run(*args):return subprocess.run(args,capture_output=True,check=True,timeout=90)
def docker(*args):return run('docker','exec',CONTAINER,*args)
def main():
 p=argparse.ArgumentParser();p.add_argument('root',type=pathlib.Path);a=p.parse_args();root=a.root.resolve();out=root/'calibration-r4';out.mkdir(exist_ok=False)
 (out/SOURCE.name).write_bytes(SOURCE.read_bytes());log=b'<configuration><root level="OFF"/></configuration>\n';(out/'logback.xml').write_bytes(log)
 browser=root/'browser';flow=json.loads((browser/'control/flow.json').read_text());rid=flow['positive_exchange']['request_id'];transcript=json.loads((browser/'transcript.json').read_text());ref=next(e['id'] for e in transcript if e['samlSummary'].get('type')=='AuthnRequest' and e['correlationId']==rid)
 req=E.fromstring((browser/'decoded'/(ref+'.xml')).read_bytes());entity=req.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer').text
 before=docker('sha256sum','/usr/local/tomcat/webapps/idp/WEB-INF/lib/opensaml-saml-impl-5.2.3.jar').stdout
 temporary='/tmp/samlscope-attester-calibration-'+SHA(str(root).encode())[:16];docker('mkdir',temporary)
 try:
  run('docker','cp',str(SOURCE),CONTAINER+':'+temporary+'/'+SOURCE.name);run('docker','cp',str(out/'logback.xml'),CONTAINER+':'+temporary+'/logback.xml')
  c=subprocess.run(['docker','exec',CONTAINER,'javac','-cp','/usr/local/tomcat/webapps/idp/WEB-INF/lib/*','-d',temporary,temporary+'/'+SOURCE.name],capture_output=True);(out/'compile.stdout').write_bytes(c.stdout);(out/'compile.stderr').write_bytes(c.stderr)
  if c.returncode:raise ValueError('Native helper compile failed; diagnostics preserved')
  j=docker('java','-Dlogback.configurationFile='+temporary+'/logback.xml','-cp',temporary+':/usr/local/tomcat/webapps/idp/WEB-INF/lib/*','ShibbolethSubjectConfirmationProducer',temporary+'/controls','http://localhost:18280/idp/shibboleth',entity,rid,req.get('AssertionConsumerServiceURL'),'/opt/reference-idp/credentials/idp-signing.key','/opt/reference-idp/credentials/idp-signing.crt')
  value=json.loads(j.stdout);assert value['nativePrivateKeyExported'] is False and value['controlsAdopted'] is False
  (out/'producer.stdout').write_bytes(j.stdout);(out/'producer.stderr').write_bytes(j.stderr)
  for name,digest in value['files'].items():
   raw=docker('cat',temporary+'/controls/'+name+'.xml').stdout;assert SHA(raw)==digest;(out/(name+'.xml')).write_bytes(raw)
  after=docker('sha256sum','/usr/local/tomcat/webapps/idp/WEB-INF/lib/opensaml-saml-impl-5.2.3.jar').stdout;assert before==after
  (out/'producer.json').write_text(json.dumps(dict(value,sourceSha256=SHA(SOURCE.read_bytes()),positiveRequestReference=ref,productConfigurationWrites=0,protocolOperations=0,productRestarts=0,humanOperations=0),sort_keys=True,indent=2)+'\n')
 finally:docker('rm','-rf',temporary)
 print('Four native signed semantic controls captured; no product outcomes assigned')
if __name__=='__main__':main()
