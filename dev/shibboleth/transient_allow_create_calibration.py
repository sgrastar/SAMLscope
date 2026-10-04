#!/usr/bin/env python3
"""Four native signed detector controls; never product observations or protocol sends."""
import argparse,hashlib,json,pathlib,subprocess,xml.etree.ElementTree as E
REPO=pathlib.Path(__file__).resolve().parents[2];CONTAINER='samlscope-reference-shibboleth';SOURCE=pathlib.Path(__file__).with_name('ShibbolethTransientAllowCreateProducer.java')
SHA=lambda b:hashlib.sha256(b).hexdigest()
def command(args):return subprocess.run(args,capture_output=True,check=True,timeout=90)
def main():
 p=argparse.ArgumentParser();p.add_argument('root',type=pathlib.Path);a=p.parse_args();root=a.root.resolve();out=root/'calibration';out.mkdir(exist_ok=False);(out/SOURCE.name).write_bytes(SOURCE.read_bytes());(out/'logback.xml').write_text('<configuration><root level="OFF"/></configuration>\n')
 entries=json.loads((root/'transcript.json').read_bytes());request=next(e for e in entries if e['samlSummary'].get('scenario_case_id')=='IIP-SSO01-fp-idp-01' and e['samlSummary'].get('fixture_id')=='transient-allow-create-true');xml=E.fromstring((root/'decoded'/(request['id']+'.xml')).read_bytes());entity=xml.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer').text;temporary='/tmp/samlscope-fp-calibration-'+SHA(str(root).encode())[:16]
 command(['docker','exec',CONTAINER,'mkdir',temporary])
 try:
  for source in [SOURCE,out/'logback.xml']:command(['docker','cp',str(source),CONTAINER+':'+temporary+'/'+source.name])
  compiled=subprocess.run(['docker','exec',CONTAINER,'javac','-cp','/usr/local/tomcat/webapps/idp/WEB-INF/lib/*','-d',temporary,temporary+'/'+SOURCE.name],capture_output=True);(out/'compile.stdout').write_bytes(compiled.stdout);(out/'compile.stderr').write_bytes(compiled.stderr)
  if compiled.returncode:raise ValueError('Native calibration compiler failed; diagnostics retained')
  result=command(['docker','exec',CONTAINER,'java','-Dlogback.configurationFile='+temporary+'/logback.xml','-cp',temporary+':/usr/local/tomcat/webapps/idp/WEB-INF/lib/*','ShibbolethTransientAllowCreateProducer',temporary+'/controls','http://localhost:18280/idp/shibboleth',entity,xml.get('ID'),xml.get('AssertionConsumerServiceURL'),'/opt/reference-idp/credentials/idp-signing.key','/opt/reference-idp/credentials/idp-signing.crt']);value=json.loads(result.stdout);assert value['nativePrivateKeyExported'] is False and value['controlsAdopted'] is False
  (out/'producer.stdout').write_bytes(result.stdout);(out/'producer.stderr').write_bytes(result.stderr)
  for name,digest in value['files'].items():
   raw=command(['docker','exec',CONTAINER,'cat',temporary+'/controls/'+name+'.xml']).stdout;assert SHA(raw)==digest;(out/(name+'.xml')).write_bytes(raw)
  (out/'producer.json').write_text(json.dumps(dict(value,sourceSha256=SHA(SOURCE.read_bytes()),positiveRequestReference=request['id'],productConfigurationWrites=0,protocolOperations=0,productRestarts=0,humanOperations=0),sort_keys=True,indent=2)+'\n')
 finally:command(['docker','exec',CONTAINER,'rm','-rf',temporary])
 print('Four native signed transient controls captured; no product operation')
if __name__=='__main__':main()
