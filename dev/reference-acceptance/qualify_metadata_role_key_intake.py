#!/usr/bin/env python3
"""Read-only native dual-role metadata conversion; never installs settings or assigns outcomes."""
import argparse,base64,hashlib,json,os,pathlib,subprocess,urllib.request,urllib.parse,datetime,xml.etree.ElementTree as E
ROOT=pathlib.Path(__file__).resolve().parents[2]
VARIANTS=('role-keys-sp-first-explicit-a','role-keys-idp-first-explicit-b','role-keys-sp-first-omitted-a','role-keys-idp-first-omitted-b')
SHA=lambda b:hashlib.sha256(b).hexdigest()
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
PHP=r'''require '/var/simplesamlphp/lib/_autoload.php';$xml=stream_get_contents(STDIN);(new \SimpleSAML\Utils\XML())->checkSAMLMessage($xml,'saml-meta');$all=\SimpleSAML\Metadata\SAMLParser::parseDescriptorsString($xml);$entity=$argv[1];$sp=$all[$entity]->getMetadata20SP();$idp=$all[$entity]->getMetadata20IdP();echo json_encode(['entityId'=>$entity,'sp'=>$sp,'peerIdp'=>$idp,'parserSha256'=>hash_file('sha256','/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php')],JSON_THROW_ON_ERROR);'''
def safe(n):
 if isinstance(n,dict):
  for k,v in n.items():
   if k.lower() in ('secret','registrationaccesstoken') or any(x in k.lower() for x in ('privatekey','private.key','password','authorization','cookie')):raise ValueError('Credential-bearing native result; never persist')
   safe(v)
 elif isinstance(n,list):
  for v in n:safe(v)
def save(p,n):p.write_text(json.dumps(n,indent=2)+'\n')
def expected(role,purpose):
 return {SHA(base64.b64decode("".join(k.find(".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate").text.split()))) for k in role.findall("{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor") if not k.get("use") or k.get("use")==purpose}
def observed(keys,purpose):
 return {SHA(base64.b64decode("".join(k['X509Certificate'].split()))) for k in keys if k.get(purpose)}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixtures',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);(a.output/'ssp-parser-command.php').write_text(PHP)
 b=urllib.parse.urlencode(dict(client_id='admin-cli',username=os.getenv('KEYCLOAK_ADMIN_USERNAME','admin'),password=os.getenv('KEYCLOAK_ADMIN_PASSWORD','admin'),grant_type='password')).encode()
 with urllib.request.urlopen(urllib.request.Request('http://localhost:18180/realms/master/protocol/openid-connect/token',data=b),timeout=15) as r:token=json.load(r)['access_token']
 rows=[]
 for variant in VARIANTS:
  raw=(a.fixtures/(variant+'-fixture.xml')).read_bytes();root=E.fromstring(raw);entity=root.get('entityID');assert len(root.findall('{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor'))==1 and len(root.findall('{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor'))==1
  (a.output/(variant+'-fixture.xml')).write_bytes(raw)
  start=NOW();r=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',PHP,entity],input=raw,capture_output=True,timeout=30);end=NOW();assert r.returncode==0,r.stderr.decode()[-500:];n=json.loads(r.stdout);safe(n);(a.output/(variant+'-ssp.json')).write_bytes(r.stdout)
  req=urllib.request.Request('http://localhost:18180/admin/realms/samlscope/client-description-converter',data=raw,method='POST',headers={'Authorization':'Bearer '+token,'Content-Type':'application/xml'})
  with urllib.request.urlopen(req,timeout=20) as response:kc=response.read();status=response.status
  k=json.loads(kc);safe(k);(a.output/(variant+'-keycloak.json')).write_bytes(kc)
  sp=root.find('{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor');idp=root.find('{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor');ssp_qualified=all(observed(n['sp']['keys'],use)==expected(sp,use) and observed(n['peerIdp']['keys'],use)==expected(idp,use) for use in ['signing','encryption']);kc_qualified=all(('saml.'+use+'.certificate') in k['attributes'] and SHA(base64.b64decode(''.join(k['attributes']['saml.'+use+'.certificate'].split()))) in expected(sp,purpose) for use,purpose in [('signing','signing'),('encryption','encryption')])
  rows.append(dict(variant=variant,sspPurposeQualified=ssp_qualified,keycloakPurposeQualified=kc_qualified,entityId=entity,fixtureSha256=SHA(raw),fullDualRoleInput=True,ssp=dict(exitCode=0,startedAt=start,completedAt=end,rawSha256=SHA(r.stdout),hasSpRole=n['sp'] is not None,hasPeerIdpRole=n['peerIdp'] is not None,spKeys=n['sp'].get('keys'),peerIdpKeys=n['peerIdp'].get('keys')),keycloak=dict(status=status,rawSha256=SHA(kc),clientId=k.get('clientId'),attributes=k.get('attributes'),converterOnlyNotSaved=True)))
 save(a.output/'qualification.json',dict(schema='samlscope-native-role-intake-qualification-v1',recordedAt=NOW(),rows=rows,fixtureSourceIsHistoricalSuiteDiagnostic=True,productProofAdopted=False,operations=dict(nativePhpParserCalls=4,nativeKeycloakConverterCalls=4,adminTokenRequests=1,productWrites=0,samlSubmissions=0,testUserCredentialPosts=0,personOperations=0)))
 print(json.dumps(dict(output=str(a.output),rows=len(rows),productWrites=0,testUserLogins=0)))
if __name__=='__main__':main()
