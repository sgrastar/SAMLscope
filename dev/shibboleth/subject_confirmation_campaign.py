#!/usr/bin/env python3
"""Group native attester-factory closure around one normal/invalid-signature browser exchange.

Only a temporary metadata registration is changed, using the existing outbox-driven
collector and its exact restoration. Profile sources and safe XML configuration
originals are read before/after; no passwords, session handles or keys are exported.
This collector never assigns an outcome.
"""
import argparse,hashlib,json,pathlib,subprocess,sys,zipfile,importlib.util
from datetime import datetime,timezone
REPO=pathlib.Path(__file__).resolve().parents[2]
_spec=importlib.util.spec_from_file_location('shibboleth_native_subject_metadata_batch',pathlib.Path(__file__).with_name('import_metadata_batch.py'))
batch=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(batch)
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
NOW=lambda:datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
CONFIGS={
 'global':'conf/global.xml','services':'conf/services.xml','relying-party':'conf/relying-party.xml','credentials':'conf/credentials.xml',
 'saml-nameid':'conf/saml-nameid.xml','c14n':'conf/c14n/subject-c14n.xml','audit':'conf/audit.xml',
 'attribute-resolver':'conf/attribute-resolver.xml','attribute-filter':'conf/attribute-filter.xml',
 'authn-events':'conf/authn/authn-events-flow.xml','intercept-events':'conf/intercept/intercept-events-flow.xml',
 'conditions-flow':'flows/authn/conditions/conditions-flow.xml'}
JARS=['idp-conf-impl','idp-saml-impl','idp-saml-api','idp-profile-impl','opensaml-saml-impl','opensaml-saml-api','opensaml-profile-impl','idp-admin-impl']
def save(path,value):pathlib.Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def snapshot(out,label,copy_jars=False):
 folder=out/label;folder.mkdir();files={}
 for name,path in CONFIGS.items():
  raw=batch.docker('cat','/opt/reference-idp/'+path);(folder/(name+'.xml')).write_bytes(raw);files[name]=dict(path=path,file=name+'.xml',sha256=SHA(raw))
 # Inventory contains only names and hashes, never arbitrary configuration values.
 inventory=batch.docker('sh','-c','find /opt/reference-idp/flows /opt/reference-idp/conf -type f -name "*.xml" -print | sort').decode().splitlines()
 save(folder/'xml-inventory.json',inventory)
 overrides=batch.docker('sh','-c','find /usr/local/tomcat/webapps/idp/WEB-INF/classes /opt/reference-idp/system -type f 2>/dev/null | sort').decode().splitlines()
 save(folder/'override-source-inventory.json',overrides)
 if overrides:raise ValueError('Unknown native source override; no adoption')
 xml_hashes={path:batch.docker('sha256sum',path).decode().split()[0] for path in inventory}
 save(folder/'xml-inventory-sha256.json',xml_hashes)
 properties=batch.docker('sh','-c','sha256sum /opt/reference-idp/conf/*.properties /opt/reference-idp/conf/authn/*.properties').decode().splitlines()
 save(folder/'properties-sha256.json',{row.split()[1]:row.split()[0] for row in properties})
 safe_properties={}
 for line in batch.docker('cat','/opt/reference-idp/conf/idp.properties').decode().splitlines():
  line=line.strip()
  if not line or line.startswith(('#','!')) or '=' not in line:continue
  key,value=line.split('=',1);key=key.strip()
  if key.startswith(('idp.profile.','idp.service.relyingparty.','idp.postAuthentication','idp.additionalProperties')):safe_properties[key]=value.strip()
 save(folder/'safe-profile-properties.json',safe_properties)
 classpath=batch.docker('sh','-c','sha256sum /usr/local/tomcat/webapps/idp/WEB-INF/lib/*.jar').decode().splitlines()
 save(folder/'classpath-sha256.json',{row.split()[1]:row.split()[0] for row in classpath})
 for name in JARS:
  path='/usr/local/tomcat/webapps/idp/WEB-INF/lib/'+name+'-5.2.3.jar';digest=batch.docker('sha256sum',path).decode().split()[0]
  if copy_jars:
   destination=out/'native-jars'/(name+'.jar');destination.parent.mkdir(exist_ok=True)
   subprocess.run(['docker','cp',batch.CONTAINER+':'+path,str(destination)],check=True,capture_output=True)
   if SHA(destination.read_bytes())!=digest:raise ValueError('Native JAR changed during readback')
  files[name]=dict(path=path,sha256=digest)
 save(folder/'observed.json',dict(recordedAt=NOW(),files=files,productConfigurationWrites=0,privateCredentialsExported=False))
PROFILE_KEYS={'authnContextTranslationStrategy','encryptionOptional','skipEndpointValidationWhenSigned','checkInResponseTo','requireSignedRequests','encryptAttributes','encryptNameIDs','proxiedAuthnInstant','disallowedFeatures','artfactConfiguration','signAssertions','ignoreScoping','signRequests','id','requireSignedAssertions','assertionLifetime','encryptAssertions','resolveAttributes','suppressAuthenticatingAuthority','includeConditionsNotBefore','ignoreRequestSignatures','checkAddress','forceAuthn','randomizeFriendlyName','signResponses'}
def profile_snapshot(out,label):
 created=json.loads((out/'browser/created.json').read_text());entity='http://localhost:18080/p/'+created['run']['planId']
 raw=batch.docker('/opt/reference-idp/bin/dumpconfig.sh','-u','http://localhost:8080/idp','--saml2','-r',entity,'-P','http://shibboleth.net/ns/profiles/saml2/sso/browser')
 value=json.loads(raw)
 # Inspect only the known public native ConfigurationSetting output. Unknown output is
 # rejected in memory before it can be written or displayed.
 if set(value)!={'RelyingPartyConfiguration','ProfileConfiguration'} or set(value['RelyingPartyConfiguration'])!={'detailedErrors','id','securityConfiguration','issuer'} or set(value['ProfileConfiguration'])!=PROFILE_KEYS:raise ValueError('Unknown native public profile schema; no output persisted')
 for group in value.values():
  for key,item in group.items():
   if not isinstance(item,(str,bool,int)) or any(term in key.lower() for term in ['secret','password','cookie','token','private','credential']):raise ValueError('Unexpected native profile field; no output persisted')
 expected={'id':'http://shibboleth.net/ns/profiles/saml2/sso/browser','authnContextTranslationStrategy':'net.shibboleth.idp.saml.authn.principal.impl.MapDrivenAuthnContextTranslationStrategy','artfactConfiguration':'shibboleth.DefaultArtifactConfiguration','assertionLifetime':'PT5M'}
 if any(value['ProfileConfiguration'][key]!=item for key,item in expected.items()) or value['RelyingPartyConfiguration']!={'detailedErrors':False,'id':'shibboleth.DefaultRelyingParty','securityConfiguration':'shibboleth.DefaultSecurityConfiguration','issuer':'http://localhost:18280/idp/shibboleth'}:raise ValueError('Unknown native string setting; no output persisted')
 (out/label/'native-effective-profile.json').write_bytes(raw)
 save(out/label/'native-effective-profile-observed.json',dict(recordedAt=NOW(),requester=entity,profile=expected['id'],source='native-dumpconfig-admin-profile',privateFieldsExported=False))
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=pathlib.Path,required=True);args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
 (out/'collector.py').write_bytes(pathlib.Path(__file__).read_bytes())
 snapshot(out,'original',True)
 original_flow=batch.flow
 def observed_flow(*args,**kwargs):
  snapshot(out,'before-protocol')
  profile_snapshot(out,'before-protocol')
  try:return original_flow(*args,**kwargs)
  finally:
   snapshot(out,'after-protocol')
   profile_snapshot(out,'after-protocol')
 batch.flow=observed_flow
 sys.argv=['import_metadata_batch.py','--output',str(out/'browser'),'--variants','control','--profile','browser_sso_idp','--capture-native-originals']
 try:batch.main()
 finally:
  snapshot(out,'final')
  if any((out/'original'/(name+'.xml')).read_bytes()!=(out/'final'/(name+'.xml')).read_bytes() for name in CONFIGS):raise ValueError('Native profile configuration changed')
  before=json.loads((out/'original/classpath-sha256.json').read_bytes());after=json.loads((out/'final/classpath-sha256.json').read_bytes())
  if before!=after:raise ValueError('Native installed runtime changed')
  save(out/'source-restoration.json',dict(unchanged=True,sourceWrites=0,productRestarts=0,privateCredentialsExported=False))
 print('Native source/configuration closed around grouped ordinary SSO; no outcome adopted')
if __name__=='__main__':main()
