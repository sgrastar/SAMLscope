#!/usr/bin/env python3
"""Public read-back for selected metadata-key trust; no product changes or private configuration export."""
import datetime,hashlib,json,os,pathlib,re,subprocess,zipfile
REPO=pathlib.Path(__file__).resolve().parents[2]
CONTAINER='samlscope-reference-shibboleth'
CONFIGS={'global':'conf/global.xml','services':'conf/services.xml','relying-party':'conf/relying-party.xml'}
JARS={'idp-conf-impl':'428e389d88bb2abcad19d69bcf759af29f7ce6beb776ccfaa5a6ea76751682ba','idp-saml-impl':'1a2a9f867d11c50eeaf2a6140bb5de88b0611d694ea6de2bbfe32f72a4a2998b','opensaml-saml-impl':'9f04221e172dc426f90fb3873d0148a0744edbf9e7a37de7ee0e6a34f7b74581','opensaml-xmlsec-impl':'cc67fc1bd9cb435cdbe7483ef04513c83cc9619a3015c04ad41bb6cc0eb6e68e'}
OLD=REPO/'build/acceptance/reference-20261001/shibboleth-subject-confirmation-v183-r1/native-jars'
XMLSEC=REPO/'build/acceptance/reference-20261001/shibboleth-rsa-sha1-metadata-v171-r5/native-libraries/opensaml-xmlsec-impl-5.2.3.jar'
PROFILE='http://shibboleth.net/ns/profiles/saml2/sso/browser'
PROFILE_KEYS={'authnContextTranslationStrategy','encryptionOptional','skipEndpointValidationWhenSigned','checkInResponseTo','requireSignedRequests','encryptAttributes','encryptNameIDs','proxiedAuthnInstant','disallowedFeatures','artfactConfiguration','signAssertions','ignoreScoping','signRequests','id','requireSignedAssertions','assertionLifetime','encryptAssertions','resolveAttributes','suppressAuthenticatingAuthority','includeConditionsNotBefore','ignoreRequestSignatures','checkAddress','forceAuthn','randomizeFriendlyName','signResponses'}
SHA=lambda b:hashlib.sha256(b).hexdigest()
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def save(path,obj):path.write_text(json.dumps(obj,sort_keys=True,indent=2)+'\n')
def docker(*args):return subprocess.run(['docker','exec',CONTAINER,*args],capture_output=True,check=True,timeout=90).stdout
def capture(folder,phase,entity):
 files={}
 for name,relative in CONFIGS.items():(folder/('trust-'+phase+'-'+name+'.xml')).write_bytes(docker('cat','/opt/reference-idp/'+relative))
 for name,digest in JARS.items():
  path='/usr/local/tomcat/webapps/idp/WEB-INF/lib/'+name+'-5.2.3.jar';assert docker('sha256sum',path).decode().split()[0]==digest;files[name]=digest;destination=folder/('native-'+name+'.jar')
  if not destination.exists():
   source=XMLSEC if name=='opensaml-xmlsec-impl' else OLD/(name+'.jar');assert SHA(source.read_bytes())==digest;os.link(source,destination)
 classpath=docker('sh','-c','sha256sum /usr/local/tomcat/webapps/idp/WEB-INF/lib/*.jar').decode().splitlines();save(folder/('trust-'+phase+'-classpath-sha256.json'),{r.split()[1]:r.split()[0] for r in classpath})
 overrides=docker('sh','-c','find /usr/local/tomcat/webapps/idp/WEB-INF/classes /opt/reference-idp/system -type f 2>/dev/null | sort').decode().splitlines();assert not overrides;save(folder/('trust-'+phase+'-override-source-inventory.json'),overrides)
 paths=docker('sh','-c','find /opt/reference-idp/conf -type f -name "*.properties" -print | sort').decode().splitlines();paths.append('/opt/reference-idp/credentials/secrets.properties');properties={};selected={}
 for path in paths:
  raw=docker('cat',path);properties[path]=SHA(raw)
  for line in raw.decode().splitlines():
   line=line.strip()
   if not line or line.startswith(('#','!')):continue
   for key in ['idp.trust.signatures','idp.security.config','idp.additionalProperties','idp.service.relyingparty.resources']:
    if re.match(re.escape(key)+r'\s*[:=]',line):
     value=re.split(r'\s*[:=]\s*',line,1)[1].strip();assert key!='idp.service.relyingparty.resources','Unknown selected security resource override';assert key!='idp.additionalProperties' or value=='/credentials/secrets.properties','Unknown additional property source';assert key not in selected;selected[key]=value
 save(folder/('trust-'+phase+'-properties-sha256.json'),properties);save(folder/('trust-'+phase+'-selected-properties.json'),selected)
 inventory=docker('sh','-c','find /opt/reference-idp/conf -type f -name "*.xml" -print | sort').decode().splitlines();save(folder/('trust-'+phase+'-xml-sha256.json'),{path:docker('sha256sum',path).decode().split()[0] for path in inventory if path not in ['/opt/reference-idp/conf/audit.xml','/opt/reference-idp/conf/metadata-providers.xml']})
 # Values stay in memory; only public override-presence facts are exported.
 processes=docker('sh','-c','for f in /proc/[0-9]*/cmdline; do tr "\\000" " " < "$f"; printf "\\n"; done').decode();java=[line for line in processes.splitlines() if 'org.apache.catalina.startup.Bootstrap' in line and 'tr ' not in line];assert len(java)==1
 env=json.loads(subprocess.run(['docker','inspect',CONTAINER],capture_output=True,check=True,timeout=20).stdout)[0]['Config'].get('Env',[]);sensitive='\n'.join(java+env);flags=dict(nativeJavaProcessObserved=True,trustOverridePresent=bool(re.search(r'-Didp\.(?:trust\.signatures|security\.config|additionalProperties|service\.relyingparty\.resources)\b',sensitive)),customAgentPresent='-javaagent' in sensitive,privateFieldsExported=False);assert not flags['trustOverridePresent'] and not flags['customAgentPresent'];save(folder/('trust-'+phase+'-process-overrides.json'),flags)
 command=['/opt/reference-idp/bin/dumpconfig.sh','-u','http://localhost:8080/idp','--saml2','-r',entity,'-P',PROFILE];profile=json.loads(docker(*command));assert set(profile)=={'RelyingPartyConfiguration','ProfileConfiguration'} and set(profile['RelyingPartyConfiguration'])=={'detailedErrors','id','securityConfiguration','issuer'} and set(profile['ProfileConfiguration'])==PROFILE_KEYS,'Unknown native public profile schema';assert all(isinstance(value,(str,bool,int)) and not any(term in key.lower() for term in ['secret','password','cookie','token','private','credential']) for group in profile.values() for key,value in group.items()),'Unexpected native profile field';save(folder/('trust-'+phase+'-native-effective-profile.json'),profile)
 save(folder/('trust-'+phase+'-observed.json'),dict(entityId=entity,profileId=PROFILE,recordedAt=NOW(),nativeJars=files,privateFieldsExported=False))
