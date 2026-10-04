#!/usr/bin/env python3
"""Public selected default-security readbacks; no settings, login, SAML, or credential export."""
import datetime, hashlib, json, pathlib, re, subprocess, zipfile
REPO=pathlib.Path(__file__).resolve().parents[2]
CONTAINER='samlscope-reference-shibboleth'
HOME='/opt/reference-idp'
LIB='/usr/local/tomcat/webapps/idp/WEB-INF/lib'
PROFILE='http://shibboleth.net/ns/profiles/saml2/sso/browser'
SLO_PROFILE='http://shibboleth.net/ns/profiles/saml2/logout'
CONFIGS={'global.xml':'ca08485a1b5ef8cf0ac1afb80ff066237759e4fb3d884d087f905d8ca0918bcc',
         'services.xml':'0c5de788ebc611af60ebb3bf4071dcd23744f599d64d65bdb0744515d11a77c0',
         'relying-party.xml':'64e2a04dfbf2ffa2a582b995bcbf121b634ab7c8766cb8f22d3397d541f31bd5'}
JARS={'idp-conf-impl':'428e389d88bb2abcad19d69bcf759af29f7ce6beb776ccfaa5a6ea76751682ba',
      'idp-saml-impl':'1a2a9f867d11c50eeaf2a6140bb5de88b0611d694ea6de2bbfe32f72a4a2998b',
      'idp-profile-impl':'aaa769a9ccdfb1428173e3932d598ced0302908fab3b8bfe2100331678c9f405',
      'opensaml-saml-impl':'9f04221e172dc426f90fb3873d0148a0744edbf9e7a37de7ee0e6a34f7b74581',
      'opensaml-xmlsec-impl':'cc67fc1bd9cb435cdbe7483ef04513c83cc9619a3015c04ad41bb6cc0eb6e68e',
      'opensaml-xmlsec-api':'3401e9e309fd170f4b9ea0d8fc68b5b778c2374bf654371378bce21952d6c6b9',
      'opensaml-profile-impl':'ed65b8524022fd870b588fedb994a7c4b2f0e4fe63a5d62085ca7c419f6a751f'}
PROPERTY_KEYS={'idp.security.config','idp.trust.signatures','idp.additionalProperties','idp.service.relyingparty.resources'}
SHA=lambda b:hashlib.sha256(b).hexdigest()
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

class Capture:
    def __init__(self,folder,commands):self.folder=pathlib.Path(folder);self.commands=commands
    def command(self,argv):
        row={'kind':'read-only-default-security','commandSha256':SHA(json.dumps(argv,separators=(',',':')).encode()),'startedAt':NOW()}
        self.commands.append(row)
        result=subprocess.run(argv,capture_output=True,timeout=90)
        row.update(completedAt=NOW(),exitCode=result.returncode,stdoutSha256=SHA(result.stdout),stderrSha256=SHA(result.stderr))
        if result.returncode:raise ValueError('Native public default-policy readback failed')
        return result.stdout
    def docker(self,*args):return self.command(['docker','exec',CONTAINER,*args])
    def capture(self,phase,entity,run):
        if phase not in {'before','after'} or not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run):raise ValueError('Unsafe default-policy capture identity')
        folder=self.folder; started=NOW(); files={};configurations={}
        def original(name,raw):
            path=folder/name
            if path.exists():
                if path.is_symlink() or path.read_bytes()!=raw:raise ValueError('Immutable native original changed')
            else:path.write_bytes(raw)
            files[name]=SHA(raw);return name
        for name,digest in CONFIGS.items():
            raw=self.docker('cat',HOME+'/conf/'+name)
            if SHA(raw)!=digest:raise ValueError('Current algorithm configuration is not the captured stock reference default')
            configurations[name]=original('default-'+phase+'-'+name,raw)
        jars={}
        for name,digest in JARS.items():
            native=LIB+'/'+name+'-5.2.3.jar'
            if self.docker('sha256sum',native).decode().split()[0]!=digest:raise ValueError('Unknown selected native default-security library')
            output='default-native-'+name+'.jar';destination=folder/output
            if not destination.exists():
                self.command(['docker','cp',CONTAINER+':'+native,str(destination)])
            if destination.is_symlink() or SHA(destination.read_bytes())!=digest:raise ValueError('Native library copy mismatch')
            files[output]=digest;jars[name]=output
        classpath={line.split()[1]:line.split()[0] for line in self.docker('sh','-c','sha256sum '+LIB+'/*.jar').decode().splitlines()}
        overrides=self.docker('sh','-c','find /usr/local/tomcat/webapps/idp/WEB-INF/classes /opt/reference-idp/system -type f 2>/dev/null | sort').decode().splitlines()
        if overrides:raise ValueError('Unknown selected native class/resource override')
        property_paths=self.docker('sh','-c','find /opt/reference-idp/conf -type f -name "*.properties" -print | sort').decode().splitlines()+[HOME+'/credentials/secrets.properties']
        properties={};selected={}
        for path in property_paths:
            raw=self.docker('cat',path);properties[path]=SHA(raw)
            for line in raw.decode().splitlines():
                line=line.strip()
                if not line or line.startswith(('#','!')):continue
                if re.search(r'(?i)(algorithm|blacklist|whitelist|excluded|included)',line.split('=',1)[0].split(':',1)[0]):
                    raise ValueError('Active algorithm property override requires another native adapter')
                for key in PROPERTY_KEYS:
                    if re.match(re.escape(key)+r'\s*[:=]',line):
                        value=re.split(r'\s*[:=]\s*',line,1)[1].strip()
                        if key in selected:raise ValueError('Duplicate selected security property')
                        selected[key]=value
        if selected.get('idp.security.config','shibboleth.DefaultSecurityConfiguration')!='shibboleth.DefaultSecurityConfiguration':raise ValueError('Selected security configuration is customized')
        if selected.get('idp.additionalProperties','/credentials/secrets.properties')!='/credentials/secrets.properties' or 'idp.service.relyingparty.resources' in selected:raise ValueError('Unknown security property/resource source')
        xml_paths=self.docker('sh','-c','find /opt/reference-idp/conf -type f -name "*.xml" -print | sort').decode().splitlines()
        xml_hashes={path:self.docker('sha256sum',path).decode().split()[0] for path in xml_paths if path not in {HOME+'/conf/audit.xml',HOME+'/conf/metadata-providers.xml',HOME+'/conf/logback.xml'}}
        processes=self.docker('sh','-c','for f in /proc/[0-9]*/cmdline; do tr "\\000" " " < "$f"; printf "\\n"; done').decode().splitlines()
        native=[line for line in processes if 'org.apache.catalina.startup.Bootstrap' in line and 'tr ' not in line]
        inspected=json.loads(self.command(['docker','inspect',CONTAINER]))[0]
        if len(native)!=1:raise ValueError('Native process identity is ambiguous')
        private_memory='\n'.join(native+inspected['Config'].get('Env',[]))
        if '-javaagent' in private_memory or re.search(r'-Didp\.(?:security\.config|signing|encryption|additionalProperties|service\.relyingparty\.resources)\b',private_memory):raise ValueError('Native algorithm process override')
        runtime={'containerId':inspected['Id'],'image':inspected['Image'],'running':inspected['State']['Running'],
                 'startedAt':inspected['State']['StartedAt'],'mounts':inspected.get('Mounts',[])}
        if not runtime['running'] or runtime['mounts']:raise ValueError('Unknown mutable native runtime')
        profiles={}
        for label,profile in [('browser',PROFILE),('logout',SLO_PROFILE)]:
            raw=self.docker(HOME+'/bin/dumpconfig.sh','-u','http://localhost:8080/idp','--saml2','-r',entity,'-P',profile)
            value=json.loads(raw)
            if set(value)!={'RelyingPartyConfiguration','ProfileConfiguration'} or value['RelyingPartyConfiguration'].get('securityConfiguration')!='shibboleth.DefaultSecurityConfiguration' or value['ProfileConfiguration'].get('id')!=profile:raise ValueError('Selected native default profile not proven')
            if any(re.search(r'(?i)password|secret|private|cookie|credential|token',key) for group in value.values() for key in group):raise ValueError('Unexpected private native profile field')
            profiles[label]=original('default-'+phase+'-'+label+'-profile.json',raw)
        value={'schema':'samlscope-shibboleth-default-security-scope-v1','runId':run,'entityId':entity,'phase':phase,
               'startedAt':started,'completedAt':NOW(),'runtime':runtime,'configurations':configurations,'jars':jars,
               'classpath':classpath,'propertiesSha256':properties,'selectedProperties':selected,'xmlSha256':xml_hashes,
               'profileFiles':profiles,'overrideSourceInventory':overrides,'nativeJavaProcessObserved':True,
               'algorithmProcessOverridePresent':False,'privateFieldsExported':False,'files':files}
        name='default-'+phase+'-scope.json';original(name,(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode())
        return name,files

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--phase',choices=['before','after'],required=True);p.add_argument('--entity',required=True);p.add_argument('--run',required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=True);commands=[]
    try:
        name,files=Capture(a.output,commands).capture(a.phase,a.entity,a.run);save(a.output/('default-'+a.phase+'-capture.json'),{'scopeFile':name,'files':files,'settingsWrites':0,'protocolSends':0,'credentialPosts':0})
    finally:save(a.output/('default-'+a.phase+'-commands.json'),commands)
