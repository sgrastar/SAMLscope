#!/usr/bin/env python3
"""Read-only stock ECP security selection and restored source configuration equality."""
import hashlib,json,pathlib,urllib.request
from default_algorithm_policy_scope import Capture,CONTAINER,HOME,NOW,SHA
ECP='http://shibboleth.net/ns/profiles/saml2/sso/ecp'
TARGET='http://localhost:18280/idp/shibboleth'

def capture(folder,phase,entity,run,source_receipt,commands):
    folder=pathlib.Path(folder);source_receipt=pathlib.Path(source_receipt)
    collector=Capture(folder,commands);name,_=collector.capture(phase,entity,run)
    scope=json.loads((folder/name).read_bytes());files=scope['files']
    def original(name,raw):
        path=folder/name
        if path.exists():
            if path.is_symlink() or path.read_bytes()!=raw:raise ValueError('Immutable current native original changed')
        else:path.write_bytes(raw)
        files[name]=SHA(raw);return name
    restored={}
    for label,native in [('providers','metadata-providers'),('audit','audit'),('logback','logback')]:
        raw=collector.docker('cat',HOME+'/conf/'+native+'.xml')
        if raw!=(source_receipt/('final-'+label+'.xml')).read_bytes():raise ValueError('Current restored source configuration differs')
        restored[label]=original('source-'+phase+'-restored-'+label+'.xml',raw)
    raw=collector.docker(HOME+'/bin/mdquery.sh','-u','http://localhost:8080/idp','-e',entity)
    selected=original('source-'+phase+'-selected-metadata.xml',raw)
    raw=collector.docker(HOME+'/bin/dumpconfig.sh','-u','http://localhost:8080/idp','--saml2','-r',entity,'-P',ECP)
    profile=json.loads(raw)
    rp=profile.get('RelyingPartyConfiguration',{})
    if rp.get('id')!='shibboleth.DefaultRelyingParty' or rp.get('securityConfiguration')!='shibboleth.DefaultSecurityConfiguration' or rp.get('issuer')!=TARGET or profile.get('ProfileConfiguration',{}).get('id')!=ECP:raise ValueError('Current ECP default-security selection is unproven')
    if any(any(word in key.lower() for word in ('password','secret','private','cookie','credential','token')) for group in profile.values() for key in group):raise ValueError('Unexpected private native profile field')
    ecp=original('source-'+phase+'-ecp-profile.json',raw)
    with urllib.request.urlopen(TARGET,timeout=30) as response:
        if response.status!=200:raise ValueError('Current native target metadata unavailable')
        target=original('source-'+phase+'-live-target-metadata.xml',response.read())
    scope.update(restoredConfigurationFiles=restored,selectionMetadataFile=selected,ecpProfileFile=ecp,
                 liveTargetMetadataFile=target,settingsWrites=0,protocolSubmissions=0,credentialPosts=0,
                 completedAt=NOW(),temporarySourceRegistrationRemovedAsRecorded=True)
    source_name='source-'+phase+'-scope.json';raw=(json.dumps(scope,sort_keys=True,separators=(',',':'))+'\n').encode()
    original(source_name,raw)
    return source_name
