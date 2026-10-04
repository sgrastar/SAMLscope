#!/usr/bin/env python3
"""Capture real native persistent attributes for one temporary principal and one peer.

One credential submission and a shared session support the original positive operation
and a diagnostic principal-valued native attribute control. Credentials stay in memory.
The collector assigns no outcome. Every setting and temporary object is restored.
"""
import argparse,base64,datetime,hashlib,json,pathlib,re,secrets,shutil,subprocess,sys,tempfile,urllib.error,urllib.parse,urllib.request,xml.etree.ElementTree as ET
from attribute_policy_capability_absence import product_token
from forceauthn_mechanism_campaign import IdentityClient
from import_metadata_batch import BASE,api
from mdiop_representation_campaign import runtime

REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture
ADMIN='http://localhost:18180/admin/realms/samlscope';TARGET='http://localhost:18180/realms/samlscope';PRODUCT='samlscope-reference-keycloak';SUITE='samlscope-reference-suite'
FORMAT='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';S='{urn:oasis:names:tc:SAML:2.0:assertion}'
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def save(path,value):
    if path.exists():raise ValueError('Immutable original already exists: '+str(path))
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def command(args,timeout=90):return subprocess.run([str(a) for a in args],check=True,capture_output=True,timeout=timeout)
def reject_sensitive(value):
    # Config keys such as access.token.claim describe emission policy and contain no token.
    if isinstance(value,dict):
        for key,item in value.items():
            if re.fullmatch(r'(?i:secret|registrationAccessToken|clientSecret|password|privateKey|credentials)',key) and item:
                raise ValueError('Sensitive native value must not be retained')
            reject_sensitive(item)
    elif isinstance(value,list):
        for item in value:reject_sensitive(item)

def membership(out,run):
    archived=out/'membership-runtime';archived.mkdir();projects={}
    for name in ['api','runner','core','store','saml','peer']:
        command(['docker','cp',SUITE+':/opt/samlscope/lib/'+name+'-0.1.0.jar',archived/(name+'.jar')]);projects[name]=SHA((archived/(name+'.jar')).read_bytes())
    dependencies=[];(archived/'dependencies').mkdir()
    for source in sorted((REPO/'api/build/install/samlscope/lib').glob('*.jar')):
        if source.name.endswith('-0.1.0.jar'):continue
        to=archived/'dependencies'/source.name;shutil.copyfile(source,to);dependencies.append(dict(name=source.name,path=str(to),sha256=SHA(to.read_bytes())))
    live={line.split()[1].rsplit('/',1)[-1]:line.split()[0] for line in command(['docker','exec',SUITE,'sha256sum',*['/opt/samlscope/lib/'+r['name'] for r in dependencies]]).stdout.decode().splitlines()}
    if live!={r['name']:r['sha256'] for r in dependencies}:raise ValueError('Installed dependency generation differs')
    helper=archived/'ReadApprovedPersistentCaseMembership.java';shutil.copyfile(REPO/'dev/reference-acceptance'/helper.name,helper)
    cp=':'.join(str(archived/(name+'.jar')) for name in projects)+':'+':'.join(r['path'] for r in dependencies)
    command(['/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin/javac','-sourcepath','','-cp',cp,'-d',archived/'classes',helper])
    remote='/tmp/kc-persistent-scope-'+secrets.token_hex(6);command(['docker','exec','-u','0',SUITE,'mkdir',remote])
    try:
        command(['docker','cp',archived/'classes',SUITE+':'+remote+'/classes']);command(['docker','exec','-u','0',SUITE,'chmod','-R','a+rX',remote])
        proof=command(['docker','exec',SUITE,'java','-cp',remote+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.ReadApprovedPersistentCaseMembership','/data',run]).stdout
        (out/'approved-membership.json').write_bytes(proof)
    finally:command(['docker','exec','-u','0',SUITE,'rm','-rf','--',remote])
    save(archived/'pins.json',dict(projects=projects,dependencies=dependencies,helperSha256=SHA(helper.read_bytes())))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=pathlib.Path,required=True);args=parser.parse_args()
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False);originals=out/'originals';originals.mkdir()
    operations=[];token=product_token();token_reads=1;credential_actions=[];observations=[];flows=[]
    username='samlscope-opaque-'+secrets.token_hex(10);password=secrets.token_urlsafe(40)
    user_id=client_id=None;profile_original=None;profile_changed=False;user_attempted=client_attempted=False;positive_user=None;restoration={}
    def native(label,path,method='GET',body=None,credential_input=False):
        nonlocal token,token_reads
        raw=body if isinstance(body,bytes) else None if body is None else json.dumps(body,separators=(',',':')).encode()
        if body is not None and not isinstance(body,bytes) and not credential_input:reject_sensitive(body)
        write=method in {'PUT','DELETE'} or method=='POST' and path!='/client-description-converter'
        row=dict(label=label,path=path,method=method,attemptedAt=now(),productSettingWrite=write);operations.append(row)
        (out/'operations.json').write_text(json.dumps(operations,sort_keys=True,indent=2)+'\n')
        request=urllib.request.Request(ADMIN+path,data=raw,method=method,headers={'Authorization':'Bearer '+token,'Content-Type':'application/xml' if isinstance(body,bytes) else 'application/json'})
        try:
            with urllib.request.urlopen(request,timeout=40) as response:code,reply,location=response.status,response.read(),response.headers.get('Location')
        except urllib.error.HTTPError as response:code,reply,location=response.code,response.read(),response.headers.get('Location')
        row.update(status=code,finishedAt=now());(out/'operations.json').write_text(json.dumps(operations,sort_keys=True,indent=2)+'\n')
        if code==401:
            token=product_token();token_reads+=1
            raise ValueError('Management epoch expired; stop and restore with refreshed in-memory token')
        value=json.loads(reply) if reply else None;record=dict(method=method,url=ADMIN+path,status=code,recordedAt=now())
        redactions=[]
        if method=='GET' and re.fullmatch(r'/clients/[0-9a-f-]{36}',path) and isinstance(value,dict):
            for key in ['secret','registrationAccessToken']:
                if key in value:value.pop(key);redactions.append('$.'+key)
            reply=json.dumps(value,separators=(',',':')).encode()
        if method=='GET' and re.fullmatch(r'/users/[0-9a-f-]{36}',path) and isinstance(value,dict):
            for key in ['credentials','disableableCredentialTypes']:
                if key in value:
                    if key=='credentials' and value[key]:raise ValueError('Credential-bearing native user representation')
                    value.pop(key);redactions.append('$.'+key)
            reply=json.dumps(value,separators=(',',':')).encode()
        if method=='GET' and path.startswith('/users?') and value:
            if label!='user-recovery-inventory' or any(row.get('username')!=username for row in value):
                raise ValueError('Unexpected existing principal; no other user attributes are retained')
        if value is not None:reject_sensitive(value)
        record.update(response_base64=base64.b64encode(reply).decode(),response_sha256=SHA(reply))
        if redactions:record.update(response_projection='native-client-public-readback-v1' if path.startswith('/clients/') else 'native-test-user-public-readback-v1',redactions=redactions)
        if credential_input:record.update(credentialInputRetained=False,publicRecipe={k:v for k,v in body.items() if k!='credentials'})
        elif raw is not None:record.update(request_base64=base64.b64encode(raw).decode(),request_sha256=SHA(raw))
        save(originals/(label+'.json'),record)
        return value,record,location
    def get(label,path):
        value,record,_=native(label,path)
        if record['status']!=200:raise ValueError('Native readback unavailable: '+path)
        return value
    def environment(label):
        inventory=command(['docker','exec',PRODUCT,'sh','-c','find /opt/keycloak/lib /opt/keycloak/providers -type f -name "*.jar" | sort | while IFS= read -r p; do sha256sum "$p"; done']).stdout
        (originals/(label+'.native-classpath.txt')).write_bytes(inventory)
        value=dict(runtime=runtime(),nativeClasspathSha256=SHA(inventory),recordedAt=now());save(originals/(label+'.environment.json'),value);return value
    before=environment('before')
    source=REPO/'build/acceptance/reference-20261004/keycloak-forceauthn-mechanism-r2/receipt'
    if (source/'native-classpath.txt').read_bytes()!=(originals/'before.native-classpath.txt').read_bytes():raise ValueError('Immutable complete native source differs from current installation')
    shutil.copytree(source/'native-complete',out/'native-complete')
    for line in (originals/'before.native-classpath.txt').read_text().splitlines():
        digest,path=line.split();copied=out/'native-complete'/path.removeprefix('/opt/keycloak/lib/')
        if copied.stat().st_nlink!=1 or SHA(copied.read_bytes())!=digest:raise ValueError('Independent native copy differs')
    (originals/'collector.py').write_bytes(pathlib.Path(__file__).read_bytes())
    plan=api('/api/plans',dict(name='Keycloak native persistent identifier construction and opacity',profile='browser_sso_idp',targetKind='IDP',targetEntityId=TARGET,
        metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},
        parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint=username,requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=created['run']['id'];membership(out,run)
    save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));peer=BASE+'/p/'+pid;client_lookup='/clients?clientId='+urllib.parse.quote(peer,safe='')
    command(['docker','cp',SUITE+':/data/target-metadata/'+run+'.xml',out/'target-metadata.xml'])
    with urllib.request.urlopen(peer+'/metadata',timeout=30) as response:fixture=response.read()
    (out/'suite-sp-metadata.xml').write_bytes(fixture)
    if get('client-inventory-before',client_lookup)!=[]:raise ValueError('Existing client must not be mutated')
    if get('user-inventory-before','/users?username='+urllib.parse.quote(username,safe='')+'&exact=true')!=[]:raise ValueError('Existing principal must not be mutated')
    scopes_before=get('client-scopes-before','/client-scopes');profile_original=get('user-profile-before','/users/profile')
    try:
        profile=dict(profile_original,unmanagedAttributePolicy='ADMIN_EDIT');profile_changed=True;_,record,_=native('user-profile-visibility-application','/users/profile','PUT',profile)
        if record['status']!=200 or get('user-profile-visible','/users/profile')!=profile:raise ValueError('Native unmanaged-attribute visibility is unavailable')
        recipe=dict(username=username,enabled=True,emailVerified=True,email=username+'@example.invalid',firstName='SAMLscope',lastName='Opaque',requiredActions=[])
        user_attempted=True;_,record,location=native('user-creation','/users','POST',dict(recipe,credentials=[dict(type='password',temporary=False,value=password)]),True)
        if record['status']!=201 or not location:raise ValueError('Temporary native principal creation failed')
        user_id=location.rsplit('/',1)[-1];user_before=get('native-user-before','/users/'+user_id)
        if user_before.get('username')!=username or user_before.get('attributes',{})!={}:raise ValueError('Fresh native user attributes are not provably empty')
        converted,record,_=native('native-converter','/client-description-converter','POST',fixture)
        if record['status']!=200 or converted.get('clientId')!=peer or converted.get('protocolMappers')!=[]:raise ValueError('Native converter yielded an unsupported mapper path')
        configured=json.loads(json.dumps(converted));configured.setdefault('attributes',{}).update({'saml.encrypt':'false','saml_force_name_id_format':'true','saml_name_id_format':'persistent'})
        configured['protocolMappers']=[dict(name='samlscope-native-principal-username',protocol='saml',protocolMapper='saml-user-property-mapper',consentRequired=False,
            config={'user.attribute':'username','attribute.name':'samlscope.native.username','attribute.nameformat':'Basic'})]
        client_attempted=True;_,record,location=native('native-client-creation','/clients','POST',configured)
        if record['status']!=201 or not location:raise ValueError('Temporary native peer creation failed')
        client_id=location.rsplit('/',1)[-1];client_before=get('native-client-before','/clients/'+client_id)
        defaults=get('client-default-scopes-before','/clients/'+client_id+'/default-client-scopes');optionals=get('client-optional-scopes-before','/clients/'+client_id+'/optional-client-scopes')
        attribute='saml.persistent.name.id.for.'+peer
        browser=IdentityClient(observations,credential_actions,'normal')
        def flow(label):
            browser.label=label;previous={row['id'] for row in api('/api/runs/'+run+'/transcript')};attempt=dict(label=label,startedAt=now(),diagnosticOnly=label=='mutant');flows.append(attempt)
            result=browser.flow(peer+'/start/m0-roundtrip?run='+run,None,username,password);attempt.update(result=result,finishedAt=now());save(out/(label+'-operation.json'),attempt)
            entries=[e for e in api('/api/runs/'+run+'/transcript') if e['id'] not in previous];requests=[e for e in entries if e['direction']=='OUTBOUND' and e['decodedSamlRef']]
            responses=[e for e in entries if e['direction']=='INBOUND' and e['decodedSamlRef']]
            if result!='recorded' or len(requests)!=1 or len(responses)!=1:raise ValueError('Ambiguous original protocol operation: '+label)
            request,response=requests[0],responses[0]
            for kind,entry in [('request',request),('response',response)]:
                ref=entry['decodedSamlRef']
                if not re.fullmatch('transcripts/'+run+r'/tx_[0-9A-HJKMNP-TV-Z]{26}\.saml\.xml',ref):raise ValueError('Foreign protocol original')
                raw=command(['docker','exec',SUITE,'cat','/data/'+ref]).stdout
                if len(raw)!=entry['decodedSamlBytes']:raise ValueError('Original byte length differs')
                (out/(label+'-'+kind+'.xml')).write_bytes(raw)
            req=ET.fromstring((out/(label+'-request.xml')).read_bytes());res=ET.fromstring((out/(label+'-response.xml')).read_bytes())
            name=res.find('.//'+S+'Assertion/'+S+'Subject/'+S+'NameID')
            if res.get('InResponseTo')!=req.get('ID') or name is None or name.get('Format')!=FORMAT:raise ValueError('Selected persistent native response is unavailable')
            save(out/(label+'-exchange.json'),dict(requestReference=request['id'],responseReference=response['id'],requestId=req.get('ID'),diagnosticOnly=label=='mutant'))
            return name.text
        normal=flow('normal');positive_user=get('native-user-after','/users/'+user_id)
        if positive_user.get('attributes',{}).get(attribute)!=[normal] or normal in {username,recipe['email'],user_id}:raise ValueError('Actual saved native attribute does not match opaque original Response')
        save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));save(out/'result-before.json',api('/api/runs/'+run+'/result.json'))
        mutated=dict(positive_user,attributes=dict(positive_user['attributes'],**{attribute:[username]}))
        _,record,_=native('diagnostic-principal-attribute-application','/users/'+user_id,'PUT',mutated)
        if record['status']!=204:raise ValueError('Native diagnostic attribute was not applied')
        mutant_user=get('native-user-mutant-before','/users/'+user_id)
        if mutant_user.get('attributes',{}).get(attribute)!=[username]:raise ValueError('Native diagnostic attribute readback failed')
        mutant=flow('mutant')
        if mutant!=username:raise ValueError('Native principal-valued producer control did not appear in original Response')
        get('native-user-mutant-after','/users/'+user_id)
        _,record,_=native('native-user-attribute-restoration','/users/'+user_id,'PUT',positive_user)
        if record['status']!=204 or get('native-user-positive-restored','/users/'+user_id)!=positive_user:raise ValueError('Native test-user attribute restoration failed')
        if get('native-client-after','/clients/'+client_id)!=client_before or get('client-scopes-after','/client-scopes')!=scopes_before \
            or get('client-default-scopes-after','/clients/'+client_id+'/default-client-scopes')!=defaults or get('client-optional-scopes-after','/clients/'+client_id+'/optional-client-scopes')!=optionals:
            raise ValueError('Selected native client/mapper scope changed')
        save(out/'observations.json',observations);save(out/'credential-actions.json',credential_actions)
        save(out/'result.json',api('/api/runs/'+run+'/result.json'));entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
    finally:
        if client_attempted and client_id is None:
            found=get('client-recovery-inventory',client_lookup)
            if len(found)>1 or any(row.get('clientId')!=peer or row.get('protocol')!='saml' for row in found):raise ValueError('Recovery client identity is ambiguous')
            if found:client_id=found[0]['id']
        if client_id:
            _,record,_=native('native-client-removal','/clients/'+client_id,'DELETE');restoration['clientRemoved']=record['status']==204
        restoration['clientAbsent']=get('client-inventory-restored',client_lookup)==[]
        if user_attempted and user_id is None:
            found=get('user-recovery-inventory','/users?username='+urllib.parse.quote(username,safe='')+'&exact=true')
            if len(found)>1:raise ValueError('Recovery principal identity is ambiguous')
            if found:user_id=found[0]['id']
        if user_id:
            _,record,_=native('native-user-removal','/users/'+user_id,'DELETE');restoration['userRemoved']=record['status']==204
        restoration['userAbsent']=get('user-inventory-restored','/users?username='+urllib.parse.quote(username,safe='')+'&exact=true')==[]
        if profile_changed:
            _,record,_=native('user-profile-restoration','/users/profile','PUT',profile_original);restoration['profileRestored']=record['status']==200 and get('user-profile-restored','/users/profile')==profile_original
        restoration['scopesRestored']=get('client-scopes-restored','/client-scopes')==scopes_before
        after=environment('after');restoration['runtimeRestored']=after['runtime']==before['runtime'] and after['nativeClasspathSha256']==before['nativeClasspathSha256']
        restoration['restored']=all(restoration.values());save(out/'restoration.json',restoration)
        save(out/'operation-counts.json',dict(productSettingWriteAttempts=sum(o['productSettingWrite'] for o in operations),successfulProductSettingWrites=sum(o['productSettingWrite'] and o.get('status') in {200,201,204} for o in operations),nativeHttpAttempts=len(operations),managementTokenAcquisitions=token_reads,
            protocolOperationsAttempted=len(flows),protocolOperationsRecorded=sum(o.get('result')=='recorded' for o in flows),credentialPosts=len(credential_actions),diagnosticPrincipalControlOnly=True,
            humanOperations=0,productRestarts=0,restored=restoration['restored']))
    print(json.dumps(dict(runId=run,planId=pid,restored=restoration['restored'],protocolOperations=len(flows),credentialPosts=len(credential_actions))))
if __name__=='__main__':main()
