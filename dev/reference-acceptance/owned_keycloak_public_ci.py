#!/usr/bin/env python3
"""Lifecycle and native SAML client setup for one NEW public-CI Keycloak only.

Never inspects an existing reference environment. Credential material and native
private representations stay in RAM; public evidence is a strict projection.
"""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, re, subprocess, time
import urllib.error, urllib.parse, urllib.request

IMAGE = 'quay.io/keycloak/keycloak:26.7.2@sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067'
VERSION = '26.7.2'
SEED = 'dev/keycloak/realm-samlscope.json'
SEED_SHA = 'fb68fa3129b14ee3c57c41d1f0473984ec4c2acf4cecaaaab683661192d45113'
SEED_BLOB = '1b28bdece9b1af90eeadf9422c5195a4cc5ffcbb'
COMPOSE = 'dev/keycloak/compose.yml'
CASE = 'IIP-IDP10-d-idp-01'
CASE_DIGEST = 'sha256:a02075559dff2bf93b50bcc17a601f9037093d5405a9ee93ff5f7f0e80fa346a'
LABEL = 'com.samlscope.owned.acceptance'
ORIGIN = 'http://localhost:28080'
SUITE = 'http://localhost:18080'
ROOT = pathlib.Path(__file__).resolve().parents[2]
PRIVATE_KEYS = {'password','passwd','authorization','cookie','setcookie','token','accesstoken','refreshtoken','idtoken','clientsecret','secret','privatekey','managementurl'}

def require(ok, reason):
    if not ok: raise ValueError(reason)

def digest(value): return hashlib.sha256(value).hexdigest()

def public(value):
    if isinstance(value, dict):
        for key, child in value.items():
            require(key.replace('_','').replace('-','').lower() not in PRIVATE_KEYS or child is None, 'Non-public evidence omitted')
            public(child)
    elif isinstance(value, list):
        for child in value: public(child)
    return value

def write(output, name, value):
    public(value)
    with (output/name).open('x') as target: json.dump(value,target,indent=2);target.write('\n')

def generation(value):
    require(bool(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,35}',value)), 'Invalid owned generation')
    return value

def reject_symlinks(path):
    for part in [path,*path.parents]: require(not part.is_symlink(),'Symlink evidence/source path rejected')

def owned_path(value):
    path=pathlib.Path(value).absolute();reject_symlinks(path)
    require('..' not in path.parts and path==path.resolve() and path.is_relative_to((ROOT/'build/acceptance').resolve()) and path!=(ROOT/'build/acceptance').resolve(),'Path outside owned acceptance scope')
    return path

def source_seed():
    path=ROOT/SEED
    reject_symlinks(path)
    require(path.is_file() and not path.is_symlink(), 'Public seed unavailable')
    body=path.read_bytes()
    require(digest(body)==SEED_SHA, 'Public seed changed')
    tracked=subprocess.run(['git','show','HEAD:'+SEED],cwd=ROOT,capture_output=True,check=True).stdout
    require(body==tracked, 'Public seed is not tracked original')
    require(subprocess.run(['git','hash-object','--stdin'],input=body,capture_output=True,check=True).stdout.decode().strip()==SEED_BLOB, 'Public seed Git blob differs')
    return {'sha256':SEED_SHA,'gitBlob':SEED_BLOB}

def labels(gen): return {LABEL:'keycloak-public-ci-nameid-v2','com.samlscope.owned.generation':generation(gen),'com.samlscope.owned.realm-blob':SEED_BLOB}

def name(gen): return 'samlscope-owned-kc-nameid-v2-'+generation(gen)

def run_args(gen):
    args=['docker','run','--detach','--pull=never','--name',name(gen),'--publish','127.0.0.1:28080:8080','--log-driver','none']
    for key,value in labels(gen).items(): args.extend(['--label',key+'='+value])
    args.extend(['--env','KC_BOOTSTRAP_ADMIN_USERNAME','--env','KC_BOOTSTRAP_ADMIN_PASSWORD','--env','KC_HOSTNAME='+ORIGIN,
                 '--tmpfs','/opt/keycloak/data:rw,nosuid,nodev,uid=1000,gid=0,mode=0770,size=512m','--tmpfs','/tmp:rw,nosuid,nodev,mode=1777,size=128m',
                 '--mount','type=bind,src='+str(ROOT/SEED)+',dst=/opt/keycloak/data/import/realm-samlscope.json,readonly',IMAGE,'start-dev','--import-realm'])
    return args

def bootstrap_environment():
    # Read only the tracked public CI compose, never a caller's .env or container Env.
    body=(ROOT/COMPOSE).read_bytes()
    require(body==subprocess.run(['git','show','HEAD:'+COMPOSE],cwd=ROOT,capture_output=True,check=True).stdout,'Public compose changed')
    text=body.decode();env={'PATH':os.environ.get('PATH','/usr/bin:/bin:/opt/homebrew/bin')}
    for key in ['KC_BOOTSTRAP_ADMIN_USERNAME','KC_BOOTSTRAP_ADMIN_PASSWORD']:
        found=re.findall(r'^\s+'+key+r': ([A-Za-z0-9-]+)\s*$',text,re.M)
        require(len(found)==1,'Public bootstrap source ambiguous');env[key]=found[0]
    return env

def docker(args, env=None):
    result=subprocess.run(['docker',*args],capture_output=True,env=env)
    require(result.returncode==0,'Owned Docker operation failed; raw diagnostics omitted')
    return result.stdout

def inspect_owned(gen, identifier, require_running=True):
    require(bool(re.fullmatch(r'[0-9a-f]{64}',identifier)),'Exact owned container ID required')
    fields={'id':'.Id','name':'.Name','image':'.Image','labels':'.Config.Labels','ports':'.NetworkSettings.Ports','startedAt':'.State.StartedAt','running':'.State.Running','mounts':'.Mounts','tmpfs':'.HostConfig.Tmpfs'}
    facts={key:json.loads(docker(['inspect','--format','{{json '+field+'}}',identifier])) for key,field in fields.items()}
    require(facts['id']==identifier and facts['name']=='/'+name(gen) and isinstance(facts['running'],bool) and (facts['running'] or not require_running),'Owned container identity changed')
    require(all(facts['labels'].get(k)==v for k,v in labels(gen).items()),'Owned container labels changed')
    require(facts['ports'].get('8080/tcp')==[{'HostIp':'127.0.0.1','HostPort':'28080'}]
            and all(v is None or k=='8080/tcp' for k,v in facts['ports'].items()),'Owned loopback port changed')
    binds=[m for m in facts['mounts'] if m.get('Type')=='bind']
    require(len(binds)==1 and binds[0].get('Source')==str(ROOT/SEED) and binds[0].get('Destination')=='/opt/keycloak/data/import/realm-samlscope.json' and binds[0].get('RW') is False
            and all(m.get('Type')=='bind' or m.get('Type')=='tmpfs' and m.get('Destination') in {'/opt/keycloak/data','/tmp'} for m in facts['mounts'])
            and set(facts['tmpfs'])=={'/opt/keycloak/data','/tmp'},'Unexpected owned persistent mount')
    repos=json.loads(docker(['image','inspect','--format','{{json .RepoDigests}}',IMAGE]));require(any(s.endswith('@'+IMAGE.split('@')[1]) for s in repos),'Pinned image manifest differs')
    require(facts['image']==json.loads(docker(['image','inspect','--format','{{json .Id}}',IMAGE])),'Owned container runs another image')
    facts['imageReference']=IMAGE;facts['publicRealmSha256']=SEED_SHA;facts['publicRealmGitBlob']=SEED_BLOB
    return facts

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args): return None

def request(url, method='GET', body=None, token=None, content_type=None, statuses=(200,)):
    parsed=urllib.parse.urlsplit(url)
    require(parsed.scheme=='http' and parsed.netloc in {'localhost:28080','localhost:18080'} and not parsed.username and not parsed.fragment,'Unowned HTTP scope')
    require(token is None or parsed.netloc=='localhost:28080' and parsed.path.startswith('/admin/'),'Refuse to send native authority outside owned admin scope')
    headers={}
    if token: headers['Authorization']='Bearer '+token
    if content_type: headers['Content-Type']=content_type
    opener=urllib.request.build_opener(NoRedirect())
    try: response=opener.open(urllib.request.Request(url,body,headers,method=method),timeout=30)
    except urllib.error.HTTPError as error: response=error
    with response:
        raw=response.read(2*1024*1024+1);status=response.status
        require(len(raw)<=2*1024*1024 and status in statuses,'Owned HTTP status or body bound failed; body omitted')
        return status,raw,dict(response.headers)

def admin_token():
    env=bootstrap_environment()
    form=urllib.parse.urlencode({'client_id':'admin-cli','username':env['KC_BOOTSTRAP_ADMIN_USERNAME'],'password':env['KC_BOOTSTRAP_ADMIN_PASSWORD'],'grant_type':'password'}).encode()
    _,raw,_=request(ORIGIN+'/realms/master/protocol/openid-connect/token','POST',form,content_type='application/x-www-form-urlencoded')
    value=json.loads(raw);require(isinstance(value.get('access_token'),str),'Owned admin authentication failed');return value['access_token']

def client_state(token):
    _,raw,_=request(ORIGIN+'/admin/realms/samlscope/clients',token=token)
    values=json.loads(raw);require(isinstance(values,list),'Native client-state shape differs')
    return digest(json.dumps(sorted(values,key=lambda v:v['id']),sort_keys=True,separators=(',',':')).encode())

ATTRIBUTES={'saml.client.signature':'true','saml.server.signature':'true','saml.assertion.signature':'true','saml.signature.algorithm':'RSA_SHA256','saml_force_name_id_format':'false','saml.encrypt':'false'}

def native_client(converted, issuer, gen):
    require(isinstance(converted,dict) and converted.get('protocol')=='saml' and converted.get('clientId')==issuer,'Native converter returned foreign client')
    client=dict(converted);client['name']='SAMLscope Owned CI NameID '+gen;client['attributes']=dict(client.get('attributes',{}))
    client['attributes'].update(ATTRIBUTES);client['attributes']['samlscope.owned.generation']=gen
    return client

def client_projection(client):
    return {'id':client['id'],'clientId':client['clientId'],'name':client['name'],'protocol':client['protocol'],'enabled':client.get('enabled'),
            'attributes':{key:client.get('attributes',{}).get(key) for key in [*ATTRIBUTES,'samlscope.owned.generation']},
            'redirectUris':client.get('redirectUris',[]),'configurationSha256':digest(json.dumps(client,sort_keys=True,separators=(',',':')).encode())}

def start(gen, output):
    source_seed();args=run_args(gen);write(output,'preflight.json',{'schema':'owned-keycloak-public-ci-preflight-v1','generation':gen,'command':args,'publicRealmSha256':SEED_SHA,'publicRealmGitBlob':SEED_BLOB,'credentialValuesExported':False,'existingReferenceInputs':False})
    identifier=None;success=False;counts={'containerCreateAttempts':1,'containersCreated':0,'publicMetadataGetAttempts':0,'publicMetadataGets':0,'failedStartCleanupAttempts':0,'failedStartCleanups':0}
    try:
        identifier=docker(args[1:],bootstrap_environment()).decode().strip();require(bool(re.fullmatch(r'[0-9a-f]{64}',identifier)),'Owned creation lacks ID');counts['containersCreated']=1
        write(output,'container-created.json',{'ownedContainerId':identifier,'ownedContainerName':name(gen),'ownedLabels':labels(gen)})
        facts=inspect_owned(gen,identifier)
        version=docker(['exec',identifier,'/opt/keycloak/bin/kc.sh','--version']).decode()
        require(bool(re.search(r'\bKeycloak\s+'+re.escape(VERSION)+r'\b',version)),'Native version differs from pinned CI image')
        deadline=time.monotonic()+150
        while True:
            try:
                counts['publicMetadataGetAttempts']+=1;_,metadata,_=request(ORIGIN+'/realms/samlscope/protocol/saml/descriptor')
                require(b'<EntityDescriptor' in metadata or b':EntityDescriptor' in metadata,'Public descriptor unavailable');counts['publicMetadataGets']+=1;break
            except Exception:
                if time.monotonic()>deadline: raise ValueError('Owned public descriptor health timed out; private logs omitted')
                time.sleep(2)
        (output/'keycloak-public-metadata.xml').write_bytes(metadata);facts['version']=VERSION;facts['targetMetadataSha256']=digest(metadata)
        facts.update({'schema':'owned-keycloak-public-ci-start-v1','generation':gen,'privateKeyReads':0,'canonicalAdoption':False,'runtimeConformanceStarted':False})
        write(output,'owned-start.json',facts);success=True
    finally:
        if identifier and not success:
            counts['failedStartCleanupAttempts']+=1
            try: docker(['rm','--force',identifier]);counts['failedStartCleanups']+=1
            except Exception: pass
        write(output,'start-operation-counts.json',counts)

def setup(gen, identifier, output, recovery=None):
    facts=inspect_owned(gen,identifier);source_seed();token=admin_token();before=client_state(token)
    counts={'nativeAdminAuthentications':1,'nativeClientCreateAttempts':0,'nativeClientsCreatedObserved':0,'nativeClientReadbacks':0,'suitePlanCreates':0,'suiteRunCreates':0,'failedSetupRestorationAttempts':0,'failedSetupRestorations':0}
    dbid=None;plan_id=None;success=False
    payload={'name':'Owned Keycloak public-CI NameID v2 '+gen,'profile':'browser_sso_idp','targetKind':'IDP','targetEntityId':ORIGIN+'/realms/samlscope','metadataSourceKind':'URL',
             'metadataSourceLocation':'http://host.docker.internal:28080/realms/samlscope/protocol/saml/descriptor','suiteMetadataDelivery':'HTTP_URL','declaredFeatures':{},
             'parameters':{'clockSkewToleranceSeconds':180,'metadataRefreshWaitSeconds':300,'requestSigningMode':'REQUIRED'},'interaction':{'allowBrowserSteps':True,'allowAttestation':False,'preset':'assisted'},'authorizedTarget':True}
    try:
        if recovery is not None:
            require(recovery.get('schema')=='owned-keycloak-plan-recovery-v1' and recovery.get('generation')==gen,'Unbound owned Plan recovery')
            plan_id=recovery['planId'];identity=recovery['definitionIdentity'];counts['existingOwnedPlanReuses']=1
            _,raw,_=request(SUITE+'/api/plans/'+plan_id);view=public(json.loads(raw));plan=view['plan']
            require(plan.get('id')==plan_id and plan.get('name')==payload['name'] and plan.get('profile')=='browser_sso_idp' and plan.get('target',{}).get('entityId')==payload['targetEntityId'],'Existing public Plan summary differs')
        else:
            _,raw,_=request(SUITE+'/api/plans','POST',json.dumps(payload).encode(),content_type='application/json',statuses=(201,));created=public(json.loads(raw));plan=created['plan']['plan'];counts['suitePlanCreates']=1
            write(output,'created-plan-reference.json',{'generation':gen,'planId':plan['id'],'actualPlanCreated':True})
            require('definitionIdentity' in plan,'Public PlanSummary omits definition identity; recover actual owned Plan before native creation')
            identity=plan['definitionIdentity']
        require(identity=={'profile':'browser_sso_idp','version':'functional-case-v2-nameid','digest':'sha256:05558838bf997f81d5be63d423df254b547ffe7c0600683157b6dadd566b7448'},'Installed NameID definition is not exact approved v2; no native client created')
        plan_id=plan['id'];require(bool(re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',plan_id)),'Invalid own Plan ID');issuer=SUITE+'/p/'+plan_id
        _,metadata,_=request(issuer+'/metadata');(output/'suite-public-metadata.xml').write_bytes(metadata)
        _,converted,_=request(ORIGIN+'/admin/realms/samlscope/client-description-converter','POST',metadata,token,'application/xml');client=native_client(json.loads(converted),issuer,gen)
        counts['nativeClientCreateAttempts']=1
        _,_,headers=request(ORIGIN+'/admin/realms/samlscope/clients','POST',json.dumps(client).encode(),token,'application/json',(201,))
        location=headers.get('Location') or headers.get('location');path=urllib.parse.urlsplit(location or '').path
        require(bool(re.fullmatch(r'/admin/realms/samlscope/clients/[a-f0-9-]{36}',path)),'Native creation lacks DB ID')
        dbid=path.rsplit('/',1)[1];counts['nativeClientsCreatedObserved']=1
        write(output,'created-client-reference.json',{'generation':gen,'clientDbId':dbid,'planId':plan_id,'originalClientStateSha256':before})
        _,readback,_=request(ORIGIN+path,token=token);readback=json.loads(readback);counts['nativeClientReadbacks']=1
        require(readback.get('id')==dbid and readback.get('clientId')==issuer and readback.get('name')=='SAMLscope Owned CI NameID '+gen
                and readback.get('attributes',{}).get('samlscope.owned.generation')==gen and all(readback.get('attributes',{}).get(k)==v for k,v in ATTRIBUTES.items()),'Native configuration readback differs')
        _,run_list,_=request(SUITE+'/api/plans/'+plan_id+'/runs');existing=public(json.loads(run_list))
        require(isinstance(existing,list) and len(existing)<=1,'Ambiguous owned Run recovery')
        if existing:
            run=existing[0];require(run.get('status')=='CREATED' and not run.get('context',{}).get('authnRequestId'),'Existing own Run already started');counts['existingOwnedRunReuses']=1
        else:
            _,run_raw,_=request(SUITE+'/api/plans/'+plan_id+'/runs','POST',b'{}',content_type='application/json',statuses=(201,));run=public(json.loads(run_raw))['run'];counts['suiteRunCreates']=1
        require(bool(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run['id'])) and run['planId']==plan_id,'Created Run is not bound to own Plan')
        _,target_md,_=request(ORIGIN+'/realms/samlscope/protocol/saml/descriptor')
        browser={'schema':'owned-keycloak-nameid-setup-v1','generation':gen,'suiteOrigin':SUITE,'targetOrigin':ORIGIN,'targetEntityId':ORIGIN+'/realms/samlscope','runId':run['id'],'planId':plan_id,
                 'caseId':CASE,'caseDigest':CASE_DIGEST,'definitionIdentity':identity,'suitePublicMetadataFile':str((output/'suite-public-metadata.xml').resolve()),'suitePublicMetadataSha256':digest(metadata),
                 'clientDbId':dbid,'ownedContainerId':identifier,'ownedContainerName':name(gen),'imageReference':IMAGE,'ownedLabels':labels(gen)}
        document={**browser,'nativeClientReadback':client_projection(readback),'originalClientStateSha256':before,'targetMetadataSha256':digest(target_md),
                  'nativeClientCreateAttempts':1,'nativeClientCreates':1,'restorationRequired':True,'metadataInterpretationConformanceClaimed':False,'canonicalAdoption':False}
        write(output,'setup.json',document);write(output,'browser-setup.json',browser);success=True
    finally:
        if not success and counts['nativeClientCreateAttempts'] and plan_id:
            counts['failedSetupRestorationAttempts']=1
            try:
                # A timed-out creation is not replayed. Discover only the uniquely owned client.
                if dbid is None:
                    _,raw,_=request(ORIGIN+'/admin/realms/samlscope/clients',token=token);candidates=[c for c in json.loads(raw) if c.get('clientId')==SUITE+'/p/'+plan_id and c.get('name')=='SAMLscope Owned CI NameID '+gen and c.get('attributes',{}).get('samlscope.owned.generation')==gen]
                    require(len(candidates)<=1,'Ambiguous owned creation');dbid=candidates[0]['id'] if candidates else None
                if dbid:
                    require(bool(re.fullmatch(r'[a-f0-9-]{36}',dbid)),'Invalid owned restoration ID');url=ORIGIN+'/admin/realms/samlscope/clients/'+dbid
                    _,raw,_=request(url,token=token);live=json.loads(raw)
                    require(live.get('clientId')==SUITE+'/p/'+plan_id and live.get('name')=='SAMLscope Owned CI NameID '+gen and live.get('attributes',{}).get('samlscope.owned.generation')==gen,'Refuse unowned failed-setup deletion')
                    request(url,'DELETE',token=token,statuses=(204,));request(url,token=token,statuses=(404,))
                after=client_state(token);require(after==before,'Failed setup native state not restored');counts['failedSetupRestorations']=1
                write(output,'failed-setup-restoration.json',{'clientDbId':dbid,'readbackStatus':404 if dbid else None,'originalClientStateSha256':before,'finalClientStateSha256':after,'restored':True})
            except Exception: write(output,'failed-setup-restoration.json',{'clientDbId':dbid,'restored':False,'privateDiagnosticsOmitted':True})
        write(output,'setup-operation-counts.json',counts)

def restore(document, output):
    gen=generation(document['generation']);inspect_owned(gen,document['ownedContainerId']);token=admin_token();dbid=document['clientDbId']
    require(bool(re.fullmatch(r'[a-f0-9-]{36}',dbid)),'Invalid owned client DB ID');url=ORIGIN+'/admin/realms/samlscope/clients/'+dbid
    _,raw,_=request(url,token=token);client=json.loads(raw)
    require(client.get('clientId')==SUITE+'/p/'+document['planId'] and client.get('name')=='SAMLscope Owned CI NameID '+gen and client.get('attributes',{}).get('samlscope.owned.generation')==gen,'Refuse to delete an unowned client')
    request(url,'DELETE',token=token,statuses=(204,));request(url,token=token,statuses=(404,))
    after=client_state(token);require(after==document['originalClientStateSha256'],'Native original client state not restored')
    write(output,'restoration.json',{'nativeClientDeleteAttempts':1,'nativeClientDeletes':1,'readbackStatus':404,'originalClientStateSha256':after,'restored':True,'credentialValuesExported':False})

def main():
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['plan','start','setup','restore','cleanup']);parser.add_argument('--generation',required=True);parser.add_argument('--output');parser.add_argument('--container-id');parser.add_argument('--setup');parser.add_argument('--existing-plan-recovery');parser.add_argument('--execute',action='store_true');args=parser.parse_args();gen=generation(args.generation)
    if args.mode=='plan':
        source_seed();print(json.dumps({'generation':gen,'command':run_args(gen),'knownPublicCredentialValuesExported':False},indent=2));return
    require(args.execute,'Explicit execution flag required');require(args.output,'Fresh owned output directory required');output=owned_path(args.output);output.mkdir()
    if args.mode=='start': start(gen,output)
    elif args.mode=='setup': setup(gen,args.container_id,output,json.loads(owned_path(args.existing_plan_recovery).read_text()) if args.existing_plan_recovery else None)
    elif args.mode=='restore':
        document=json.loads(owned_path(args.setup).read_text());require(document['schema']=='owned-keycloak-nameid-setup-v1' and document['generation']==gen,'Restoration schema/generation differs');restore(document,output)
    elif args.mode=='cleanup':
        inspect_owned(gen,args.container_id,require_running=False);docker(['rm','--force',args.container_id]);write(output,'cleanup.json',{'ownedContainerId':args.container_id,'ownedContainerRemoved':True,'imageAndOtherContainersRetained':True})

if __name__=='__main__':
    try: main()
    except Exception: raise SystemExit('Owned Keycloak operation incomplete; private diagnostics omitted')
