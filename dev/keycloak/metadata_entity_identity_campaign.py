#!/usr/bin/env python3
"""Two native XML imports, one shared login, and simultaneous duplicate identity conflict.

Credentials exist only in memory. Converter output is POSTed unchanged. This collector
does not replace clients or decide conformance, and deletes only its two fresh clients.
"""
import argparse,base64,datetime,hashlib,json,os,pathlib,re,subprocess,sys,urllib.error,urllib.parse,urllib.request,zlib
import xml.etree.ElementTree as ET
from attribute_policy_capability_absence import product_token
from import_metadata_batch import api,save,BASE
from mdiop_representation_campaign import runtime
from algorithm_preference_campaign import recorded
from reference_flow import Client

REPO=pathlib.Path(__file__).resolve().parents[2];sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture
ADMIN='http://localhost:18180/admin/realms/samlscope';TARGET='http://localhost:18180/realms/samlscope';CONTAINER='samlscope-reference-keycloak'
CAMPAIGN='native-metadata-entity-identity';SCHEMA='samlscope-keycloak-metadata-entity-identity-original-v1'
JARS=['org.keycloak.keycloak-services-26.7.2.jar','org.keycloak.keycloak-model-jpa-26.7.2.jar','org.keycloak.keycloak-core-26.7.2.jar','org.keycloak.keycloak-server-spi-26.7.2.jar','org.keycloak.keycloak-server-spi-private-26.7.2.jar']
sha=lambda raw:hashlib.sha256(raw).hexdigest()
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def reject(value):
    if isinstance(value,dict):
        for key,item in value.items():
            if re.search('private|password|secret|credential|token|cookie|authorization',key,re.I) and not (key=='client.secret.creation.time' and isinstance(item,str) and re.fullmatch(r'[0-9]+',item)):raise ValueError('Sensitive native field refused before recording')
            reject(item)
    elif isinstance(value,list):
        for item in value:reject(item)

class SharedNormalRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self,owner):self.owner=owner
    def redirect_request(self,request,fp,status,message,headers,url):
        part=urllib.parse.urlsplit(url)
        if part.hostname not in {'localhost','127.0.0.1'}:raise ValueError('Nonlocal redirect refused')
        if part.path=='/realms/samlscope/protocol/saml':
            values=urllib.parse.parse_qs(part.query,strict_parsing=True)
            if 'SAMLRequest' in values:
                if len(values['SAMLRequest'])!=1:raise ValueError('Ambiguous SAML request')
                raw=zlib.decompress(base64.b64decode(values['SAMLRequest'][0],validate=True),-15);xml=ET.fromstring(raw)
                if xml.get('ForceAuthn','false') not in {'false','0'} or xml.get('IsPassive','false') not in {'false','0'}:raise ValueError('Fresh-session boundary: normal session reuse stopped before target')
                self.owner.arrivals.append(dict(requestId=xml.get('ID'),requestSha256=sha(raw),rawQuerySha256=sha(part.query.encode('ascii')),method='GET',recordedAt=now(),freshSessionRequired=False))
        return super().redirect_request(request,fp,status,message,headers,url)
class SharedNormalClient(Client):
    def __init__(self):
        super().__init__();self.credential_posts=0;self.arrivals=[]
        self.op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),SharedNormalRedirect(self))
    def request(self,url,fields=None):
        if fields and ('password' in fields or 'j_password' in fields):self.credential_posts+=1
        return super().request(url,fields)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);args=p.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    operations=[];peers=[];token=product_token();token_reads=1;client=SharedNormalClient();protocol=0;normal_attempts=0;root_created=None
    def native(path,method='GET',body=None,xml=False):
        nonlocal token,token_reads
        raw=body if isinstance(body,bytes) else None if body is None else json.dumps(body,separators=(',',':')).encode()
        if raw is not None and not xml:reject(json.loads(raw))
        for attempt in range(2):
            row=dict(method=method,url=ADMIN+path,startedAt=now(),productSettingWrite=method in {'PUT','DELETE'} or method=='POST' and path!='/client-description-converter');operations.append(row);save(out/'operations.json',operations)
            request=urllib.request.Request(ADMIN+path,data=raw,method=method,headers={'Authorization':'Bearer '+token,'Content-Type':'application/xml' if xml else 'application/json'})
            try:
                with urllib.request.urlopen(request,timeout=40) as response:status,reply,location=response.status,response.read(),response.headers.get('Location')
            except urllib.error.HTTPError as response:status,reply,location=response.code,response.read(),response.headers.get('Location')
            row.update(status=status,finishedAt=now());save(out/'operations.json',operations)
            if status!=401:break
            token=product_token();token_reads+=1
        value=json.loads(reply) if reply else None;redactions=[]
        if method=='GET' and re.fullmatch('/clients/[0-9a-f-]{36}',path) and isinstance(value,dict):
            for name in ['secret','registrationAccessToken']:
                if name in value:del value[name];redactions.append('$.'+name)
            reply=json.dumps(value,separators=(',',':')).encode()
        reject(value);record=dict(row,response_base64=base64.b64encode(reply).decode(),response_sha256=sha(reply))
        if raw is not None:record.update(request_base64=base64.b64encode(raw).decode(),request_sha256=sha(raw))
        if method=='GET' and re.fullmatch('/clients/[0-9a-f-]{36}',path):record.update(response_projection='native-client-public-readback-v1',redactions=redactions)
        return value,record,location,reply
    def original(record_label,kind,**value):
        data=dict(schema=SCHEMA,runId=root_created['run']['id'],campaignId=CAMPAIGN,targetMetadataSha256=sha((out/'primary/target-metadata.xml').read_bytes()),recordedAt=now(),kind=kind,**value)
        return recorded(out,root_created,data,record_label)
    def policy():return {name:native('/client-policies/'+name)[0] for name in ['policies','profiles']}
    source=out/'native-runtime';source.mkdir();pins={}
    for name in JARS:
        subprocess.run(['docker','cp',CONTAINER+':/opt/keycloak/lib/lib/main/'+name,str(source/name)],check=True,capture_output=True);pins[name]=sha((source/name).read_bytes())
    save(source/'pins.json',pins);before_runtime=runtime();before_policy=policy();frames=[];duplicate=None;restored=False
    try:
        for label in ['primary','secondary']:
            folder=out/label;folder.mkdir();plan=api('/api/plans',dict(name='Keycloak native metadata entity identity '+label,profile='metadata_idp',targetKind='IDP',targetEntityId=TARGET,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=False,allowAttestation=False,preset='quick'),authorizedTarget=True));save(folder/'plan.json',plan);pid=plan['plan']['plan']['id'];created=api('/api/plans/'+pid+'/runs',{});save(folder/'created.json',created)
            peer=dict(label=label,folder=folder,created=created,planId=pid,runId=created['run']['id'],entity=BASE+'/p/'+pid,clientId=None);peers.append(peer)
            if root_created is None:root_created=created;save(out/'created.json',created);save(out/'plan.json',plan)
            save(folder/'preflight.json',api('/api/runs/'+peer['runId']+'/preflight',{}));subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+peer['runId']+'.xml',str(folder/'target-metadata.xml')],check=True,capture_output=True)
            if label=='primary':(out/'target-metadata.xml').write_bytes((folder/'target-metadata.xml').read_bytes())
            lookup='/clients?clientId='+urllib.parse.quote(peer['entity'],safe='')+'&briefRepresentation=true';peer['lookup']=lookup
            empty,initial,_,_=native(lookup)
            if empty!=[]:raise ValueError('Refusing preexisting entity')
            peer['initial']=original(label+'-initial','initial-native-inventory',label=label,entityId=peer['entity'],native=initial)
            with urllib.request.urlopen(peer['entity']+'/metadata',timeout=30) as response:xml=response.read()
            (folder/'fixture.xml').write_bytes(xml)
            converted,conversion,_,raw=native('/client-description-converter','POST',xml,True)
            if conversion['status']!=200 or converted.get('clientId')!=peer['entity'] or converted.get('protocol')!='saml' or converted.get('id'):raise ValueError('Native XML converter prerequisite failed')
            peer['conversion']=original(label+'-conversion','native-metadata-conversion',label=label,entityId=peer['entity'],fixtureBase64=base64.b64encode(xml).decode(),fixtureSha256=sha(xml),native=conversion)
            _,creation,location,_=native('/clients','POST',raw)
            if creation['status']!=201 or not location:raise ValueError('Native fresh client creation failed')
            peer['clientId']=location.rsplit('/',1)[-1]
            if not re.fullmatch('[0-9a-f-]{36}',peer['clientId']):raise ValueError('Native client DB identity invalid')
            peer['creation']=original(label+'-creation','native-simultaneous-create',label=label,entityId=peer['entity'],clientDatabaseId=peer['clientId'],native=creation)
        def state(label):
            values=[]
            for peer in peers:
                saved,record,_,_=native('/clients/'+peer['clientId'])
                if record['status']!=200 or saved.get('clientId')!=peer['entity'] or saved.get('id')!=peer['clientId']:raise ValueError('Operative native entity readback differs')
                values.append(dict(label=peer['label'],entityId=peer['entity'],runId=peer['runId'],planId=peer['planId'],clientDatabaseId=peer['clientId'],native=record))
            return original(label,'simultaneous-native-entities',peers=values,runtime=runtime(),policies=policy())
        normal_before=state('normal-before')
        for peer in peers:
            entries=api('/api/runs/'+peer['runId']+'/transcript');ids={e['id'] for e in entries};normal_attempts+=1
            result=client.flow(peer['entity']+'/start/m0-roundtrip?run='+peer['runId'],None,os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
            added=[e for e in api('/api/runs/'+peer['runId']+'/transcript') if e['id'] not in ids];rq=[e for e in added if e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='AuthnRequest'];rs=[e for e in added if e['direction']=='INBOUND' and e['samlSummary'].get('normalFlowAccepted') is True]
            protocol+=len(rq)
            if result!='recorded' or len(rq)!=1 or len(rs)!=1 or rs[0]['samlSummary'].get('inResponseTo')!=rq[0]['samlSummary'].get('id'):raise ValueError('Shared normal prerequisite incomplete; no repeated login')
            peer['normal']=dict(requestReference=rq[0]['id'],responseReference=rs[0]['id']);save(peer['folder']/'normal.json',peer['normal'])
        normal_after=state('normal-after')
        primary=peers[0];run=primary['runId'];save(out/'duplicate-campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=['multiple-signing-keys'],pollingDelaySeconds=0)));lab=api('/api/runs/'+run+'/metadata-lab')
        with urllib.request.urlopen(lab['automaticStartUrl'],timeout=30) as response:
            if response.status!=202:raise ValueError('Duplicate fixture preparation gate missing')
        with urllib.request.urlopen(lab['metadataUrl'],timeout=30) as response:xml=response.read()
        (out/'duplicate-fixture.xml').write_bytes(xml);converted,conversion,_,raw=native('/client-description-converter','POST',xml,True)
        if conversion['status']!=200 or converted.get('clientId')!=primary['entity'] or converted.get('protocol')!='saml' or converted.get('id'):raise ValueError('Duplicate XML converter prerequisite failed')
        conversion_ref=original('duplicate-conversion','native-metadata-conversion',entityId=primary['entity'],fixtureSha256=sha(xml),native=conversion)
        duplicate_before=state('duplicate-before');_,creation,_,_=native('/clients','POST',raw);creation_ref=original('duplicate-create','native-simultaneous-duplicate-create',entityId=primary['entity'],native=creation)
        duplicate_after=state('duplicate-after')
        save(out/'observations.json',dict(normalBefore=normal_before,normalAfter=normal_after,duplicateBefore=duplicate_before,duplicateAfter=duplicate_after,duplicateConversion=conversion_ref,duplicateCreation=creation_ref))
        save(out/'native-browser-observations.json',client.arrivals)
        for peer in peers:save(peer['folder']/'tests-start.json',api('/api/runs/'+peer['runId']+'/tests/start',{}))
    finally:
        cleanup=[];errors=[]
        for peer in reversed(peers):
            if peer['clientId']:
                try:
                    _,record,_,_=native('/clients/'+peer['clientId'],'DELETE');cleanup.append(dict(entityId=peer['entity'],clientDatabaseId=peer['clientId'],native=record))
                    if record['status']!=204:errors.append('Native fresh-client cleanup failed')
                except Exception as error:errors.append(type(error).__name__)
            try:
                empty,record,_,_=native(peer['lookup']);cleanup.append(dict(entityId=peer['entity'],native=record))
                if empty!=[]:errors.append('Native entity remains')
            except Exception as error:errors.append(type(error).__name__)
        after_runtime=runtime();after_policy=policy();restored=not errors and before_runtime==after_runtime and before_policy==after_policy
        if root_created:save(out/'restoration-ref.json',original('restoration','native-restoration',runtimeBefore=before_runtime,runtimeAfter=after_runtime,policiesBefore=before_policy,policiesAfter=after_policy,cleanup=cleanup,restored=restored))
        save(out/'restoration.json',dict(restored=restored,errors=errors));save(out/'operation-counts.json',dict(nativeHttpAttempts=len(operations),nativeConverterAttempts=sum(r['url']==ADMIN+'/client-description-converter' for r in operations),nativeConfigurationWriteAttempts=sum(r['productSettingWrite'] for r in operations),nativeConfigurationWrites=sum(r['productSettingWrite'] and r['status'] in {200,201,204} for r in operations),duplicateRegistrationAttempts=sum(r['productSettingWrite'] and r['status']==409 for r in operations),restorationWrites=sum(r['method']=='DELETE' and r['status']==204 for r in operations),normalFlowsAttempted=normal_attempts,protocolSubmissions=protocol,credentialPosts=client.credential_posts,sharedAuthenticatedClients=1,reusedNormalSubmissions=max(0,len(client.arrivals)-1),freshSessionBoundaries=1,productRestarts=0,personOperations=0,administratorTokenReads=token_reads,runCreations=len(peers),restored=restored))
        for peer in peers:
            try:
                entries=api('/api/runs/'+peer['runId']+'/transcript');save(peer['folder']/'transcript.json',entries);capture(peer['folder'],peer['runId'],entries);save(peer['folder']/'result-before.json',api('/api/runs/'+peer['runId']+'/result.json'))
            except Exception as error:save(peer['folder']/'export-incomplete.json',dict(reason=type(error).__name__,verdictAdopted=False))
        if root_created:
            entries=api('/api/runs/'+root_created['run']['id']+'/transcript');save(out/'transcript.json',entries);capture(out,root_created['run']['id'],entries)
        save(out/'peers.json',[{k:v for k,v in peer.items() if k not in {'folder','created'}} for peer in peers])
    print('Native entity identity collection complete, restored='+str(restored)+'; no verdict adopted',flush=True)
if __name__=='__main__':main()
