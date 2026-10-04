#!/usr/bin/env python3
"""Two native XML imports, one shared login, and six registered signer outbox checks.

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
from browser_probe_selection import prepare_and_skip
from capture_browser_originals import capture as capture_browser

REPO=pathlib.Path(__file__).resolve().parents[2];sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture
ADMIN='http://localhost:18180/admin/realms/samlscope';TARGET='http://localhost:18180/realms/samlscope';CONTAINER='samlscope-reference-keycloak'
CAMPAIGN='native-registered-signer';SCHEMA='samlscope-keycloak-registered-signer-original-v1'
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
        super().__init__();self.credential_posts=0;self.arrivals=[];self.protocol_posts=0;self.last_protocol_http=None
        self.op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),SharedNormalRedirect(self))
    def request(self,url,fields=None):
        if fields and ('password' in fields or 'j_password' in fields):
            if self.credential_posts:raise ValueError('Shared login prerequisite failed; repeated credential entry refused before target')
            self.credential_posts+=1
        started=now();xml=None
        if fields and 'SAMLRequest' in fields:
            raw=base64.b64decode(fields['SAMLRequest'],validate=True);xml=ET.fromstring(raw)
            if xml.get('ForceAuthn','false') not in {'false','0'} or xml.get('IsPassive','false') not in {'false','0'}:raise ValueError('Fresh boundary refused before target')
            self.protocol_posts+=1
        location,page,status=super().request(url,fields)
        if xml is not None:
            self.last_protocol_http=dict(method='POST',requestUrl=url,responseUrl=location,requestId=xml.get('ID'),requestSha256=sha(raw),startedAt=started,finishedAt=now(),responseStatus=status,responseBodySha256=sha(page.encode()),responseBodyBytes=len(page.encode()))
        return location,page,status

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
        old=REPO/'build/acceptance/reference-20261002/keycloak-metadata-entity-identity-r1/native-runtime'/name
        actual=subprocess.check_output(['docker','exec',CONTAINER,'sha256sum','/opt/keycloak/lib/lib/main/'+name],timeout=30).decode().split()[0]
        if old.is_file() and sha(old.read_bytes())==actual:os.link(old,source/name)
        else:subprocess.run(['docker','cp',CONTAINER+':/opt/keycloak/lib/lib/main/'+name,str(source/name)],check=True,capture_output=True,timeout=90)
        pins[name]=sha((source/name).read_bytes())
        if pins[name]!=actual:raise ValueError('Native binary source changed')
    save(source/'pins.json',pins);before_runtime=runtime();before_policy=policy();frames=[];duplicate=None;restored=False
    try:
        for label in ['primary','secondary']:
            folder=out/label;folder.mkdir();plan=api('/api/plans',dict(name='Keycloak registered signer '+label,profile='browser_sso_idp',targetKind='IDP',targetEntityId=TARGET,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(folder/'plan.json',plan);pid=plan['plan']['plan']['id'];created=api('/api/plans/'+pid+'/runs',{});save(folder/'created.json',created)
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
            return original(label,'registered-signer-native-clients',peers=values,runtime=runtime(),policies=policy(),nativeServicesSha256=subprocess.check_output(['docker','exec',CONTAINER,'sha256sum','/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar'],timeout=30).decode().split()[0])
        prerequisites_before=state('prerequisites-before')
        for peer in peers:
            entries=api('/api/runs/'+peer['runId']+'/transcript');ids={e['id'] for e in entries};normal_attempts+=1
            result=client.flow(peer['entity']+'/start/m0-roundtrip?run='+peer['runId'],None,os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
            added=[e for e in api('/api/runs/'+peer['runId']+'/transcript') if e['id'] not in ids];rq=[e for e in added if e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='AuthnRequest'];rs=[e for e in added if e['direction']=='INBOUND' and e['samlSummary'].get('normalFlowAccepted') is True]
            protocol+=len(rq)
            if result!='recorded' or len(rq)!=1 or len(rs)!=1 or rs[0]['samlSummary'].get('inResponseTo')!=rq[0]['samlSummary'].get('id'):raise ValueError('Shared normal prerequisite incomplete; no repeated login')
            peer['normal']=dict(requestReference=rq[0]['id'],responseReference=rs[0]['id']);save(peer['folder']/'normal.json',peer['normal'])
        probes_before=state('probes-before')
        save(out/'peers.json',[{k:v for k,v in peer.items() if k!='created' and k!='folder'} for peer in peers])
        install_count=0
        for peer in peers:
            stage=out/('preparation-'+peer['label']);stage.mkdir()
            for member in peers:
                for name in ['fixture.xml','created.json']:
                    dest=stage/member['label']/name;dest.parent.mkdir(exist_ok=True);dest.write_bytes((out/member['label']/name).read_bytes())
            (stage/'target-metadata.xml').write_bytes((out/'target-metadata.xml').read_bytes())
            files={str(f.relative_to(stage)):sha(f.read_bytes()) for f in stage.rglob('*') if f.is_file()}
            save(stage/'preparation.json',dict(schema='samlscope-registered-signer-preparation-v1',campaignId=CAMPAIGN,localRunId=peer['runId'],targetMetadataSha256=sha((out/'target-metadata.xml').read_bytes()),peers=load(out/'peers.json'),files=files))
            remote='/data/keycloak-registered-signer-evidence/'+peer['runId']
            subprocess.run(['docker','exec','samlscope-reference-suite','mkdir','-p',remote],check=True,capture_output=True,timeout=30)
            subprocess.run(['docker','cp',str(stage)+'/.','samlscope-reference-suite:'+remote],check=True,capture_output=True,timeout=60);install_count+=1
            save(out/peer['label']/'tests-start.json',api('/api/runs/'+peer['runId']+'/tests/start',{}))
        probes=[];skipped=[]
        for peer in peers:
            sent=0
            for _ in range(500):
                status=api('/api/runs/'+peer['runId']+'/active-probe')
                if status.get('caseId')=='IIP-SSO01-al-idp-01':
                    if status.get('state')!='READY':raise ValueError('Selected signer probe is not ready; no repeated login')
                    if status.get('requiresFreshSession') is not False:raise ValueError('Unknown/fresh boundary; shared login stopped before target')
                    action=status['actionId'];before=api('/api/runs/'+peer['runId']+'/transcript');oldids={e['id'] for e in before};http_record=None
                    def terminal(url,page,code,reason):
                        nonlocal http_record
                        if client.last_protocol_http is None:raise ValueError('Native terminal has no actual target POST')
                        http_record=dict(client.last_protocol_http)
                        if http_record['requestId']!='_'+action or http_record['responseUrl']!=url or http_record['responseStatus']!=code or http_record['responseBodySha256']!=sha(page.encode()):raise ValueError('Native terminal not action-correlated')
                        api('/api/runs/'+peer['runId']+'/active-probe/browser-response',dict(actionId=action,status=code,url=url,body=page))
                    result=client.flow(status['startUrl'],None,os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'),terminal_observer=terminal)
                    added=[e for e in api('/api/runs/'+peer['runId']+'/transcript') if e['id'] not in oldids];rq=[e for e in added if e['direction']=='OUTBOUND' and e.get('correlationId')==action and e['samlSummary'].get('type')=='AuthnRequest']
                    terminal_entries=[e for e in added if e['direction']=='INBOUND' and (e.get('correlationId')==action and e['samlSummary'].get('type')=='BrowserResponseObservation' or e['samlSummary'].get('inResponseTo')=='_'+action)]
                    if len(rq)!=1 or len(terminal_entries)!=1:raise ValueError('Signer action lacks exactly one recorded request and response')
                    name=['local-normal','local-invalid-signature','local-other-signer'][sent]
                    row=dict(fixture=name,runId=peer['runId'],actionId=action,requestReference=rq[0]['id'],responseReference=terminal_entries[0]['id'],receipt=result,reusedAuthenticatedClient=True,requiresFreshSession=False)
                    if http_record is not None:
                        label=peer['label']+'-'+name+'-http';original(label,'native-http-response',observedRunId=peer['runId'],requestReference=rq[0]['id'],responseReference=terminal_entries[0]['id'],actionId=action,native=http_record);row['nativeHttpOriginal']=label
                    probes.append(row);save(out/'probes.json',probes);sent+=1
                    if sent==3:break
                elif status.get('state')=='READY':
                    skipped.append(dict(runId=peer['runId'],**prepare_and_skip(BASE,peer['runId'],status,api)));save(out/'suite-only-skips.json',skipped)
                else:raise ValueError('Selected signer case not reachable; no repeated login')
            if sent!=3:raise ValueError('Incomplete signer chain')
        probes_after=state('probes-after');save(out/'probe-state.json',dict(before=probes_before,after=probes_after))
        save(out/'observations.json',dict(protocolPairs=len(probes),baselinePairs=normal_attempts,selectedFixtureCount=6,credentialPosts=client.credential_posts,preparationInstallations=install_count))
    finally:
        cleanup=[]
        for peer in reversed(peers):
            if peer.get('clientId'):
                _,deletion,_,_=native('/clients/'+peer['clientId'],'DELETE');remaining,inventory,_,_=native(peer['lookup']);cleanup.append(dict(label=peer['label'],deletion=deletion,inventory=inventory,remaining=remaining))
        cleanup.reverse();restored=len(cleanup)==len(peers)==2 and all(p['deletion']['status']==204 and p['remaining']==[] for p in cleanup)
        final_runtime=runtime();final_policy=policy()
        if root_created:
            restoration=original('restoration','native-restoration',restored=restored,peers=cleanup,runtime=final_runtime,policies=final_policy);save(out/'restoration-ref.json',restoration)
        save(out/'restoration.json',dict(restored=restored,before_runtime=before_runtime,after_runtime=final_runtime,before_policy=before_policy,after_policy=final_policy))
        counts=dict(nativeHttpAttempts=len(operations),nativeConverterAttempts=sum(o['url'].endswith('/client-description-converter') for o in operations),nativeConfigurationWriteAttempts=sum(o['productSettingWrite'] for o in operations),nativeConfigurationWrites=sum(o['productSettingWrite'] and 200<=o.get('status',0)<300 for o in operations),restorationWrites=sum(o['method']=='DELETE' and o.get('status')==204 for o in operations),protocolSubmissions=len(client.arrivals)+client.protocol_posts,baselineProtocolSubmissions=len(client.arrivals),selectedOutboxProtocolSubmissions=client.protocol_posts,normalFlowsAttempted=normal_attempts,credentialPosts=client.credential_posts,sharedAuthenticatedClients=1,freshSessionBoundaries=1,productRestarts=0,personOperations=0,administratorTokenReads=token_reads,runCreations=len(peers),restored=restored)
        save(out/'operation-counts.json',counts)
    if not restored:raise ValueError('Native settings not restored')
    for peer in peers:
        entries=api('/api/runs/'+peer['runId']+'/transcript');save(out/peer['label']/'transcript.json',entries);save(out/peer['label']/'result.json',api('/api/runs/'+peer['runId']+'/result.json'));capture(out/peer['label'],peer['runId'],entries);capture_browser(out/peer['label'],entries)
    print('Native registered signer observations captured; products restored; credentials not persisted')
def load(p):return json.loads(p.read_bytes())
if __name__=='__main__':main()
