#!/usr/bin/env python3
"""Actual same-Run SOAP continuation trials; no protocol bytes are built here.

The case prepares every AuthnRequest and SOAP origin through the Suite outbox.
Only signed MetadataPrepared originals configure the three participant routes.
Credentials and browser capabilities stay in memory; every owned setting restores.
"""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'dev/shibboleth'),str(REPO/'dev/keycloak'),str(REPO/'dev/reference-acceptance'),str(REPO/'dev/slo')]
from slo_registered_signer_campaign import ShibbolethProduct,public_configuration,ROOT,PROVIDERS,AUDIT,CONTAINER,PROFILE,TRUST,SIGNER
from registered_signer_common import SHA,NOW,require,save,runtime,MD,public_json
from import_metadata_batch import api,BASE
from reference_flow import Client
from browser_probe_selection import prepare_and_skip
from capture_run_originals import capture

CASE='IIP-IDP17-r-idp-01';PUBLIC=ROOT+'/metadata/idp-metadata.xml'
SOAP='urn:oasis:names:tc:SAML:2.0:bindings:SOAP';P='urn:oasis:names:tc:SAML:2.0:protocol'
SCHEMA='samlscope-shibboleth-native-soap-continuation-v1'
TRIALS=('failure','all-success');LABELS=('primary','fail','remain','remain2')
AUTHN_FLOWS=('conditions-flow.xml','account-locked/account-locked-flow.xml','expired-password/expired-password-flow.xml','expiring-password/expiring-password-flow.xml')

def validate_flow_inventory(inventory,originals,jar):
    expected={ROOT+'/flows/authn/conditions/'+p:jar.read('net/shibboleth/idp/module/flows/authn/conditions/'+p)for p in AUTHN_FLOWS}
    require(set(originals)==set(expected),'Whole original native authentication flow set required')
    require(all(originals[p]==raw for p,raw in expected.items()),'Native authentication flow differs from stock JAR source')
    rows=inventory.decode().splitlines();require(len(rows)==len(set(rows)),'Duplicate native flow inventory entry')
    require(set(expected).issubset(rows),'Original native authentication flows absent from actual inventory')
    for path in rows:require(path.startswith(ROOT+'/')and not path.endswith(('.class','.jar'))
        and('/flows/'not in path or path in expected),'Unqualified selected native flow override')

def action(run,trial,stage,label='primary'):
    phase='slo-basic-v6-soap-propagation-'+trial+(''if label=='primary'else '-'+label)+'-'+stage
    return 'action_'+SHA('\x1f'.join((run,CASE,phase,'0')).encode())[:32]

def origin_final(entries,run,trial):
    chosen=action(run,trial,'logout')
    requests=[e for e in entries if e.get('direction')=='OUTBOUND'and e.get('correlationId')==chosen
        and e.get('samlSummary',{}).get('type')=='LogoutRequest'and e.get('samlSummary',{}).get('action_id')==chosen
        and e.get('samlSummary',{}).get('probe_transport')=='direct-soap']
    require(len(requests)<=1,'Duplicate origin action; no retry')
    if not requests:return None
    responses=[e for e in entries if e.get('direction')=='INBOUND'and e.get('samlSummary',{}).get('request_transcript')==requests[0]['id']
        and e.get('samlSummary',{}).get('type')=='SloProbeHttpResponse'and e.get('samlSummary',{}).get('saml_message')=='LogoutResponse'
        and e.get('samlSummary',{}).get('probe_transport')=='direct-soap']
    require(len(responses)<=1,'Duplicate origin response; no retry')
    return (requests[0],responses[0])if responses else None

def select_configuration(run,out,skips):
    for _ in range(350):
        pending=api('/api/runs/'+run+'/interactions')
        if any(x['caseId']==CASE and x['kind']=='CONFIGURATION'for x in pending):return
        status=api('/api/runs/'+run+'/active-probe')
        # Selection can start a configuration case without creating a browser outbox.
        pending=api('/api/runs/'+run+'/interactions')
        if any(x['caseId']==CASE and x['kind']=='CONFIGURATION'for x in pending):return
        require(status.get('state')=='READY'and status.get('caseId')!=CASE,'Selected preparation did not reach configuration wait')
        skips.append(prepare_and_skip(BASE,run,status,api));save(out/'suite-only-skips.json',skips)
    raise ValueError('Suite-only selection bound exceeded')

def soap_advertisement(raw,target):
    root=ET.fromstring(public_configuration(raw))
    require(root.tag=='{'+MD+'}EntityDescriptor' and root.get('entityID')==target
            and not root.findall('./{http://www.w3.org/2000/09/xmldsig#}Signature'),'Unsigned native hosted IdP metadata required')
    roles=root.findall('./{'+MD+'}IDPSSODescriptor');require(len(roles)==1,'One hosted IdP role required')
    role=roles[0];endpoints=role.findall('./{'+MD+'}SingleLogoutService')
    require(endpoints and not any(x.get('Binding')==SOAP for x in endpoints),'Fresh SOAP advertisement required')
    positions=[i for i,x in enumerate(role) if x.tag=='{'+MD+'}SingleLogoutService']
    role.insert(max(positions)+1,ET.Element('{'+MD+'}SingleLogoutService',{'Binding':SOAP,
        'Location':target.rsplit('/',1)[0]+'/profile/SAML2/SOAP/SLO'}))
    return ET.tostring(root,encoding='utf-8',xml_declaration=True)

def prepared_peers(raw,plan,run,trial):
    root=ET.fromstring(public_configuration(raw));require(root.tag=='{'+MD+'}EntitiesDescriptor','Actual prepared aggregate required')
    entity=BASE+'/p/'+plan;peers=[]
    for node in root.findall('./{'+MD+'}EntityDescriptor'):
        value=node.get('entityID');label='primary' if value==entity else value.removeprefix(entity+'/sp-')
        require(label in LABELS and all(p['label']!=label for p in peers),'Unexpected or duplicate prepared participant')
        role=node.findall('./{'+MD+'}SPSSODescriptor');require(len(role)==1,'Prepared SP role is ambiguous')
        slo=[x for x in role[0].findall('./{'+MD+'}SingleLogoutService') if x.get('Binding')==SOAP]
        require(len(slo)==1,'Prepared SOAP endpoint missing')
        url=urllib.parse.urlsplit(slo[0].get('Location',''));require(url.hostname=='host.docker.internal' and url.port==18080
                and url.scheme=='http'and url.path=='/p/'+plan+'/sp/slo/soap'
                and not url.username and not url.password and not url.fragment,'Prepared callback base is not qualified')
        expected={}if label=='primary'else dict(run=[run],propagation=['error-v2'],participant=[label],trial=[trial],mode=['first-arrival'if trial=='failure'else'all-success'])
        pairs=urllib.parse.parse_qsl(url.query,keep_blank_values=True,strict_parsing=True)
        require(len(pairs)==len(expected)and urllib.parse.parse_qs(url.query)==expected,'Prepared marker scope differs')
        peers.append(dict(label=label,entity=value,runId=run,planId=plan,soapEndpoint=slo[0].get('Location')))
    require({p['label']for p in peers}==set(LABELS),'Whole four-entity preparation required')
    return peers

class PropagationClient(Client):
    def __init__(self,out):
        super().__init__();self.out=out;self.auth=[];self.protocol=[]
        owner=self
        class Redirects(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,req,fp,code,msg,headers,newurl):
                url=urllib.parse.urlsplit(newurl);require(url.hostname in ('localhost','127.0.0.1'),'Foreign authentication redirect')
                if url.port==18280 and any(k=='SAMLRequest'for k,v in urllib.parse.parse_qsl(url.query)):
                    owner.protocol.append(dict(method='GET',urlSha256=SHA(newurl.encode()),startedAt=NOW(),rawQuerySha256=SHA(url.query.encode()),completed=False))
                    save(owner.out/'browser-protocol-attempts.json',owner.protocol)
                return super().redirect_request(req,fp,code,msg,headers,newurl)
        self.op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),Redirects())
    def request(self,url,fields=None):
        chosen=urllib.parse.urlsplit(url);row=None;auth=None
        if fields and any(k in fields for k in ('password','j_password')):
            require(len(self.auth)<3,'Additional credential boundary refused before transport')
            auth=dict(ordinal=len(self.auth)+1,startedAt=NOW(),completed=False,credentialValuesExported=False);self.auth.append(auth);save(self.out/'credential-boundaries.json',self.auth)
        if fields and 'SAMLRequest'in fields and chosen.port==18280:
            raw=base64.b64decode(fields['SAMLRequest'],validate=True);xml=ET.fromstring(raw)
            require(xml.tag=='{'+P+'}AuthnRequest' and xml.get('ForceAuthn')not in ('true','1'),'Only actual ordinary outbox AuthnRequest accepted')
            row=dict(method='POST',requestId=xml.get('ID'),requestSha256=SHA(raw),startedAt=NOW(),completed=False);self.protocol.append(row);save(self.out/'browser-protocol-attempts.json',self.protocol)
        try:
            result=super().request(url,fields)
            if row:row.update(completed=True,completedAt=NOW(),responseStatus=result[2]);save(self.out/'browser-protocol-attempts.json',self.protocol)
            if auth:auth.update(completed=True,completedAt=NOW());save(self.out/'credential-boundaries.json',self.auth)
            return result
        except Exception as error:
            for record in (row,auth):
                if record:record.update(failedAt=NOW(),failureClass=type(error).__name__)
            save(self.out/'browser-protocol-attempts.json',self.protocol);save(self.out/'credential-boundaries.json',self.auth);raise

class Product(ShibbolethProduct):
    def preflight(self):
        super().preflight()
        # Protocol originals provide request-bound failure proof; audit rewriting is unnecessary.
        self.audit_changed=False;self.audit_configured=self.original[AUDIT]
        raw=public_configuration(self.command('cat',PUBLIC));self.original[PUBLIC]=self.expected[PUBLIC]=raw
        self.public_configured=soap_advertisement(raw,self.target)
        (self.receipt/'original-target-metadata.xml').write_bytes(raw);(self.receipt/'configured-target-metadata.xml').write_bytes(self.public_configured)
        self.published('original')
        for kind,relative in TRUST.CONFIGS.items():
            raw=public_configuration(self.command('cat',ROOT+'/'+relative));(self.receipt/('original-'+kind+'.xml')).write_bytes(raw)
        (self.receipt/'original-providers.xml').write_bytes(self.original[PROVIDERS]);(self.receipt/'original-audit.xml').write_bytes(self.original[AUDIT])
        native=self.receipt/'native';native.mkdir();os.link(self.receipt/'native-source/idp-conf-impl.jar',native/'idp-conf-impl.jar')
        with zipfile.ZipFile(native/'idp-conf-impl.jar') as jar:
            for name in ('slo-back-flow.xml','slo-back-beans.xml'):(native/name).write_bytes(jar.read('net/shibboleth/idp/flows/saml/saml2/'+name))
    def setup(self,run,baseline):
        self.source=ROOT+'/metadata/registered-signer-'+run+'.xml';require(self.command('test','-e',self.source,allow_failure=True).returncode==1,'Fresh owned source already exists')
        self.owned_sources[self.source]=baseline
        self.provider=SIGNER.provider_configuration(self.original[PROVIDERS],[dict(runId=run,sourcePath=self.source)])
        (self.receipt/'configured-providers.xml').write_bytes(self.provider)
        self.write(PUBLIC,self.public_configured,'advertise-stock-soap');self.write(self.source,baseline,'baseline-source');self.write(PROVIDERS,self.provider,'register-provider');self.activate('prepare')
        self.published('configured')
    def published(self,label):
        with urllib.request.urlopen(self.target,timeout=30)as response:
            require(response.status==200,'Native public metadata unavailable');raw=response.read(1024*1024+1)
        require(raw==self.expected[PUBLIC],'Native HTTP metadata differs from effective static source')
        (self.receipt/(label+'-published-target-metadata.xml')).write_bytes(raw)
    def apply(self,raw,trial):
        self.write(self.source,raw,'participant-source-'+trial);self.owned_sources[self.source]=raw;self.activate('participant-'+trial)
        (self.receipt/(trial+'-prepared-metadata.xml')).write_bytes(raw)
    def trial_state(self,run,trial,phase,raw,peers):
        start=NOW();scope='soap-'+trial+'-'+phase;native=self.receipt/'native';native_peers={}
        profile=json.loads(self.command(ROOT+'/bin/dumpconfig.sh','-u','http://localhost:8080/idp','--saml2','-r',peers[0]['entity'],'-P',PROFILE))
        previous=TRUST.docker;TRUST.docker=self.command;TRUST.PROFILE=PROFILE;TRUST.PROFILE_KEYS=set(profile['ProfileConfiguration'])
        try:TRUST.capture(native,scope,peers[0]['entity'])
        finally:TRUST.docker=previous
        for peer in peers:
            url='http://localhost:8080/idp/profile/admin/mdquery?entityID='+urllib.parse.quote(peer['entity'],safe='')
            cmd=['curl','--silent','--show-error','--max-time','20','--write-out','\n%{http_code}',url];before=NOW();result=self.command(*cmd,allow_failure=True);after=NOW()
            body,_,status=result.stdout.rpartition(b'\n');require(result.returncode==0 and status==b'200','Native peer query unavailable; no label-only registration proof')
            xml=ET.fromstring(body);require(xml.tag=='{'+MD+'}EntityDescriptor'and xml.get('entityID')==peer['entity'],'Native query returned another peer')
            name=trial+'-'+phase+'-'+peer['label']+'-native-metadata.xml';(self.receipt/name).write_bytes(body);native_peers[peer['label']]=name
            save(self.receipt/(trial+'-'+phase+'-'+peer['label']+'-query.json'),dict(command=cmd,startedAt=before,finishedAt=after,exitCode=result.returncode,responseStatus=int(status),stdoutSha256=SHA(result.stdout),responseBodySha256=SHA(body)))
        inventory=self.command('sh','-c','for d in /opt/reference-idp/views /opt/reference-idp/flows /opt/reference-idp/edit-webapp/WEB-INF/lib /opt/reference-idp/dist/plugin-webapp/WEB-INF/lib /usr/local/tomcat/webapps/idp/WEB-INF/classes; do if test -d "$d"; then find "$d" -type f; fi; done')
        inventory_file=trial+'-'+phase+'-flow-overrides.txt';(self.receipt/inventory_file).write_bytes(inventory)
        native_flows={};flow_originals={}
        for relative in AUTHN_FLOWS:
            path=ROOT+'/flows/authn/conditions/'+relative;original=public_configuration(self.command('cat',path))
            file=trial+'-'+phase+'-authn-'+relative.replace('/','-');(self.receipt/file).write_bytes(original);native_flows[path]=file;flow_originals[path]=original
        with zipfile.ZipFile(native/'idp-conf-impl.jar')as jar:validate_flow_inventory(inventory,flow_originals,jar)
        properties=self.command('sh','-c',"sed -n '/^[[:space:]]*idp.session.trackSPSessions[[:space:]]*=/p' /opt/reference-idp/conf/idp.properties")
        lines=[x.strip()for x in properties.decode().splitlines()if x.strip()];require(len(lines)==1 and lines[0].split('=',1)[1].strip()=='true','Actual session tracking prerequisite absent')
        properties_file=trial+'-'+phase+'-session-properties.json';save(self.receipt/properties_file,{'idp.session.trackSPSessions':'true','nativeRawFile':trial+'-'+phase+'-session-properties.txt','nativeRawSha256':SHA(properties)});(self.receipt/(trial+'-'+phase+'-session-properties.txt')).write_bytes(properties)
        require(self.command('cat',self.source)==raw and self.command('cat',PROVIDERS)==self.provider,'Native effective input changed')
        actual_runtime=runtime(CONTAINER)
        name=trial+'-'+phase+'-state.json';save(self.receipt/name,dict(runId=run,trial=trial,startedAt=start,finishedAt=NOW(),runtime=actual_runtime,providersFile='configured-providers.xml',metadataFile=trial+'-prepared-metadata.xml',scopePrefix='native/trust-'+scope+'-',flowOverrideInventoryFile=inventory_file,nativeFlowOriginals=native_flows,sessionPropertiesFile=properties_file))
        return name,native_peers
    def finalize_restore(self):
        for name,path in [('target-metadata',PUBLIC),('providers',PROVIDERS),('audit',AUDIT)]:
            raw=self.command('cat',path);require(raw==self.original[path],'Final native setting differs');(self.receipt/('final-'+name+'.xml')).write_bytes(raw)
        for kind,relative in TRUST.CONFIGS.items():
            raw=public_configuration(self.command('cat',ROOT+'/'+relative));require(raw==(self.receipt/('original-'+kind+'.xml')).read_bytes(),'Stable native security configuration changed');(self.receipt/('final-'+kind+'.xml')).write_bytes(raw)
        self.published('final')

def decoded_copy(out,run,entry):
    expected='transcripts/'+run+'/'+entry['id']+'.saml.xml';require(entry.get('decodedSamlRef')==expected,'Foreign decoded original')
    path=out/('prepared-'+entry['id']+'.xml');subprocess.run(['docker','cp','samlscope-reference-suite:/data/'+expected,str(path)],capture_output=True,check=True,timeout=30);return path.read_bytes()

def build_trial(run,trial,prepared,entries,before,after,native_peers):
    result=origin_final(entries,run,trial);require(result is not None,'Origin final SOAP response unavailable');origin,final=result
    participants=[];baselines=[]
    for label in LABELS:
        baseline=[e for e in entries if e['direction']=='INBOUND'and e.get('correlationId')=='_'+action(run,trial,'login',label)
            and e.get('samlSummary',{}).get('type')=='Response']
        require(len(baseline)==1,'Actual trial session registration is ambiguous');baselines.append(dict(label=label,responseReference=baseline[0]['id']))
        if label=='primary':continue
        requests=[e for e in entries if e['direction']=='INBOUND'and e.get('samlSummary',{}).get('propagationTrial')==trial and e.get('samlSummary',{}).get('propagationParticipant')==label and e.get('samlSummary',{}).get('type')=='LogoutRequest']
        responses=[e for e in entries if e['direction']=='OUTBOUND'and e.get('samlSummary',{}).get('propagationTrial')==trial and e.get('samlSummary',{}).get('propagationParticipant')==label and e.get('samlSummary',{}).get('type')=='LogoutResponse']
        require(len(requests)==len(responses)==1,'Native participant attempt/reply incomplete or duplicate')
        participants.append(dict(label=label,requestReference=requests[0]['id'],responseReference=responses[0]['id'],nativeMetadataFile=native_peers[label]))
    return dict(trial=trial,preparedReference=prepared['id'],originRequestReference=origin['id'],originResponseReference=final['id'],beforeFile=before,afterFile=after,participants=participants,baselines=baselines)

def prior_original_refs(folder,run):
    names=['created.json','operation-counts.json','native-restoration.json']
    if (folder/'failure.json').is_file():names.append('failure.json')
    else:
        # A complete collection can still be unadoptable. Retain the actual order
        # diagnosis and transcript instead of inventing a runtime failure record.
        name='diagnosis/first-arrival-order-unqualified.json';diagnosis=json.loads((folder/name).read_text())
        require(diagnosis.get('schema')=='samlscope-soap-first-error-order-diagnosis-v1'
            and diagnosis.get('runId')==run and diagnosis.get('adoptionAllowed')is False
            and diagnosis.get('originalsChanged')is False,'Prior completed campaign lacks its own unadopted diagnosis')
        require(diagnosis.get('sourceFile')==str((folder/'transcript-final.json').relative_to(REPO))
            and diagnosis.get('sourceSha256')==SHA((folder/'transcript-final.json').read_bytes()),
            'Prior order diagnosis is not bound to its actual transcript')
        names.extend([name,'transcript-final.json'])
    return {name:SHA((folder/name).read_bytes())for name in names}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--prior',type=Path,action='append',default=[]);args=p.parse_args()
    require(os.statvfs(REPO).f_bavail*os.statvfs(REPO).f_frsize>=96*1024*1024,'Insufficient host space before setup')
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False);receipt=out/'receipt';receipt.mkdir();(out/'collector-source.py').write_bytes(Path(__file__).read_bytes())
    prior=[]
    for folder in args.prior:
        folder=folder.resolve();require(folder!=out and not folder.is_symlink(),'Unsafe prior campaign folder')
        created_prior=json.loads((folder/'created.json').read_text());counts_prior=json.loads((folder/'operation-counts.json').read_text());restore_prior=json.loads((folder/'native-restoration.json').read_text())
        require(counts_prior.get('restored')is True and restore_prior.get('restored')is True and not restore_prior.get('errors'),'Prior failed campaign not restored')
        require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',created_prior['run']['id'])is not None,'Prior identity invalid')
        for k,v in counts_prior.items():require(k=='restored'or(type(v)is int and v>=0),'Prior counts unqualified')
        refs=prior_original_refs(folder,created_prior['run']['id'])
        prior.append(dict(folder=str(folder),runId=created_prior['run']['id'],counts=counts_prior,files=refs))
    product=Product();product.bind(out,receipt);client=PropagationClient(out);product.client=client;created=None;restored=False;trials=[];skips=[];error=None;stage='read-only-preflight'
    try:
        product.preflight()
        stage='fresh-plan-and-run'
        plan=api('/api/plans',dict(name='Shibboleth native sequential SOAP SLO continuation',profile='single_logout_idp',targetKind='IDP',targetEntityId=product.target,metadataSourceKind='URL',metadataSourceLocation=product.metadata_source,suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=30,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',plan);plan_id=plan['plan']['plan']['id']
        created=api('/api/plans/'+plan_id+'/runs',{});save(out/'created.json',created);run=created['run']['id']
        with urllib.request.urlopen(BASE+'/p/'+plan_id+'/metadata',timeout=30)as r:baseline=r.read(1024*1024+1)
        stage='native-baseline-configuration';product.setup(run,baseline);save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
        user=os.environ.get('REFERENCE_USERNAME','samlscope-m0-user');password=os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password')
        stage='m0-prerequisite';require(client.flow(BASE+'/p/'+plan_id+'/start/m0-roundtrip?run='+run,None,user,password)=='recorded','M0 prerequisite failed; no retry');save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));stage='suite-only-selection'
        select_configuration(run,out,skips)
        report=api('/api/runs/'+run+'/result.json');save(out/'formal-slot.json',report);slots=[x for req in report['requirements']for x in req['cases']if x['id']==CASE];require(len(slots)==1 and slots[0]['mode']=='BROWSER','Real approved slot unavailable')
        entries=api('/api/runs/'+run+'/transcript')
        for trial in TRIALS:
            stage='trial-'+trial+'-configuration'
            pending=api('/api/runs/'+run+'/interactions');require(any(x['caseId']==CASE and x['kind']=='CONFIGURATION'for x in pending),'Trial did not reach real configuration wait')
            prepared=[e for e in entries if e.get('samlSummary',{}).get('type')=='MetadataPrepared'and e.get('samlSummary',{}).get('variant')=='slo-propagation-soap-'+trial];require(len(prepared)==1,'Real case metadata preparation unavailable')
            prepared=prepared[0];raw=decoded_copy(out,run,prepared);peers=prepared_peers(raw,plan_id,run,trial);product.apply(raw,trial)
            before,native_peers=product.trial_state(run,trial,'before',raw,peers);save(out/(trial+'-configured.json'),api('/api/runs/'+run+'/cases/'+CASE+'/configure',dict(value='CONFIRMED',note='')))
            for ordinal in range(4):
                stage='trial-'+trial+'-registration-'+LABELS[ordinal]
                status=api('/api/runs/'+run+'/active-probe');require(status.get('caseId')==CASE and status.get('state')=='READY'
                    and status.get('actionId')==action(run,trial,'login',LABELS[ordinal]),'Expected same-case ordinary registration outbox unavailable')
                require(status.get('requiresFreshSession')is (ordinal==0),'Unexpected session boundary; do not invent a fresh session')
                if ordinal==0:
                    client.jar.clear();save(out/(trial+'-browser-session-boundary.json'),dict(startedAt=NOW(),previousCookiesDiscarded=True,credentialValuesExported=False))
                require(client.flow(status['startUrl'],None,user,password)=='recorded','Trial registration incomplete; no retry')
            # The case's SOAP origin uses HttpOutboundSender, never a collector-created message.
            deadline=time.monotonic()+75
            stage='trial-'+trial+'-origin-soap-completion'
            while True:
                pending=api('/api/runs/'+run+'/interactions');snapshot=api('/api/runs/'+run+'/transcript')
                if origin_final(snapshot,run,trial) is not None:break
                require(time.monotonic()<deadline,'Origin final response unobserved; do not resend');time.sleep(.25)
            after,_=product.trial_state(run,trial,'after',raw,peers);entries=api('/api/runs/'+run+'/transcript');trials.append(build_trial(run,trial,prepared,entries,before,after,native_peers));save(out/'trials.json',trials)
    except Exception as failure:
        error=dict(exceptionClass=type(failure).__name__,reason='original-backed-campaign-incomplete',stage=stage);save(out/'failure.json',error)
    finally:
        try:
            restored=product.restore([]);product.finalize_restore()
        except Exception as failure:
            restored=False;save(out/'restoration-failure.json',dict(exceptionClass=type(failure).__name__))
        save(receipt/'restoration.json',dict(restored=restored,temporaryRemoved=restored,errors=[]if restored else ['restoration-unqualified']))
        counts=dict(nativeConfigurationWrites=sum(x['operation']=='write'for x in product.operations),restorationWrites=sum(x['operation']=='write'and x['label'].startswith('restore')for x in product.operations),metadataReloads=sum(x['operation']=='reload'for x in product.operations),productRestarts=sum(x['operation']=='restart'for x in product.operations),nativeCliExecutions=len(product.commands),credentialPostAttempts=len(client.auth),credentialPosts=sum(x['completed']for x in client.auth),browserSamlAttemptCount=len(client.protocol),humanOperations=0,restored=restored)
        counts.update(suiteOnlySelectionCampaigns=int(bool(skips)),suiteOnlyPreparedAbortedFixtures=len(skips))
        save(out/'operation-counts.json',counts)
        if created:
            run=created['run']['id'];entries=api('/api/runs/'+run+'/transcript');save(out/'transcript-final.json',entries);capture(out,run,entries)
            (receipt/'target-metadata.xml').write_bytes((out/'target-metadata.xml').read_bytes());soap=receipt/'soap';soap.mkdir(exist_ok=True)
            for e in entries:
                if e.get('samlSummary',{}).get('transport')=='SOAP'or e.get('samlSummary',{}).get('probe_transport')=='direct-soap':
                    require(e.get('bodyRef')=='transcripts/'+run+'/'+e['id']+'.body','Foreign SOAP raw body reference');subprocess.run(['docker','cp','samlscope-reference-suite:/data/'+e['bodyRef'],str(soap/(e['id']+'.xml'))],capture_output=True,check=True,timeout=30)
            if not error and restored and len(trials)==2:
                files={str(x.relative_to(receipt)):SHA(x.read_bytes())for x in receipt.rglob('*')if x.is_file()}
                save(receipt/'manifest.json',dict(schema=SCHEMA,runId=run,planId=created['run']['planId'],targetMetadataSha256=SHA((receipt/'target-metadata.xml').read_bytes()),files=files,trials=trials,counterfactualCalibrationOnly=False))
            counts.update(originSoapAttemptCount=sum(e['direction']=='OUTBOUND'and e.get('samlSummary',{}).get('type')=='LogoutRequest'and e.get('samlSummary',{}).get('probe_transport')=='direct-soap'for e in entries),
                nativeParticipantSoapAttemptCount=sum(e['direction']=='INBOUND'and e.get('samlSummary',{}).get('type')=='LogoutRequest'and e.get('samlSummary',{}).get('transport')=='SOAP'for e in entries))
            counts['protocolSubmissions']=counts['browserSamlAttemptCount']+counts['originSoapAttemptCount'];save(out/'operation-counts.json',counts)
        totals={k:sum(item['counts'].get(k,0)for item in prior)+v for k,v in counts.items()if type(v)is int}
        save(out/'failed-inclusive-operation-counts.json',dict(current=counts,prior=prior,cumulative=totals,settingsRestored=restored and all(item['counts']['restored']for item in prior),humanOperations=0))
        require(restored,'Native restoration failed; lease remains blocked')
    if error:raise SystemExit('Unadopted campaign stopped; exact restoration completed')
    print(out)

if __name__=='__main__':main()
