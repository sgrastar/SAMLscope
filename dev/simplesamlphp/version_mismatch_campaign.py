#!/usr/bin/env python3
"""One-login original-backed SSO01.ep campaign; never a product verdict.

All requests come from the Suite outbox. Native parser/configuration qualification
precedes login, and an exact finally-restoration precedes final evidence installation.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zlib
import xml.etree.ElementTree as ET

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/keycloak'))
from import_metadata_batch import api,save,BASE
from reference_flow import Client
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from browser_probe_selection import prepare_and_skip
from capture_run_originals import capture as capture_run
from algorithm_preference_campaign import recorded
from version_mismatch_native_preflight import capture as native_preflight,inspect,REFLECTION,SSP_SOURCES
sys.path.insert(0,str(Path(__file__).resolve().parent))
from configuration_batch import ConfigurationBatch
from registered_signer_campaign import PARSER
sys.path.insert(0,str(REPO/'dev/slo'))
from registered_signer_common import without_public_language_navigation

CASE='IIP-SSO01-ep-idp-01';FIXTURES=('baseline-success','invalid-issue-instant','version-1-1')
CONTAINER='samlscope-reference-ssp';SUITE='samlscope-reference-suite';TARGET='http://localhost:18380/idp'
REMOTE='/var/simplesamlphp/metadata/saml20-sp-remote.php'
CONFIG=REPO/'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php'
INSTALL='/data/version-mismatch-evidence'
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def require(condition,message):
    if not condition:raise ValueError(message)


def public_url_projection(url):
    """Keep capability-bearing URLs in memory; record only a path and irreversible hash."""
    parts=urllib.parse.urlsplit(url)
    require(parts.scheme in ('http','https') and parts.hostname in {'localhost','127.0.0.1'}
            and parts.username is None and parts.password is None,'Nonlocal/credential-bearing public URL refused')
    values=urllib.parse.parse_qs(parts.query,keep_blank_values=True)
    public=not parts.fragment and all(len(v)==1 for v in values.values())
    for key,items in values.items():
        value=items[0] if len(items)==1 else ''
        public &= (key=='run' and re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',value) is not None
                   or key=='mdv' and value=='control'
                   or key=='language' and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,15}',value) is not None)
    # Do not parse/rebuild any signed SAML query. A non-public query is omitted
    # from this operation ledger; its exact original bytes are represented by SHA.
    projected=url if public else urllib.parse.urlunsplit((parts.scheme,parts.netloc,parts.path,'',''))
    return dict(url=projected,originalSha256=SHA(url.encode()),originalBytes=len(url.encode()),redacted=not public)


def public_terminal_url(url):
    projected=public_url_projection(url)
    require(projected['redacted'] is False,'Terminal URL contains an unqualified capability; no public observation recorded')
    return url


def public_terminal(page):
    """Inspect only the exact stock language menu; persist the unchanged full body."""
    try:
        inspected=without_public_language_navigation(page)
        return len(page.encode())<=262144 and re.search(r'<\s*(?:input|textarea|select|form)\b|SAMLResponse|SAMLRequest|Authorization\s*:|Cookie\s*:|logout-resume[^\s<>]*[?&](?:amp;)?id=|[?&](?:amp;)?(?:AuthState|session_code|execution|csrf|auth_session_id|tab_id|client_data|kc_action)=',inspected,re.I) is None
    except ValueError:return False


def request_shape(raw,fixture,action,issuer,acs,endpoint):
    root=ET.fromstring(raw)
    require(root.tag=='{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest' and root.get('ID')=='_'+action,'Foreign request ID/type')
    require(root.get('Version')==('1.1' if fixture=='version-1-1' else '2.0'),'Fixture version mismatch')
    if fixture=='invalid-issue-instant':require(root.get('IssueInstant')=='not-a-saml-timestamp','Wrong timestamp fixture')
    else:
        require(isinstance(root.get('IssueInstant'),str) and root.get('IssueInstant').endswith('Z'),'Missing/non-UTC normal timestamp')
        datetime.datetime.fromisoformat(root.get('IssueInstant').replace('Z','+00:00'))
    require(root.get('Destination')==endpoint and root.get('AssertionConsumerServiceURL')==acs,'Foreign fixture endpoint')
    require(root.findtext('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')==issuer,'Foreign fixture issuer')
    require(root.get('ForceAuthn') is None and root.get('IsPassive') is None,'Unexpected authentication modifier')
    require(len(root.findall('{http://www.w3.org/2000/09/xmldsig#}Signature'))==1,'Unsigned fixture')
    return root.get('ID')


class RedirectCapture(urllib.request.HTTPRedirectHandler):
    def __init__(self,client):self.client=client
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        require(urllib.parse.urlsplit(newurl).hostname in {'localhost','127.0.0.1'},'Nonlocal redirect refused')
        self.client.observed_redirect(newurl)
        return super().redirect_request(req,fp,code,msg,headers,newurl)


class SharedClient(Client):
    def __init__(self):
        super().__init__();self.credential_posts=0;self.credential_attempts=0;self.protocol_posts=[];self.protocol_gets=[];self.target_gets=[]
        # M0 uses the advertised Redirect binding. Observe the actual redirect
        # before urllib follows it; neither reconstruct its signed query nor hide
        # this native operation behind the outer Suite GET.
        self.op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),RedirectCapture(self))
    def observed_redirect(self,url):
        parts=urllib.parse.urlsplit(url)
        if parts.port!=18380:return
        values=urllib.parse.parse_qs(parts.query,keep_blank_values=True)
        if 'SAMLRequest' not in values:return
        require(len(values['SAMLRequest'])==1,'Ambiguous Redirect request')
        compressed=base64.b64decode(values['SAMLRequest'][0],validate=True);decoder=zlib.decompressobj(-15);raw=decoder.decompress(compressed,131073)
        require(len(raw)<=131072 and decoder.eof and not decoder.unused_data,'Oversized/invalid Redirect message')
        root=ET.fromstring(raw);require(root.tag=='{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest' and root.get('ForceAuthn') in (None,'false','0') and root.get('IsPassive') in (None,'false','0'),'Unqualified Redirect authentication request')
        self.protocol_gets.append(dict(method='GET',requestUrl=urllib.parse.urlunsplit((parts.scheme,parts.netloc,parts.path,'','')),rawQuerySha256=SHA(parts.query.encode()),requestId=root.get('ID'),requestSha256=SHA(raw),startedAt=NOW()))
    def request(self,url,fields=None):
        if fields and 'freshSessionConfirmed' in fields:raise ValueError('Unexpected fresh-session confirmation')
        if fields and any(k in fields for k in ('password','j_password')):
            self.credential_attempts+=1;require(self.credential_posts==0,'Additional credential submission refused');self.credential_posts+=1
        row=None
        if fields is None and urllib.parse.urlsplit(url).port==18380:self.target_gets.append(dict(method='GET',url=url.split('?',1)[0],startedAt=NOW(),samlRequestPresent='SAMLRequest=' in urllib.parse.urlsplit(url).query))
        if urllib.parse.urlsplit(url).port==18380 and fields and 'SAMLRequest' in fields:
            raw=base64.b64decode(fields['SAMLRequest'],validate=True);root=ET.fromstring(raw)
            require(root.get('ForceAuthn') in (None,'false','0') and root.get('IsPassive') in (None,'false','0'),'Fresh authentication request refused')
            public_terminal_url(url)
            row=dict(method='POST',requestUrl=url,requestId=root.get('ID'),requestSha256=SHA(raw),startedAt=NOW());self.protocol_posts.append(row)
        final,page,status=super().request(url,fields)
        if row:
            projection=public_url_projection(final)
            row.update(completedAt=NOW(),responseUrl=projection['url'],responseUrlOriginalSha256=projection['originalSha256'],
                responseUrlOriginalBytes=projection['originalBytes'],responseUrlRedacted=projection['redacted'],responseStatus=status,
                responseBodySha256=SHA(page.encode()),responseBodyBytes=len(page.encode()),samlResponseFormPresent='SAMLResponse' in page)
        return final,page,status


def planned_slot(run,out,diagnostics):
    source=REPO/'dev/reference-acceptance/ReadVersionMismatchPlannedSlot.java';remote='/tmp/version-planned-'+run;started=NOW()
    with tempfile.TemporaryDirectory(prefix='version-planned-') as folder:
        classes=Path(folder)/'classes';classes.mkdir()
        java=Path('/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin')
        subprocess.run([str(java/'javac'),'-cp',str(REPO/'api/build/install/samlscope/lib/*'),'-d',str(classes),str(source)],check=True,capture_output=True,timeout=30)
        subprocess.run(['docker','exec','-u','0',SUITE,'mkdir',remote],check=True,capture_output=True,timeout=20)
        try:
            subprocess.run(['docker','cp',str(classes),SUITE+':'+remote+'/classes'],check=True,capture_output=True,timeout=20)
            r=subprocess.run(['docker','exec',SUITE,'java','-cp',remote+'/classes:/opt/samlscope/lib/*','com.samlscope.api.ReadVersionMismatchPlannedSlot','/data',run],check=True,capture_output=True,timeout=30)
            value=json.loads(r.stdout);require(value['caseId']==CASE and value['runId']==run and value['mode']=='BROWSER' and value['profile']=='browser_sso_idp' and value['caseStarted'] is False,'Actual approved slot missing')
            (out/'planned-slot-before-login.json').write_bytes(r.stdout)
        finally:subprocess.run(['docker','exec','-u','0',SUITE,'rm','-rf','--',remote],check=True,capture_output=True,timeout=20)
    diagnostics.append(dict(operation='actual-planned-slot-read-only',hostCompiler=1,suiteJava=1,startedAt=started,completedAt=NOW(),sourceSha256=SHA(source.read_bytes())))


def fixture_preflight(run,metadata,out,diagnostics):
    source=REPO/'dev/reference-acceptance/PreflightVersionMismatchFixtures.java';remote='/tmp/version-fixtures-'+run;started=NOW()
    with tempfile.TemporaryDirectory(prefix='version-fixtures-') as folder:
        classes=Path(folder)/'classes';classes.mkdir();java=Path('/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin')
        subprocess.run([str(java/'javac'),'-cp',str(REPO/'api/build/install/samlscope/lib/*'),'-d',str(classes),str(source)],check=True,capture_output=True,timeout=30)
        subprocess.run(['docker','exec','-u','0',SUITE,'mkdir',remote],check=True,capture_output=True,timeout=20)
        try:
            subprocess.run(['docker','cp',str(classes),SUITE+':'+remote+'/classes'],check=True,capture_output=True,timeout=20)
            subprocess.run(['docker','cp',str(metadata),SUITE+':'+remote+'/suite.xml'],check=True,capture_output=True,timeout=20)
            # Temporary helper/metadata copies are public; make them readable by the Suite user.
            subprocess.run(['docker','exec','-u','0',SUITE,'chmod','-R','a+rX',remote],check=True,capture_output=True,timeout=20)
            result=subprocess.run(['docker','exec',SUITE,'java','-cp',remote+'/classes:/opt/samlscope/lib/*','com.samlscope.runner.cases.PreflightVersionMismatchFixtures','/data',run,remote+'/suite.xml'],check=True,capture_output=True,timeout=30)
            value=json.loads(result.stdout);require(value['runId']==run and value['caseId']==CASE and value['privateKeyExported'] is False,'Fixture scope changed')
            require([r['fixtureId'] for r in value['fixtures']]==list(FIXTURES) and all(r['signatureValid'] is True for r in value['fixtures']),'Full three fixture preflight incomplete')
            (out/'fixture-preflight-before-login.json').write_bytes(result.stdout)
        finally:subprocess.run(['docker','exec','-u','0',SUITE,'rm','-rf','--',remote],check=True,capture_output=True,timeout=20)
    diagnostics.append(dict(operation='public-all-fixture-preflight',hostCompiler=1,suiteJava=1,startedAt=started,completedAt=NOW(),sourceSha256=SHA(source.read_bytes()),privateKeyExported=False))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--max-suite-skips',type=int,default=350)
    args=parser.parse_args();require(0<=args.max_suite_skips<=500,'Invalid Suite-only skip limit');out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    require(os.environ.get('SAML_SCOPE_FLOW_DIAGNOSTIC')!='1','Raw login-page diagnostics must be disabled before collection')
    receipt=out/'receipt';receipt.mkdir();(out/'collector-source.py').write_bytes(Path(__file__).read_bytes())
    skip_source=REPO/'dev/reference-acceptance/browser_probe_selection.py';skip_bytes=skip_source.read_bytes()
    require(Path(prepare_and_skip.__code__.co_filename).resolve()==skip_source.resolve(),'Unqualified Suite-only skipper implementation')
    (out/'prepare-and-skip-source.py').write_bytes(skip_bytes)
    preflight=native_preflight(out/'native-preflight');require(preflight['nativeHttpTerminalAdapterQualified'] is True,'Native adapter unqualified; no login or target setting performed')
    mounts=json.loads((out/'native-preflight/runtime-before.json').read_bytes())['mounts'];bound=[m for m in mounts if m['Destination']==REMOTE]
    require(len(bound)==1 and bound[0]['Type']=='bind' and bound[0]['RW'] is True and Path(bound[0]['Source']).resolve()==CONFIG.resolve(),'Native writable registration mount is not the exact host file; no preparation performed')
    original_inode=CONFIG.stat().st_ino
    batch=ConfigurationBatch(CONFIG);batch.container,batch.container_path=CONTAINER,REMOTE
    calls=[];diagnostics=[];client=SharedClient();probes=[];skips=[];restoration={'restored':False};run=None
    user=os.environ.get('REFERENCE_USERNAME','samlscope-m0-user');password=os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password')
    def docker(*arguments,container=CONTAINER,data=None):
        row=dict(container=container,executable=arguments[0],startedAt=NOW(),completed=False);calls.append(row);save(out/'native-command-counts.json',calls)
        r=subprocess.run(['docker','exec','-i',container,*arguments],input=data,capture_output=True,timeout=40)
        row.update(completedAt=NOW(),completed=True,exitCode=r.returncode);save(out/'native-command-counts.json',calls)
        require(r.returncode==0,'Native command failed; private stderr not persisted');return r.stdout
    def runtime():
        return {**inspect(CONTAINER),**json.loads(docker('php','-r',REFLECTION))}
    def original(name,raw):
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}',name) is not None,'Unsafe original filename');(receipt/name).write_bytes(raw);return name
    try:
        require(b'?>' not in batch.original and docker('cat',REMOTE)==batch.original,'Unexpected native metadata baseline')
        require(re.search(rb'(?i)private[._-]?key|password|passwd|authorization|cookie|client[._-]?secret',batch.original) is None,'Credential-bearing native metadata refused')
        original('original-configuration.php',batch.original)
        plan=api('/api/plans',dict(name='SimpleSAMLphp version status controls',profile='browser_sso_idp',targetKind='IDP',targetEntityId=TARGET,
            metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},
            parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint=user,requestSigningMode='REQUIRED'),
            interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',plan)
        plan_id=plan['plan']['plan']['id'];created=api('/api/plans/'+plan_id+'/runs',{});save(out/'created.json',created);run=created['run']['id'];planned_slot(run,out,diagnostics)
        save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));entity=BASE+'/p/'+plan_id
        with urllib.request.urlopen(entity+'/metadata',timeout=30) as response:fixture=response.read()
        original('suite-metadata.xml',fixture);target=docker('cat','/data/target-metadata/'+run+'.xml',container=SUITE);original('target-metadata.xml',target)
        peer=ET.fromstring(fixture);require(peer.get('entityID')==entity,'Suite entity differs from actual Plan')
        roles=peer.findall('{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor');require(len(roles)==1,'Suite SP role ambiguous');acs=roles[0].find('{urn:oasis:names:tc:SAML:2.0:metadata}AssertionConsumerService').get('Location')
        require(acs==entity+'/sp/acs/0','Native framework ACS differs from advertisement')
        fixture_preflight(run,receipt/'suite-metadata.xml',out,diagnostics)
        parsed_raw=docker('php','-r',PARSER,entity,data=fixture);parsed=json.loads(parsed_raw);original('parser-output.json',parsed_raw)
        require(parsed['entityId']==entity and parsed['validateAuthnRequest'] is True,'Native parser did not bind the original signed SP metadata')
        batch.apply(parsed['php'].encode());original('configured-configuration.php',batch.expected);require(docker('cat',REMOTE)==batch.expected,'Native registration read-back failed');time.sleep(3)
        baseline=client.flow(BASE+'/p/'+plan_id+'/start/m0-roundtrip?run='+run,None,user,password);save(out/'baseline.json',dict(receipt=baseline,credentialPosts=client.credential_posts))
        require(baseline=='recorded' and len(client.protocol_posts)+len(client.protocol_gets)==1 and client.credential_posts<=1,'Initial baseline did not complete once')
        require(not any(r['samlRequestPresent'] for r in client.target_gets),'Direct unobserved Redirect request refused')
        native_before=runtime();original('runtime-before.json',(json.dumps(native_before,sort_keys=True)+'\n').encode())
        for name,(path,_) in SSP_SOURCES.items():original('source-before.php' if name=='Message.php' else 'utils-before.php',docker('cat',path))
        save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
        for fixture_id in FIXTURES:
            selected=None
            for _ in range(args.max_suite_skips+1):
                status=api('/api/runs/'+run+'/active-probe');require(status.get('state')=='READY','Selected case is terminal/not ready; do not resend')
                if status.get('caseId')==CASE:selected=status;break
                skips.append(prepare_and_skip(BASE,run,status,api));save(out/'suite-only-skips.json',skips)
            require(selected is not None and selected.get('requiresFreshSession') is False,'Suite does not explicitly allow session reuse')
            action=selected['actionId'];before={e['id'] for e in api('/api/runs/'+run+'/transcript')};first=len(client.protocol_posts)
            def terminal(url,page,code,reason):
                public_terminal_url(url)
                require(public_terminal(page),'Terminal page not public-safe; no hidden data persisted')
                api('/api/runs/'+run+'/active-probe/browser-response',dict(actionId=action,status=code,url=url,body=page))
            result=client.flow(selected['startUrl'],None,user,password,terminal_observer=terminal)
            entries=api('/api/runs/'+run+'/transcript');issued=[e for e in entries if e['id'] not in before and e['direction']=='OUTBOUND' and e.get('correlationId')==action]
            require(len(issued)==1 and len(client.protocol_posts)==first+1,'Actual selected request ambiguous');request=issued[0];http=client.protocol_posts[-1]
            raw=docker('cat','/data/'+request['decodedSamlRef'],container=SUITE);require(len(raw)==request['decodedSamlBytes'] and SHA(raw)==http['requestSha256'],'Request raw bytes differ from actual native POST')
            request_id=request_shape(raw,fixture_id,action,entity,acs,http['requestUrl']);require(request_id==http['requestId'],'Native ID differs from raw request')
            replies=[e for e in entries if e['direction']=='INBOUND' and (e.get('samlSummary',{}).get('inResponseTo')==request_id or e.get('correlationId')==action and e.get('method')=='BROWSER')]
            require(len(replies)==1,'Known response original is absent/ambiguous');response=replies[0]
            probes.append(dict(fixtureId=fixture_id,actionId=action,requestReference=request['id'],requestId=request_id,responseReference=response['id'],receipt=result,nativeHttpFile=original(fixture_id+'-http.json',(json.dumps(dict(http,runId=run,actionId=action),sort_keys=True)+'\n').encode()),browser=response.get('method')=='BROWSER'))
            save(out/'probes.json',probes)
        native_after=runtime();original('runtime-after.json',(json.dumps(native_after,sort_keys=True)+'\n').encode());require(native_before==native_after,'Native runtime/source changed across probes')
        for name,(path,_) in SSP_SOURCES.items():original('source-after.php' if name=='Message.php' else 'utils-after.php',docker('cat',path))
    finally:
        try:
            restoration=batch.restore();final=docker('cat',REMOTE);restoration['restored']=restoration.get('restored') is True and final==batch.original and CONFIG.stat().st_ino==original_inode
            restoration['hostInodePreserved']=CONFIG.stat().st_ino==original_inode;restoration['nativeMountDestination']=REMOTE;restoration['nativeMountSource']=bound[0]['Source'];restoration['nativeMountRW']=bound[0]['RW']
            if final==batch.original:original('final-configuration.php',final)
        except Exception as error:restoration=dict(restored=False,errorType=type(error).__name__)
        save(out/'restoration.json',restoration);save(out/'native-protocol-posts.json',client.protocol_posts);save(out/'diagnostic-operations.json',diagnostics)
        save(out/'native-target-get-operations.json',client.target_gets);save(out/'native-protocol-get-operations.json',client.protocol_gets)
        preflight_commands=preflight.get('nativeReadOnlyCommands',{})
        save(out/'operation-counts.json',dict(protocolSubmissions=len(client.protocol_posts)+len(client.protocol_gets),nativeProtocolPosts=len(client.protocol_posts),nativeProtocolRedirectGets=len(client.protocol_gets),selectedProbes=len(probes),initialBaselineSubmissions=1 if len(client.protocol_posts)+len(client.protocol_gets)>0 else 0,credentialPosts=client.credential_posts,credentialPostAttempts=client.credential_attempts,personOperations=0,productWrites=batch.write_count,restorationWrites=batch.restoration_writes,productRestarts=0,directNativeCliExecutions=sum(c['container']==CONTAINER for c in calls),preflightNativeCliExecutions=preflight_commands.get('cat',0)+preflight_commands.get('php',0),configurationWriteCliExecutions=batch.write_count,nativeCliExecutions=sum(c['container']==CONTAINER for c in calls)+preflight_commands.get('cat',0)+preflight_commands.get('php',0)+batch.write_count,hostHelperCompilers=sum(c['hostCompiler'] for c in diagnostics),suitePublicHelperJavaInvocations=sum(c['suiteJava'] for c in diagnostics),restored=restoration.get('restored') is True))
    require(restoration.get('restored') is True and len(probes)==3,'Incomplete campaign; preserve originals, do not adopt')
    require(skip_source.read_bytes()==skip_bytes,'Suite-only skipper source changed during campaign')
    entries=api('/api/runs/'+run+'/transcript');save(receipt/'transcript.json',entries);capture_run(receipt,run,entries)
    terminals=[]
    for row in probes:
        if not row['browser']:continue
        browser=next(e for e in entries if e['id']==row['responseReference']);body=docker('cat','/data/'+browser['bodyRef'],container=SUITE)
        require(len(body)==browser['bodyBytes'] and public_terminal(body.decode()),'Public browser original mismatch');body_file=original(row['fixtureId']+'-body.txt',body)
        http=(receipt/row['nativeHttpFile']).read_bytes();captured=dict(schema='samlscope-native-version-terminal-capture-v1',runId=run,caseId=CASE,fixtureId=row['fixtureId'],requestReference=row['requestReference'],requestId=row['requestId'],requestSha256=json.loads(http)['requestSha256'],browserReference=browser['id'],targetMetadataSha256=SHA(target),nativeHttpSha256=SHA(http),bodySha256=SHA(body),messageSourceSha256=SHA((receipt/'source-before.php').read_bytes()),utilsSourceSha256=SHA((receipt/'utils-before.php').read_bytes()),runtimeBeforeSha256=SHA((receipt/'runtime-before.json').read_bytes()),runtimeAfterSha256=SHA((receipt/'runtime-after.json').read_bytes()))
        reference=recorded(receipt,created,captured,row['fixtureId']+'-capture');capture_file=original(row['fixtureId']+'-capture.json',(receipt/'native-originals'/(row['fixtureId']+'-capture.json')).read_bytes())
        terminals.append(dict(fixtureId=row['fixtureId'],requestReference=row['requestReference'],browserReference=browser['id'],bodyFile=body_file,nativeHttpFile=row['nativeHttpFile'],captureReference=reference['reference'],captureFile=capture_file))
    entries=api('/api/runs/'+run+'/transcript');save(receipt/'transcript.json',entries);capture_run(receipt,run,entries)
    files=[dict(file=p.name,size=p.stat().st_size,sha256=SHA(p.read_bytes())) for p in receipt.iterdir() if p.is_file() and p.name!='manifest.json']
    manifest=dict(schema='samlscope-native-version-terminal-v1',runId=run,caseId=CASE,counterfactualCalibrationOnly=False,targetMetadataSha256=SHA(target),adapter='simplesamlphp-native-message-version',sourceBeforeFile='source-before.php',sourceAfterFile='source-after.php',utilsBeforeFile='utils-before.php',utilsAfterFile='utils-after.php',runtimeBeforeFile='runtime-before.json',runtimeAfterFile='runtime-after.json',terminals=terminals,files=files)
    save(receipt/'manifest.json',manifest)
    print(json.dumps(dict(status='collected-restored-not-installed',runId=run,probeCount=len(probes),terminalCount=len(terminals),finalReceiptInstalled=False,storedBeforeRequired=True)))

if __name__=='__main__':main()
