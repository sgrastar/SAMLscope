#!/usr/bin/env python3
"""Read the loaded native MetaUI model, with one M0 login and no UI-case SAML request.

Original Suite bytes are installed without rewriting. mdquery queries the running
MetadataResolverService. Credentials and cookie jars remain only in memory; native
configuration and model exports are public projections. Every mutation is restored
in finally, including failures after a filesystem write reached the target.
"""
import argparse, base64, datetime, hashlib, json, os, pathlib, re, subprocess, sys
import urllib.parse, urllib.request, xml.etree.ElementTree as ET

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'dev/keycloak'), str(REPO/'dev/reference-acceptance')]
from import_metadata_batch import api, save, BASE, recorded_exchange
from algorithm_preference_campaign import recorded
from capture_run_originals import capture
from preflight_observation_adoption import approved_case, scope_preflight
import reference_flow

CONTAINER = 'samlscope-reference-shibboleth'
PROVIDERS = '/opt/reference-idp/conf/metadata-providers.xml'
NAMESPACE = 'urn:mace:shibboleth:2.0:metadata'
XSI = 'http://www.w3.org/2001/XMLSchema-instance'
CASE = 'IIP-MD05-f-idp-01'
SCHEMA = 'samlscope-metadata-full-ui-native-v1'
ADAPTER = 'shibboleth-metadata-resolver-full-ui-v1'
CAMPAIGN = 'native-metadata-full-ui'
ORIGINAL = 'samlscope-metadata-full-ui-original-v1'
JARS = {
    'native-conf.jar': ('/usr/local/tomcat/webapps/idp/WEB-INF/lib/idp-conf-impl-5.2.3.jar',
        '428e389d88bb2abcad19d69bcf759af29f7ce6beb776ccfaa5a6ea76751682ba',
        'reference-20261003/shibboleth-role-self-contained-trust-r2/receipt/native-idp-conf-impl.jar'),
    'native-saml.jar': ('/usr/local/tomcat/webapps/idp/WEB-INF/lib/opensaml-saml-impl-5.2.3.jar',
        '9f04221e172dc426f90fb3873d0148a0744edbf9e7a37de7ee0e6a34f7b74581',
        'reference-20261003/shibboleth-role-self-contained-trust-r2/receipt/native-opensaml-saml-impl.jar'),
    'native-profile.jar': ('/usr/local/tomcat/webapps/idp/WEB-INF/lib/idp-profile-impl-5.2.3.jar',
        'aaa769a9ccdfb1428173e3932d598ced0302908fab3b8bfe2100331678c9f405',
        'reference-20261003/cross-cluster-audit/shibboleth-full-ui-native-entry/native-profile.jar'),
    'native-cli.jar': ('/opt/reference-idp/dist/binlib/idp-cli-5.2.3.jar',
        '2258de2a92d4c079398d36265cda8a59e40e66bdce8dfb84571be418faa7dc7c',
        'reference-20261003/cross-cluster-audit/shibboleth-full-ui-native-entry/native-cli.jar')}
NOW = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
SHA = lambda b: hashlib.sha256(b).hexdigest()
B64 = lambda b: base64.b64encode(b).decode()

def docker(*args, data=None, check=True):
    return subprocess.run(['docker','exec','-i',CONTAINER,*args], input=data,
            capture_output=True, timeout=40, check=check)

def runtime():
    command = ['docker','inspect','--format',
        '{"containerId":{{json .Id}},"image":{{json .Image}},"startedAt":{{json .State.StartedAt}},"running":{{json .State.Running}},"mounts":{{json .Mounts}}}', CONTAINER]
    value = json.loads(subprocess.run(command, capture_output=True, check=True, timeout=20).stdout)
    if value['running'] is not True or value['mounts'] != [] or value['image'] != 'sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a':
        raise ValueError('Native runtime requires a qualified metadata-query adapter')
    return value

def public_xml(raw):
    root = ET.fromstring(raw)
    for node in root.iter():
        names = [node.tag.split('}')[-1], *node.attrib]
        if any(re.search(r'privatekey|password|credential|authorization|cookie|secret|token', n, re.I) for n in names):
            raise ValueError('Credential-bearing native XML cannot be exported')
    if b'PRIVATE KEY' in raw: raise ValueError('Private key cannot be exported')
    return raw

def query_command(entity):
    return ['env','-u','CLASSPATH','-u','JAVA_OPTS','-u','SHIB_OPTS',
        '/opt/reference-idp/bin/mdquery.sh','-u','http://localhost:8080/idp','-e',entity]

def capture_sources(receipt):
    receipt.mkdir(parents=True,exist_ok=True)
    pins = {}
    for name, (native, expected, retained) in JARS.items():
        digest = docker('sha256sum', native).stdout.decode().split()[0]
        if digest != expected: raise ValueError('Installed native metadata implementation changed')
        retained = REPO/'build/acceptance'/retained
        if SHA(retained.read_bytes()) != expected: raise ValueError('Retained immutable native JAR changed')
        path = receipt/name
        if not path.exists(): os.link(retained, path)
        pins[name] = digest
    for script in ['mdquery.sh','runclass.sh']:
        raw = docker('cat','/opt/reference-idp/bin/'+script).stdout
        (receipt/('native-'+script)).write_bytes(raw); pins[script] = SHA(raw)
    directories = ['/opt/reference-idp/views','/opt/reference-idp/flows',
        '/opt/reference-idp/edit-webapp/WEB-INF/lib','/opt/reference-idp/dist/plugin-webapp/WEB-INF/lib',
        '/usr/local/tomcat/webapps/idp/WEB-INF/classes']
    command = 'for d in '+ ' '.join(directories) + '; do if test -d "$d"; then find "$d" -type f; fi; done'
    inventory = docker('sh','-c',command).stdout
    for line in inventory.decode().splitlines():
        if not line.startswith('/opt/reference-idp/') or line.endswith(('/admin/mdquery.vm','.jar','.class')) or '/flows/admin/mdquery' in line:
            raise ValueError('Native metadata query override requires another source qualification')
    (receipt/'native-override-inventory.txt').write_bytes(inventory); pins['overrideInventory'] = SHA(inventory)
    return dict(sourceSha256=pins, overrideInventorySha256=SHA(inventory), mdqueryViewOverrideAbsent=True)

def restore(write, reload, native, original, configured, temporary, changed, written, remove=None):
    restored_provider=False
    if changed:
        current=native('cat',PROVIDERS).stdout
        if current not in [configured,original]: raise ValueError('Concurrent provider change; do not overwrite')
        if current==configured: write(PROVIDERS, original, 'restore-providers');restored_provider=True
    if written and native('sh','-c','test -e '+temporary,check=False).returncode==0:
        if remove is None: native('rm','--',temporary)
        else: remove(temporary)
    if restored_provider: reload('restore-providers')
    if native('cat',PROVIDERS).stdout != original: raise ValueError('Original provider bytes not restored')
    if native('sh','-c','test ! -e '+temporary,check=False).returncode != 0:
        raise ValueError('Temporary metadata source remains')

class M0Client(reference_flow.Client):
    def __init__(self):
        super().__init__(); self.credential_posts = 0; self.saml_attempts = 0
        owner=self
        class RedirectCounter(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,req,fp,code,msg,headers,newurl):
                parsed=urllib.parse.urlparse(newurl)
                if parsed.hostname not in {'localhost','127.0.0.1'}:raise ValueError('Nonlocal M0 redirect')
                if parsed.port==18280 and 'SAMLRequest=' in parsed.query:owner.saml_attempts+=1
                return super().redirect_request(req,fp,code,msg,headers,newurl)
        self.op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),RedirectCounter())
    def request(self, url, fields=None):
        if fields and ('password' in fields or 'j_password' in fields):
            if self.credential_posts: raise ValueError('Unexpected second M0 credential interaction')
            self.credential_posts += 1
        native = urllib.parse.urlparse(url).port == 18280
        if native and ((fields and 'SAMLRequest' in fields) or 'SAMLRequest=' in urllib.parse.urlparse(url).query):
            self.saml_attempts += 1
        return super().request(url, fields)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args(); out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    save(out/'collector-invocation.json',dict(command=[sys.executable,str(pathlib.Path(__file__).resolve()),'--output',str(out)],
        sourceSha256=SHA(pathlib.Path(__file__).read_bytes()),startedAt=NOW(),credentialsExported=False,
        cookiesExported=False,authorizationExported=False))
    receipt = out/'receipt'; receipt.mkdir(); ledger=[]; originals={}; changed=False; written=False; failure=None
    sources = capture_sources(receipt); stock_runtime = runtime()
    original = public_xml(docker('cat',PROVIDERS).stdout); (receipt/'original-providers.xml').write_bytes(original)
    plan = api('/api/plans',dict(name='Shibboleth complete native UI metadata readback',profile='metadata_idp',
        targetKind='IDP',targetEntityId='http://localhost:18280/idp/shibboleth',metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',suiteMetadataDelivery='HTTP_URL',
        declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,
            testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(out/'plan.json',plan); pid=plan['plan']['plan']['id']; created=api('/api/plans/'+pid+'/runs',{})
    save(out/'created.json',created); run=created['run']['id']; entity=plan['plan']['entityId']
    if entity != BASE+'/p/'+pid or created['run']['planId']!=pid: raise ValueError('Peer scope differs')
    save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
    target=subprocess.run(['docker','exec','samlscope-reference-suite','cat','/data/target-metadata/'+run+'.xml'],capture_output=True,check=True,timeout=20).stdout
    public_xml(target); (out/'target-metadata.xml').write_bytes(target); target_sha=SHA(target)
    approved,digests=approved_case(CASE,REPO); profile=json.loads((REPO/'profiles/metadata_idp.json').read_bytes())
    slots=[r for r in profile['cases'] if r['id']==CASE]
    if len(slots)!=1 or approved['mode']!='CONFIG' or approved['role']!='idp': raise ValueError('Approved full UI CONFIG slot absent')
    save(out/'planned-scope.json',dict(scope_only=True,formal_case_slot_verified=False,caseId=CASE,runId=run,
        profile='metadata_idp',catalogDigests=digests,plannedMembership=slots[0],targetMetadataSha256=target_sha))
    lab=api('/api/runs/'+run+'/metadata-lab')
    if not {'control','full-ui-info'} <= set(lab['availableVariants']): raise ValueError('Complete native input unavailable')
    temporary='/opt/reference-idp/metadata/full-ui-'+run+'.xml'
    if docker('sh','-c','test ! -e '+temporary,check=False).returncode: raise ValueError('Temporary source already exists')
    ET.register_namespace('',NAMESPACE); ET.register_namespace('xsi',XSI)
    tree=ET.fromstring(original); tree.insert(0,ET.Element('{'+NAMESPACE+'}MetadataProvider',
        {'id':'FullUi'+run,'{'+XSI+'}type':'FilesystemMetadataProvider','metadataFile':temporary}))
    configured=ET.tostring(tree); public_xml(configured); (receipt/'configured-providers.xml').write_bytes(configured)
    def row(operation,label):
        value=dict(operation=operation,label=label,startedAt=NOW(),completed=False);ledger.append(value);save(out/'operations.json',ledger);return value
    def write(path,raw,label):
        public_xml(raw); value=row('write',label); value.update(path=path,sha256=SHA(raw));save(out/'operations.json',ledger)
        docker('sh','-c','cat > '+path,data=raw)
        if docker('cat',path).stdout!=raw: raise ValueError('Native exact write readback failed')
        value.update(completed=True,finishedAt=NOW());save(out/'operations.json',ledger)
    def reload(label):
        value=row('reload',label); result=docker('/opt/reference-idp/bin/reload-service.sh','-id','shibboleth.MetadataResolverService','-u','http://localhost:8080/idp')
        (receipt/(label+'-reload.txt')).write_bytes(result.stdout)
        value.update(completed=True,finishedAt=NOW());save(out/'operations.json',ledger)
    def remove(path):
        value=row('remove','restore-temporary-source');value['path']=path;save(out/'operations.json',ledger)
        docker('rm','--',path)
        if docker('test','-e',path,check=False).returncode!=1:raise ValueError('Temporary source deletion not read back')
        value.update(completed=True,finishedAt=NOW());save(out/'operations.json',ledger)
    def payload(kind,**value):
        return dict(schema=ORIGINAL,campaignId=CAMPAIGN,runId=run,peerEntityId=entity,
            targetMetadataSha256=target_sha,kind=kind,recordedAt=NOW(),**value)
    def read_model(variant,fixture):
        value=row('query',variant); command=query_command(entity); result=docker(*command,check=False);finished=NOW()
        value.update(completed=result.returncode==0,finishedAt=finished,exitCode=result.returncode);save(out/'operations.json',ledger)
        public_xml(result.stdout)
        if result.returncode: raise ValueError('Native metadata resolver read-back failed')
        (receipt/(variant+'-native-output.xml')).write_bytes(result.stdout); (receipt/(variant+'-native-stderr.txt')).write_bytes(result.stderr)
        if runtime()!=stock_runtime or docker('cat',PROVIDERS).stdout!=configured or docker('cat',temporary).stdout!=fixture:
            raise ValueError('Native epoch/readback changed')
        return payload(variant+'-readback',providersBase64=B64(configured),fixtureBase64=B64(fixture),runtime=stock_runtime,
            query=dict(command=command,exitCode=result.returncode,startedAt=value['startedAt'],finishedAt=finished,
                stdoutBase64=B64(result.stdout),stderrBase64=B64(result.stderr),stdoutSha256=SHA(result.stdout),stderrSha256=SHA(result.stderr)))
    before=payload('before',providersBase64=B64(original),temporaryPath=temporary,temporaryAbsent=True,
        sourceSha256=sources['sourceSha256'],runtime=stock_runtime); save(out/'before.json',before)
    client=M0Client()
    try:
        save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=['control','full-ui-info'],pollingDelaySeconds=0)))
        for variant in ['control','full-ui-info']:
            state=api('/api/runs/'+run+'/metadata-lab')
            if state['selectedVariant']!=variant: raise ValueError('Prepared native input differs')
            with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as response:
                if response.status!=202: raise ValueError('Expected Suite metadata preparation gate')
            with urllib.request.urlopen(state['metadataUrl'],timeout=30) as response: fixture=response.read()
            public_xml(fixture); (receipt/(variant+'-input.xml')).write_bytes(fixture)
            if variant=='full-ui-info':
                role=ET.fromstring(fixture).find('{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor')
                ext=role.find('{urn:oasis:names:tc:SAML:2.0:metadata}Extensions'); ui='{urn:oasis:names:tc:SAML:metadata:ui}'
                if ext.find(ui+'UIInfo') is None or ext.find(ui+'DiscoHints') is None or ext.find(ui+'UIInfo').find(ui+'DiscoHints') is not None:
                    raise ValueError('Corrected full UI fixture is not deployed; no native write for this member')
            written=True;write(temporary,fixture,'fixture-'+variant)
            if not changed: changed=True;write(PROVIDERS,configured,'apply-providers')
            reload('apply-'+variant); model=read_model(variant,fixture)
            kind='control-readback' if variant=='control' else 'full-ui-readback';model['kind']=kind;save(out/(kind+'.json'),model)
            if variant=='control':
                ids={e['id'] for e in api('/api/runs/'+run+'/transcript')}
                result=client.flow(state['automaticStartUrl'],None,os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
                exchange=recorded_exchange(run,'control',ids); save(out/'initial-baseline.json',dict(receipt=result,exchange=exchange,
                    credentialSubmissions=client.credential_posts,actualSamlAttempts=client.saml_attempts))
                if not exchange['success']: raise ValueError('M0 correlated normal flow incomplete')
                save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));save(out/'scope-result.json',api('/api/runs/'+run+'/result.json'))
                slot=scope_preflight(CASE,out/'scope-result.json');save(out/'formal-slot-preflight.json',slot)
                if slot.get('scope_ready') is not True: raise ValueError('Formal full UI slot not established')
            else:
                # Only orchestration advances; it supplies no metadata-consumer conclusion or SAML.
                current=api('/api/runs/'+run+'/metadata-lab')
                with urllib.request.urlopen(urllib.request.Request(current['automaticContinueUrl'],data=b''),timeout=30) as response: response.read()
    except Exception as error:
        failure=dict(errorType=type(error).__name__,message=str(error));save(out/'failure.json',failure)
    finally:
        try: restore(write,reload,docker,original,configured,temporary,changed,written,remove)
        except Exception as error: save(out/'restoration-failed.json',dict(errorType=type(error).__name__));raise
        restored=docker('cat',PROVIDERS).stdout==original; sources_after=capture_sources(out/'native-source-after')
        if sources_after!=sources or runtime()!=stock_runtime: raise ValueError('Native source/runtime changed during campaign')
        after=payload('after',providersBase64=B64(original),temporaryPath=temporary,temporaryAbsent=True,restored=restored,
            sourceSha256=sources_after['sourceSha256'],runtime=stock_runtime);save(out/'after.json',after)
        save(out/'restoration.json',dict(restored=restored,originalSha256=SHA(original),finalSha256=SHA(docker('cat',PROVIDERS).stdout),temporaryRemoved=True))
        counts=dict(restored=restored,fullUiTesterLogins=0,fullUiSamlSubmissions=0,productRestarts=0,humanOperations=0,
            initialBaselineSubmissions=client.saml_attempts,initialCredentialSubmissions=client.credential_posts,
            configurationWriteAttempts=sum(r['operation']=='write' for r in ledger),
            restorationWrites=sum(r['operation']=='write' and r['label'].startswith('restore-') for r in ledger),
            metadataReloadAttempts=sum(r['operation']=='reload' for r in ledger),nativeModelQueries=sum(r['operation']=='query' for r in ledger),ledger=ledger)
        save(out/'operation-counts.json',counts)
    if failure: raise ValueError('Native full UI campaign failed and was restored; immutable failure and costs retained')
    for kind in ['before','control-readback','full-ui-readback','after']:
        originals[kind]=recorded(receipt,created,json.loads((out/(kind+'.json')).read_bytes()),kind)
    source=payload('native-source',**sources);originals['native-source']=recorded(receipt,created,source,'native-source')
    operations=payload('operations',**counts);originals['operations']=recorded(receipt,created,operations,'operations')
    entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
    files={str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file()}
    manifest=dict(schema=SCHEMA,adapter=ADAPTER,campaignId=CAMPAIGN,runId=run,planId=pid,peerEntityId=entity,
        targetEntityId='http://localhost:18280/idp/shibboleth',targetMetadataSha256=target_sha,
        counterfactualCalibrationOnly=False,files=files,originals=originals)
    save(receipt/'manifest.json',manifest);save(out/'protocol-evidence-before-installation.json',api('/api/runs/'+run+'/protocol-evidence'))
    print(run,'native full UI values captured and restored; no verdict inferred')

if __name__=='__main__': main()
