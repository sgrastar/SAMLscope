#!/usr/bin/env python3
"""Native grouped SLO propagation trials, Suite-outbox-only SAML and exact restoration."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/keycloak'));sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from import_metadata_batch import api,save,BASE
from reference_flow import Client
from browser_probe_selection import prepare_and_skip
from capture_terminal_http_runtime import capture_target
from capture_run_originals import capture
CONTAINER='samlscope-reference-shibboleth';CONFIG='/opt/reference-idp/conf/metadata-providers.xml'
MD='urn:oasis:names:tc:SAML:2.0:metadata';XSI='http://www.w3.org/2001/XMLSchema-instance'
SHA=lambda b:hashlib.sha256(b).hexdigest()
NOW=lambda:datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def docker(*args,data=None):
    return subprocess.run(['docker','exec','-i',CONTAINER,*args],input=data,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,check=True,timeout=90).stdout
def metadata(primary,plan,run,failure):
    """Native operational three-SP configuration; retain original Suite keys/ACS."""
    primary=ET.fromstring(primary);sp=primary.find('{'+MD+'}SPSSODescriptor')
    if primary.get('entityID')!=BASE+'/p/'+plan or sp is None:raise ValueError('Foreign primary SP metadata')
    # Force actual browser bindings in the operational harness. SOAP failure endpoint cannot
    # currently record the decoded failure request; do not count its empty original as proof.
    for slo in list(sp.findall('{'+MD+'}SingleLogoutService')):
        if slo.get('Binding')=='urn:oasis:names:tc:SAML:2.0:bindings:SOAP':sp.remove(slo)
    root=ET.Element('{'+MD+'}EntitiesDescriptor');root.append(primary)
    keys=list(sp.findall('{'+MD+'}KeyDescriptor'));acs=sp.find('{'+MD+'}AssertionConsumerService')
    for suffix in ('fail','remain','remain2'):
        entity=ET.SubElement(root,'{'+MD+'}EntityDescriptor',{'entityID':BASE+'/p/'+plan+'/sp-'+suffix,'ID':'_'+suffix})
        role=ET.SubElement(entity,'{'+MD+'}SPSSODescriptor',{'protocolSupportEnumeration':'urn:oasis:names:tc:SAML:2.0:protocol',
            'AuthnRequestsSigned':'false','WantAssertionsSigned':'true'})
        for key in keys:role.append(ET.fromstring(ET.tostring(key)))
        endpoint=BASE+'/p/'+plan+('/idp/slo' if suffix=='remain2' else '/sp/'+('slo-fail' if failure and suffix=='fail' else 'slo'))+'?run='+run
        for binding in ('HTTP-POST',):
            ET.SubElement(role,'{'+MD+'}SingleLogoutService',{'Binding':'urn:oasis:names:tc:SAML:2.0:bindings:'+binding,'Location':endpoint})
        role.append(ET.fromstring(ET.tostring(acs)))
    return ET.tostring(root)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--only-trial',choices=['failure','all-success']);args=parser.parse_args()
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    for name in ('native_slo_propagation_campaign.py','observe_native_slo_propagation.mjs','slo_propagation_observation.mjs'):
        (out/('source-'+name)).write_bytes(Path(__file__).with_name(name).read_bytes())
    original=docker('cat',CONFIG);(out/'original-providers.xml').write_bytes(original)
    stable={'relying-party':'/opt/reference-idp/conf/relying-party.xml','authn-properties':'/opt/reference-idp/conf/authn/authn.properties',
        'global':'/opt/reference-idp/conf/global.xml','logout-propagate-view':'/opt/reference-idp/views/logout-propagate.vm',
        'logout-view':'/opt/reference-idp/views/logout.vm','logout-complete-view':'/opt/reference-idp/views/logout-complete.vm'}
    original_stable={kind:docker('cat',path) for kind,path in stable.items()}
    for kind,raw in original_stable.items():(out/('original-'+kind)).write_bytes(raw)
    projection=docker('sh','-c',r"grep -E '^[[:space:]]*idp\.(session\.trackSPSessions|logout\.[A-Za-z0-9.]+)[[:space:]]*=' /opt/reference-idp/conf/idp.properties || true")
    (out/'original-session-properties.txt').write_bytes(projection)
    native='/usr/local/tomcat/webapps/idp/WEB-INF/lib/idp-conf-impl-5.2.3.jar'
    (out/'native-logout-propagate.vm').write_bytes(docker('unzip','-p',native,'net/shibboleth/idp/views/logout/propagate.vm'))
    for name in ('saml/saml2/slo-front-abstract-flow.xml','saml/saml2/slo-post-flow.xml','saml/saml2/slo-post-beans.xml',
        'logout/logout-propagation-flow.xml','logout/logout-propagation-beans.xml','saml/logout/saml2-logoutprop-flow.xml','saml/logout/saml2-logoutprop-beans.xml'):
        (out/('native-'+name.replace('/','-'))).write_bytes(docker('unzip','-p',native,'net/shibboleth/idp/flows/'+name))
    capture_target(out,'shibboleth','start');(out/'native-status-start.txt').write_bytes(docker('curl','-sf','http://localhost:8080/idp/status'))
    created=api('/api/plans',dict(name='Shibboleth native three-participant SLO propagation',profile='single_logout_idp',
        targetKind='IDP',targetEntityId='http://localhost:18280/idp/shibboleth',metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',suiteMetadataDelivery='HTTP_URL',
        declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,
            testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(out/'plan.json',created);plan=created['plan']['plan']['id']
    with urllib.request.urlopen(BASE+'/p/'+plan+'/metadata',timeout=30) as response:primary=response.read()
    (out/'suite-primary-original.xml').write_bytes(primary)
    temporary='/opt/reference-idp/metadata/native-slo-'+plan+'.xml'
    if docker('sh','-c','test ! -e '+temporary+' || echo exists').strip():raise ValueError('Temporary path exists')
    ns='urn:mace:shibboleth:2.0:metadata';ET.register_namespace('',ns);ET.register_namespace('xsi',XSI)
    root=ET.fromstring(original);root.insert(0,ET.Element('{'+ns+'}MetadataProvider',{'id':'NativeSlo'+plan,
        '{'+XSI+'}type':'FilesystemMetadataProvider','metadataFile':temporary}))
    configured=ET.tostring(root);(out/'configured-providers.xml').write_bytes(configured)
    operations=[];changed=written=False;trial_failures=[]
    def write(path,raw,label):
        row=dict(operation='write',path=path,label=label,recordedAt=NOW(),sha256=SHA(raw),readBack=False)
        operations.append(row);save(out/'operations.json',operations);docker('sh','-c','cat > '+path,data=raw)
        if docker('cat',path)!=raw:raise RuntimeError('Native write read-back failed')
        row['readBack']=True;save(out/'operations.json',operations)
    def reload(label):
        row=dict(operation='reload',label=label,recordedAt=NOW(),completed=False);operations.append(row);save(out/'operations.json',operations)
        (out/(label+'-reload.log')).write_bytes(docker('/opt/reference-idp/bin/reload-service.sh','-id','shibboleth.MetadataResolverService','-u','http://localhost:8080/idp'))
        row.update(completed=True,completedAt=NOW());save(out/'operations.json',operations)
    def readback(folder,phase,fixture):
        if docker('cat',CONFIG)!=configured or docker('cat',temporary)!=fixture:raise RuntimeError('Native provider changed')
        rows=[]
        for kind,path in stable.items():
            raw=docker('cat',path)
            if raw!=original_stable[kind]:raise RuntimeError('Native SLO setup changed')
            name=phase+'-'+kind;(folder/name).write_bytes(raw);rows.append(dict(kind=kind,file=name,sha256=SHA(raw)))
        (folder/(phase+'-providers.xml')).write_bytes(configured);(folder/(phase+'-fixture.xml')).write_bytes(fixture)
        save(folder/(phase+'-readback.json'),dict(recordedAt=NOW(),providerSha256=SHA(configured),fixtureSha256=SHA(fixture),configurationFiles=rows))
    trials=[args.only_trial] if args.only_trial else ['failure','all-success']
    try:
        for trial in trials:
            folder=out/trial;folder.mkdir();created=api('/api/plans/'+plan+'/runs',{});save(folder/'created.json',created);run=created['run']['id']
            save(folder/'preflight.json',api('/api/runs/'+run+'/preflight',{}));fixture=metadata(primary,plan,run,trial=='failure')
            (folder/'configured-sp-metadata.xml').write_bytes(fixture);written=True;write(temporary,fixture,'fixture-'+trial)
            if not changed:changed=True;write(CONFIG,configured,'apply-provider')
            reload('import-'+trial);readback(folder,'before',fixture)
            for suffix in ('','/sp-fail','/sp-remain','/sp-remain2'):
                (folder/('effective-'+(suffix.split('-')[-1] if suffix else 'primary')+'.xml')).write_bytes(docker('/opt/reference-idp/bin/mdquery.sh',
                    '-u','http://localhost:8080/idp','-e',BASE+'/p/'+plan+suffix))
            baseline=Client().flow(BASE+'/p/'+plan+'/start/m0-roundtrip?run='+run,None,
                os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
            save(folder/'baseline.json',dict(runId=run,receipt=baseline))
            if baseline!='recorded':raise RuntimeError('Baseline SSO failed')
            save(folder/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));skipped=[]
            for _ in range(200):
                status=api('/api/runs/'+run+'/active-probe')
                if status.get('caseId')=='IIP-IDP17-a-idp-01' and status['state']=='READY':break
                if status['state']!='READY':raise RuntimeError('Cannot prepare selected SLO case '+str(status))
                skipped.append(prepare_and_skip(BASE,run,status,api));save(folder/'skipped.json',skipped)
            else:raise RuntimeError('Selected SLO case unavailable')
            save(folder/'browser-input.json',dict(runId=run,planId=plan,trial=trial,initialProbe=status))
            browser=subprocess.run(['node',str(Path(__file__).with_name('observe_native_slo_propagation.mjs')),str(folder/'browser-input.json')],
                env=os.environ,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=170)
            (folder/'browser.log').write_bytes(browser.stdout);(folder/'browser-error.log').write_bytes(browser.stderr)
            readback(folder,'after',fixture);save(folder/'transcript.json',api('/api/runs/'+run+'/transcript'))
            capture(folder,run,json.loads((folder/'transcript.json').read_text()))
            if browser.returncode:trial_failures.append(dict(trial=trial,browserExit=browser.returncode))
            try:save(folder/'conclude.json',api('/api/runs/'+run+'/target-initiated/conclude',{}))
            except RuntimeError:pass
            save(folder/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}));save(folder/'result.json',api('/api/runs/'+run+'/result.json'))
            save(folder/'transcript-final.json',api('/api/runs/'+run+'/transcript'))
    finally:
        failures=[]
        if changed:
            try:
                if docker('cat',CONFIG)!=configured:raise RuntimeError('Concurrent provider change')
                write(CONFIG,original,'restore-provider');reload('restore-provider')
            except Exception as error:failures.append(type(error).__name__)
        if written and not failures:docker('rm','--',temporary)
        final=docker('cat',CONFIG);(out/'final-providers.xml').write_bytes(final)
        removed=not docker('sh','-c','test ! -e '+temporary+' || echo exists').strip()
        checks=[dict(kind=kind,unchanged=docker('cat',path)==original_stable[kind]) for kind,path in stable.items()]
        restored=not failures and final==original and removed and all(row['unchanged'] for row in checks)
        save(out/'restoration.json',dict(restored=restored,temporaryRemoved=removed,configurationFiles=checks,failures=failures))
        recorded=0; prepared=0; sends=0
        for folder in out.iterdir():
            if folder.is_dir() and (folder/'transcript.json').exists():
                skipped=json.loads((folder/'skipped.json').read_text()) if (folder/'skipped.json').exists() else []
                unsent={row['actionId'] for row in skipped if row.get('prepared') is True and row.get('sentToTarget') is False}
                for entry in json.loads((folder/'transcript.json').read_text()):
                    if entry['direction']=='OUTBOUND' and entry['samlSummary'].get('type') in ('AuthnRequest','LogoutRequest','LogoutResponse'):
                        recorded+=1
                        if entry['samlSummary'].get('action_id') in unsent:prepared+=1
                        else:sends+=1
        save(out/'operation-counts.json',dict(productConfigurationWrites=sum(r['operation']=='write' for r in operations),
            productReloads=sum(r['operation']=='reload' for r in operations),productRestarts=0,humanOperations=0,
            outboundRecordedMessages=recorded,preparedAndSkippedMessages=prepared,
            outboundProtocolMessages=sends,trialFailures=trial_failures,restored=restored))
        capture_target(out,'shibboleth','end');(out/'native-status-end.txt').write_bytes(docker('curl','-sf','http://localhost:8080/idp/status'))
        if not restored:raise RuntimeError('Native restoration failed')
    print(out,trial_failures)
if __name__=='__main__':main()
