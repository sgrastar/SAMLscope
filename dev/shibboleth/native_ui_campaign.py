#!/usr/bin/env python3
"""One native UI campaign: original fixtures, fresh challenges, read-back and exact restore.

Only the Suite outbox delivers SAML requests. Native metadata/filesystem operations are
operational setup, never a product verdict. Passwords, cookies and hidden values remain
in the subprocess/browser memory; only the explicit safe properties projection is saved.
"""
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
sys.path.insert(0,str(REPO/'dev/keycloak'))
from import_metadata_batch import api, save, flow, BASE
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_terminal_http_runtime import capture_target
from ui_display_comparison import candidates as display_candidates
CONTAINER='samlscope-reference-shibboleth'
XSI='http://www.w3.org/2001/XMLSchema-instance'

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
NOW=lambda:datetime.now(timezone.utc).isoformat()
def docker(*args,data=None):
    return subprocess.run(['docker','exec','-i',CONTAINER,*args],input=data,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=90).stdout
CONFIG='/opt/reference-idp/conf/metadata-providers.xml'
UIJAR='/usr/local/tomcat/webapps/idp/WEB-INF/lib/idp-ui-5.2.3.jar'
CLASS='net/shibboleth/idp/ui/context/RelyingPartyUIContext.class'
DISPLAY=['ui-consumer-display-'+value for value in ('all','service','entity')]
URLS=['ui-url-'+element+'-'+scheme for element in ('logo','information','privacy')
      for scheme in ('http','https','data','javascript','file')]
SAFETY=['ui-safety-logo-data','ui-safety-information-javascript','ui-safety-privacy-javascript']
VARIANTS=['control','full-ui-info',*DISPLAY,*URLS,*SAFETY]
PATHS={
    'login-template':'/opt/reference-idp/views/login.vm',
    'authn-properties':'/opt/reference-idp/conf/authn/authn.properties',
    'password-config':'/opt/reference-idp/conf/authn/password-authn-config.xml',
    'relying-party':'/opt/reference-idp/conf/relying-party.xml',
    'global':'/opt/reference-idp/conf/global.xml',
}


def projection():
    # Do not export idp.properties, which also contains private sealer credentials.
    return docker('sh','-c',"grep -E '^[[:space:]]*idp\\.(ui\\.fallbackLanguages|authn\\.flows)[[:space:]]*=' /opt/reference-idp/conf/idp.properties")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--variants',help='Subset for diagnostics only; complete adoption uses all required scopes')
    parser.add_argument('--existing',type=Path,help='Append only selected conditions to an immutable existing campaign Run')
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    variants=args.variants.split(',') if args.variants else VARIANTS
    if not variants or (not args.existing and variants[0]!='control') or any(v not in VARIANTS for v in variants) or len(set(variants))!=len(variants):raise ValueError('Invalid variants')
    original=docker('cat',CONFIG);(out/'original-providers.xml').write_bytes(original)
    stable={kind:docker('cat',path) for kind,path in PATHS.items()};stable['parent-ui-authn-properties']=projection()
    for kind,raw in stable.items():(out/('original-'+kind)).write_bytes(raw)
    native_class=docker('unzip','-p',UIJAR,CLASS);(out/'native-ui-context.class').write_bytes(native_class)
    native_conf='/usr/local/tomcat/webapps/idp/WEB-INF/lib/idp-conf-impl-5.2.3.jar'
    for label,path in {'flow-selection':'net/shibboleth/idp/flows/authn/authn-beans.xml',
            'flow-descriptors':'net/shibboleth/idp/conf/authn-system.xml'}.items():
        (out/('native-'+label+'.xml')).write_bytes(docker('unzip','-p',native_conf,path))
    inventory=docker('find','/opt/reference-idp/views','-type','f');(out/'native-view-inventory.txt').write_bytes(inventory)
    # Overlay views can replace shipped UI behavior. Pin every active override, not only login.vm.
    views=[]
    for path in sorted(inventory.decode().splitlines()):
        if not path.startswith('/opt/reference-idp/views/') or not re.fullmatch(r'[A-Za-z0-9/._-]+',path):raise ValueError('Unsafe view inventory')
        raw=docker('cat',path);file='native-view-'+str(len(views))+'.vm';(out/file).write_bytes(raw)
        views.append(dict(path=path,file=file,sha256=SHA(raw)))
    (out/'native-views.json').write_text(json.dumps(views,indent=2)+'\n')
    capture_target(out,'shibboleth','start')
    health=docker('curl','-sf','http://localhost:8080/idp/status');(out/'native-status-start.txt').write_bytes(health)
    if args.existing:
        previous=args.existing.resolve()
        created=json.loads((previous/'plan.json').read_text());save(out/'plan.json',created);plan=created['plan']['plan']['id']
        created=json.loads((previous/'created.json').read_text());save(out/'created.json',created);run=created['run']['id']
        save(out/'reuse.json',dict(original=str(previous),runId=run,planId=plan,productTrialAppendOnly=True,recordedAt=NOW()))
        if original!=(previous/'original-providers.xml').read_bytes():raise ValueError('Previous provider state not restored')
    else:
        created=api('/api/plans',dict(name='Shibboleth grouped native metadata UI',profile='metadata_idp',
        targetKind='IDP',targetEntityId='http://localhost:18280/idp/shibboleth',metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',
        suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),
            interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
        save(out/'plan.json',created);plan=created['plan']['plan']['id']
        created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run):raise ValueError('Invalid Run')
    if not args.existing:save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
    initial_transcript=api('/api/runs/'+run+'/transcript');save(out/'transcript-before.json',initial_transcript)
    initial_ids={entry['id'] for entry in initial_transcript}
    temporary='/opt/reference-idp/metadata/native-ui-'+run+'.xml'
    if docker('sh','-c','test ! -e '+temporary+' || echo exists').strip():raise ValueError('Temporary path already exists')
    ns='urn:mace:shibboleth:2.0:metadata';ET.register_namespace('',ns);ET.register_namespace('xsi',XSI)
    root=ET.fromstring(original);root.insert(0,ET.Element('{'+ns+'}MetadataProvider',
        {'id':'NativeUi'+run,'{'+XSI+'}type':'FilesystemMetadataProvider','metadataFile':temporary}))
    configured=ET.tostring(root);(out/'configured-providers.xml').write_bytes(configured)
    operations=[];observations=[];changed=False;temporary_written=False;failure=None

    def write(path,raw,label):
        row=dict(operation='product-config-write',label=label,path=path,recordedAt=NOW(),sha256=SHA(raw),readBack=False)
        operations.append(row);save(out/'operations.json',operations)
        docker('sh','-c','cat > '+path,data=raw)
        if docker('cat',path)!=raw:raise RuntimeError('Write read-back failed')
        row['readBack']=True;save(out/'operations.json',operations)

    def reload(label):
        row=dict(operation='product-reload',label=label,recordedAt=NOW(),completed=False)
        operations.append(row);save(out/'operations.json',operations)
        raw=docker('/opt/reference-idp/bin/reload-service.sh','-id','shibboleth.MetadataResolverService','-u','http://localhost:8080/idp')
        (out/(label+'-reload.log')).write_bytes(raw);row.update(completed=True,completedAt=NOW());save(out/'operations.json',operations)

    def readback(folder,phase):
        at=NOW();provider=docker('cat',CONFIG);fixture=docker('cat',temporary)
        if provider!=configured:raise RuntimeError('Concurrent provider change')
        (folder/(phase+'-providers.xml')).write_bytes(provider);(folder/(phase+'-fixture.xml')).write_bytes(fixture)
        rows=[]
        for kind,path in PATHS.items():
            raw=docker('cat',path)
            if raw!=stable[kind]:raise RuntimeError('Concurrent native UI configuration change')
            file=phase+'-'+kind;(folder/file).write_bytes(raw);rows.append(dict(kind=kind,file=file,sha256=SHA(raw)))
        raw=projection()
        if raw!=stable['parent-ui-authn-properties']:raise RuntimeError('Concurrent UI/authentication setting change')
        file=phase+'-parent-ui-authn-properties';(folder/file).write_bytes(raw);rows.append(dict(kind='parent-ui-authn-properties',file=file,sha256=SHA(raw)))
        record=dict(phase=phase,recordedAt=at,providerFile=phase+'-providers.xml',providerSha256=SHA(provider),
            fixtureFile=phase+'-fixture.xml',fixtureSha256=SHA(fixture),configurationFiles=rows)
        save(folder/(phase+'-readback.json'),record);return record

    try:
        state=api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=variants,pollingDelaySeconds=0))
        save(out/'campaign.json',state)
        for variant in variants:
            folder=out/variant;folder.mkdir();state=api('/api/runs/'+run+'/metadata-lab')
            if state['selectedVariant']!=variant:raise RuntimeError('Unexpected campaign state')
            with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as response:
                if response.status!=202:raise RuntimeError('Missing metadata fetch gate')
                response.read()
            with urllib.request.urlopen(state['metadataUrl'],timeout=30) as response:raw=response.read()
            (folder/'fixture.xml').write_bytes(raw);temporary_written=True;write(temporary,raw,'fixture-'+variant)
            if not changed:changed=True;write(CONFIG,configured,'apply-provider')
            reload('import-'+variant)
            before=readback(folder,'before')
            effective=docker('/opt/reference-idp/bin/mdquery.sh','-u','http://localhost:8080/idp','-e',BASE+'/p/'+plan)
            (folder/'native-effective-metadata.xml').write_bytes(effective)
            save(folder/'native-effective-read.json',dict(runId=run,variant=variant,entityId=BASE+'/p/'+plan,
                recordedAt=NOW(),sha256=SHA(effective),command='mdquery.sh native MetadataResolverService'))
            if variant=='control':
                flow(run,folder/'flow.json',suite_signature_control=True)
                save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
            else:
                tree=ET.fromstring(raw)
                if variant in DISPLAY:candidates=display_candidates(raw,variant)
                else:
                    nodes=[node for node in tree.iter() if node.tag in ('{urn:oasis:names:tc:SAML:metadata:ui}Logo',
                        '{urn:oasis:names:tc:SAML:metadata:ui}InformationURL','{urn:oasis:names:tc:SAML:metadata:ui}PrivacyStatementURL')]
                    candidates={'control':'Login to '+('SAMLscope UI display candidate (en)' if variant=='full-ui-info' else 'SAMLscope URL policy control')}
                    if variant!='full-ui-info':
                        if len(nodes)!=1:raise ValueError('Ambiguous UI input')
                        candidates['probe']=nodes[0].text
                save(folder/'browser-input.json',dict(runId=run,variant=variant,startUrl=state['automaticStartUrl'],
                    candidates=candidates,authenticate=False,activeSinkControl=variant=='ui-safety-logo-data'))
                row=dict(operation='fresh-native-browser-challenge',variant=variant,recordedAt=NOW(),completed=False)
                operations.append(row);save(out/'operations.json',operations)
                result=subprocess.run(['node',str(Path(__file__).with_name('observe_native_ui.mjs')),str(folder/'browser-input.json')],
                    env=os.environ,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=100)
                row.update(exitCode=result.returncode,completed=result.returncode==0,completedAt=NOW());save(out/'operations.json',operations)
                if result.returncode:raise RuntimeError('Native browser challenge capture failed: '+variant)
                current=api('/api/runs/'+run+'/metadata-lab')
                with urllib.request.urlopen(urllib.request.Request(current['automaticContinueUrl'],data=b''),timeout=30) as response:response.read()
            after=readback(folder,'after')
            observations.append(dict(variant=variant,fixtureSha256=SHA(raw),nativeMetadataSha256=SHA(effective),before=before,after=after))
            save(out/'observations.json',observations);print(variant,'captured',flush=True)
    except Exception as error:
        failure=dict(error=type(error).__name__,message=str(error)[:300]);save(out/'failure.json',failure);raise
    finally:
        failures=[]
        if changed:
            try:
                if docker('cat',CONFIG)!=configured:raise RuntimeError('Concurrent provider change before restore')
                write(CONFIG,original,'restore-provider');reload('restore-provider')
            except Exception as error:failures.append(type(error).__name__)
        if temporary_written and not failures:
            docker('rm','--',temporary);operations.append(dict(operation='product-temporary-file-delete',recordedAt=NOW(),path=temporary))
        final=docker('cat',CONFIG);(out/'final-providers.xml').write_bytes(final)
        config_final=[]
        for kind,path in PATHS.items():
            raw=docker('cat',path);(out/('final-'+kind)).write_bytes(raw);config_final.append(dict(kind=kind,unchanged=raw==stable[kind]))
        raw=projection();(out/'final-parent-ui-authn-properties').write_bytes(raw)
        config_final.append(dict(kind='parent-ui-authn-properties',unchanged=raw==stable['parent-ui-authn-properties']))
        removed=not docker('sh','-c','test ! -e '+temporary+' || echo exists').strip()
        restored=final==original and removed and not failures and all(row['unchanged'] for row in config_final)
        save(out/'restoration.json',dict(restored=restored,originalSha256=SHA(original),finalSha256=SHA(final),
            temporaryRemoved=removed,failures=failures,configurationFiles=config_final,recordedAt=NOW()))
        capture_target(out,'shibboleth','end');(out/'native-status-end.txt').write_bytes(docker('curl','-sf','http://localhost:8080/idp/status'))
        transcript=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',transcript)
        decoded=[]
        for entry in transcript:
            if not entry.get('decodedSamlRef'):continue
            expected='transcripts/'+run+'/'+entry['id']+'.saml.xml'
            if entry.get('runId')!=run or entry['decodedSamlRef']!=expected:raise ValueError('Foreign transcript original')
            destination=out/'decoded'/(entry['id']+'.xml');destination.parent.mkdir(exist_ok=True)
            subprocess.run(['docker','cp','samlscope-reference-suite:/data/'+expected,str(destination)],capture_output=True,check=True)
            decoded.append(dict(id=entry['id'],file=str(destination.relative_to(out)),sha256=SHA(destination.read_bytes())))
        save(out/'decoded-manifest.json',decoded);save(out/'operations.json',operations)
        save(out/'operation-counts.json',dict(productConfigurationWrites=sum(r['operation']=='product-config-write' for r in operations),
            productReloads=sum(r['operation']=='product-reload' for r in operations),productRestarts=0,humanOperations=0,
            freshBrowserChallenges=sum(r['operation']=='fresh-native-browser-challenge' for r in operations),
            protocolSends=sum(e['id'] not in initial_ids and e.get('direction')=='OUTBOUND' and e.get('samlSummary',{}).get('type')=='AuthnRequest' for e in transcript),
            totalRunProtocolSends=sum(e.get('direction')=='OUTBOUND' and e.get('samlSummary',{}).get('type')=='AuthnRequest' for e in transcript),
            restored=restored))
        if not restored:raise RuntimeError('Native UI restoration failed')
    print(run,'all originals captured; no verdict assigned')


if __name__=='__main__':main()
