#!/usr/bin/env python3
"""Native metadata import and request-bound HTTP evidence for the common EC signature case."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
from attribute_name_capability import native,api,save,BASE,Client,ConfigurationBatch,REPO
from import_metadata_batch import flow

spec=importlib.util.spec_from_file_location('ssp_signature_observer',Path(__file__).with_name('signed_request_observation.py'))
observer=importlib.util.module_from_spec(spec);spec.loader.exec_module(observer)
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
VARIANTS=['control','ecdsa-sha256','ecdsa-sha256-invalid-signature']
VERIFIER_SOURCE='/var/simplesamlphp/modules/saml/src/Message.php'
CONTAINER='samlscope-reference-ssp'
SOURCE_FILES={
    'message':VERIFIER_SOURCE,
    'module':'/var/simplesamlphp/public/module.php',
    'routes':'/var/simplesamlphp/modules/saml/routing/routes/routes.yml',
    'web-browser-sso':'/var/simplesamlphp/modules/saml/src/Controller/WebBrowserSingleSignOn.php',
    'idp-saml2':'/var/simplesamlphp/modules/saml/src/IdP/SAML2.php',
}

class NativeImportUnavailable(RuntimeError):
    pass


def running_product_binding(data):
    """Return the live container identity and prove its native source tree is image-backed."""
    state=data['State']
    if state['Running'] is not True:raise RuntimeError('SimpleSAMLphp container is not running')
    container_id=data['Id'];image_id=data['Image'];started_at=state['StartedAt']
    if len(container_id)!=64 or not image_id.startswith('sha256:') or not started_at:raise RuntimeError('Incomplete product identity')
    source_root='/var/simplesamlphp/modules/saml/src'
    if any(mount.get('Destination','')==source_root or mount.get('Destination','').startswith(source_root+'/')
           or mount.get('Destination','')=='/var/simplesamlphp/public/module.php' for mount in data['Mounts']):
        raise RuntimeError('Native SAML source tree is covered by a mount')
    if not any(mount.get('Destination')=='/var/simplesamlphp/metadata/saml20-sp-remote.php' and mount.get('RW') is True
               for mount in data['Mounts']):
        raise RuntimeError('Expected writable SP metadata configuration mount is absent')
    mappings=data['NetworkSettings']['Ports'].get('80/tcp') or []
    if not any(item.get('HostIp')=='127.0.0.1' and item.get('HostPort')=='18380' for item in mappings):
        raise RuntimeError('Expected localhost SimpleSAMLphp port mapping is absent')
    return dict(container_name=CONTAINER,container_id=container_id,image_id=image_id,
        container_started_at=started_at,running_at_capture=True,container_port='80/tcp',host_ip='127.0.0.1',host_port=18380,
        source_tree_mounted=False)


def capture_runtime_originals(out,label):
    raw=subprocess.check_output(['docker','inspect',CONTAINER],timeout=30)
    data=json.loads(raw)[0];binding=running_product_binding(data)
    inspect=out/f'native-runtime-inspect-{label}.json';inspect.write_bytes(raw)
    sources={}
    for name,path in SOURCE_FILES.items():
        content=subprocess.check_output(['docker','exec',CONTAINER,'cat',path],timeout=30)
        filename='native-verifier-source.php' if name=='message' else f'native-{name}-source.php'
        (out/filename).write_bytes(content)
        sources[name]=dict(container_path=path,sha256=SHA(content),file=filename)
    save(out/f'native-call-path-sources-{label}.json',dict(binding=binding,inspect_file=inspect.name,sources=sources))
    return binding,sources


def main(default_matrix="ec"):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--profiles',default='browser_sso_idp,metadata_idp,ecp_idp,single_logout_idp')
    parser.add_argument('--matrix',choices=['ec','keys'],default=default_matrix)
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    variants=VARIANTS
    if args.matrix=='keys':
        sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
        from metadata_key_matrix import KEY_CAMPAIGN
        variants=list(KEY_CAMPAIGN)
    save(out/'matrix.json',dict(matrix=args.matrix,variants=variants,verdict_adopted=False))
    profiles=args.profiles.split(',')
    if len(profiles)!=len(set(profiles)) or not set(profiles)<={'browser_sso_idp','metadata_idp','ecp_idp','single_logout_idp'}:
        raise ValueError('Invalid profiles')
    configuration=ConfigurationBatch(REPO/'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php')
    if b'?>' in configuration.original:raise ValueError('Ambiguous configuration overlay')
    binding,sources=capture_runtime_originals(out,'start')
    verifier_source=(out/sources['message']['file']).read_bytes()
    save(out/'native-verifier-source.json',dict(container_path=VERIFIER_SOURCE,
        sha256=SHA(verifier_source),**binding))
    save(out/'native-call-path-sources.json',dict(binding=binding,sources=sources,
        start_original='native-call-path-sources-start.json'))
    credentials=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
    operations=[]
    try:
        for profile in profiles:
            folder=out/profile;folder.mkdir();records=[]
            plan=api('/api/plans',dict(name='SimpleSAMLphp native '+args.matrix+' signature observations',profile=profile,targetKind='IDP',
                targetEntityId='http://localhost:18380/idp',metadataSourceKind='URL',
                metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
                suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,
                metadataRefreshWaitSeconds=300,testUserHint=credentials[0],requestSigningMode='REQUIRED'),
                interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
            save(folder/'plan.json',plan);entity=BASE+'/p/'+plan['plan']['plan']['id']
            if entity.encode() in configuration.original:raise ValueError('Refusing existing entity overwrite')
            created=api('/api/plans/'+plan['plan']['plan']['id']+'/runs',{});save(folder/'created.json',created);run=created['run']['id']
            save(folder/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
            save(folder/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=variants,pollingDelaySeconds=0)))
            def apply_fixture(destination,url):
                with urllib.request.urlopen(url,timeout=30) as response:fixture=response.read()
                (destination/'fixture.xml').write_bytes(fixture)
                parsed=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',native.PHP,entity,'default'],
                    input=fixture,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
                if parsed.returncode:raise NativeImportUnavailable('Native metadata parser rejected the fixture')
                data=json.loads(parsed.stdout)
                if data['entity_id']!=entity:raise ValueError('Native parser returned a different entity')
                if data['validate_authnrequest'] is not True:raise NativeImportUnavailable('Native signature policy unavailable')
                (destination/'parser-output.json').write_bytes(parsed.stdout)
                digest=configuration.apply(data['php'].encode());time.sleep(3)
                result=dict(run=run,entity_id=entity,import_path='native-parser-cli',fixture_sha256=SHA(fixture),
                    parser_output_sha256=SHA(parsed.stdout),configuration_sha256=digest,configuration_read_back=True,
                    validate_authnrequest=True)
                save(destination/'import.json',result);return result
            try:
                for variant in variants:
                    p=folder/variant;p.mkdir();state=api('/api/runs/'+run+'/metadata-lab')
                    if state['selectedVariant']!=variant:raise RuntimeError('Unexpected campaign variant')
                    with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as response:
                        if response.status!=202:raise RuntimeError('Expected metadata fetch gate')
                    try:
                        imported=apply_fixture(p,state['metadataUrl']);imported['variant']=variant
                    except NativeImportUnavailable as error:
                        # A parser rejection is unavailable setup, never a target signature verdict.
                        # Do not send against the previous condition's still-installed metadata.
                        if variant=='control':raise
                        row=dict(profile=profile,run=run,variant=variant,flow='not-executed',
                            reason='native-metadata-import-unavailable',error_type=type(error).__name__)
                        operations.append(row);save(p/'import-unavailable.json',row);save(out/'operations.json',operations)
                        pending=api('/api/runs/'+run+'/metadata-lab')
                        if pending['campaignIndex']!=state['campaignIndex']:raise RuntimeError('Unexpected campaign advancement')
                        with urllib.request.urlopen(urllib.request.Request(pending['automaticContinueUrl'],data=b''),timeout=30) as response:response.read()
                        row['continued_without_verdict']=True
                        continue
                    row=dict(profile=profile,run=run,variant=variant);operations.append(row)
                    try:
                        flow(run,p/'flow.json',suite_signature_control=variant!='ecdsa-sha256-invalid-signature',
                            login_inputs=credentials,client_factory=lambda:observer.SignatureClient(records))
                        row['flow']='correlated-success'
                    except RuntimeError as error:
                        row['flow']='inconclusive';row['reason']=str(error)
                        if variant=='control':raise
                    finally:
                        save(p/'import.json',imported);save(out/'operations.json',operations)
                    if variant=='control':save(folder/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
                    pending=api('/api/runs/'+run+'/metadata-lab')
                    if pending['campaignIndex']==state['campaignIndex']:
                        with urllib.request.urlopen(urllib.request.Request(pending['automaticContinueUrl'],data=b''),timeout=30) as response:response.read()
                        row['continued_without_verdict']=True
                baseline=folder/'baseline';baseline.mkdir();apply_fixture(baseline,entity+'/metadata')
                receipt=observer.SignatureClient(records).flow(entity+'/start/m0-roundtrip?run='+run,None,*credentials)
                save(baseline/'flow.json',receipt)
                if receipt!='recorded':raise RuntimeError('Normal login not recorded')
            finally:
                save(folder/'native-http-observations.json',dict(run=run,records=records,
                    product_verdict_assigned=False,product_binding=binding,
                    native_verifier_sha256=SHA(verifier_source)))
                for name in ['result.json','transcript','protocol-evidence']:
                    save(folder/(name if '.' in name else name+'.json'),api('/api/runs/'+run+'/'+name))
            print(profile,'collected',run,flush=True)
    finally:
        restored=configuration.restore();save(out/'restoration.json',restored)
        final_binding,final_sources=capture_runtime_originals(out,'end')
        if final_binding!=binding:raise RuntimeError('SimpleSAMLphp container identity changed during campaign')
        if {name:value['sha256'] for name,value in final_sources.items()}!={name:value['sha256'] for name,value in sources.items()}:
            raise RuntimeError('Native SAML call-path source changed during campaign')
        save(out/'native-call-path-sources.json',dict(binding=binding,sources=sources,
            start_original='native-call-path-sources-start.json',end_original='native-call-path-sources-end.json'))
        save(out/'operations.json',operations)
        save(out/'operation-counts.json',dict(configuration_write_attempts=configuration.write_count,
            matrix=args.matrix,applied_conditions=configuration.applied_count,human_operations=0,product_restarts=0,
            native_verifier_sha256=SHA(verifier_source),native_verifier_read_back=True,
            native_call_path_sources_read_back=len(sources),runtime_identity_read_backs=2,restored=restored['restored']))
    if args.matrix=='keys':
        from capture_run_originals import capture
        captured=[]
        for profile in profiles:
            folder=out/profile;created=json.loads((folder/'created.json').read_text())
            entries=json.loads((folder/'transcript.json').read_text())
            manifest=capture(folder,created['run']['id'],entries)
            captured.append(dict(profile=profile,run=created['run']['id'],originals=len(manifest)))
        save(out/'original-capture.json',dict(profiles=captured,restored=restored['restored'],verdict_adopted=False))



if __name__=='__main__':main()
