#!/usr/bin/env python3
"""Local reference harness: import original Suite fixtures through the product UI, then exercise SSO.

Uses the Suite's existing correlated fixture campaign. It does not translate XML to client attributes
or assign verdicts. The Suite evaluates the recorded protocol evidence after the batch.
"""
import argparse, hashlib, json, os, pathlib, shlex, shutil, subprocess, sys
import urllib.request, urllib.error

REPO = pathlib.Path(__file__).resolve().parents[2]
BASE = 'http://localhost:18080'
VARIANTS = ['control', 'entity-root', 'entities-root-one', 'certificate-expired',
    'certificate-not-yet-valid', 'certificate-sha1', 'certificate-sha512',
    'certificate-critical-extension', 'certificate-noncritical-extension',
    'certificate-no-digital-signature', 'certificate-unrelated-eku',
    'certificate-empty-subject', 'certificate-unknown-ca', 'certificate-long-validity',
    'unknown-extension', 'mdrpi-registration-info']

def api(path, body=None):
    request = urllib.request.Request(BASE + path, data=None if body is None else json.dumps(body).encode(),
        headers={'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Suite API {error.code}: {error.read().decode()[:800]}") from None

def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')

def recorded_exchange(run, variant, previous_ids):
    entries=api('/api/runs/'+run+'/transcript')
    requests=[e for e in entries if e['id'] not in previous_ids and e['direction']=='OUTBOUND'
        and e['samlSummary'].get('type')=='AuthnRequest' and e['samlSummary'].get('variant')==variant]
    if len(requests)!=1:return dict(success=False,reason='ambiguous-issued-request')
    request=requests[0];request_id=request['samlSummary']['id']
    responses=[e for e in entries if e['direction']=='INBOUND'
        and e['samlSummary'].get('metadataProbeAccepted') is True
        and e['samlSummary'].get('inResponseTo')==request_id]
    statuses={e['samlSummary'].get('statusCode') for e in responses}
    return dict(success=statuses=={'urn:oasis:names:tc:SAML:2.0:status:Success'},
        request_id=request_id,status_codes=sorted(s for s in statuses if isinstance(s,str)),
        transcript_ids=[request['id'],*[e['id'] for e in responses]])

def flow(run, record_path, signature_control=False, suite_signature_control=False):
    import reference_flow as pc
    state = api('/api/runs/' + run + '/metadata-lab')
    variant, index = state['selectedVariant'], state['campaignIndex']
    control = None
    if suite_signature_control:
        before_ids={e['id'] for e in api('/api/runs/'+run+'/transcript')}
        receipt=pc.Client().flow(state['automaticStartUrl']+'&signatureControl=invalid',None,
            os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),
            os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
        exchange=recorded_exchange(run,variant,before_ids)
        control=dict(source='suite',receipt=receipt,exchange=exchange,correlated_success=exchange['success'])
        save(record_path,dict(run=run,variant=variant,negative_control=control,correlated_success=False))
        if api('/api/runs/'+run+'/metadata-lab')['campaignIndex']!=index:
            raise RuntimeError('Suite negative control must not advance the fixture')
    elif signature_control:
        mutation = pc.SignatureMutation()
        receipt = pc.Client(signature_mutation=mutation).flow(state['automaticStartUrl'], None,
            os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),
            os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
        after_negative = api('/api/runs/' + run + '/metadata-lab')
        control = dict(receipt=receipt, mutations=mutation.records,
            correlated_success=after_negative['campaignIndex'] == index + 1)
        save(record_path, dict(run=run,variant=variant,negative_control=control,correlated_success=False))
        if len(mutation.records) != 1:
            raise RuntimeError('Negative control did not mutate exactly one signed request')
        if control['correlated_success']:
            raise RuntimeError('Corrupted signature accepted; this flow cannot prove key consumption')
        if after_negative['campaignIndex'] != index:
            raise RuntimeError('Unexpected campaign advancement during negative control')
    before_ids={e['id'] for e in api('/api/runs/'+run+'/transcript')}
    receipt = pc.Client().flow(state['automaticStartUrl'], None,
        os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),
        os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
    after = api('/api/runs/' + run + '/metadata-lab')
    exchange=recorded_exchange(run,variant,before_ids)
    # A correlated SAML error can also advance orchestration. Inspect the actual response.
    accepted = after['campaignIndex'] == index + 1 and exchange['success']
    save(record_path, dict(run=run, variant=variant, before_index=index,
        after_index=after['campaignIndex'], receipt=receipt, correlated_success=accepted,
        negative_control=control,positive_exchange=exchange))
    if not accepted:
        raise RuntimeError('No correlated Success; retain NOT_VERIFIED and inspect the saved evidence')
    if suite_signature_control and control['correlated_success']:
        raise RuntimeError('Suite-issued corrupt signature accepted; do not adopt key consumption')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=pathlib.Path,required=True)
    parser.add_argument('--playwright-modules',type=pathlib.Path)
    parser.add_argument('--flow-run')
    parser.add_argument('--signature-control',action='store_true',help='Exercise a corrupt signature before each normal flow')
    parser.add_argument('--suite-signature-control',action='store_true',help='Use Suite-issued and recorded invalid-signature controls')
    parser.add_argument('--run',help='Append a new fixture campaign to an existing reference Run')
    parser.add_argument('--profile',choices=['metadata_idp','browser_sso_idp'],default='metadata_idp')
    parser.add_argument('--variants',help='Comma-separated Suite fixture IDs, beginning with control')
    args=parser.parse_args()
    if args.flow_run:
        flow(args.flow_run,args.output,args.signature_control,args.suite_signature_control);return
    if args.playwright_modules is None:parser.error('--playwright-modules is required for a batch')
    out=args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Output directory must be empty; do not overwrite prior evidence')
    out.mkdir(parents=True,exist_ok=True)
    stage=out/'driver';stage.mkdir(exist_ok=True)
    shutil.copy2(REPO/'dev/keycloak/console_import.mjs',stage/'console_import.mjs')
    if not (stage/'node_modules').exists():(stage/'node_modules').symlink_to(args.playwright_modules.resolve(),target_is_directory=True)
    operations=[]
    if args.run:
        run=args.run
        existing=api('/api/runs/'+run)
        plan_id=existing['planId']
        save(out/'created.json',dict(run=dict(id=run,planId=plan_id),reused=True))
    else:
        plan=api('/api/plans',dict(name='Keycloak original metadata import batch',profile=args.profile,
            targetKind='IDP',targetEntityId='http://localhost:18180/realms/samlscope',
            metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',
            suiteMetadataDelivery='HTTP_URL',declaredFeatures={},
            parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),
            interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
        save(out/'plan.json',plan);plan_id=plan['plan']['plan']['id']
        created=api('/api/plans/'+plan_id+'/runs',{});save(out/'created.json',created);run=created['run']['id']
        save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
    variants=args.variants.split(',') if args.variants else VARIANTS
    if not variants or variants[0]!='control':raise ValueError('Campaign requires control first')
    state=api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=variants,pollingDelaySeconds=0))
    save(out/'campaign.json',state)
    try:
        for variant in variants:
            state=api('/api/runs/'+run+'/metadata-lab')
            if state['selectedVariant']!=variant:raise RuntimeError('Campaign variant mismatch')
            folder=out/variant;folder.mkdir(exist_ok=True)
            # Arm the selected fixture before its download; this request must wait for a fetch.
            with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as response:
                if response.status != 202:raise RuntimeError('Unexpected pre-import campaign dispatch')
                response.read()
            with urllib.request.urlopen(state['metadataUrl'],timeout=30) as response:fixture=response.read()
            (folder/'fixture.xml').write_bytes(fixture)
            follow=shlex.join([sys.executable,str(pathlib.Path(__file__).resolve()),'--flow-run',run,'--output',str(folder/'flow.json')]
                + (['--signature-control'] if args.signature_control else []))
            if args.suite_signature_control and not variant.startswith('default-acs-'):
                follow += ' --suite-signature-control'
            command=['node',str(stage/'console_import.mjs'),'--fixture',str(folder/'fixture.xml'),
                '--record',str(folder/'import.json'),'--entity-id',BASE+'/p/'+plan_id,'--verify-command',follow,'--delete']
            result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=420)
            (folder/'driver.log').write_text(result.stdout)
            operations.append(dict(variant=variant,fixture_sha256=hashlib.sha256(fixture).hexdigest(),
                driver_exit=result.returncode,record=str(folder/'import.json')))
            save(out/'operations.json',operations)
            print(variant,'verified' if result.returncode==0 else 'incomplete',flush=True)
            imported=json.loads((folder/'import.json').read_text())
            if not imported.get('cleanup',{}).get('read_back_absent'):
                raise RuntimeError('Cleanup not verified; stop before another import')
            if variant=='control':
                if result.returncode:raise RuntimeError('Baseline failed; no target verdict is justified')
                save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
            if result.returncode:
                # Advance orchestration only; no rejection or product verdict is fabricated.
                pending=api('/api/runs/'+run+'/metadata-lab')
                # A corrupted request can itself produce a correlated response. Do not skip
                # the following fixture when the negative control advanced the campaign.
                if pending['campaignIndex'] == state['campaignIndex']:
                    with urllib.request.urlopen(urllib.request.Request(pending['automaticContinueUrl'],data=b''),timeout=30) as response:
                        response.read()
                    operations[-1]['continued_without_verdict']=True
                save(out/'operations.json',operations)
    finally:
        # Evaluate only Suite-recorded evidence; never submit an operator verdict.
        try:
            if not (out/'tests-start.json').exists():
                save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
            save(out/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}))
        except Exception as error:
            save(out/'evaluation-unavailable.json',dict(reason=str(error)))
        for suffix in ['result.json','report.html','transcript','protocol-evidence']:
            try:
                with urllib.request.urlopen(BASE+'/api/runs/'+run+'/'+suffix,timeout=30) as response:
                    (out/(suffix if '.' in suffix else suffix+'.json')).write_bytes(response.read())
            except Exception as error:print('Export unavailable',suffix,type(error).__name__)
        save(out/'final-state.json',api('/api/runs/'+run+'/metadata-lab'))
        print('Run',run,flush=True)
if __name__=='__main__':main()
