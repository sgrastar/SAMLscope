#!/usr/bin/env python3
"""Import the Suite's ordinary metadata, enable assertion encryption, exercise normal SSO, restore."""
import argparse
import base64
import secrets
import hashlib
import json
import pathlib
import subprocess
import sys
import time
import urllib.request
import urllib.error
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'keycloak'))
from import_metadata_batch import api, save, BASE, REPO
from reference_flow import Client
# Local module has the product-native parser, distinct from the Keycloak helper above.
import importlib.util
spec=importlib.util.spec_from_file_location('ssp_native',pathlib.Path(__file__).with_name('import_metadata_batch.py'))
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=pathlib.Path,required=True)
    parser.add_argument('--shared-key-gcm',type=int,choices=[128,256],help='Generate an ephemeral AES key; retain only its digest')
    parser.add_argument('--wrong-key-control',action='store_true',help='Evaluate using an unrelated key; no algorithm may pass')
    args=parser.parse_args();out=args.output.resolve()
    if args.wrong_key_control and not args.shared_key_gcm:parser.error('--wrong-key-control requires --shared-key-gcm')
    shared_key=secrets.token_bytes(args.shared_key_gcm//8) if args.shared_key_gcm else None
    if out.exists() and any(out.iterdir()):raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True,exist_ok=True)
    config=REPO/'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php'
    original=config.read_bytes()
    if b'?>' in original:raise ValueError('Unexpected PHP closing tag')
    created=api('/api/plans',dict(name='SimpleSAMLphp normal encrypted SSO',profile='browser_sso_idp',
        targetKind='IDP',targetEntityId='http://localhost:18380/idp',metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
        suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(out/'plan.json',created);plan=created['plan']['plan']['id'];entity=BASE+'/p/'+plan
    if entity.encode() in original:raise ValueError('Refusing to overwrite existing entity')
    created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id']
    save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
    record=dict(status='incomplete',run=run,entity_id=entity,import_path='native-parser-cli',assertion_encryption_override=True)
    if shared_key:
        record['shared_key_bits']=args.shared_key_gcm
        record['shared_key_sha256']=hashlib.sha256(shared_key).hexdigest()
    try:
        with urllib.request.urlopen(BASE+'/p/'+plan+'/metadata',timeout=30) as response:fixture=response.read()
        (out/'fixture.xml').write_bytes(fixture);record['fixture_sha256']=hashlib.sha256(fixture).hexdigest()
        parsed=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',native.PHP,entity,'encrypt'],
            input=fixture,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40,check=True)
        (out/'parser-output.json').write_bytes(parsed.stdout);record['parser_output_sha256']=hashlib.sha256(parsed.stdout).hexdigest()
        data=json.loads(parsed.stdout)
        assert data['assertion_encryption'] is True and data['validate_authnrequest'] is True
        configured=original+b'\n'+data['php'].encode()+b'\n'
        if shared_key:
            # Only the temporary product configuration contains the key. Never save it in evidence.
            encoded=base64.b64encode(shared_key).decode()
            configured+=("$metadata['"+entity+"']['sharedkey'] = base64_decode('"+encoded+"');\n"+
                "$metadata['"+entity+"']['sharedkey_algorithm'] = 'http://www.w3.org/2009/xmlenc11#aes"+str(args.shared_key_gcm)+"-gcm';\n").encode()
        config.write_bytes(configured)
        record['configuration_written']=True;record['configuration_read_back']=config.read_bytes()==configured
        time.sleep(3);record['configuration_settle_seconds']=3
        receipt=Client().flow(BASE+'/p/'+plan+'/start/m0-roundtrip?run='+run,None,'samlscope-m0-user','samlscope-m0-password')
        save(out/'flow.json',dict(run=run,receipt=receipt))
        save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
        evaluation_key=secrets.token_bytes(len(shared_key)) if args.wrong_key_control else shared_key
        evaluation_input={'sharedKeyBase64':base64.b64encode(evaluation_key).decode()} if evaluation_key else {}
        save(out/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',evaluation_input))
        if shared_key:
            # The saved diagnostics contain algorithm tokens and counts, never the key.
            save(out/'shared-key-evaluation.json',dict(input_sha256=hashlib.sha256(evaluation_key).hexdigest(),wrong_key_control=args.wrong_key_control,key_persisted=False))
        if shared_key and args.wrong_key_control:
            try:
                request=urllib.request.Request(BASE+'/api/runs/'+run+'/protocol-evidence/evaluate',
                    data=json.dumps({'sharedKeyBase64':base64.b64encode(shared_key).decode()}).encode(),
                    headers={'Content-Type':'application/json'},method='POST')
                with urllib.request.urlopen(request,timeout=30) as response:response.read()
            except urllib.error.HTTPError as error:
                if error.code!=400:raise
                save(out/'fixed-input-control.json',dict(replacement_rejected=True,status=error.code))
            else:raise RuntimeError('Run key replacement was incorrectly accepted')
        record['status']='completed-observation'
    finally:
        config.write_bytes(original)
        record['restored']=config.read_bytes()==original
        save(out/'import.json',record)
        save(out/'restoration.json',dict(restored=record['restored'],original_sha256=hashlib.sha256(original).hexdigest(),final_sha256=hashlib.sha256(config.read_bytes()).hexdigest()))
        for suffix in ['result.json','transcript','protocol-evidence']:
            with urllib.request.urlopen(BASE+'/api/runs/'+run+'/'+suffix,timeout=30) as response:
                (out/(suffix if '.' in suffix else suffix+'.json')).write_bytes(response.read())
    decoded=[]
    for entry in json.loads((out/'transcript.json').read_text()):
        ref=entry.get('decodedSamlRef')
        if not ref:continue
        relative=pathlib.Path('decoded')/(entry['id']+'.xml')
        destination=out/relative;destination.parent.mkdir(exist_ok=True)
        subprocess.run(['docker','cp','samlscope-reference-suite:/data/'+ref,str(destination)],check=True,stdout=subprocess.DEVNULL)
        decoded.append(dict(id=entry['id'],file=str(relative),sha256=hashlib.sha256(destination.read_bytes()).hexdigest()))
    save(out/'decoded-manifest.json',decoded)
    if shared_key:
        needles=[shared_key,base64.b64encode(shared_key),evaluation_key,base64.b64encode(evaluation_key)]
        for artifact in out.rglob('*'):
            if artifact.is_file() and any(needle in artifact.read_bytes() for needle in needles):
                raise RuntimeError('Secret detected in evidence artifact')
        save(out/'secret-scan.json',dict(passed=True,files_checked=sum(p.is_file() for p in out.rglob('*'))))
    print('Run',run,'settings restored',record['restored'])

if __name__=='__main__':main()
