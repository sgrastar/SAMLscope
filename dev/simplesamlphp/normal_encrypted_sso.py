#!/usr/bin/env python3
"""Import the Suite's ordinary metadata, enable assertion encryption, exercise normal SSO, restore."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import time
import urllib.request
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
    args=parser.parse_args();out=args.output.resolve()
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
    try:
        with urllib.request.urlopen(BASE+'/p/'+plan+'/metadata',timeout=30) as response:fixture=response.read()
        (out/'fixture.xml').write_bytes(fixture);record['fixture_sha256']=hashlib.sha256(fixture).hexdigest()
        parsed=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',native.PHP,entity,'encrypt'],
            input=fixture,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40,check=True)
        (out/'parser-output.json').write_bytes(parsed.stdout);record['parser_output_sha256']=hashlib.sha256(parsed.stdout).hexdigest()
        data=json.loads(parsed.stdout)
        assert data['assertion_encryption'] is True and data['validate_authnrequest'] is True
        configured=original+b'\n'+data['php'].encode()+b'\n';config.write_bytes(configured)
        record['configuration_written']=True;record['configuration_read_back']=config.read_bytes()==configured
        time.sleep(3);record['configuration_settle_seconds']=3
        receipt=Client().flow(BASE+'/p/'+plan+'/start/m0-roundtrip?run='+run,None,'samlscope-m0-user','samlscope-m0-password')
        save(out/'flow.json',dict(run=run,receipt=receipt))
        save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
        save(out/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}))
        record['status']='completed-observation'
    finally:
        config.write_bytes(original)
        record['restored']=config.read_bytes()==original
        save(out/'import.json',record)
        save(out/'restoration.json',dict(restored=record['restored'],original_sha256=hashlib.sha256(original).hexdigest(),final_sha256=hashlib.sha256(config.read_bytes()).hexdigest()))
        for suffix in ['result.json','transcript','protocol-evidence']:
            with urllib.request.urlopen(BASE+'/api/runs/'+run+'/'+suffix,timeout=30) as response:
                (out/(suffix if '.' in suffix else suffix+'.json')).write_bytes(response.read())
    print('Run',run,'settings restored',record['restored'])

if __name__=='__main__':main()
