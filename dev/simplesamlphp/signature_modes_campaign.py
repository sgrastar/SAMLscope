#!/usr/bin/env python3
"""Exercise native signing configurations with a temporary SP; preserve and restore configuration bytes."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from configuration_batch import ConfigurationBatch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'dev/keycloak'))
from import_metadata_batch import api, save, BASE
from reference_flow import Client
spec = importlib.util.spec_from_file_location('ssp_native_import', Path(__file__).with_name('import_metadata_batch.py'))
native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PHASES = [('both', True, True), ('assertion-only', False, True), ('response-only', True, False)]
READBACK = r'''
$metadata=[]; require '/var/simplesamlphp/metadata/saml20-sp-remote.php';
$m=$metadata[$argv[1]]??null;
if ($m===null) throw new \RuntimeException('Temporary SP missing');
echo json_encode(['response_signed'=>$m['saml20.sign.response']??null,
 'assertion_signed'=>$m['saml20.sign.assertion']??null,'encrypted'=>$m['assertion.encryption']??null]);
'''


def main(default_matrix="signature"):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--matrix', choices=['signature', 'encryption'], default=default_matrix)
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    configuration = ConfigurationBatch(REPO/'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php')
    if b'?>' in configuration.original: raise ValueError('Unexpected PHP closing tag')
    created = api('/api/plans', dict(name='SimpleSAMLphp native ' + args.matrix + ' modes', profile='browser_sso_idp',
        targetKind='IDP', targetEntityId='http://localhost:18380/idp', metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300, testUserHint='samlscope-m0-user', requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    save(out/'plan.json', created); plan = created['plan']['plan']['id']
    if not re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}', plan): raise ValueError('Invalid plan')
    entity = BASE+'/p/'+plan
    if entity.encode() in configuration.original: raise ValueError('Existing SP cannot be overwritten')
    created = api('/api/plans/'+plan+'/runs', {}); save(out/'created.json', created); run = created['run']['id']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', run): raise ValueError('Invalid Run')
    save(out/'preflight.json', api('/api/runs/'+run+'/preflight', {}))
    metadata_url = entity+'/metadata?run='+run
    if args.matrix == 'signature': metadata_url += '&variant=signature-modes-optional'
    with urllib.request.urlopen(metadata_url, timeout=30) as response: fixture = response.read()
    (out/'fixture.xml').write_bytes(fixture)
    role = ET.fromstring(fixture).find('{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor')
    if role is None or (args.matrix == 'signature' and role.get('WantAssertionsSigned') != 'false'):
        raise ValueError('Signature matrix requires optional Assertion signing metadata')
    parsed = subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',native.PHP,entity,'default'],
        input=fixture, capture_output=True, timeout=40, check=True)
    data = json.loads(parsed.stdout); (out/'native-import.json').write_bytes(parsed.stdout)
    if data['entity_id'] != entity or data['validate_authnrequest'] is not True:
        raise ValueError('Native metadata import mismatch')
    phases = []; readback_attempts = 0; readback_successes = 0
    try:
        matrix = [(mode, rs, ass, False) for mode, rs, ass in PHASES] if args.matrix == 'signature' else [
            ('unencrypted-control', True, True, False), ('encrypted', True, True, True),
            ('encrypted-repeat', True, True, True)]
        for mode, response_signed, assertion_signed, encrypted in matrix:
            folder = out/mode; folder.mkdir()
            requested = dict(response_signed=response_signed, assertion_signed=assertion_signed, encrypted=encrypted)
            overlay = data['php'] + '\n' + '\n'.join(
                "$metadata['"+entity+"']['"+key+"'] = "+str(value).lower()+";"
                for key,value in [('saml20.sign.response',response_signed),('saml20.sign.assertion',assertion_signed),('assertion.encryption',encrypted)])
            configured = configuration.apply(overlay.encode())
            readback_attempts += 1
            readback = json.loads(subprocess.check_output(['docker','exec','samlscope-reference-ssp','php','-r',READBACK,entity], timeout=30))
            if readback != requested: raise ValueError('Native signing settings differ')
            readback_successes += 1
            save(folder/'native-readback.json', readback)
            time.sleep(3)  # Reference PHP worker metadata/opcode cache settling; counted explicitly.
            before = {e['id'] for e in api('/api/runs/'+run+'/transcript')}
            receipt = Client().flow(entity+'/start/m0-roundtrip?run='+run, None,
                os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'), os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
            after = api('/api/runs/'+run+'/transcript')
            row = dict(run=run, phase=mode, requested=requested, receipt=receipt, configuration_sha256=configured,
                added_transcripts=[e['id'] for e in after if e['id'] not in before], settle_seconds=3,
                readback_sha256=SHA((folder/'native-readback.json').read_bytes()), verdict_adopted=False)
            phases.append(row); save(folder/'flow.json', row)
            if receipt != 'recorded': raise RuntimeError('Native signing flow did not complete')
            print(mode, 'recorded', flush=True)
        save(out/'tests-start.json', api('/api/runs/'+run+'/tests/start', {}))
        save(out/'evaluation.json', api('/api/runs/'+run+'/protocol-evidence/evaluate', {}))
        save(out/'result.json', api('/api/runs/'+run+'/result.json'))
    finally:
        restoration = configuration.restore(); save(out/'restoration.json', restoration)
        save(out/'operations.json', dict(run=run, matrix=args.matrix, phases=phases, restored=restoration['restored'],
            configuration_write_attempts=configuration.write_count, native_readback_attempts=readback_attempts, native_readback_successes=readback_successes,
            product_restarts=0, human_operations=0, evidence_scope='explicit-native-settings-and-browser-sso'))
        entries = api('/api/runs/'+run+'/transcript'); save(out/'transcript.json', entries)
        manifest=[]; (out/'decoded').mkdir(exist_ok=True)
        for entry in entries:
            if not entry.get('decodedSamlRef'): continue
            if not re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}', entry['id']): raise ValueError('Invalid transcript')
            expected='transcripts/'+run+'/'+entry['id']+'.saml.xml'
            if entry['decodedSamlRef'] != expected: raise ValueError('Unexpected original path')
            file=out/'decoded'/(entry['id']+'.xml')
            subprocess.run(['docker','cp','samlscope-reference-suite:/data/'+expected,str(file)],capture_output=True,check=True,timeout=30)
            manifest.append(dict(id=entry['id'],file=str(file.relative_to(out)),sha256=SHA(file.read_bytes())))
        save(out/'decoded-manifest.json', manifest)
        subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],capture_output=True,check=True,timeout=30)
    print('Run', run, 'native metadata restored; no new verdict adopted')


if __name__ == '__main__': main()
