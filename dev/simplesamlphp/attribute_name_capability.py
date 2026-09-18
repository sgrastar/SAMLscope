#!/usr/bin/env python3
"""Exercise a standard attribute control and custom names/formats, then restore product settings."""
import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
from configuration_batch import ConfigurationBatch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import api, save, BASE
from reference_flow import Client
spec = importlib.util.spec_from_file_location('ssp_native', Path(__file__).with_name('import_metadata_batch.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
CASE = 'IIP-IDP01-a-idp-01'
URN = 'urn:samlscope:test:attribute-name'
STRING = 'SAMLscope arbitrary attribute'
FORMAT = 'urn:samlscope:test:attribute-name-format'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True, exist_ok=True)
    config = ConfigurationBatch(REPO / 'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php')
    created = api('/api/plans', dict(name='SimpleSAMLphp arbitrary attribute names and formats', profile='browser_sso_idp',
        targetKind='IDP', targetEntityId='http://localhost:18380/idp', metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300, testUserHint='samlscope-m0-user', requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    save(out / 'plan.json', created)
    plan = created['plan']['plan']['id']
    if not re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}', plan):
        raise ValueError('Invalid generated plan identifier')
    entity = BASE + '/p/' + plan
    if entity.encode() in config.original or b'?>' in config.original:
        raise ValueError('Refusing an ambiguous metadata overlay')
    run_result = api('/api/plans/' + plan + '/runs', {})
    save(out / 'created.json', run_result)
    run = run_result['run']['id']
    save(out / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))
    with urllib.request.urlopen(BASE + '/p/' + plan + '/metadata', timeout=30) as response:
        fixture = response.read()
    (out / 'fixture.xml').write_bytes(fixture)
    parsed = subprocess.run(['docker', 'exec', '-i', 'samlscope-reference-ssp', 'php', '-r', native.PHP, entity, 'default'],
                            input=fixture, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=40)
    (out / 'parser-output.json').write_bytes(parsed.stdout)
    data = json.loads(parsed.stdout)
    assert data['entity_id'] == entity and data['validate_authnrequest'] is True
    records = []
    try:
        for variant in ['standard-control', 'custom-names-and-format']:
            overlay = data['php'].encode()
            if variant != 'standard-control':
                # These are explicit product policy settings, separate from native XML interpretation.
                overlay += ("\n$metadata['" + entity + "']['attributes.NameFormat'] = '" + FORMAT + "';\n"
                    "$metadata['" + entity + "']['authproc'] = [50 => ['class' => 'core:AttributeMap', "
                    "'uid' => '" + STRING + "', 'eduPersonAffiliation' => '" + URN + "']];\n").encode()
            record = dict(variant=variant, configuration_sha256=config.apply(overlay), configuration_read_back=True)
            records.append(record)
            time.sleep(3)
            record['configuration_settle_seconds'] = 3
            record['flow_receipt'] = Client().flow(BASE + '/p/' + plan + '/start/m0-roundtrip?run=' + run,
                None, 'samlscope-m0-user', 'samlscope-m0-password')
            if variant == 'standard-control':
                save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
                save(out / 'control-protocol-evidence.json', api('/api/runs/' + run + '/protocol-evidence'))
        save(out / 'protocol-evidence-before.json', api('/api/runs/' + run + '/protocol-evidence'))
        save(out / 'result-before.json', api('/api/runs/' + run + '/result.json'))
        save(out / (CASE + '-configure.json'), api('/api/runs/' + run + '/cases/' + CASE + '/configure', {'value': 'confirmed'}))
    finally:
        restoration = config.restore()
        save(out / 'restoration.json', restoration)
        save(out / 'operations.json', dict(run=run, entity_id=entity, operations=records,
            fixture_sha256=hashlib.sha256(fixture).hexdigest(), parser_output_sha256=hashlib.sha256(parsed.stdout).hexdigest(),
            settings=dict(attribute_map={'uid': STRING, 'eduPersonAffiliation': URN}, name_format=FORMAT), restored=restoration['restored']))
        for endpoint in ['result.json', 'transcript', 'protocol-evidence']:
            save(out / (endpoint if endpoint.endswith('.json') else endpoint + '.json'), api('/api/runs/' + run + '/' + endpoint))
    manifest = []
    for entry in json.loads((out / 'transcript.json').read_text()):
        if not entry.get('decodedSamlRef'):
            continue
        path = out / 'decoded' / (entry['id'] + '.xml')
        path.parent.mkdir(exist_ok=True)
        subprocess.run(['docker', 'cp', 'samlscope-reference-suite:/data/' + entry['decodedSamlRef'], str(path)], check=True, stdout=subprocess.DEVNULL)
        manifest.append(dict(id=entry['id'], file=str(path.relative_to(out)), sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    save(out / 'decoded-manifest.json', manifest)
    subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True)
    print('Run', run, 'restored', restoration['restored'], 'configuration writes', restoration['configuration_write_attempts'])


if __name__ == '__main__':
    main()
