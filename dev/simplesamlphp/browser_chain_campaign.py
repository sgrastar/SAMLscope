#!/usr/bin/env python3
"""Drive the Suite's browser-assisted active-probe chain against SimpleSAMLphp and capture evidence.

The Suite SP metadata is imported through the product's own SAML metadata parser into
saml20-sp-remote.php, held fixed for the whole chain, and restored byte-for-byte afterwards.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))

_spec = importlib.util.spec_from_file_location('ssp_import', REPO / 'dev/simplesamlphp/import_metadata_batch.py')
ssp = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(ssp)
_cspec = importlib.util.spec_from_file_location('ssp_config', REPO / 'dev/simplesamlphp/configuration_batch.py')
ssp_config = importlib.util.module_from_spec(_cspec); _cspec.loader.exec_module(ssp_config)
from reference_flow import Client
from capture_run_originals import capture

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CONFIG = REPO / 'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php'
USER = os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user')
PASSWORD = os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-probes', type=int, default=400)
    parser.add_argument('--profile', default='browser_sso_idp')
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True, exist_ok=True)
    api = ssp.api
    plan_result = api('/api/plans', dict(name='SimpleSAMLphp browser-assisted chain', profile=args.profile,
        targetKind='IDP', targetEntityId='http://localhost:18380/idp', metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300, testUserHint=USER, requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    ssp.save(out / 'plan.json', plan_result)
    plan = plan_result['plan']['plan']['id']
    created = api('/api/plans/' + plan + '/runs', {}); ssp.save(out / 'created.json', created)
    run = created['run']['id']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', run):
        raise ValueError('Invalid Run identifier')
    ssp.save(out / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))
    entity = ssp.BASE + '/p/' + plan
    configuration = ssp_config.ConfigurationBatch(CONFIG)
    if b'?>' in configuration.original:
        raise ValueError('Unexpected PHP closing tag')
    with urllib.request.urlopen(ssp.BASE + '/p/' + plan + '/metadata', timeout=30) as response:
        fixture = response.read()
    (out / 'fixture.xml').write_bytes(fixture)
    parsed = subprocess.run(['docker', 'exec', '-i', 'samlscope-reference-ssp', 'php', '-r', ssp.PHP, entity, 'default'],
                            input=fixture, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
    (out / 'parser.stderr').write_bytes(parsed.stderr)
    if parsed.returncode:
        raise RuntimeError('Product native parser rejected the Suite SP metadata')
    data = json.loads(parsed.stdout)
    if data['entity_id'] != entity or data['validate_authnrequest'] is not True:
        raise RuntimeError('Native parser did not confirm the expected entity and signature policy')
    operations = []
    steps = []
    changed = False
    try:
        changed = True
        digest = configuration.apply(data['php'].encode())
        operations.append(dict(operation='write', label='suite-sp-metadata', sha256=digest, read_back=True))
        ssp.save(out / 'operations.json', operations)
        import time
        time.sleep(3)
        login = Client().flow(ssp.BASE + '/p/' + plan + '/start/m0-roundtrip?run=' + run, None, USER, PASSWORD)
        ssp.save(out / 'initial-login.json', dict(receipt=login))
        if login != 'recorded':
            raise RuntimeError('Initial login did not complete: ' + str(login))
        ssp.save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
        repeated = 0; previous = None
        for _ in range(args.max_probes):
            status = api('/api/runs/' + run + '/active-probe')
            if status['state'] == 'AWAITING_RESPONSE':
                api('/api/runs/' + run + '/active-probe/abort', {})
                steps.append(dict(caseId=status.get('caseId'), actionId=status.get('actionId'), action='abort'))
                ssp.save(out / 'steps.json', steps); continue
            if status['state'] != 'READY':
                steps.append(dict(caseId=status.get('caseId'), state=status['state'], action='stop')); break
            result = Client().flow(status['startUrl'], None, USER, PASSWORD)
            after = api('/api/runs/' + run + '/active-probe')
            steps.append(dict(caseId=status.get('caseId'), actionId=status.get('actionId'), result=result,
                              nextState=after['state'], nextActionId=after.get('actionId')))
            ssp.save(out / 'steps.json', steps)
            if after.get('actionId') == status.get('actionId') and after['state'] == 'AWAITING_RESPONSE':
                api('/api/runs/' + run + '/active-probe/abort', {})
            if after.get('actionId') == previous: repeated += 1
            else: repeated = 0
            previous = after.get('actionId')
            if repeated >= 3: break
        ssp.save(out / 'evaluation.json', api('/api/runs/' + run + '/protocol-evidence/evaluate', {}))
    finally:
        entries = api('/api/runs/' + run + '/transcript')
        ssp.save(out / 'transcript.json', entries)
        for name in ['result.json', 'report.html', 'protocol-evidence']:
            try:
                with urllib.request.urlopen(ssp.BASE + '/api/runs/' + run + '/' + name, timeout=30) as response:
                    (out / name).write_bytes(response.read())
            except Exception as error:
                ssp.save(out / (name.replace('.', '-') + '-unavailable.json'), dict(reason=str(error)))
        if not (out / 'decoded-manifest.json').exists():
            capture(out, run, entries)
        failures = []
        if changed:
            try:
                restoration = configuration.restore()
                if not restoration['restored']:
                    failures.append('configuration-not-restored')
            except Exception as error:
                failures.append(type(error).__name__)
        restored = not failures and configuration.path.read_bytes() == configuration.original
        ssp.save(out / 'restoration.json', dict(restored=restored, failures=failures,
            original_sha256=SHA(configuration.original), final_sha256=SHA(configuration.path.read_bytes()),
            configuration_write_attempts=configuration.write_count, restoration_write_attempts=configuration.restoration_writes))
        ssp.save(out / 'operation-counts.json', dict(restored=restored, human_operations=0,
            probes=len([s for s in steps if 'result' in s]), verdict_adopted=False))
        if failures:
            raise RuntimeError('Native restoration incomplete: ' + ','.join(failures))
    print('SimpleSAMLphp browser chain collected', len(steps), 'probe steps;', run)


if __name__ == '__main__':
    main()
