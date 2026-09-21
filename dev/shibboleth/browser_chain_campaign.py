#!/usr/bin/env python3
"""Drive the Suite's browser-assisted active-probe chain with the reference driver and capture evidence.

The Suite sends one front-channel SAML request at a time. This driver follows the Suite's probe
pages, performs the ordinary login when the target asks, and records the correlated Response the
Suite stores. It never enters a verdict; aborted probes are reported as no-response.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
import importlib.util
_cap_spec = importlib.util.spec_from_file_location('shib_cap', REPO / 'dev/shibboleth/attribute_name_capability.py')
_cap = importlib.util.module_from_spec(_cap_spec)
_cap_spec.loader.exec_module(_cap)
docker, api, save, BASE, XSI, Client = _cap.docker, _cap.api, _cap.save, _cap.BASE, _cap.XSI, _cap.Client
from capture_run_originals import capture
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CONFIG = '/opt/reference-idp/conf/metadata-providers.xml'
USER = os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user')
PASSWORD = os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-probes', type=int, default=600)
    parser.add_argument('--profile', default='browser_sso_idp')
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True, exist_ok=True)
    plan_result = api('/api/plans', dict(name='Shibboleth browser-assisted chain', profile=args.profile,
        targetKind='IDP', targetEntityId='http://localhost:18280/idp/shibboleth', metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300, testUserHint=USER, requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    save(out / 'plan.json', plan_result)
    plan = plan_result['plan']['plan']['id']
    created = api('/api/plans/' + plan + '/runs', {}); save(out / 'created.json', created)
    run = created['run']['id']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', run):
        raise ValueError('Invalid Run identifier')
    save(out / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))
    original = docker('cat', CONFIG)
    temporary = '/opt/reference-idp/metadata/chain-' + run + '.xml'
    if docker('sh', '-c', 'test ! -e ' + temporary + ' && echo absent').strip() != b'absent':
        raise ValueError('Temporary metadata already exists')
    with urllib.request.urlopen(BASE + '/p/' + plan + '/metadata', timeout=30) as response:
        fixture = response.read()
    (out / 'fixture.xml').write_bytes(fixture)
    ns = 'urn:mace:shibboleth:2.0:metadata'
    ET.register_namespace('', ns); ET.register_namespace('xsi', XSI)
    root = ET.fromstring(original)
    root.insert(0, ET.Element('{' + ns + '}MetadataProvider', {'id': 'Chain' + run,
        '{' + XSI + '}type': 'FilesystemMetadataProvider', 'metadataFile': temporary}))
    configured = ET.tostring(root)
    operations = []
    def write(path, raw, label):
        record = dict(operation='write', label=label, sha256=SHA(raw), read_back=False)
        operations.append(record)
        docker('sh', '-c', 'cat > ' + path, data=raw)
        if docker('cat', path) != raw:
            raise RuntimeError('Native write read-back mismatch')
        record['read_back'] = True
        save(out / 'operations.json', operations)
    def reload(label):
        record = dict(operation='reload', label=label)
        operations.append(record)
        log = docker('/opt/reference-idp/bin/reload-service.sh', '-id', 'shibboleth.MetadataResolverService',
                     '-u', 'http://localhost:8080/idp')
        (out / (label + '-reload.log')).write_bytes(log)
        record['completed'] = True
        save(out / 'operations.json', operations)
    steps = []
    changed = False
    try:
        changed = True
        write(temporary, fixture, 'suite-metadata')
        write(CONFIG, configured, 'provider')
        reload('provider')
        login = Client().flow(BASE + '/p/' + plan + '/start/m0-roundtrip?run=' + run, None, USER, PASSWORD)
        save(out / 'initial-login.json', dict(receipt=login))
        if login != 'recorded':
            raise RuntimeError('Initial login did not complete: ' + str(login))
        save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
        repeated = 0
        previous = None
        for _ in range(args.max_probes):
            status = api('/api/runs/' + run + '/active-probe')
            if status['state'] == 'AWAITING_RESPONSE':
                api('/api/runs/' + run + '/active-probe/abort', {})
                steps.append(dict(caseId=status.get('caseId'), actionId=status.get('actionId'), action='abort'))
                save(out / 'steps.json', steps)
                continue
            if status['state'] != 'READY':
                steps.append(dict(caseId=status.get('caseId'), state=status['state'], action='stop'))
                break
            client = Client()
            result = client.flow(status['startUrl'], None, USER, PASSWORD)
            after = api('/api/runs/' + run + '/active-probe')
            steps.append(dict(caseId=status.get('caseId'), actionId=status.get('actionId'),
                              result=result, nextState=after['state'], nextActionId=after.get('actionId')))
            save(out / 'steps.json', steps)
            if after.get('actionId') == status.get('actionId') and after['state'] == 'AWAITING_RESPONSE':
                api('/api/runs/' + run + '/active-probe/abort', {})
            if after.get('actionId') == previous:
                repeated += 1
            else:
                repeated = 0
            previous = after.get('actionId')
            if repeated >= 3:
                break
        save(out / 'evaluation.json', api('/api/runs/' + run + '/protocol-evidence/evaluate', {}))
    finally:
        entries = api('/api/runs/' + run + '/transcript')
        save(out / 'transcript.json', entries)
        for name in ['result.json', 'report.html', 'protocol-evidence']:
            try:
                with urllib.request.urlopen(BASE + '/api/runs/' + run + '/' + name, timeout=30) as response:
                    (out / name).write_bytes(response.read())
            except Exception as error:
                save(out / (name.replace('.', '-') + '-unavailable.json'), dict(reason=str(error)))
        if not (out / 'decoded-manifest.json').exists():
            capture(out, run, entries)
        failures = []
        if changed:
            try:
                if docker('cat', CONFIG) != configured:
                    raise RuntimeError('Concurrent native configuration change')
                write(CONFIG, original, 'restore-provider')
                reload('restore-provider')
            except Exception as error:
                failures.append(type(error).__name__)
        try:
            docker('rm', '-f', temporary)
            removed = docker('sh', '-c', 'test ! -e ' + temporary + ' && echo absent').strip() == b'absent'
        except Exception:
            removed = False
        if not removed:
            failures.append('temporary-file-remains')
        restored = not failures and docker('cat', CONFIG) == original
        save(out / 'restoration.json', dict(restored=restored, failures=failures,
            original_sha256=SHA(original), final_sha256=SHA(docker('cat', CONFIG)),
            temporary_file_removed=removed))
        save(out / 'operations.json', operations)
        save(out / 'operation-counts.json', dict(restored=restored, human_operations=0,
            configuration_write_attempts=sum(1 for item in operations if item['operation'] == 'write'),
            reloads=sum(1 for item in operations if item['operation'] == 'reload'),
            probes=len([s for s in steps if 'result' in s]), verdict_adopted=False))
        if failures:
            raise RuntimeError('Native restoration incomplete: ' + ','.join(failures))
    print('Browser chain collected', len(steps), 'probe steps;', run)


if __name__ == '__main__':
    main()
