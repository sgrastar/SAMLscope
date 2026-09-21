#!/usr/bin/env python3
"""Drive the Suite browser-assisted active-probe chain against Keycloak's own console import.

The Suite SP metadata is imported through the product console (console_import.mjs) and held for the
chain, then removed through the admin API with read-back. No verdict is assigned here.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse as urls
import urllib.request as http
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
from import_metadata_batch import api, save, BASE  # noqa: E402
from reference_flow import Client  # noqa: E402
from capture_run_originals import capture  # noqa: E402

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ADMIN = 'http://localhost:18180/admin/realms/samlscope'
TOKEN_URL = 'http://localhost:18180/realms/master/protocol/openid-connect/token'
CONTAINER = 'samlscope-reference-keycloak'
USER = os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user')
PASSWORD = os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password')


def admin_token():
    body = urls.urlencode(dict(client_id='admin-cli', username='admin', password='admin',
                               grant_type='password')).encode()
    with http.urlopen(http.Request(TOKEN_URL, data=body), timeout=30) as response:
        return json.load(response)['access_token']


def find_client(token, client_id):
    request = http.Request(ADMIN + '/clients?clientId=' + urls.quote(client_id),
                           headers={'Authorization': 'Bearer ' + token})
    with http.urlopen(request, timeout=30) as response:
        clients = json.load(response)
    return clients[0] if clients else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--playwright-modules', type=Path, required=True)
    parser.add_argument('--max-probes', type=int, default=400)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True, exist_ok=True)
    plan_result = api('/api/plans', dict(name='Keycloak browser-assisted chain', profile='browser_sso_idp',
        targetKind='IDP', targetEntityId='http://localhost:18180/realms/samlscope',
        metadataSourceKind='URL', metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',
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
    entity = BASE + '/p/' + plan
    with http.urlopen(BASE + '/p/' + plan + '/metadata', timeout=30) as response:
        fixture = response.read()
    (out / 'suite-sp-metadata.xml').write_bytes(fixture)
    stage = out / 'driver'; stage.mkdir(exist_ok=True)
    shutil.copyfile(REPO / 'dev/keycloak/console_import.mjs', stage / 'console_import.mjs')
    if not (stage / 'node_modules').exists():
        (stage / 'node_modules').symlink_to(args.playwright_modules.resolve(), target_is_directory=True)
    import_record = out / 'import.json'
    operations = []
    steps = []
    token = admin_token()
    if find_client(token, entity) is not None:
        raise ValueError('Refusing an existing imported client')
    try:
        import_result = subprocess.run(['node', str(stage / 'console_import.mjs'),
            '--fixture', str(out / 'suite-sp-metadata.xml'), '--record', str(import_record),
            '--entity-id', entity], capture_output=True, text=True, timeout=300)
        (out / 'console-import.log').write_text(import_result.stdout + import_result.stderr)
        if import_result.returncode:
            raise RuntimeError('Console import failed: ' + import_result.stdout[-500:])
        login = Client().flow(BASE + '/p/' + plan + '/start/m0-roundtrip?run=' + run, None, USER, PASSWORD)
        save(out / 'initial-login.json', dict(receipt=login))
        if login != 'recorded':
            raise RuntimeError('Initial login did not complete: ' + str(login))
        save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
        repeated = 0; previous = None
        for _ in range(args.max_probes):
            status = api('/api/runs/' + run + '/active-probe')
            if status['state'] == 'AWAITING_RESPONSE':
                api('/api/runs/' + run + '/active-probe/abort', {})
                steps.append(dict(caseId=status.get('caseId'), actionId=status.get('actionId'), action='abort'))
                save(out / 'steps.json', steps); continue
            if status['state'] != 'READY':
                steps.append(dict(caseId=status.get('caseId'), state=status['state'], action='stop')); break
            result = Client().flow(status['startUrl'], None, USER, PASSWORD)
            after = api('/api/runs/' + run + '/active-probe')
            steps.append(dict(caseId=status.get('caseId'), actionId=status.get('actionId'), result=result,
                              nextState=after['state'], nextActionId=after.get('actionId')))
            save(out / 'steps.json', steps)
            if after.get('actionId') == status.get('actionId') and after['state'] == 'AWAITING_RESPONSE':
                api('/api/runs/' + run + '/active-probe/abort', {})
            if after.get('actionId') == previous: repeated += 1
            else: repeated = 0
            previous = after.get('actionId')
            if repeated >= 3: break
        save(out / 'evaluation.json', api('/api/runs/' + run + '/protocol-evidence/evaluate', {}))
    finally:
        entries = api('/api/runs/' + run + '/transcript')
        save(out / 'transcript.json', entries)
        for name in ['result.json', 'report.html', 'protocol-evidence']:
            try:
                with http.urlopen(BASE + '/api/runs/' + run + '/' + name, timeout=30) as response:
                    (out / name).write_bytes(response.read())
            except Exception as error:
                save(out / (name.replace('.', '-') + '-unavailable.json'), dict(reason=str(error)))
        if not (out / 'decoded-manifest.json').exists():
            capture(out, run, entries)
        cleanup = dict(attempted=True)
        try:
            token = admin_token(); client = find_client(token, entity)
            if client is None:
                cleanup.update(already_absent=False)
            else:
                request = http.Request(ADMIN + '/clients/' + client['id'], method='DELETE',
                                       headers={'Authorization': 'Bearer ' + token})
                with http.urlopen(request, timeout=30) as response:
                    cleanup['delete_status'] = response.status
                cleanup['read_back_absent'] = find_client(token, entity) is None
            operations.append(dict(operation='delete-imported-client', **cleanup))
        except Exception as error:
            cleanup['error'] = str(error); operations.append(dict(operation='delete-imported-client', **cleanup))
        save(out / 'operations.json', operations)
        import_ok = import_record.exists() and json.loads(import_record.read_text()).get('status') == 'success'
        restored = import_ok and cleanup.get('read_back_absent') is True
        save(out / 'restoration.json', dict(restored=restored, import_ok=import_ok, cleanup=cleanup))
        if not restored:
            raise RuntimeError('Imported client cleanup incomplete; inspect operations')
    print('Keycloak browser chain collected', len(steps), 'probe steps;', run)


if __name__ == '__main__':
    main()
