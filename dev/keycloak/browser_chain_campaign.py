#!/usr/bin/env python3
"""Drive the Suite browser-assisted active-probe chain against Keycloak's own console import.

The Suite SP metadata is imported through the product console (console_import.mjs) and held for the
chain, then removed through the admin API with read-back. No verdict is assigned here.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse as urls
import urllib.error
import urllib.request as http
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
from import_metadata_batch import api, save, BASE  # noqa: E402
from reference_flow import Client  # noqa: E402
from capture_run_originals import capture  # noqa: E402
from capture_browser_originals import capture as capture_browser_originals  # noqa: E402
from capture_terminal_http_runtime import capture as capture_target_runtime  # noqa: E402
from browser_probe_selection import selected_cases, prepare_and_skip  # noqa: E402
from schema_admission_campaign import reject_sensitive  # noqa: E402

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ADMIN = 'http://localhost:18180/admin/realms/samlscope'
TOKEN_URL = 'http://localhost:18180/realms/master/protocol/openid-connect/token'
CONTAINER = 'samlscope-reference-keycloak'
USER = os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user')
PASSWORD = os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password')
TERMINAL_HTTP_CASES = {
    'IIP-SSO01-d-idp-01',
    'IIP-SSO01-ak-idp-01',
    'IIP-SSO01-em-idp-01',
    'IIP-IDP12-b-idp-01',
}


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


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def public_client_readback(value):
    """Remove only native generated credentials before any evidence is written."""
    public = copy.deepcopy(value)
    redactions = []
    for field in ('secret', 'registrationAccessToken'):
        if field in public:
            del public[field]
            redactions.append('$.' + field)
    reject_sensitive(public)
    def reject_headers(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if key.lower() in {'cookie', 'set-cookie', 'authorization', 'proxy-authorization'}:
                    raise ValueError('Sensitive native header field; no persistence')
                reject_headers(child)
        elif isinstance(item, list):
            for child in item:
                reject_headers(child)
    reject_headers(public)
    return public, dict(response_projection='native-client-public-readback-v1',
                        redactions=redactions, response_sha256=SHA(canonical(public)))


class SessionDriver:
    """Count actual credential submissions without retaining their values or cookies."""
    def __init__(self, reuse_session=False, factory=Client):
        self.reuse_session = reuse_session
        self.factory = factory
        self.login_submissions = 0
        self.fresh_session_boundaries = 0
        self.fresh_session_requirements = 0
        self.reused_submissions = 0
        self.initial_client = self.new_client()

    def new_client(self):
        client = self.factory()
        request = client.request

        def counted(url, fields=None):
            if fields is not None and ('password' in fields or 'j_password' in fields):
                self.login_submissions += 1
            return request(url, fields)

        client.request = counted
        return client

    def probe_client(self, status):
        if status.get('requiresFreshSession') is True:
            self.fresh_session_requirements += 1
        reused = self.reuse_session and status.get('requiresFreshSession') is False
        if reused:
            self.reused_submissions += 1
            return self.initial_client, True
        # Missing or malformed boundaries never authorize cookie reuse.
        self.fresh_session_boundaries += 1
        return self.new_client(), False


def admin(token, path, body=None, method='GET'):
    encoded = None if body is None else canonical(body)
    request = http.Request(ADMIN + path, data=encoded, method=method,
                           headers={'Authorization': 'Bearer ' + token,
                                    'Content-Type': 'application/json'})
    with http.urlopen(request, timeout=30) as response:
        raw = response.read()
        return None if not raw else json.loads(raw)


def client_detail(token, client_id):
    summary = find_client(token, client_id)
    if summary is None:
        return None
    detail = admin(token, '/clients/' + summary['id'])
    if detail.get('clientId') != client_id or detail.get('id') != summary.get('id'):
        raise RuntimeError('Keycloak client read-back identity mismatch')
    return detail


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--playwright-modules', type=Path, required=True)
    parser.add_argument('--max-probes', type=int, default=400)
    parser.add_argument('--stop-after-case', help='Finish after all probes for this case, then evaluate and restore')
    parser.add_argument('--profile', default='browser_sso_idp')
    parser.add_argument('--only-cases', help='Comma-separated cases to send; prepare/abort other probes at the Suite')
    parser.add_argument('--reuse-session', action='store_true',
                        help='Reuse the initial client only for explicit requiresFreshSession=false')
    args = parser.parse_args()
    try:
        selected = selected_cases(args.only_cases)
    except ValueError as error:
        parser.error(str(error))
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True, exist_ok=True)
    plan_result = api('/api/plans', dict(name='Keycloak browser-assisted chain', profile=args.profile,
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
    secondary_acs = entity + '/sp/acs/1'
    hostile_acs = entity + '/samlscope-other-sp/acs'
    other_entity = entity + '/other-entity'
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
    setup_write_attempts = 0
    setup_writes = 0
    initial_baseline_submissions = 0
    sessions = SessionDriver(args.reuse_session)
    public_readbacks = {}

    def write_client_readback(name, value):
        public, projection = public_client_readback(value)
        (out / name).write_bytes(canonical(public))
        public_readbacks[name] = projection
        save(out / 'public-readback-projections.json', public_readbacks)
        return public
    token = admin_token()
    if client_detail(token, entity) is not None or client_detail(token, other_entity) is not None:
        raise ValueError('Refusing an existing imported client')
    initially_absent = True
    main_original = None
    main_identifier = None
    other_identifier = None
    capture_target_runtime(out, 'keycloak', 'start')
    try:
        setup_write_attempts += 1
        import_result = subprocess.run(['node', str(stage / 'console_import.mjs'),
            '--fixture', str(out / 'suite-sp-metadata.xml'), '--record', str(import_record),
            '--entity-id', entity], capture_output=True, text=True, timeout=300)
        (out / 'console-import.log').write_text(import_result.stdout + import_result.stderr)
        if import_result.returncode:
            raise RuntimeError('Console import failed: ' + import_result.stdout[-500:])
        setup_writes += 1
        token = admin_token()
        main_original = client_detail(token, entity)
        if main_original is None:
            raise RuntimeError('Console import did not create the Suite SP client')
        main_identifier = main_original['id']
        main_original_public = write_client_readback('main-client-original.json', main_original)
        configured = copy.deepcopy(main_original)
        redirects = configured.get('redirectUris')
        if not isinstance(redirects, list) or entity + '/sp/acs/0' not in redirects:
            raise RuntimeError('Native import did not register the primary ACS')
        configured['redirectUris'] = sorted(set(redirects) | {secondary_acs})
        configured['attributes'] = copy.deepcopy(configured.get('attributes') or {})
        configured['attributes']['saml.client.signature'] = 'false'
        setup_write_attempts += 1
        admin(token, '/clients/' + main_identifier, configured, 'PUT')
        setup_writes += 1
        main_readback = client_detail(token, entity)
        if main_readback is None or set(main_readback.get('redirectUris', [])) != set(configured['redirectUris']):
            raise RuntimeError('Keycloak did not read back both requester ACS locations')
        if main_readback.get('attributes') != configured.get('attributes'):
            raise RuntimeError('Requester signed/unsigned setting read-back mismatch')
        main_public = write_client_readback('main-client-configured-readback.json', main_readback)

        other_config = {
            'clientId': other_entity,
            'name': 'SAMLscope temporary other SP',
            'enabled': True,
            'protocol': 'saml',
            'redirectUris': [hostile_acs],
            'attributes': {
                'saml.force.post.binding': 'true',
                'saml.server.signature': 'true',
                'saml.client.signature': 'false',
            },
        }
        setup_write_attempts += 1
        admin(token, '/clients', other_config, 'POST')
        setup_writes += 1
        other_readback = client_detail(token, other_entity)
        if other_readback is None or other_readback.get('redirectUris') != [hostile_acs]:
            raise RuntimeError('Keycloak did not read back the other-entity hostile ACS')
        other_identifier = other_readback['id']
        other_public = write_client_readback('other-client-configured-readback.json', other_readback)
        save(out / 'native-configuration.json', dict(
            requester_entity=entity, requester_client_id=main_identifier,
            requester_original_sha256=SHA(canonical(main_original_public)),
            requester_configured_sha256=SHA(canonical(main_public)),
            registered_acs=[entity + '/sp/acs/0', secondary_acs],
            accepts_signed_and_unsigned_requests=True,
            other_entity=other_entity, other_client_id=other_identifier,
            other_entity_readback_sha256=SHA(canonical(other_public)),
            hostile_acs=hostile_acs))
        initial_before = sessions.login_submissions
        initial_baseline_submissions += 1
        login = sessions.initial_client.flow(BASE + '/p/' + plan + '/start/m0-roundtrip?run=' + run, None, USER, PASSWORD)
        save(out / 'initial-login.json', dict(receipt=login,
            credential_posts=sessions.login_submissions-initial_before, values_persisted=False))
        if login != 'recorded':
            raise RuntimeError('Initial login did not complete: ' + str(login))
        save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
        repeated = 0; previous = None
        target_seen = False
        for _ in range(args.max_probes):
            status = api('/api/runs/' + run + '/active-probe')
            if target_seen and status.get('caseId') != args.stop_after_case:
                steps.append(dict(caseId=args.stop_after_case, state=status['state'], action='target-complete'))
                break
            if args.stop_after_case and status.get('caseId') == args.stop_after_case:
                target_seen = True
            if status['state'] == 'AWAITING_RESPONSE':
                api('/api/runs/' + run + '/active-probe/abort', {})
                steps.append(dict(caseId=status.get('caseId'), actionId=status.get('actionId'), action='abort'))
                save(out / 'steps.json', steps); continue
            if status['state'] != 'READY':
                steps.append(dict(caseId=status.get('caseId'), state=status['state'], action='stop')); break
            if selected is not None and status.get('caseId') not in selected:
                steps.append(prepare_and_skip(BASE, run, status, api))
                save(out / 'steps.json', steps)
                continue
            terminal = None
            if status.get('caseId') in TERMINAL_HTTP_CASES:
                def terminal(url, page, code, reason, action=status['actionId']):
                    api('/api/runs/' + run + '/active-probe/browser-response', dict(
                        actionId=action, status=code, url=url, body=page))
            client, reused = sessions.probe_client(status)
            credentials_before = sessions.login_submissions
            result = client.flow(status['startUrl'], None, USER, PASSWORD,
                                 terminal_observer=terminal)
            after = api('/api/runs/' + run + '/active-probe')
            steps.append(dict(caseId=status.get('caseId'), actionId=status.get('actionId'), result=result,
                              prepared=True, sentToTarget=True,
                              reused_authenticated_client=reused,
                              fresh_session_required=status.get('requiresFreshSession'),
                              credential_posts=sessions.login_submissions-credentials_before,
                              credential_values_persisted=False,
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
        try:
            entries = api('/api/runs/' + run + '/transcript')
            save(out / 'transcript.json', entries)
            capture_browser_originals(out, entries)
            for name in ['result.json', 'report.html', 'protocol-evidence']:
                try:
                    with http.urlopen(BASE + '/api/runs/' + run + '/' + name, timeout=30) as response:
                        (out / name).write_bytes(response.read())
                except Exception as error:
                    save(out / (name.replace('.', '-') + '-unavailable.json'), dict(reason=type(error).__name__))
            if not (out / 'decoded-manifest.json').exists():
                capture(out, run, entries)
        except Exception as error:
            save(out / 'evidence-capture-unavailable.json', dict(reason=type(error).__name__))

        # Evidence export is best-effort. Cleanup is mandatory even if a Suite artifact is
        # unavailable or docker cp times out while fetching decoded transcript originals.
        cleanup = dict(attempted=True, requester_restore_attempted=False,
                       requester_delete_attempted=False, other_delete_attempted=False)
        try:
            token = admin_token()
            main_current = client_detail(token, entity)
            if main_current is not None and main_original is not None:
                if main_current['id'] != main_identifier:
                    raise RuntimeError('Concurrent requester client replacement detected')
                cleanup['requester_restore_attempted'] = True
                admin(token, '/clients/' + main_identifier, main_original, 'PUT')
                main_restored = client_detail(token, entity)
                cleanup['requester_restore_read_back'] = (
                    main_restored is not None
                    and main_restored.get('redirectUris') == main_original.get('redirectUris')
                    and main_restored.get('attributes') == main_original.get('attributes'))
                if not cleanup['requester_restore_read_back']:
                    raise RuntimeError('Requester client restore read-back mismatch')
                write_client_readback('main-client-restored-readback.json', main_restored)
                cleanup['requester_delete_attempted'] = True
                admin(token, '/clients/' + main_identifier, method='DELETE')
            other_current = client_detail(token, other_entity)
            if other_current is not None:
                if other_identifier is not None and other_current['id'] != other_identifier:
                    raise RuntimeError('Concurrent other-entity client replacement detected')
                cleanup['other_delete_attempted'] = True
                admin(token, '/clients/' + other_current['id'], method='DELETE')
            cleanup['requester_read_back_absent'] = client_detail(token, entity) is None
            cleanup['other_read_back_absent'] = client_detail(token, other_entity) is None
            final_absence = {
                'requester_query': admin(token, '/clients?clientId=' + urls.quote(entity, safe='')),
                'other_entity_query': admin(token, '/clients?clientId=' + urls.quote(other_entity, safe='')),
            }
            (out / 'final-client-absence-readback.json').write_bytes(canonical(final_absence))
            if final_absence != {'requester_query': [], 'other_entity_query': []}:
                raise RuntimeError('Final client absence read-back is not empty')
            cleanup['read_back_absent'] = (cleanup['requester_read_back_absent']
                                           and cleanup['other_read_back_absent'])
            cleanup['initially_absent'] = initially_absent
        except Exception as error:
            cleanup['error'] = type(error).__name__
        operations.append(dict(operation='restore-and-delete-temporary-clients', **cleanup))
        save(out / 'operations.json', operations)
        import_ok = import_record.exists() and json.loads(import_record.read_text()).get('status') == 'success'
        restored = initially_absent and cleanup.get('read_back_absent') is True
        save(out / 'restoration.json', dict(restored=restored, import_ok=import_ok, cleanup=cleanup))
        save(out / 'operation-counts.json', dict(
            restored=restored, human_operations=0,
            probes=len([step for step in steps if 'result' in step]), verdict_adopted=False,
            prepared_actions=sum(step.get('prepared') is True for step in steps),
            skipped_before_target_submission=sum(step.get('sentToTarget') is False for step in steps),
            target_submissions=sum(step.get('sentToTarget') is True for step in steps),
            initial_baseline_submissions=initial_baseline_submissions,
            temporary_configuration_apply_writes=setup_writes,
            temporary_configuration_apply_write_attempts=setup_write_attempts,
            restoration_writes=sum(1 for name in (
                'requester_restore_attempted', 'requester_delete_attempted', 'other_delete_attempted')
                if cleanup.get(name) is True),
            product_restarts=0))
        counts = json.loads((out / 'operation-counts.json').read_text())
        counts.update(login_submissions=sessions.login_submissions,
                      automated_credential_posts=sessions.login_submissions,
                      test_user_operations=0, administrator_setup_writes=setup_writes,
                      fresh_session_boundaries=sessions.fresh_session_boundaries,
                      fresh_clients_created=sessions.fresh_session_boundaries,
                      initial_baseline_clients_created=1,
                      fresh_session_requirements=sessions.fresh_session_requirements,
                      authenticated_session_reuse_enabled=args.reuse_session,
                      reused_authenticated_client_submissions=sessions.reused_submissions)
        save(out / 'operation-counts.json', counts)
        capture_target_runtime(out, 'keycloak', 'end')
        if not restored:
            raise RuntimeError('Imported client cleanup incomplete; inspect operations')
    print('Keycloak browser chain collected', len(steps), 'probe steps;', run)


if __name__ == '__main__':
    main()
