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
import urllib.parse
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
from capture_browser_originals import capture as capture_browser_originals
from public_runtime_capture import capture_target as capture_target_runtime
from browser_probe_selection import selected_cases, prepare_and_skip

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CONFIG = REPO / 'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php'
CONTAINER = 'samlscope-reference-ssp'
SSP = 'http://localhost:18380'
USER = os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user')
PASSWORD = os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password')
CONTAINER_CONFIG = '/var/simplesamlphp/metadata/saml20-sp-remote.php'
TERMINAL_HTTP_CASES = {
    'IIP-SSO01-d-idp-01',
    'IIP-SSO01-ak-idp-01',
    'IIP-SSO01-em-idp-01',
    'IIP-IDP12-b-idp-01',
}


def reload_metadata_cache(out, operations, entity, expect_resolved=True):
    """Make a newly written saml20-sp-remote.php visible to the running web workers.

    A file change alone is not enough: Apache workers hold the parsed metadata and APCu caches
    it, so a graceful reload plus an APCu clear through the web path is required. The CLI probe
    has its own APCu segment and cannot substitute for the HTTP path.
    """
    import time
    result = subprocess.run(['docker', 'exec', CONTAINER, 'apache2ctl', 'graceful'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    operations.append(dict(step='apache-graceful-reload', returncode=result.returncode))
    if result.returncode:
        raise RuntimeError('SimpleSAMLphp graceful reload failed')
    probe_name = 'samlscope-apcu-clear.php'
    probe_path = '/var/simplesamlphp/public/' + probe_name
    probe = ("<?php require '/var/simplesamlphp/lib/_autoload.php';"
             "if (function_exists('apcu_clear_cache')) apcu_clear_cache(); echo 'CLEARED';")
    subprocess.run(['docker', 'exec', '-i', CONTAINER, 'sh', '-c', 'cat > ' + probe_path],
                   input=probe.encode(), check=True, timeout=30)
    try:
        with urllib.request.urlopen(SSP + '/simplesaml/' + probe_name, timeout=30) as response:
            cleared = response.read().decode()[:40]
            operations.append(dict(step='apcu-clear', output=cleared))
            if cleared != 'CLEARED':
                raise RuntimeError('SimpleSAMLphp APCu clear did not complete')
    finally:
        subprocess.run(['docker', 'exec', CONTAINER, 'rm', '-f', probe_path], timeout=30)
    time.sleep(2)
    probe_name = 'samlscope-resolve-probe.php'
    probe_path = '/var/simplesamlphp/public/' + probe_name
    probe_src = ("<?php require '/var/simplesamlphp/lib/_autoload.php';"
                 "try { \\SimpleSAML\\Metadata\\MetaDataStorageHandler::getMetadataHandler()"
                 "->getMetaData('" + entity + "','saml20-sp-remote'); echo 'RESOLVED'; }"
                 "catch (\\Throwable $e) { echo 'UNRESOLVED '.get_class($e); }")
    subprocess.run(['docker', 'exec', '-i', CONTAINER, 'sh', '-c', 'cat > ' + probe_path],
                   input=probe_src.encode(), check=True, timeout=30)
    try:
        resolved = ''
        for _ in range(30):
            with urllib.request.urlopen(SSP + '/simplesaml/' + probe_name, timeout=30) as response:
                resolved = response.read().decode('utf-8', 'replace')[:200]
            observed = resolved.startswith('RESOLVED')
            if observed == expect_resolved:
                break
            time.sleep(1)
    finally:
        subprocess.run(['docker', 'exec', CONTAINER, 'rm', '-f', probe_path], timeout=30)
    operations.append(dict(step='resolve-probe', output=resolved))
    return resolved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-probes', type=int, default=400)
    parser.add_argument('--stop-after-case', help='Finish after all probes for this case, then evaluate and restore')
    parser.add_argument('--reuse-session', action='store_true',
                        help='Reuse the authenticated browser only when the Suite explicitly permits the same session')
    parser.add_argument('--profile', default='browser_sso_idp')
    parser.add_argument('--only-cases', help='Comma-separated cases to send; prepare/abort other probes at the Suite')
    parser.add_argument('--no-idp-initiated-sso', action='store_true',
                        help='Skip the IdP-initiated (unsolicited) SSO step that IIP-SSO01.g/z require')
    args = parser.parse_args()
    try:
        selected = selected_cases(args.only_cases)
    except ValueError as error:
        parser.error(str(error))
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
    configuration.container = CONTAINER
    configuration.container_path = CONTAINER_CONFIG
    if b'?>' in configuration.original:
        raise ValueError('Unexpected PHP closing tag')
    product_original = subprocess.check_output(
        ['docker', 'exec', CONTAINER, 'cat', CONTAINER_CONFIG], timeout=30)
    if product_original != configuration.original:
        raise RuntimeError('Host and product metadata configuration differ before the campaign')
    (out / 'original-sp-config.php').write_bytes(product_original)
    with urllib.request.urlopen(ssp.BASE + '/p/' + plan + '/metadata', timeout=30) as response:
        fixture = response.read()
    (out / 'suite-sp-metadata.xml').write_bytes(fixture)
    (out / 'fixture.xml').write_bytes(fixture)
    parsed = subprocess.run(['docker', 'exec', '-i', 'samlscope-reference-ssp', 'php', '-r', ssp.PHP, entity, 'default'],
                            input=fixture, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
    (out / 'parser.stdout').write_bytes(parsed.stdout)
    (out / 'parser.stderr').write_bytes(parsed.stderr)
    if parsed.returncode:
        raise RuntimeError('Product native parser rejected the Suite SP metadata')
    data = json.loads(parsed.stdout)
    if data['entity_id'] != entity or data['validate_authnrequest'] is not True:
        raise RuntimeError('Native parser did not confirm the expected entity and signature policy')
    operations = []
    steps = []
    login_submissions = 0
    fresh_session_boundaries = 0
    fresh_session_requirements = 0
    fresh_clients_created = 0
    def count_logins(browser):
        original_request = browser.request
        def request(url, fields=None):
            nonlocal login_submissions
            if fields is not None and any(name in fields for name in ('password', 'j_password')):
                login_submissions += 1
            return original_request(url, fields)
        browser.request = request
        return browser
    changed = False
    capture_target_runtime(out, 'simplesamlphp', 'start')
    try:
        changed = True
        digest = configuration.apply(data['php'].encode())
        operations.append(dict(operation='write', label='suite-sp-metadata', sha256=digest, read_back=True))
        configured = subprocess.check_output(
            ['docker', 'exec', CONTAINER, 'cat', CONTAINER_CONFIG], timeout=30)
        if configured != configuration.expected or SHA(configured) != digest:
            raise RuntimeError('Product native configuration read-back mismatch')
        (out / 'configured-sp-config.php').write_bytes(configured)
        ssp.save(out / 'native-configuration.json', dict(
            requester_entity=entity, fixture_sha256=SHA(fixture),
            parser_output_sha256=SHA(parsed.stdout), configured_sha256=SHA(configured),
            validate_authnrequest=data['validate_authnrequest']))
        resolution = reload_metadata_cache(out, operations, entity)
        if not resolution.startswith('RESOLVED'):
            raise RuntimeError('SimpleSAMLphp did not resolve the temporary Suite SP')
        ssp.save(out / 'operations.json', operations)
        import time
        time.sleep(3)
        client = count_logins(Client())
        login = client.flow(ssp.BASE + '/p/' + plan + '/start/m0-roundtrip?run=' + run, None, USER, PASSWORD)
        ssp.save(out / 'initial-login.json', dict(receipt=login))
        if login != 'recorded':
            raise RuntimeError('Initial login did not complete: ' + str(login))
        if not args.no_idp_initiated_sso and args.profile == 'browser_sso_idp':
            # IIP-SSO01.g requires both an SP-initiated and an IdP-initiated success path in one
            # run; IIP-SSO01.z records the unsolicited success. SimpleSAMLphp supports IdP-initiated
            # SSO through its SSOService with spentityid, and the Suite records the assertion only
            # against a prepared single-use intent.
            api('/api/runs/' + run + '/target-initiated', dict(kind='UNSOLICITED_SSO'))
            url = (SSP + '/simplesaml/module.php/saml/idp/singleSignOnService?spentityid='
                   + urllib.parse.quote(entity, safe=''))
            receipt = client.flow(url, None, USER, PASSWORD)
            steps.append(dict(caseId='idp-initiated-sso', result=receipt))
            ssp.save(out / 'steps.json', steps)
        ssp.save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
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
                ssp.save(out / 'steps.json', steps); continue
            if status['state'] != 'READY':
                steps.append(dict(caseId=status.get('caseId'), state=status['state'], action='stop')); break
            if selected is not None and status.get('caseId') not in selected:
                steps.append(prepare_and_skip(ssp.BASE, run, status, api))
                ssp.save(out / 'steps.json', steps)
                continue
            terminal = None
            if status.get('caseId') in TERMINAL_HTTP_CASES:
                def terminal(url, page, code, reason, action=status['actionId']):
                    api('/api/runs/' + run + '/active-probe/browser-response', dict(
                        actionId=action, status=code, url=url, body=page))
            # Retain the same in-memory cookies only when the approved fixture explicitly
            # allows that session. Missing or malformed policy never permits reuse.
            fresh_session = status.get('requiresFreshSession')
            reused_session = args.reuse_session and fresh_session is False
            if reused_session:
                probe_client = client
            else:
                probe_client = count_logins(Client())
                fresh_clients_created += 1
                fresh_session_boundaries += 1
                if fresh_session is True:
                    fresh_session_requirements += 1
            result = probe_client.flow(status['startUrl'], None, USER, PASSWORD,
                                       terminal_observer=terminal)
            after = api('/api/runs/' + run + '/active-probe')
            steps.append(dict(caseId=status.get('caseId'), actionId=status.get('actionId'), result=result,
                              prepared=True, sentToTarget=True,
                              reused_authenticated_client=reused_session,
                              fresh_session_required=fresh_session,
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
        failures = []
        configured_sha256 = None
        if (out / 'configured-sp-config.php').exists():
            configured_sha256 = SHA((out / 'configured-sp-config.php').read_bytes())
        if changed:
            try:
                restoration = configuration.restore()
                if not restoration['restored']:
                    failures.append('configuration-not-restored')
            except Exception as error:
                failures.append(type(error).__name__)
        try:
            final_product = subprocess.check_output(
                ['docker', 'exec', CONTAINER, 'cat', CONTAINER_CONFIG], timeout=30)
            (out / 'final-sp-config.php').write_bytes(final_product)
            if final_product != configuration.original:
                failures.append('product-configuration-not-restored')
        except Exception as error:
            final_product = b''
            failures.append('product-final-read-back-' + type(error).__name__)
        if changed and not failures:
            try:
                restored_resolution = reload_metadata_cache(
                    out, operations, entity, expect_resolved=False)
                resolution_record = dict(
                    result=restored_resolution,
                    entity_absent=restored_resolution.startswith('UNRESOLVED'))
                ssp.save(out / 'restoration-resolution-readback.json', resolution_record)
                if not resolution_record['entity_absent']:
                    failures.append('temporary-entity-still-resolves')
            except Exception as error:
                failures.append('runtime-restoration-' + type(error).__name__)
        restored = (not failures and configuration.path.read_bytes() == configuration.original
                    and final_product == configuration.original)
        ssp.save(out / 'restoration.json', dict(restored=restored, failures=failures,
            original_sha256=SHA(configuration.original), configured_sha256=configured_sha256,
            final_sha256=SHA(final_product), configuration_write_attempts=configuration.write_count,
            restoration_write_attempts=configuration.restoration_writes))
        ssp.save(out / 'operations.json', operations)
        ssp.save(out / 'operation-counts.json', dict(restored=restored, human_operations=0,
            probes=len([s for s in steps if 'result' in s]), verdict_adopted=False,
            prepared_actions=sum(step.get('prepared') is True for step in steps),
            skipped_before_target_submission=sum(step.get('sentToTarget') is False for step in steps),
            target_submissions=sum(step.get('sentToTarget') is True for step in steps),
            initial_baseline_submissions=1,
            unsolicited_sso_submissions=sum(step.get('caseId') == 'idp-initiated-sso' for step in steps),
            configuration_write_attempts=configuration.write_count,
            restoration_write_attempts=configuration.restoration_writes,
            reloads=sum(1 for item in operations if item.get('step') == 'apache-graceful-reload'),
            product_restarts=0,
            login_submission_attempts=login_submissions,
            fresh_session_boundaries=fresh_session_boundaries,
            fresh_session_requirements=fresh_session_requirements,
            fresh_clients_created=fresh_clients_created,
            authenticated_session_reuse_enabled=args.reuse_session,
            reused_authenticated_client_submissions=sum(s.get('reused_authenticated_client') is True for s in steps)))
        capture_target_runtime(out, 'simplesamlphp', 'end')

        # Evidence export is best-effort and cannot postpone target restoration.
        try:
            entries = api('/api/runs/' + run + '/transcript')
            ssp.save(out / 'transcript.json', entries)
            capture_browser_originals(out, entries)
            for name in ['result.json', 'report.html', 'protocol-evidence']:
                try:
                    with urllib.request.urlopen(
                            ssp.BASE + '/api/runs/' + run + '/' + name, timeout=30) as response:
                        (out / name).write_bytes(response.read())
                except Exception as error:
                    ssp.save(out / (name.replace('.', '-') + '-unavailable.json'),
                             dict(reason=type(error).__name__))
            if not (out / 'decoded-manifest.json').exists():
                capture(out, run, entries)
        except Exception as error:
            ssp.save(out / 'evidence-capture-unavailable.json', dict(reason=type(error).__name__))
        if failures:
            raise RuntimeError('Native restoration incomplete: ' + ','.join(failures))
    print('SimpleSAMLphp browser chain collected', len(steps), 'probe steps;', run)


if __name__ == '__main__':
    main()
