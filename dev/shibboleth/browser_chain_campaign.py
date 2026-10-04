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
import urllib.parse
import urllib.request
import urllib.error
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
from capture_browser_originals import capture as capture_browser_originals
from capture_terminal_http_runtime import capture as capture_target_runtime
from browser_probe_selection import selected_cases as parse_selected_cases, prepare_and_skip
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CONFIG = '/opt/reference-idp/conf/metadata-providers.xml'
USER = os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user')
PASSWORD = os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password')
TERMINAL_HTTP_CASES = {
    'IIP-SSO01-d-idp-01',
    'IIP-SSO01-ak-idp-01',
    'IIP-SSO01-em-idp-01',
    'IIP-IDP12-b-idp-01',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-probes', type=int, default=600)
    parser.add_argument('--stop-after-case', help='Finish after all probes for this case, then evaluate and restore')
    parser.add_argument('--profile', default='browser_sso_idp')
    parser.add_argument('--request-signing-mode', default='REQUIRED')
    parser.add_argument('--dynamic-mdq', action='store_true',
                        help='Resolve the new Suite SP through the product DynamicHTTPMetadataProvider')
    parser.add_argument('--existing-native-source', action='store_true',
                        help='Use an already configured generic Suite MDQ source without product writes')
    parser.add_argument('--only-cases',
                        help='Comma-separated cases to send; prepare/abort other fixtures before target submission')
    parser.add_argument('--capture-authentication-challenge', action='store_true',
                        help='Capture the initial native Password challenge before submitting credentials')
    parser.add_argument('--reuse-session', action='store_true',
                        help='Reuse the authenticated browser unless the current fixture requires a fresh session')
    args = parser.parse_args()
    if args.existing_native_source and args.dynamic_mdq:
        parser.error('Choose an existing source or install a dynamic source')
    try:
        selected_cases = parse_selected_cases(args.only_cases)
    except ValueError as error:
        parser.error(str(error))
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True, exist_ok=True)
    plan_result = api('/api/plans', dict(name='Shibboleth browser-assisted chain', profile=args.profile,
        targetKind='IDP', targetEntityId='http://localhost:18280/idp/shibboleth', metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300, testUserHint=USER, requestSigningMode=args.request_signing_mode),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    save(out / 'plan.json', plan_result)
    plan = plan_result['plan']['plan']['id']
    created = api('/api/plans/' + plan + '/runs', {}); save(out / 'created.json', created)
    run = created['run']['id']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', run):
        raise ValueError('Invalid Run identifier')
    save(out / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))
    original = docker('cat', CONFIG)
    if args.existing_native_source:
        native = ET.fromstring(original)
        templates = native.findall('.//{urn:mace:shibboleth:2.0:metadata}Template')
        if not any(value.text == 'http://samlscope-reference-suite:8080/mdq/${entityID}'
                   for value in templates):
            raise ValueError('Generic Suite MDQ source is not configured')
    (out / 'original-providers.xml').write_bytes(original)
    save(out / 'original-providers.json', dict(sha256=SHA(original), bytes=len(original)))
    temporary = '/opt/reference-idp/metadata/chain-' + run + '.xml'
    if docker('sh', '-c', 'test ! -e ' + temporary + ' && echo absent').strip() != b'absent':
        raise ValueError('Temporary metadata already exists')
    with urllib.request.urlopen(BASE + '/p/' + plan + '/metadata', timeout=30) as response:
        fixture = response.read()
    (out / 'suite-sp-metadata.xml').write_bytes(fixture)
    (out / 'fixture-main.xml').write_bytes(fixture)
    md = 'urn:oasis:names:tc:SAML:2.0:metadata'
    main_entity = ET.fromstring(fixture)
    requester_entity = BASE + '/p/' + plan
    if main_entity.tag != '{' + md + '}EntityDescriptor' or main_entity.get('entityID') != requester_entity:
        raise RuntimeError('Unexpected Suite requester metadata')
    requester_roles = main_entity.findall('{' + md + '}SPSSODescriptor')
    if len(requester_roles) != 1:
        raise RuntimeError('Suite requester metadata must contain one SPSSODescriptor')
    requester_roles[0].set('AuthnRequestsSigned', 'false')
    hostile_acs = requester_entity + '/samlscope-other-sp/acs'
    other_entity_id = requester_entity + '/other-entity'
    aggregate = ET.Element('{' + md + '}EntitiesDescriptor', {'Name': 'IDP12b-' + run})
    aggregate.append(main_entity)
    other = ET.SubElement(aggregate, '{' + md + '}EntityDescriptor', {'entityID': other_entity_id})
    other_sp = ET.SubElement(other, '{' + md + '}SPSSODescriptor', {
        'protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'AuthnRequestsSigned': 'false', 'WantAssertionsSigned': 'false'})
    ET.SubElement(other_sp, '{' + md + '}AssertionConsumerService', {
        'Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        'Location': hostile_acs, 'index': '0', 'isDefault': 'true'})
    fixture = ET.tostring(aggregate, xml_declaration=True, encoding='UTF-8')
    (out / 'fixture.xml').write_bytes(fixture)
    save(out / 'native-configuration.json', dict(
        requester_entity=requester_entity,
        requester_metadata_sha256=SHA(ET.tostring(main_entity)),
        registered_acs=[requester_entity + '/sp/acs/0', requester_entity + '/sp/acs/1'],
        accepts_signed_and_unsigned_requests=not args.existing_native_source,
        source_mode='existing-generic-mdq' if args.existing_native_source else 'temporary-provider',
        other_entity=None if args.existing_native_source else other_entity_id,
        hostile_acs=None if args.existing_native_source else hostile_acs,
        aggregate_sha256=SHA(fixture)))
    if args.dynamic_mdq:
        mdq_url = BASE + '/mdq/' + urllib.parse.quote(BASE + '/p/' + plan, safe='')
        with urllib.request.urlopen(mdq_url, timeout=30) as response:
            (out / 'mdq-response.xml').write_bytes(response.read())
        save(out / 'mdq-request.json', dict(url=mdq_url, entity_id=BASE + '/p/' + plan,
                                            response_sha256=SHA((out / 'mdq-response.xml').read_bytes())))
    ns = 'urn:mace:shibboleth:2.0:metadata'
    ET.register_namespace('', ns); ET.register_namespace('xsi', XSI)
    root = ET.fromstring(original)
    if args.dynamic_mdq:
        provider = ET.Element('{' + ns + '}MetadataProvider', {'id': 'Dynamic' + run,
            '{' + XSI + '}type': 'DynamicHTTPMetadataProvider'})
        # The Suite serves /mdq/<encoded entityID>; the Shibboleth MDQ profile adds
        # /entities/, so use the product's documented Template transform instead.
        ET.SubElement(provider, '{' + ns + '}Template', {'encodingStyle': 'form'}).text = (
            'http://samlscope-reference-suite:8080/mdq/${entityID}?run=' + run)
    else:
        provider = ET.Element('{' + ns + '}MetadataProvider', {'id': 'Chain' + run,
            '{' + XSI + '}type': 'FilesystemMetadataProvider', 'metadataFile': temporary})
    root.insert(0, provider)
    configured = ET.tostring(root)
    if args.existing_native_source:
        configured = original
    (out / 'configured-providers.xml').write_bytes(configured)
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
    login_submissions = 0
    fresh_session_boundaries = 0
    def count_logins(client):
        original_request = client.request
        def request(url, fields=None):
            nonlocal login_submissions
            if fields is not None and any(name in fields for name in ('password', 'j_password')):
                login_submissions += 1
            return original_request(url, fields)
        client.request = request
        return client
    changed = False
    capture_target_runtime(out, 'shibboleth', 'start')
    try:
        changed = not args.existing_native_source
        if not args.dynamic_mdq and not args.existing_native_source:
            write(temporary, fixture, 'suite-metadata')
            readback = docker('cat', temporary)
            if readback != fixture:
                raise RuntimeError('Other-entity metadata native read-back mismatch')
            (out / 'fixture-readback.xml').write_bytes(readback)
        if not args.existing_native_source:
            write(CONFIG, configured, 'provider')
        configured_readback = docker('cat', CONFIG)
        if configured_readback != configured:
            raise RuntimeError('Configured provider native read-back mismatch')
        (out / 'configured-providers-readback.xml').write_bytes(configured_readback)
        if not args.existing_native_source:
            reload('provider')
        if args.capture_authentication_challenge:
            from authentication_challenge_capture import ChallengeClient
            initial_client=ChallengeClient(out/'authentication-challenge')
        else:
            initial_client=Client()
        initial_client=count_logins(initial_client)
        login = initial_client.flow(BASE + '/p/' + plan + '/start/m0-roundtrip?run=' + run, None, USER, PASSWORD)
        if args.capture_authentication_challenge:
            initial_client.finish()
        save(out / 'initial-login.json', dict(receipt=login))
        if args.dynamic_mdq:
            (out / 'mdq-product-observation.log').write_bytes(docker('sh', '-c',
                "grep 'Dynamic" + run + "' /opt/reference-idp/logs/idp-process.log | tail -20"))
        if login != 'recorded':
            raise RuntimeError('Initial login did not complete: ' + str(login))
        save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
        repeated = 0
        previous = None
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
                save(out / 'steps.json', steps)
                continue
            if status['state'] != 'READY':
                steps.append(dict(caseId=status.get('caseId'), state=status['state'], action='stop'))
                break
            if selected_cases is not None and status.get('caseId') not in selected_cases:
                steps.append(prepare_and_skip(BASE, run, status, api))
                save(out / 'steps.json', steps)
                continue
            # A normal SSO operation can reuse its authenticated session. Explicit empty-session
            # boundaries still get a new in-memory cookie jar before any target submission.
            fresh_session = status.get('requiresFreshSession', True)
            if args.reuse_session and fresh_session is False:
                client = initial_client
                reused_session = True
            else:
                client = count_logins(Client())
                reused_session = False
                if fresh_session is True:
                    fresh_session_boundaries += 1
            terminal = None
            if status.get('caseId') in TERMINAL_HTTP_CASES:
                def terminal(url, page, code, reason, action=status['actionId']):
                    api('/api/runs/' + run + '/active-probe/browser-response', dict(
                        actionId=action, status=code, url=url, body=page))
            result = client.flow(status['startUrl'], None, USER, PASSWORD,
                                 terminal_observer=terminal)
            after = api('/api/runs/' + run + '/active-probe')
            steps.append(dict(caseId=status.get('caseId'), actionId=status.get('actionId'),
                              result=result, prepared=True, sentToTarget=True,
                              reused_authenticated_client=reused_session,
                              fresh_session_required=fresh_session,
                              nextState=after['state'], nextActionId=after.get('actionId')))
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
        # Restore the target before collecting Suite evidence. The Suite may have failed or
        # disconnected while driving a fixture; that must never skip product-side restoration.
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
        try:
            final_config = docker('cat', CONFIG)
            (out / 'final-providers.xml').write_bytes(final_config)
        except Exception as error:
            final_config = None
            failures.append('final-configuration-read-back-' + type(error).__name__)
        restored = not failures and final_config == original
        save(out / 'restoration.json', dict(restored=restored, failures=failures,
            original_sha256=SHA(original), final_sha256=SHA(final_config) if final_config is not None else None,
            temporary_file_removed=removed))
        save(out / 'operations.json', operations)
        save(out / 'operation-counts.json', dict(restored=restored, human_operations=0,
            configuration_write_attempts=sum(1 for item in operations if item['operation'] == 'write'),
            restoration_write_attempts=sum(1 for item in operations if item['operation'] == 'write'
                                           and item.get('label') == 'restore-provider'),
            reloads=sum(1 for item in operations if item['operation'] == 'reload'),
            probes=len([s for s in steps if 'result' in s]), verdict_adopted=False,
            product_restarts=0, prepared_actions=sum(s.get('prepared') is True for s in steps),
            skipped_before_target_submission=sum(s.get('sentToTarget') is False for s in steps),
            target_submissions=sum(s.get('sentToTarget') is True for s in steps), initial_baseline_submissions=1))
        counts = json.loads((out / 'operation-counts.json').read_text())
        counts.update(login_submissions=login_submissions, fresh_session_boundaries=fresh_session_boundaries,
                      authenticated_session_reuse_enabled=args.reuse_session,
                      reused_authenticated_client_submissions=sum(s.get('reused_authenticated_client') is True for s in steps))
        save(out / 'operation-counts.json', counts)
        capture_target_runtime(out, 'shibboleth', 'end')

        # Evidence export is best-effort and intentionally happens after restoration.
        try:
            entries = api('/api/runs/' + run + '/transcript')
            save(out / 'transcript.json', entries)
            capture_browser_originals(out, entries)
            for name in ['result.json', 'report.html', 'protocol-evidence']:
                try:
                    with urllib.request.urlopen(BASE + '/api/runs/' + run + '/' + name, timeout=30) as response:
                        (out / name).write_bytes(response.read())
                except Exception as error:
                    save(out / (name.replace('.', '-') + '-unavailable.json'), dict(reason=type(error).__name__))
            if not (out / 'decoded-manifest.json').exists():
                capture(out, run, entries)
        except Exception as error:
            save(out / 'evidence-capture-unavailable.json', dict(error=type(error).__name__))
        if failures:
            raise RuntimeError('Native restoration incomplete: ' + ','.join(failures))
    print('Browser chain collected', len(steps), 'probe steps;', run)


if __name__ == '__main__':
    main()
