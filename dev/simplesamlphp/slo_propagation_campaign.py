#!/usr/bin/env python3
"""Reference SimpleSAMLphp single-logout propagation campaign with Suite participant sessions.

Registers the Suite SP plus two propagation participants in a single native metadata write,
establishes each participant's IdP session through the product's unsolicited SSO profile
(preparing one single-use intent per participant), then runs the Suite single-logout chain so
the product's own propagation reaches the participants. Everything is restored in a finally
block; the campaign adopts no verdict.
"""
import argparse
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.parse
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
sys.path.insert(0, str(REPO / 'dev/simplesamlphp'))
from configuration_batch import ConfigurationBatch  # noqa: E402
from capture_run_originals import capture  # noqa: E402
_spec = importlib.util.spec_from_file_location(
    'ssp_native_import', str(REPO / 'dev/simplesamlphp/import_metadata_batch.py'))
native = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(native)
PHP = native.PHP
api, save, BASE = native.api, native.save, native.BASE

CONTAINER = 'samlscope-reference-ssp'
SP_REMOTE = REPO / 'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php'
SSP = 'http://localhost:18380'
USER = 'samlscope-m0-user'
PASSWORD = 'samlscope-m0-password'


BINDING = {
    'redirect': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'post': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    'soap': 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
}


def participant_entry(entity_id, slo_location, acs_location, cert_b64, bindings):
    def php(value):
        return "'" + value.replace('\\', '\\\\').replace("'", "\\'") + "'"
    slo = ''.join(
        "    array ('Binding' => %s, 'Location' => %s),\n" % (php(BINDING[name]), php(slo_location))
        for name in bindings)
    return (
        "$metadata[%s] = array (\n"
        "  'entityid' => %s,\n"
        "  'AssertionConsumerService' => array (\n"
        "    array ('index' => 0, 'isDefault' => true, 'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', 'Location' => %s),\n"
        "  ),\n"
        "  'SingleLogoutService' => array (\n"
        "%s"
        "  ),\n"
        "  'keys' => array (\n"
        "    array ('encryption' => false, 'signing' => true, 'type' => 'X509Certificate', 'X509Certificate' => %s),\n"
        "  ),\n"
        "  'validate.authnrequest' => false,\n"
        "  'saml20.sign.response' => true,\n"
        "  'saml20.sign.assertion' => true,\n"
        ");\n"
    ) % (php(entity_id), php(entity_id), php(acs_location), slo, php(cert_b64))


def unsolicited_url(provider_entity_id):
    return (SSP + '/simplesaml/module.php/saml/idp/singleSignOnService?spentityid='
            + urllib.parse.quote(provider_entity_id, safe=''))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--max-probes', type=int, default=400)
    parser.add_argument('--logout-url', default='')
    parser.add_argument('--participant-bindings', default='redirect,post,soap',
                        help='Comma-separated SLO bindings advertised by the Suite participants')
    args = parser.parse_args()
    participant_bindings = [name.strip() for name in args.participant_bindings.split(',') if name.strip()]
    for name in participant_bindings:
        if name not in BINDING:
            raise ValueError('Unknown participant binding: ' + name)
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True, exist_ok=True)

    created = api('/api/plans', dict(name='SimpleSAMLphp SLO propagation', profile='single_logout_idp',
        targetKind='IDP', targetEntityId='http://localhost:18380/idp', metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300, testUserHint=USER, requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    save(out / 'plan.json', created)
    plan = created['plan']['plan']['id']
    entity = BASE + '/p/' + plan
    created = api('/api/plans/' + plan + '/runs', {})
    save(out / 'created.json', created)
    run = created['run']['id']
    save(out / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))

    configuration = ConfigurationBatch(SP_REMOTE)
    configuration.container = CONTAINER
    configuration.container_path = '/var/simplesamlphp/metadata/saml20-sp-remote.php'
    original = configuration.original
    if b'?>' in original:
        raise ValueError('Unexpected PHP closing tag')
    if entity.encode() in original:
        raise ValueError('Refusing to overwrite an existing Suite entity')
    operations = []
    try:
        with urllib.request.urlopen(BASE + '/p/' + plan + '/metadata', timeout=30) as response:
            fixture = response.read()
        (out / 'fixture.xml').write_bytes(fixture)
        parsed = subprocess.run(['docker', 'exec', '-i', CONTAINER, 'php', '-r', PHP, entity, 'default'],
                                input=fixture, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
        (out / 'parser.stderr').write_bytes(parsed.stderr)
        if parsed.returncode:
            raise RuntimeError('Product native parser rejected fixture')
        data = json.loads(parsed.stdout)
        import xml.etree.ElementTree as ET
        role = ET.fromstring(fixture).find('{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor')
        acs = role.find('{urn:oasis:names:tc:SAML:2.0:metadata}AssertionConsumerService').get('Location')
        x509 = role.find('{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor').find(
            '{http://www.w3.org/2000/09/xmldsig#}KeyInfo').find(
            '{http://www.w3.org/2000/09/xmldsig#}X509Data').find(
            '{http://www.w3.org/2000/09/xmldsig#}X509Certificate').text.strip()
        base = BASE + '/p/' + plan
        overlay = data['php']
        overlay += participant_entry(base + '/sp-fail', base + '/sp/slo-fail?run=' + run, acs, x509,
                                     participant_bindings)
        overlay += participant_entry(base + '/sp-remain', base + '/sp/slo?run=' + run, acs, x509,
                                     participant_bindings)
        configuration.apply(overlay.encode())
        time.sleep(3)
        reload_result = subprocess.run(['docker', 'exec', CONTAINER, 'apache2ctl', 'graceful'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        operations.append(dict(step='apache-graceful-reload', returncode=reload_result.returncode))
        if os.environ.get('SSP_SLO_APCU', '1') != '0':
            probe_name = 'samlscope-apcu-clear.php'
            probe_path = '/var/simplesamlphp/public/' + probe_name
            probe = ("<?php require '/var/simplesamlphp/lib/_autoload.php';"
                     "if (function_exists('apcu_clear_cache')) apcu_clear_cache(); echo 'CLEARED';")
            subprocess.run(['docker', 'exec', '-i', CONTAINER, 'sh', '-c', 'cat > ' + probe_path],
                           input=probe.encode(), check=True, timeout=30)
            try:
                with urllib.request.urlopen(SSP + '/simplesaml/' + probe_name, timeout=30) as response:
                    operations.append(dict(step='apcu-clear', output=response.read().decode()[:40]))
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
                if resolved.startswith('RESOLVED'):
                    break
                time.sleep(1)
        finally:
            subprocess.run(['docker', 'exec', CONTAINER, 'rm', '-f', probe_path], timeout=30)
        operations.append(dict(step='resolve-probe', output=resolved))
        save(out / 'prepared.json', dict(plan=plan, run=run, entity=entity, acs=acs))
        sys.path.insert(0, str(REPO / 'dev/keycloak'))
        from reference_flow import Client  # noqa: E402
        client = Client()
        login = client.flow(BASE + '/p/' + plan + '/start/m0-roundtrip?run=' + run, None, USER, PASSWORD)
        save(out / 'initial-login.json', dict(receipt=login))
        operations.append(dict(step='initial-login', receipt=login))
        if login != 'recorded':
            raise RuntimeError('Initial login did not complete: ' + str(login))

        participants = []
        for suffix, entity_suffix in [('fail', '/sp-fail'), ('remain', '/sp-remain')]:
            intent = api('/api/runs/' + run + '/target-initiated', dict(kind='UNSOLICITED_SSO'))
            url = unsolicited_url(base + entity_suffix)
            receipt = client.flow(url, None, USER, PASSWORD)
            participants.append(dict(suffix=suffix, entity=base + entity_suffix, url=url,
                                     receipt=receipt, intent=intent, bindings=participant_bindings))
        save(out / 'participants.json', participants)
        operations.append(dict(step='participant-sessions', participants=participants))

        save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
        if args.logout_url:
            try:
                api('/api/runs/' + run + '/target-initiated', dict(kind='TARGET_LOGOUT'))
                receipt = client.flow(args.logout_url, None, USER, PASSWORD)
                operations.append(dict(step='target-initiated-logout', url=args.logout_url, receipt=receipt))
            except Exception as error:  # a failed trigger stays NOT_VERIFIED, never a product verdict
                operations.append(dict(step='target-initiated-logout', url=args.logout_url,
                                       error=str(error)[:300]))
        steps = []
        for _ in range(args.max_probes):
            status = api('/api/runs/' + run + '/active-probe')
            if status['state'] == 'AWAITING_RESPONSE':
                api('/api/runs/' + run + '/active-probe/abort', {})
                steps.append(dict(caseId=status.get('caseId'), action='abort'))
                continue
            if status['state'] != 'READY':
                steps.append(dict(caseId=status.get('caseId'), state=status['state'], action='stop'))
                break
            # Reuse the authenticated browser session: SimpleSAMLphp stores its logout
            # associations in the PHP session, so a fresh cookie jar cannot propagate.
            result = client.flow(status['startUrl'], None, USER, PASSWORD)
            after = api('/api/runs/' + run + '/active-probe')
            steps.append(dict(caseId=status.get('caseId'), result=result, nextState=after['state']))
            if after.get('actionId') == status.get('actionId') and after['state'] == 'AWAITING_RESPONSE':
                api('/api/runs/' + run + '/active-probe/abort', {})
        save(out / 'steps.json', steps)
        try:
            api('/api/runs/' + run + '/target-initiated/conclude', {})
        except Exception:
            pass
        save(out / 'evaluation.json', api('/api/runs/' + run + '/protocol-evidence/evaluate', {}))
        save(out / 'result.json', api('/api/runs/' + run + '/result.json'))
    finally:
        restoration = configuration.restore()
        save(out / 'restoration.json', restoration)
        save(out / 'operations.json', dict(run=run, operations=operations, restored=restoration['restored']))
        entries = api('/api/runs/' + run + '/transcript')
        save(out / 'transcript.json', entries)
        capture(out, run, entries)
        if not restoration['restored']:
            raise RuntimeError('Restore verification failed')
    print('Run', run)


if __name__ == '__main__':
    main()
