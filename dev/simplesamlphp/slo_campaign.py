#!/usr/bin/env python3
"""Reference SimpleSAMLphp single-logout campaign.

Imports the Suite SP through the product's native metadata parser, registers two propagation
participants (a failing /sp/slo-fail endpoint and a recorded /sp/slo?run= endpoint), then drives a
Suite-initiated logout so the Suite records the target's propagation. Everything is restored in a
finally block; the campaign adopts no verdict.
"""
import argparse
import hashlib
import os
import importlib.util
import json
import pathlib
import subprocess
import sys
import time
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


def participant_entry(entity_id, slo_location, acs_location, cert_b64):
    def php(value):
        return "'" + value.replace('\\', '\\\\').replace("'", "\\'") + "'"
    return (
        "$metadata[%s] = array (\n"
        "  'entityid' => %s,\n"
        "  'AssertionConsumerService' => array (\n"
        "    array ('index' => 0, 'isDefault' => true, 'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', 'Location' => %s),\n"
        "  ),\n"
        "  'SingleLogoutService' => array (\n"
        "    array ('Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'Location' => %s),\n"
        "    array ('Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', 'Location' => %s),\n"
        "    array ('Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP', 'Location' => %s),\n"
        "  ),\n"
        "  'keys' => array (\n"
        "    array ('encryption' => false, 'signing' => true, 'type' => 'X509Certificate', 'X509Certificate' => %s),\n"
        "  ),\n"
        "  'validate.authnrequest' => false,\n"
        "  'saml20.sign.response' => true,\n"
        "  'saml20.sign.assertion' => true,\n"
        ");\n"
    ) % (php(entity_id), php(entity_id), php(acs_location), php(slo_location),
         php(slo_location), php(slo_location), php(cert_b64))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)

    created = api('/api/plans', dict(name='SimpleSAMLphp single logout', profile='single_logout_idp',
        targetKind='IDP', targetEntityId='http://localhost:18380/idp', metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300, testUserHint='samlscope-m0-user', requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    save(out / 'plan.json', created)
    plan = created['plan']['plan']['id']
    entity = BASE + '/p/' + plan
    created = api('/api/plans/' + plan + '/runs', {})
    save(out / 'created.json', created)
    run = created['run']['id']
    save(out / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))

    configuration = ConfigurationBatch(SP_REMOTE)
    original = configuration.original
    if b'?>' in original:
        raise ValueError('Unexpected PHP closing tag')
    if entity.encode() in original:
        raise ValueError('Refusing to overwrite an existing Suite entity')
    operations = []
    try:
        # Use the baseline Suite SP metadata, exactly as the successful SSO campaigns do: a
        # metadata-lab variant would add ?mdv=..&run=.. to the endpoints and break the SSO flow.
        with urllib.request.urlopen(BASE + '/p/' + plan + '/metadata', timeout=30) as response:
            fixture = response.read()
        (out / 'fixture.xml').write_bytes(fixture)
        parsed = subprocess.run(['docker', 'exec', '-i', CONTAINER, 'php', '-r', PHP, entity, 'default'],
                                input=fixture, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
        (out / 'parser.stderr').write_bytes(parsed.stderr)
        if parsed.returncode:
            raise RuntimeError('Product native parser rejected fixture')
        data = json.loads(parsed.stdout)
        configuration.apply(data['php'].encode())
        # Register the two participants on the same recorded routes the Shibboleth harness uses.
        import xml.etree.ElementTree as ET
        role = ET.fromstring(fixture).find('{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor')
        acs = role.find('{urn:oasis:names:tc:SAML:2.0:metadata}AssertionConsumerService').get('Location')
        x509 = role.find('{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor').find(
            '{http://www.w3.org/2000/09/xmldsig#}KeyInfo').find(
            '{http://www.w3.org/2000/09/xmldsig#}X509Data').find(
            '{http://www.w3.org/2000/09/xmldsig#}X509Certificate').text.strip()
        base = BASE + '/p/' + plan
        overlay = ''
        if os.environ.get('SSP_SLO_PARTICIPANTS', '1') == '1':
            overlay = participant_entry(base + '/sp-fail', base + '/sp/slo-fail?run=' + run, acs, x509)
            overlay += participant_entry(base + '/sp-remain', base + '/sp/slo?run=' + run, acs, x509)
            configuration.apply(overlay.encode())
        time.sleep(3)
        # The suite SP is added to saml20-sp-remote.php, but a running SimpleSAMLphp worker keeps
        # its metadata in memory. A graceful Apache reload picks up the new file without downtime.
        reload_result = subprocess.run(['docker', 'exec', CONTAINER, 'apache2ctl', 'graceful'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        operations.append(dict(step='apache-graceful-reload', returncode=reload_result.returncode))
        time.sleep(3)
        probe = subprocess.run(['docker', 'exec', CONTAINER, 'php', '-r',
            "require '/var/simplesamlphp/lib/_autoload.php';"
            "try { \\SimpleSAML\\Metadata\\MetaDataStorageHandler::getMetadataHandler()"
            "->getMetaData('" + entity + "','saml20-sp-remote'); echo 'RESOLVED'; }"
            "catch (\\Throwable $e) { echo 'UNRESOLVED: '.get_class($e); }"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
        (out / 'resolve-probe.txt').write_bytes(probe.stdout + b'\n' + probe.stderr)
        operations.append(dict(step='resolve-probe', output=probe.stdout.decode('utf-8', 'replace')[:200]))
        grep = subprocess.run(['docker', 'exec', CONTAINER, 'sh', '-c',
            'grep -c "' + plan + '" /var/simplesamlphp/metadata/saml20-sp-remote.php'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        operations.append(dict(step='container-grep', plan=plan,
                               count=grep.stdout.decode().strip(), stderr=grep.stderr.decode()[:120]))
        # Complete the initial login and the profile tests with the reference HTTP driver, exactly
        # as the successful Shibboleth/SSP SSO campaigns do.
        save(out / 'prepared.json', dict(plan=plan, run=run, entity=entity))
        sys.path.insert(0, str(REPO / 'dev/keycloak'))
        from reference_flow import Client  # noqa: E402
        login = Client().flow(BASE + '/p/' + plan + '/start/m0-roundtrip?run=' + run, None,
                              'samlscope-m0-user', 'samlscope-m0-password')
        save(out / 'initial-login.json', dict(receipt=login))
        operations.append(dict(step='initial-login', receipt=login))
        if login != 'recorded':
            raise RuntimeError('Initial login did not complete: ' + str(login))
        save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
        steps = []
        for _ in range(400):
            status = api('/api/runs/' + run + '/active-probe')
            if status['state'] == 'AWAITING_RESPONSE':
                api('/api/runs/' + run + '/active-probe/abort', {})
                steps.append(dict(caseId=status.get('caseId'), action='abort'))
                continue
            if status['state'] != 'READY':
                steps.append(dict(caseId=status.get('caseId'), state=status['state'], action='stop'))
                break
            result = Client().flow(status['startUrl'], None, 'samlscope-m0-user', 'samlscope-m0-password')
            after = api('/api/runs/' + run + '/active-probe')
            steps.append(dict(caseId=status.get('caseId'), result=result, nextState=after['state']))
            if after.get('actionId') == status.get('actionId') and after['state'] == 'AWAITING_RESPONSE':
                api('/api/runs/' + run + '/active-probe/abort', {})
        save(out / 'steps.json', steps)
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
