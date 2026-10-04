#!/usr/bin/env python3
"""SimpleSAMLphp single-logout propagation campaign using the IdP's iframe logout handler.

Registers the Suite SP plus two participants in one native metadata write, switches the pinned
reference IdP to its supported iframe logout handler, then drives the Suite browser chain in a real
browser. All configuration is restored byte-for-byte; no verdict is assigned here.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
sys.path.insert(0, str(REPO / 'dev/simplesamlphp'))
from capture_run_originals import capture  # noqa: E402
from slo_propagation_campaign import participant_entry  # noqa: E402
from configuration_batch import ConfigurationBatch  # noqa: E402
import importlib.util  # noqa: E402
_spec = importlib.util.spec_from_file_location(
    'ssp_native_import2', str(REPO / 'dev/simplesamlphp/import_metadata_batch.py'))
native = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(native)
PHP = native.PHP
api, save, BASE = native.api, native.save, native.BASE

CONTAINER = 'samlscope-reference-ssp'
SP_REMOTE = REPO / 'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php'
HOSTED = REPO / 'build/acceptance/reference-20260914/ssp-config/saml20-idp-hosted.php'
OVERRIDE = REPO / 'build/acceptance/reference-20260914/ssp-config/config-override.php'
SSP = 'http://localhost:18380'
CHAIN = REPO / 'dev/simplesamlphp/slo_iframe_chain.mjs'
USER = 'samlscope-m0-user'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True, exist_ok=True)

    created = api('/api/plans', dict(name='SimpleSAMLphp iframe SLO propagation', profile='single_logout_idp',
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
    hosted_original = HOSTED.read_bytes()
    if b'?>' in original or b'?>' in hosted_original:
        raise ValueError('Unexpected PHP closing tag')
    if entity.encode() in original:
        raise ValueError('Refusing to overwrite an existing Suite entity')
    if b'logouttype' in hosted_original:
        raise ValueError('The reference hosted IdP already sets logouttype')
    override_before = OVERRIDE.read_bytes()
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
                                     ['redirect', 'post', 'soap'])
        overlay += participant_entry(base + '/sp-remain', base + '/sp/slo?run=' + run, acs, x509,
                                     ['redirect', 'post', 'soap'])
        (out / 'configured-sp-metadata.php').write_bytes(original + b'\n' + overlay.encode() + b'\n')
        configuration.apply(overlay.encode())
        lint = subprocess.run(['docker', 'exec', CONTAINER, 'php', '-l', configuration.container_path],
                              capture_output=True, text=True, timeout=30)
        operations.append(dict(step='sp-metadata-lint', returncode=lint.returncode,
                               output=(lint.stdout + lint.stderr)[:300]))
        if lint.returncode:
            raise RuntimeError('Native SP metadata PHP syntax invalid')
        hosted = re.sub(rb'\];\s*$', b",'logouttype'=>'iframe'];\n", hosted_original)
        if b"'logouttype'=>'iframe'" not in hosted:
            raise RuntimeError('Unable to set logouttype in the hosted configuration')
        HOSTED.write_bytes(hosted)
        operations.append(dict(step='hosted-logouttype', value='iframe'))
        # The reference security headers set default-src 'none' without frame-src, which blocks the
        # product's own iframe-logout participant frames. Override frame-src for this campaign only.
        OVERRIDE.write_bytes(override_before + (
            b"\n$config['headers.security']['Content-Security-Policy']="
            b"\"default-src 'none'; frame-src http://localhost:18080; form-action 'self' "
            b"http://localhost:18080 http://localhost:18380; frame-ancestors 'self'; "
            b"object-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; "
            b"connect-src 'self'; media-src data:; img-src 'self' data:; base-uri 'none'\";\n"))
        operations.append(dict(step='csp-frame-src', value='http://localhost:18080'))
        lint = subprocess.run(['docker', 'exec', CONTAINER, 'php', '-l',
                               '/var/simplesamlphp/config/config-override.php'],
                              capture_output=True, text=True, timeout=30)
        operations.append(dict(step='csp-config-lint', returncode=lint.returncode,
                               output=(lint.stdout + lint.stderr)[:300]))
        if lint.returncode:
            raise RuntimeError('Native CSP override PHP syntax invalid')
        time.sleep(3)
        reload_result = subprocess.run(['docker', 'exec', CONTAINER, 'apache2ctl', 'graceful'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        operations.append(dict(step='apache-graceful-reload', returncode=reload_result.returncode))
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
        probe_src = ("<?php require '/var/simplesamlphp/lib/_autoload.php';"
                     "try { \\SimpleSAML\\Metadata\\MetaDataStorageHandler::getMetadataHandler()"
                     "->getMetaData('" + entity + "','saml20-sp-remote'); echo 'RESOLVED'; }"
                     "catch (\\Throwable $e) { echo 'UNRESOLVED '.get_class($e).' '.substr($e->getMessage(),0,250); }")
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
        if not resolved.startswith('RESOLVED'):
            raise RuntimeError('Native SP metadata did not resolve: ' + resolved)
        headers_probe = ("require '/var/simplesamlphp/lib/_autoload.php'; "
                         "echo json_encode(\\SimpleSAML\\Configuration::getInstance()"
                         "->getArray('headers.security', []));")
        effective_headers = subprocess.check_output(
            ['docker', 'exec', CONTAINER, 'php', '-r', headers_probe], timeout=30)
        (out / 'effective-security-headers.json').write_bytes(effective_headers)
        csp = json.loads(effective_headers).get('Content-Security-Policy', '')
        if 'frame-src http://localhost:18080' not in csp or 'form-action' not in csp:
            raise RuntimeError('Reference IdP CSP override not effective')
        stage = out / 'driver'
        stage.mkdir(exist_ok=True)
        shutil.copyfile(CHAIN, stage / CHAIN.name)
        modules = os.environ.get('SAML_SCOPE_PLAYWRIGHT_MODULES', '/private/tmp/samlscope-playwright/node_modules')
        if not (stage / 'node_modules').exists():
            (stage / 'node_modules').symlink_to(modules, target_is_directory=True)
        node = subprocess.run(['node', str(stage / CHAIN.name), plan, run, str(out)],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=1500)
        (out / 'iframe-chain.log').write_text(node.stdout)
        operations.append(dict(step='iframe-chain', returncode=node.returncode))
    finally:
        restoration = configuration.restore()
        HOSTED.write_bytes(hosted_original)
        OVERRIDE.write_bytes(override_before)
        save(out / 'restoration.json', restoration)
        save(out / 'operations.json', dict(run=run, operations=operations, restored=restoration['restored']))
        browser_record = out / 'iframe-chain-record.json'
        browser = json.loads(browser_record.read_text()) if browser_record.exists() else {}
        save(out / 'operation-counts.json', dict(
            product_configuration_changes=3, product_configuration_restorations=3,
            sp_metadata_write_attempts=restoration['configuration_write_attempts'],
            service_reloads=sum(item['step'] == 'apache-graceful-reload' for item in operations),
            browser_continue_clicks=browser.get('partialLogoutContinues', 0),
            human_operations=0, restored=restoration['restored']
                and HOSTED.read_bytes() == hosted_original and OVERRIDE.read_bytes() == override_before,
            hosted_original_sha256=hashlib.sha256(hosted_original).hexdigest(),
            hosted_final_sha256=hashlib.sha256(HOSTED.read_bytes()).hexdigest(),
            override_original_sha256=hashlib.sha256(override_before).hexdigest(),
            override_final_sha256=hashlib.sha256(OVERRIDE.read_bytes()).hexdigest()))
        try:
            api('/api/runs/' + run + '/target-initiated/conclude', {})
        except Exception:
            pass
        try:
            save(out / 'evaluation.json', api('/api/runs/' + run + '/protocol-evidence/evaluate', {}))
        except Exception:
            pass
        entries = api('/api/runs/' + run + '/transcript')
        save(out / 'transcript.json', entries)
        save(out / 'result.json', api('/api/runs/' + run + '/result.json'))
        capture(out, run, entries)
        if not restoration['restored']:
            raise RuntimeError('Restore verification failed')
        if HOSTED.read_bytes() != hosted_original:
            raise RuntimeError('Hosted configuration restore failed')
    print('Run', run)


if __name__ == '__main__':
    main()
