#!/usr/bin/env python3
"""Import original UI fixtures, observe the native login screen, and restore exactly. No verdicts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET
from attribute_name_capability import docker, XSI

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import api, save, BASE

VARIANTS = ['ui-consumer-display-all', 'ui-consumer-display-service', 'ui-consumer-display-entity',
            'ui-consumer-logo-localized', 'ui-consumer-logo-fallback']
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    config_path = '/opt/reference-idp/conf/metadata-providers.xml'
    original = docker('cat', config_path)
    created = api('/api/plans', dict(name='Shibboleth UI consumer observation', profile='metadata_idp',
        targetKind='IDP', targetEntityId='http://localhost:18280/idp/shibboleth', metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300, testUserHint='samlscope-m0-user', requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    save(out / 'plan.json', created)
    plan = created['plan']['plan']['id']
    created = api('/api/plans/' + plan + '/runs', {})
    save(out / 'created.json', created)
    run = created['run']['id']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', run):
        raise ValueError('Invalid Run')
    save(out / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))
    temporary = '/opt/reference-idp/metadata/ui-consumer-' + run + '.xml'
    if docker('sh', '-c', 'if test -e ' + temporary + '; then echo exists; fi').strip():
        raise ValueError('Temporary metadata exists')
    ns = 'urn:mace:shibboleth:2.0:metadata'
    ET.register_namespace('', ns)
    ET.register_namespace('xsi', XSI)
    tree = ET.fromstring(original)
    tree.insert(0, ET.Element('{' + ns + '}MetadataProvider', {'id': 'UiConsumer' + run,
        '{' + XSI + '}type': 'FilesystemMetadataProvider', 'metadataFile': temporary}))
    configured = ET.tostring(tree)
    operations = []
    changed = temporary_written = False

    def write(path, raw, label):
        record = dict(operation='write', label=label, attempted=True, read_back=False)
        operations.append(record)
        docker('sh', '-c', 'cat > ' + path, data=raw)
        if docker('cat', path) != raw:
            raise RuntimeError('Read-back mismatch')
        record.update(read_back=True, sha256=SHA(raw))

    def reload(label):
        record = dict(operation='reload', label=label, attempted=True, completed=False)
        operations.append(record)
        log = docker('/opt/reference-idp/bin/reload-service.sh', '-id', 'shibboleth.MetadataResolverService',
                     '-u', 'http://localhost:8080/idp')
        (out / (label + '-reload.log')).write_bytes(log)
        record['completed'] = True

    try:
        for variant in VARIANTS:
            folder = out / variant
            folder.mkdir()
            state = api('/api/runs/' + run + '/metadata-lab/automatic-polling', dict(variants=[variant], pollingDelaySeconds=0))
            save(folder / 'campaign.json', state)
            with urllib.request.urlopen(state['automaticStartUrl'], timeout=30) as response:
                if response.status != 202:
                    raise RuntimeError('Expected fetch preparation gate')
                response.read()
            with urllib.request.urlopen(state['metadataUrl'], timeout=30) as response:
                raw = response.read()
            fixture = folder / 'fixture.xml'
            fixture.write_bytes(raw)
            temporary_written = True
            write(temporary, raw, variant)
            if not changed:
                changed = True
                write(config_path, configured, 'metadata-providers')
            reload(variant)
            if docker('cat', config_path) != configured:
                raise RuntimeError('Concurrent provider configuration change')
            receipt = folder / 'native-import.json'
            save(receipt, dict(run=run, fixture_sha256=SHA(raw), provider_sha256=SHA(configured),
                native_path='FilesystemMetadataProvider', file_read_back=True, resolver_reload_completed=True,
                product_consumption_verified=False))
            tree = ET.fromstring(raw)
            kind = 'logo' if '-logo-' in variant else 'display-name'
            if kind == 'logo':
                logos = tree.findall('.//{urn:oasis:names:tc:SAML:metadata:ui}Logo')
                candidates = {('localized' if logo.get('{http://www.w3.org/XML/1998/namespace}lang') else 'default'): logo.text for logo in logos}
            else:
                # The native template supplies this fixed English prefix; it is not metadata text.
                candidates = {'display': 'Login to SAMLscope UI display candidate',
                    'service': 'Login to SAMLscope service candidate', 'entity': 'Login to ' + tree.attrib['entityID'],
                    'hostname': 'Login to localhost'}
            inputs = dict(startUrl=state['automaticStartUrl'], output=str(folder / 'browser-observation.json'),
                observation=dict(runId=run, condition=variant, fixturePath=str(fixture),
                    importReceiptPath=str(receipt), kind=kind, candidates=candidates))
            save(folder / 'browser-input.json', inputs)
            record = dict(operation='browser', label=variant, attempted=True)
            operations.append(record)
            result = subprocess.run(['node', str(Path(__file__).with_name('observe_ui_consumer.mjs')),
                str(folder / 'browser-input.json')], env=os.environ, capture_output=True, timeout=100)
            record['exit_code'] = result.returncode
            # Do not persist raw process output: it could include protocol-bearing exception URLs.
            print(variant, 'browser exit', result.returncode, flush=True)
    finally:
        failures = []
        if changed:
            try:
                if docker('cat', config_path) != configured:
                    raise RuntimeError('Concurrent configuration change; refusing overwrite')
                write(config_path, original, 'restore-provider')
                reload('restore-provider')
            except Exception as error:
                failures.append(type(error).__name__)
        if temporary_written and not failures:
            operations.append(dict(operation='delete', label='temporary-metadata', attempted=True))
            docker('rm', '--', temporary)
        removed = not docker('sh', '-c', 'if test -e ' + temporary + '; then echo exists; fi').strip()
        restored = not failures and removed and docker('cat', config_path) == original
        save(out / 'operations.json', dict(run=run, operations=operations, restored=restored, verdict_adopted=False))
        save(out / 'restoration.json', dict(restored=restored, original_sha256=SHA(original),
            final_sha256=SHA(docker('cat', config_path)), temporary_removed=removed, failures=failures))
        transcript = api('/api/runs/' + run + '/transcript')
        save(out / 'transcript.json', transcript)
        manifest = []
        for entry in transcript:
            if not entry.get('decodedSamlRef'):
                continue
            if not re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}', entry['id']):
                raise ValueError('Invalid transcript ID')
            expected = 'transcripts/' + run + '/' + entry['id'] + '.saml.xml'
            if entry['decodedSamlRef'] != expected:
                raise ValueError('Unexpected transcript path')
            destination = out / 'decoded' / (entry['id'] + '.xml')
            destination.parent.mkdir(exist_ok=True)
            subprocess.run(['docker', 'cp', 'samlscope-reference-suite:/data/' + expected, str(destination)],
                           check=True, capture_output=True, timeout=30)
            manifest.append(dict(id=entry['id'], file=str(destination.relative_to(out)), sha256=SHA(destination.read_bytes())))
        save(out / 'decoded-manifest.json', manifest)
        # This diagnostic stops before authentication and never starts case evaluation.
        # Consequently no result artifact is expected; do not start tests merely to create one.
        save(out / 'evaluation-status.json', dict(evaluation_started=False, verdict_adopted=False))
        if not restored:
            raise RuntimeError('Restoration failed')
    print('Run', run, 'restored', restored, '; no verdict assigned')


if __name__ == '__main__':
    main()
