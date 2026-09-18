#!/usr/bin/env python3
"""Complete the ordinary login prerequisite of an existing Run, with native import and exact restore."""
import argparse
from pathlib import Path
import os
import re
import urllib.request
import xml.etree.ElementTree as ET
from attribute_name_capability import docker, XSI, api, save, BASE, Client
from ui_consumer_campaign import SHA


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', args.run):
        raise ValueError('Invalid Run')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    run = api('/api/runs/' + args.run)
    plan = run['planId']
    if not re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}', plan):
        raise ValueError('Invalid plan')
    config = '/opt/reference-idp/conf/metadata-providers.xml'
    original = docker('cat', config)
    temporary = '/opt/reference-idp/metadata/ui-baseline-' + args.run + '.xml'
    if docker('sh', '-c', 'if test -e ' + temporary + '; then echo exists; fi').strip():
        raise ValueError('Temporary file exists')
    with urllib.request.urlopen(BASE + '/p/' + plan + '/metadata', timeout=30) as response:
        fixture = response.read()
    (out / 'fixture.xml').write_bytes(fixture)
    namespace = 'urn:mace:shibboleth:2.0:metadata'
    ET.register_namespace('', namespace)
    ET.register_namespace('xsi', XSI)
    root = ET.fromstring(original)
    root.insert(0, ET.Element('{' + namespace + '}MetadataProvider', {'id': 'UiBaseline' + args.run,
        '{' + XSI + '}type': 'FilesystemMetadataProvider', 'metadataFile': temporary}))
    configured = ET.tostring(root)
    operations = []
    changed = written = False
    def write(path, raw, label):
        operations.append(dict(operation='write', label=label, attempted=True))
        docker('sh', '-c', 'cat > ' + path, data=raw)
        if docker('cat', path) != raw: raise RuntimeError('Read-back mismatch')
        operations[-1].update(read_back=True, sha256=SHA(raw))
    def reload(label):
        operations.append(dict(operation='reload', label=label, attempted=True))
        log = docker('/opt/reference-idp/bin/reload-service.sh', '-id', 'shibboleth.MetadataResolverService', '-u', 'http://localhost:8080/idp')
        (out / (label + '-reload.log')).write_bytes(log)
        operations[-1]['completed'] = True
    try:
        written = True
        write(temporary, fixture, 'baseline-metadata')
        changed = True
        write(config, configured, 'provider')
        reload('provider')
        operations.append(dict(operation='ordinary-login', attempted=True))
        receipt = Client().flow(BASE + '/p/' + plan + '/start/m0-roundtrip?run=' + args.run, None,
            os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user'),
            os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password'))
        save(out / 'flow.json', receipt)
        if receipt != 'recorded':
            raise RuntimeError('Ordinary login did not complete')
        save(out / 'run-after.json', api('/api/runs/' + args.run))
    finally:
        failures = []
        if changed:
            try:
                if docker('cat', config) != configured: raise RuntimeError('Concurrent configuration change')
                write(config, original, 'restore-provider')
                reload('restore-provider')
            except Exception as error: failures.append(type(error).__name__)
        if written and not failures:
            operations.append(dict(operation='delete', label='temporary-metadata', attempted=True))
            docker('rm', '--', temporary)
        removed = not docker('sh', '-c', 'if test -e ' + temporary + '; then echo exists; fi').strip()
        restored = not failures and removed and docker('cat', config) == original
        save(out / 'operations.json', dict(run=args.run, operations=operations, restored=restored, failures=failures,
            original_sha256=SHA(original), final_sha256=SHA(docker('cat', config)), temporary_removed=removed))
        if not restored: raise RuntimeError('Restoration incomplete')
    print('Ordinary login recorded and native configuration restored')


if __name__ == '__main__': main()
