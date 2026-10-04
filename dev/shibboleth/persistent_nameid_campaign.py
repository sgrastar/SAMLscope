#!/usr/bin/env python3
"""Capture two native persistent-NameID peers under one unchanged reference configuration.

The public reference-only salt is a fixture input, not a production secret. Authentication
credentials remain in the child browser driver's memory. Native request-ID audit contains
the authenticated principal but deliberately omits identifier values and session cookies.
This recorder does not adopt a verdict.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import save
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
from capture_terminal_http_runtime import capture_target
from md06b_multi_peer_campaign import capture_suite, shib_configuration
spec = importlib.util.spec_from_file_location('persistent_native_import', Path(__file__).with_name('import_metadata_batch.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
docker = native.docker

CONTAINER = 'samlscope-reference-shibboleth'
PATHS = {
    'properties': '/opt/reference-idp/conf/saml-nameid.properties',
    'generators': '/opt/reference-idp/conf/saml-nameid.xml',
    'providers': '/opt/reference-idp/conf/metadata-providers.xml',
    'audit': '/opt/reference-idp/conf/audit.xml',
    'resolver': '/opt/reference-idp/conf/attribute-resolver.xml',
}
PUBLIC_SALT = 'samlscope-reference-public-fixture-persistent-id-v1'
AUDIT_FORMAT = 'SAMLscope-persistent-v1|%I|%SP|%u|%S|%b|%P'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def configuration(originals, campaign):
    properties = originals['properties']
    for key in (b'idp.persistentId.sourceAttribute', b'idp.persistentId.useUnfilteredAttributes', b'idp.persistentId.salt'):
        if any(line.strip().startswith(key + b' ') or line.strip().startswith(key + b'=')
               for line in properties.splitlines()):
            raise ValueError('Refusing to override an active persistent-ID setting')
    properties += ('\n# Public reference campaign input; never use this salt in production.\n'
                   'idp.persistentId.sourceAttribute = uid\n'
                   'idp.persistentId.useUnfilteredAttributes = true\n'
                   'idp.persistentId.salt = ' + PUBLIC_SALT + '\n').encode()
    beans = 'http://www.springframework.org/schema/beans'
    util = 'http://www.springframework.org/schema/util'
    generators = ET.fromstring(originals['generators'])
    lists = [node for node in generators if node.tag == '{' + util + '}list'
             and node.get('id') == 'shibboleth.SAML2NameIDGenerators']
    if len(lists) != 1 or any(node.get('bean') == 'shibboleth.SAML2PersistentGenerator' for node in lists[0]):
        raise ValueError('Unexpected persistent generator configuration')
    ET.SubElement(lists[0], '{' + beans + '}ref', {'bean': 'shibboleth.SAML2PersistentGenerator'})
    audit = ET.fromstring(originals['audit'])
    entries = audit.findall('.//{' + util + '}map[@id="shibboleth.AuditFormattingMap"]/{' + beans + '}entry[@key="Shibboleth-Audit"]')
    if len(entries) != 1:
        raise ValueError('Unexpected native audit map')
    entries[0].set('value', AUDIT_FORMAT)
    return {'properties': properties,
            'generators': ET.tostring(generators, encoding='UTF-8', xml_declaration=True),
            'providers': shib_configuration(originals['providers'], campaign),
            'audit': ET.tostring(audit, encoding='UTF-8', xml_declaration=True),
            'resolver': originals['resolver']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    originals = {name: docker('cat', path) for name, path in PATHS.items()}
    configured = configuration(originals, out.name)
    for name in PATHS:
        (out / ('original-' + name + '.xml' if name != 'properties' else 'original-properties.properties')).write_bytes(originals[name])
        (out / ('configured-' + name + '.xml' if name != 'properties' else 'configured-properties.properties')).write_bytes(configured[name])
    operations, changed, peers, failures = [], [], [], []

    def write(name, raw, label):
        item = dict(operation='product-config-write', label=label, path=PATHS[name],
                    sha256=SHA(raw), recordedAt=time.time(), readBack=False)
        operations.append(item)
        save(out / 'operations.json', operations)
        docker('sh', '-c', 'cat > ' + PATHS[name], data=raw)
        if docker('cat', PATHS[name]) != raw:
            raise RuntimeError('Native configuration read-back differs')
        item['readBack'] = True
        item['readBackSha256'] = SHA(docker('cat', PATHS[name]))
        save(out / 'operations.json', operations)

    def restart(label):
        item = dict(operation='product-restart', label=label, recordedAt=time.time(), completed=False)
        operations.append(item)
        save(out / 'operations.json', operations)
        subprocess.run(['docker', 'restart', CONTAINER], check=True, timeout=60, stdout=subprocess.PIPE)
        docker('/usr/local/tomcat/bin/startup.sh')
        deadline = time.monotonic() + 110
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen('http://localhost:18280/idp/shibboleth', timeout=3) as response:
                    if response.status == 200:
                        item['completed'], item['completedAt'] = True, time.time()
                        save(out / 'operations.json', operations)
                        return
            except Exception:
                time.sleep(1)
        raise RuntimeError('Native IdP did not become healthy')

    def readback(label):
        states = {name: docker('cat', path) for name, path in PATHS.items()}
        if states != configured:
            raise RuntimeError('Native settings changed during the pairwise campaign')
        for name, raw in states.items():
            (out / (label + '-' + name + ('.properties' if name == 'properties' else '.xml'))).write_bytes(raw)
        record = dict(recordedAt=time.time(), files={name: SHA(raw) for name, raw in states.items()})
        save(out / (label + '-configuration.json'), record)
        return record

    try:
        for name in PATHS:
            if configured[name] == originals[name]:
                continue
            changed.append(name)
            write(name, configured[name], 'apply-' + name)
        restart('prepare-native-persistent')
        capture_target(out, 'shibboleth', 'start')
        capture_suite(out, 'start')
        for label in ('primary', 'secondary'):
            before = readback(label + '-before')
            child = out / label
            completed = subprocess.run([sys.executable, str(Path(__file__).with_name('browser_chain_campaign.py')),
                '--output', str(child), '--existing-native-source', '--stop-after-case', 'IIP-SSO05-a3-idp-01',
                '--only-cases', 'IIP-IDP10-a-idp-01,IIP-IDP10-d-idp-01,IIP-SSO05-a3-idp-01'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1800)
            (out / (label + '-campaign.log')).write_bytes(completed.stdout)
            after = readback(label + '-after')
            created = json.loads((child / 'created.json').read_text())
            peer = dict(label=label, runId=created['run']['id'], planId=created['run']['planId'],
                        before=before, after=after, exitCode=completed.returncode)
            peers.append(peer)
            save(out / 'peers.json', peers)
            print(label, peer['runId'], 'exit', completed.returncode, flush=True)
            if completed.returncode != 0:
                raise RuntimeError(label + ' browser campaign did not complete')
        request_ids = set()
        for peer in peers:
            child = out / peer['label']
            originals_by_id = {row['id']: child / row['file']
                               for row in json.loads((child / 'decoded-manifest.json').read_text())}
            for entry in json.loads((child / 'transcript.json').read_text()):
                if entry.get('samlSummary', {}).get('type') != 'AuthnRequest':
                    continue
                # Browser outbox summaries intentionally omit XML ID; bind the native audit
                # to the real request original, rather than to a receipt/summary declaration.
                root = ET.fromstring(originals_by_id[entry['id']].read_bytes())
                request_ids.add(root.get('ID'))
        audit_lines = []
        for line in docker('cat', '/opt/reference-idp/logs/idp-audit.log').decode().splitlines():
            if 'SAMLscope-persistent-v1|' not in line:
                continue
            fields = line.split('SAMLscope-persistent-v1|', 1)[1].split('|')
            if len(fields) == 6 and fields[0] in request_ids:
                audit_lines.append('SAMLscope-persistent-v1|' + '|'.join(fields))
        (out / 'native-principal-audit.log').write_text('\n'.join(audit_lines) + '\n')
        (out / 'native-campaign-process.log').write_text('\n'.join(
            line for line in docker('cat', '/opt/reference-idp/logs/idp-process.log').decode().splitlines()
            if any(peer['planId'] in line for peer in peers)) + '\n')
        configured_runtime = out / 'configured-end-runtime'
        configured_runtime.mkdir()
        capture_target(configured_runtime, 'shibboleth', 'end')
        capture_suite(out, 'end')
    finally:
        for name in reversed(changed):
            try:
                if docker('cat', PATHS[name]) != configured[name]:
                    raise RuntimeError('Concurrent native change; refusing overwrite of ' + name)
                write(name, originals[name], 'restore-' + name)
            except Exception as error:
                failures.append(str(error))
        if changed and not failures:
            try:
                restart('restore-native-persistent')
            except Exception as error:
                failures.append(str(error))
        restored = not failures and all(docker('cat', path) == originals[name] for name, path in PATHS.items())
        for name, path in PATHS.items():
            (out / ('final-' + name + ('.properties' if name == 'properties' else '.xml'))).write_bytes(docker('cat', path))
        save(out / 'restoration.json', dict(restored=restored, failures=failures,
             original={name: SHA(raw) for name, raw in originals.items()},
             final={name: SHA(docker('cat', path)) for name, path in PATHS.items()}))
        save(out / 'operation-counts.json', dict(product_configuration_writes=sum(item['operation']=='product-config-write' for item in operations),
             restoration_writes=sum(item['label'].startswith('restore-') and item['operation']=='product-config-write' for item in operations),
             product_restarts=sum(item['operation']=='product-restart' for item in operations), product_reloads=0,
             human_operations=0, run_creations=len(peers), restored=restored, verdict_adopted=False))
        capture_target(out, 'shibboleth', 'end')
        if not restored:
            raise RuntimeError('Native persistent configuration restoration failed')
    print('Persistent two-peer campaign captured; exact restoration verified', flush=True)


if __name__ == '__main__':
    main()
