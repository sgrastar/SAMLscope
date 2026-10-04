#!/usr/bin/env python3
"""Capture native Password-only, session-disabled SSO controls and restore every setting.

The child driver sends only Suite outbox requests. Passwords and session cookies remain
in driver memory. The parent idp.properties file is never exported because it contains
sealer credentials; only native authentication/session setting lines are captured.
This collector does not decide a conformance outcome.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import save
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
from md06b_multi_peer_campaign import capture_suite, shib_configuration
from capture_terminal_http_runtime import capture_target
sys.path.insert(0, str(Path(__file__).resolve().parent))
from attribute_name_capability import docker

CONTAINER = 'samlscope-reference-shibboleth'
JAR = '/usr/local/tomcat/webapps/idp/WEB-INF/lib/idp-conf-impl-5.2.3.jar'
PATHS = {
    'authn-properties': '/opt/reference-idp/conf/authn/authn.properties',
    'password-validator': '/opt/reference-idp/conf/authn/password-authn-config.xml',
    'global': '/opt/reference-idp/conf/global.xml',
    'relying-party': '/opt/reference-idp/conf/relying-party.xml',
    'providers': '/opt/reference-idp/conf/metadata-providers.xml',
    'audit': '/opt/reference-idp/conf/audit.xml',
    'condition-base': '/opt/reference-idp/flows/authn/conditions/conditions-flow.xml',
    'condition-locked': '/opt/reference-idp/flows/authn/conditions/account-locked/account-locked-flow.xml',
    'condition-expired': '/opt/reference-idp/flows/authn/conditions/expired-password/expired-password-flow.xml',
    'condition-expiring': '/opt/reference-idp/flows/authn/conditions/expiring-password/expiring-password-flow.xml',
}
SOURCES = {
    'flow-selection': 'net/shibboleth/idp/flows/authn/authn-beans.xml',
    'flow-descriptors': 'net/shibboleth/idp/conf/authn-system.xml',
    'conditions': 'net/shibboleth/idp/conf/conditions.xml',
    'condition-base': 'net/shibboleth/idp/module/flows/authn/conditions/conditions-flow.xml',
    'condition-locked': 'net/shibboleth/idp/module/flows/authn/conditions/account-locked/account-locked-flow.xml',
    'condition-expired': 'net/shibboleth/idp/module/flows/authn/conditions/expired-password/expired-password-flow.xml',
    'condition-expiring': 'net/shibboleth/idp/module/flows/authn/conditions/expiring-password/expiring-password-flow.xml',
}
AUDIT_FORMAT = 'SAMLscope-identity-v1|%I|%SP|%u|%e|%S|%AF|%SSO|%b|%P'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
NOW = lambda: datetime.now(timezone.utc).isoformat()


def projection():
    # The command output consists solely of the actual native setting lines. Do not
    # export the parent file or any password, sealer, or private credential property.
    return docker('sh', '-c', "grep -E '^[[:space:]]*idp\\.(authn\\.|session\\.enabled)' /opt/reference-idp/conf/idp.properties")


def configure(originals):
    raw = originals['authn-properties']
    keys = ('idp.authn.flows', 'idp.session.enabled', 'idp.authn.Password.reuseCondition')
    if any(re.search(r'^\s*' + re.escape(key) + r'\s*[=:]', raw.decode(), re.M) for key in keys):
        raise ValueError('Active authentication override requires a separate campaign')
    configured = dict(originals)
    configured['authn-properties'] = raw + (
        '\n# Temporary native identity campaign; restored after collection.\n'
        'idp.authn.flows = Password\n'
        'idp.session.enabled = false\n'
        'idp.authn.Password.reuseCondition = shibboleth.Conditions.FALSE\n').encode()
    root = ET.fromstring(originals['audit'])
    entries = root.findall('.//{http://www.springframework.org/schema/util}map'
        '[@id="shibboleth.AuditFormattingMap"]/{http://www.springframework.org/schema/beans}entry'
        '[@key="Shibboleth-Audit"]')
    if len(entries) != 1:
        raise ValueError('Native audit map ambiguous')
    entries[0].set('value', AUDIT_FORMAT)
    configured['audit'] = ET.tostring(root, encoding='UTF-8', xml_declaration=True)
    return configured


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    out = parser.parse_args().output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    originals = {kind: docker('cat', path) for kind, path in PATHS.items()}
    parent_before = projection()
    if parent_before.strip() != b'idp.authn.flows=Password':
        raise ValueError('Parent authentication settings are not the audited reference defaults')
    configured = configure(originals)
    configured['providers'] = shib_configuration(originals['providers'], out.name)
    for kind, raw in originals.items():
        (out / ('original-' + kind)).write_bytes(raw)
        (out / ('configured-' + kind)).write_bytes(configured[kind])
    (out / 'original-parent-authn.properties').write_bytes(parent_before)
    for kind, path in SOURCES.items():
        (out / ('native-' + kind + '.xml')).write_bytes(docker('unzip', '-p', JAR, path))
    subprocess.run(['docker', 'cp', CONTAINER + ':' + JAR, str(out / 'native-idp-conf-impl.jar')], check=True, stdout=subprocess.DEVNULL)
    save(out / 'native-source-provenance.json', dict(container=CONTAINER, nativeJar=JAR,
        jarFile='native-idp-conf-impl.jar', jarSha256=SHA((out / 'native-idp-conf-impl.jar').read_bytes()), sources=SOURCES))
    inventory = docker('find', '/opt/reference-idp/flows/authn', '-type', 'f')
    (out / 'native-custom-flow-inventory.txt').write_bytes(inventory)
    operations, changed, readbacks, failures = [], [], [], []

    def write(kind, raw, label):
        item = dict(operation='product-config-write', kind=kind, label=label,
                    recordedAt=NOW(), sha256=SHA(raw), readBack=False)
        operations.append(item)
        save(out / 'operations.json', operations)
        docker('sh', '-c', 'cat > ' + PATHS[kind], data=raw)
        if docker('cat', PATHS[kind]) != raw:
            raise RuntimeError('Native read-back mismatch')
        item['readBack'] = True
        save(out / 'operations.json', operations)

    def restart(label):
        item = dict(operation='product-restart', label=label, recordedAt=NOW(), completed=False)
        operations.append(item)
        save(out / 'operations.json', operations)
        subprocess.run(['docker', 'restart', CONTAINER], check=True, timeout=60, stdout=subprocess.PIPE)
        docker('/usr/local/tomcat/bin/startup.sh')
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen('http://localhost:18280/idp/shibboleth', timeout=3) as response:
                    if response.status == 200:
                        item.update(completed=True, completedAt=NOW())
                        save(out / 'operations.json', operations)
                        return
            except Exception:
                time.sleep(1)
        raise RuntimeError('Native IdP failed to become ready')

    def readback(phase):
        for kind, path in PATHS.items():
            raw = docker('cat', path)
            if raw != configured[kind]:
                raise RuntimeError('Native settings changed during controls')
            name = phase + '-' + kind
            (out / name).write_bytes(raw)
            readbacks.append(dict(kind=kind, phase=phase, file=name, sha256=SHA(raw), recordedAt=NOW()))
        raw = projection()
        if raw != parent_before:
            raise RuntimeError('Parent authentication configuration changed')
        (out / (phase + '-parent-authn.properties')).write_bytes(raw)
        save(out / 'readbacks.json', readbacks)

    child = out / 'browser'
    try:
        for kind in PATHS:
            if originals[kind] == configured[kind]:
                continue
            changed.append(kind)
            write(kind, configured[kind], 'prepare-' + kind)
        restart('prepare-password-only-no-session')
        capture_target(out, 'shibboleth', 'start')
        readback('before')
        command = [sys.executable, str(Path(__file__).with_name('browser_chain_campaign.py')),
                   '--output', str(child), '--existing-native-source',
                   '--capture-authentication-challenge',
                   '--only-cases', 'IIP-IDP06-c-idp-01', '--stop-after-case', 'IIP-IDP06-c-idp-01']
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out / 'browser-driver.log').write_bytes(completed.stdout + completed.stderr)
        operations.append(dict(operation='selected-browser-campaign', returncode=completed.returncode,
                               recordedAt=NOW(), humanOperations=0))
        save(out / 'operations.json', operations)
        if completed.returncode:
            raise RuntimeError('Selected browser campaign failed')
        plan=json.loads((child/'created.json').read_text())['run']['planId']
        entity='http://localhost:18080/p/'+plan
        command=['/opt/reference-idp/bin/mdquery.sh','-u','http://localhost:8080/idp','-e',entity]
        effective=docker(*command)
        (out/'native-effective-sp-metadata.xml').write_bytes(effective)
        save(out/'native-effective-sp-metadata-read.json',dict(container=CONTAINER,command=command,
            runId=json.loads((child/'created.json').read_text())['run']['id'],entityId=entity,
            recordedAt=NOW(),exitCode=0,sha256=SHA(effective)))
        readback('after')
        run = json.loads((child / 'created.json').read_text())['run']['id']
        audit = docker('cat', '/opt/reference-idp/logs/idp-audit.log')
        # Only the dedicated campaign format is exported, without session indexes,
        # NameID values, cookies, credentials, or unrelated principals.
        marker = b'SAMLscope-identity-v1|'
        (out / 'native-identity-audit.log').write_bytes(b'\n'.join(
            line for line in audit.splitlines() if marker in line) + b'\n')
        capture_suite(out, 'start')
        save(out / 'campaign.json', dict(runId=run, selectedCases=['IIP-IDP06-c-idp-01'],
                                       identityCase='IIP-SSO01-ae-idp-01', humanOperations=0))
    finally:
        for kind in reversed(changed):
            try:
                if docker('cat', PATHS[kind]) != configured[kind]:
                    raise RuntimeError('Concurrent native setting change')
                write(kind, originals[kind], 'restore-' + kind)
            except Exception as error:
                failures.append(kind + ':' + type(error).__name__)
        if changed and not failures:
            try:
                restart('restore-native-authentication')
            except Exception as error:
                failures.append('restart:' + type(error).__name__)
        finals = {kind: docker('cat', path) for kind, path in PATHS.items()}
        for kind, raw in finals.items():
            (out / ('final-' + kind)).write_bytes(raw)
        final_parent = projection()
        (out / 'final-parent-authn.properties').write_bytes(final_parent)
        restored = not failures and finals == originals and final_parent == parent_before
        save(out / 'restoration.json', dict(restored=restored, failures=failures,
            originalSha256={kind: SHA(raw) for kind, raw in originals.items()},
            finalSha256={kind: SHA(raw) for kind, raw in finals.items()}))
        child_counts = json.loads((child / 'operation-counts.json').read_text()) if (child / 'operation-counts.json').exists() else {}
        save(out / 'operation-counts.json', dict(restored=restored, humanOperations=0,
            productConfigWrites=sum(row['operation'] == 'product-config-write' for row in operations),
            restorationWrites=sum(row.get('label', '').startswith('restore-') and row['operation'] == 'product-config-write' for row in operations),
            productRestarts=sum(row['operation'] == 'product-restart' for row in operations),
            protocolSubmissions=child_counts.get('target_submissions', 0) + child_counts.get('initial_baseline_submissions', 0),
            preparedActions=child_counts.get('prepared_actions', 0),
            skippedBeforeTarget=child_counts.get('skipped_before_target_submission', 0), verdictAdopted=False))
        capture_target(out, 'shibboleth', 'end')
        if not restored:
            raise RuntimeError('Native authentication restoration incomplete')
    print('Native authentication identity controls captured and restored:', run)


if __name__ == '__main__':
    main()
