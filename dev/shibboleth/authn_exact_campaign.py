#!/usr/bin/env python3
"""Prepare a native exact-DeclRef, share ordinary SSO, and restore the product verbatim."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/shibboleth'))
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
from attribute_name_capability import docker, CONTAINER
from public_runtime_capture import capture_target

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PATH = '/opt/reference-idp/conf/authn/authn.properties'
KEY = 'idp.authn.Password.supportedPrincipals'
PRINCIPALS = ', '.join([
    'saml2/urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
    'saml2/urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
    'saml1/urn:oasis:names:tc:SAML:1.0:am:password',
    'saml2declref/urn:samlscope:fixture:authn-context-decl'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    original = docker('cat', PATH)
    if re.search(rb'^\s*idp\.authn\.Password\.supportedPrincipals\s*[=:]', original, re.M):
        raise ValueError('Existing Password principal override needs explicit adaptation before login')
    configured = original + ('\n# Temporary exact AuthnContext fixture; restored after collection.\n'
                             + KEY + ' = ' + PRINCIPALS + '\n').encode()
    (out / 'original-authn.properties').write_bytes(original)
    (out / 'configured-authn.properties').write_bytes(configured)
    operations = []
    changed = False

    def save(name, value):
        (out / name).write_text(json.dumps(value, indent=2) + '\n')

    def write(raw, label):
        record = dict(operation='configuration-write', label=label, sha256=SHA(raw), read_back=False)
        operations.append(record)
        save('operations-in-progress.json', operations)
        docker('sh', '-c', 'cat > ' + PATH, data=raw)
        if docker('cat', PATH) != raw:
            raise RuntimeError('Native authentication property read-back mismatch')
        record['read_back'] = True

    def restart(label):
        record = dict(operation='container-restart', label=label, completed=False)
        operations.append(record)
        save('operations-in-progress.json', operations)
        subprocess.run(['docker', 'restart', CONTAINER], check=True, capture_output=True, timeout=60)
        docker('/usr/local/tomcat/bin/catalina.sh', 'start')
        operations.append(dict(operation='tomcat-start', label=label, completed=True))
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen('http://localhost:18280/idp/shibboleth', timeout=3) as response:
                    if response.status == 200:
                        record['completed'] = True
                        return
            except Exception:
                pass
            time.sleep(1)
        raise RuntimeError('Native metadata endpoint did not become ready')

    failures = []
    capture_target(out, 'shibboleth', 'start')
    try:
        changed = True
        write(configured, 'prepare-exact-context')
        restart('prepare-exact-context')
        (out / 'configured-authn-readback.properties').write_bytes(docker('cat', PATH))
        if (out / 'configured-authn-readback.properties').read_bytes() != configured:
            raise RuntimeError('Native preparation changed before sending SAML')
        spec = importlib.util.spec_from_file_location('exact_browser_chain',
                                                      REPO / 'dev/shibboleth/browser_chain_campaign.py')
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        driver.capture_target_runtime = capture_target
        prior = sys.argv
        try:
            sys.argv = [str(REPO / 'dev/shibboleth/browser_chain_campaign.py'),
                        '--output', str(out / 'browser'), '--only-cases',
                        'IIP-IDP08-a-idp-01,IIP-IDP12-d-idp-01,IIP-IDP12-f-idp-01',
                        '--reuse-session']
            driver.main()
        finally:
            sys.argv = prior
        after = docker('cat', PATH)
        (out / 'after-authn-readback.properties').write_bytes(after)
        if after != configured:
            raise RuntimeError('Native exact-context setup changed during SAML collection')
    finally:
        if changed:
            try:
                if docker('cat', PATH) != configured:
                    raise RuntimeError('Concurrent native authentication configuration change')
                write(original, 'restore-authentication')
                restart('restore-authentication')
            except Exception as error:
                failures.append(type(error).__name__)
        final = docker('cat', PATH)
        (out / 'final-authn.properties').write_bytes(final)
        restored = not failures and final == original
        save('restoration.json', dict(restored=restored, failures=failures,
                                     original_sha256=SHA(original), final_sha256=SHA(final)))
        save('operations.json', operations)
        save('operation-counts.json', dict(restored=restored, person_operations=0,
             product_configuration_writes=sum(row['operation'] == 'configuration-write' for row in operations),
             restoration_writes=sum(row.get('label') == 'restore-authentication'
                                    and row['operation'] == 'configuration-write' for row in operations),
             product_restarts=sum(row['operation'] == 'container-restart' for row in operations)))
        capture_target(out, 'shibboleth', 'end')
        if not restored:
            raise RuntimeError('Native authentication restoration incomplete')
    print('Exact AuthnContext native preparation restored; inspect original outcomes before adoption')


if __name__ == '__main__':
    main()
