#!/usr/bin/env python3
"""Prepare a Run-bound SimpleSAMLphp RSA-SHA1 metadata capability campaign.

The product temporarily signs its own generated metadata with RSA-SHA1. The same installed product
then verifies those exact bytes with its native SAMLParser, with tampered-content, wrong-key and
unsigned controls. The configuration is restored byte-for-byte before the receipt is emitted.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import api, save

CONTAINER = 'samlscope-reference-ssp'
CONFIG = REPO / 'build/acceptance/reference-20260914/ssp-config/config-override.php'
VERIFIER = REPO / 'dev/simplesamlphp/verify_rsa_sha1_metadata_capability.php'
TARGET_METADATA_HOST = 'http://localhost:18380/simplesaml/module.php/saml/idp/metadata'
TARGET_METADATA_SUITE = 'http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata'
TARGET_ENTITY = 'http://localhost:18380/idp'
SIGNER_SOURCE = '/var/simplesamlphp/src/SimpleSAML/Metadata/Signer.php'
PARSER_SOURCE = '/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php'
VERSION_SOURCE = '/var/simplesamlphp/src/SimpleSAML/Configuration.php'
OVERLAY = b"""
// samlscope-rsa-sha1-capability-probe
$config['metadata.sign.enable'] = true;
$config['metadata.sign.privatekey'] = 'server.pem';
$config['metadata.sign.certificate'] = 'server.crt';
$config['metadata.sign.algorithm'] = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
"""
TMP = '/tmp/samlscope-rsa-sha1-capability'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def docker(*args, data=None, check=True):
    return subprocess.run(['docker', 'exec', *(['-i'] if data is not None else []), CONTAINER, *args],
                          input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=check, timeout=90)


def write_in_place(path, value):
    with open(path, 'r+b') as handle:
        handle.seek(0)
        handle.write(value)
        handle.truncate()
    if path.read_bytes() != value:
        raise RuntimeError('Host configuration read-back mismatch')
    for _ in range(30):
        read_back = docker('cat', '/var/simplesamlphp/config/config-override.php').stdout
        if read_back == value:
            return read_back
        time.sleep(0.2)
    raise RuntimeError('Product configuration read-back mismatch')


def fetch_metadata():
    request = urllib.request.Request(TARGET_METADATA_HOST, headers={'Accept': 'application/samlmetadata+xml'})
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status != 200:
            raise RuntimeError('Target metadata HTTP failure')
        return response.read()


def inspect_product():
    raw = subprocess.check_output(['docker', 'inspect', CONTAINER], timeout=30)
    parsed = json.loads(raw)
    if not isinstance(parsed, list) or len(parsed) != 1:
        raise RuntimeError('Ambiguous product container')
    item = parsed[0]
    state = item.get('State', {})
    if state.get('Running') is not True:
        raise RuntimeError('Product container is not running')
    protected = ('/var/simplesamlphp/src', '/var/simplesamlphp/vendor')
    for mount in item.get('Mounts', []):
        destination = mount.get('Destination', '')
        if any(destination == root or destination.startswith(root + '/') for root in protected):
            raise RuntimeError('Product executable source is mount-shadowed')
    return raw, {
        'containerName': item['Name'].removeprefix('/'),
        'containerId': item['Id'],
        'imageId': item['Image'],
        'startedAt': state['StartedAt'],
        'runningAtCapture': True,
    }


def blob(raw):
    return {'base64': base64.b64encode(raw).decode(), 'sha256': SHA(raw)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    original = CONFIG.read_bytes()
    if b'samlscope-rsa-sha1-capability-probe' in original:
        raise RuntimeError('Probe overlay already present')
    configured = original + OVERLAY
    verifier_source = VERIFIER.read_bytes()
    (out / 'original-config.php').write_bytes(original)
    (out / 'configured-config.php').write_bytes(configured)
    (out / 'native-verifier.php').write_bytes(verifier_source)
    inspect_start, runtime = inspect_product()
    (out / 'target-container-inspect-start.json').write_bytes(inspect_start)
    signer_source = docker('cat', SIGNER_SOURCE).stdout
    parser_source = docker('cat', PARSER_SOURCE).stdout
    version_source = docker('cat', VERSION_SOURCE).stdout
    version_match = re.search(rb"public const string VERSION = '([^']+)';", version_source)
    if version_match is None:
        raise RuntimeError('Product version source is unrecognized')
    product_version = docker('php', '-r',
        "require '/var/simplesamlphp/lib/_autoload.php'; echo \\SimpleSAML\\Configuration::VERSION;").stdout.decode()
    if product_version != version_match.group(1).decode():
        raise RuntimeError('Product runtime/version-source mismatch')
    for name, raw in [('target-signer-source.php', signer_source),
                      ('target-parser-source.php', parser_source),
                      ('target-version-source.php', version_source)]:
        (out / name).write_bytes(raw)

    plan = run = None
    configured_read_back = None
    target_metadata = None
    observation_raw = None
    wrong_certificate = None
    restored = False
    try:
        configured_read_back = write_in_place(CONFIG, configured)
        first = fetch_metadata()
        second = fetch_metadata()
        if first != second:
            raise RuntimeError('Generated metadata is not byte-stable')
        target_metadata = first
        if b'http://www.w3.org/2000/09/xmldsig#rsa-sha1' not in target_metadata:
            raise RuntimeError('Target did not generate RSA-SHA1 metadata')
        (out / 'target-metadata.xml').write_bytes(target_metadata)

        created = api('/api/plans', dict(
            name='SimpleSAMLphp native RSA-SHA1 metadata capability', profile='metadata_idp',
            targetKind='IDP', targetEntityId=TARGET_ENTITY, metadataSourceKind='URL',
            metadataSourceLocation=TARGET_METADATA_SUITE, suiteMetadataDelivery='HTTP_URL',
            declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
                metadataRefreshWaitSeconds=300, testUserHint='samlscope-m0-user',
                requestSigningMode='REQUIRED'),
            interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'),
            authorizedTarget=True))
        save(out / 'plan.json', created)
        plan = created['plan']['plan']['id']
        created = api('/api/plans/' + plan + '/runs', {})
        save(out / 'created.json', created)
        run = created['run']['id']
        preflight = api('/api/runs/' + run + '/preflight', {})
        save(out / 'preflight.json', preflight)
        if not any(check['code'] == 'target_metadata' and check['status'] == 'PASS'
                   for check in preflight['checks']):
            raise RuntimeError('Suite did not pin target metadata')
        third = fetch_metadata()
        if target_metadata != third:
            raise RuntimeError('Target metadata changed after Suite snapshot')

        docker('rm', '-rf', TMP)
        docker('mkdir', '-p', TMP)
        docker('sh', '-c', 'cat > ' + TMP + '/metadata.xml', data=target_metadata)
        docker('sh', '-c', 'cat > ' + TMP + '/verifier.php', data=verifier_source)
        wrong = docker('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                       '-subj', '/CN=samlscope-wrong-rsa-sha1-control',
                       '-keyout', TMP + '/wrong.key', '-out', TMP + '/wrong.crt')
        if wrong.returncode != 0:
            raise RuntimeError('Could not prepare wrong-key control')
        wrong_certificate = docker('cat', TMP + '/wrong.crt').stdout
        (out / 'wrong-certificate.pem').write_bytes(wrong_certificate)
        verified = docker('php', TMP + '/verifier.php', TMP + '/metadata.xml',
                          '/var/simplesamlphp/cert/server.crt', TMP + '/wrong.crt', check=False)
        (out / 'native-verifier.stdout').write_bytes(verified.stdout)
        (out / 'native-verifier.stderr').write_bytes(verified.stderr)
        save(out / 'native-verifier-exit.json', {'exitCode': verified.returncode})
        if verified.returncode != 0:
            raise RuntimeError('Native verification controls failed')
        observation = json.loads(verified.stdout)
        observation_raw = verified.stdout
        if observation['inputSha256'] != SHA(target_metadata):
            raise RuntimeError('Native observation input mismatch')
    finally:
        try:
            docker('rm', '-rf', TMP, check=False)
        finally:
            if CONFIG.read_bytes() == configured:
                write_in_place(CONFIG, original)
            elif CONFIG.read_bytes() != original:
                raise RuntimeError('Concurrent configuration change; refusing overwrite')
            restored = CONFIG.read_bytes() == original
            final_read_back = docker('cat', '/var/simplesamlphp/config/config-override.php').stdout
            if final_read_back != original:
                restored = False
            (out / 'final-config.php').write_bytes(final_read_back)
            save(out / 'restoration.json', {
                'restored': restored,
                'originalSha256': SHA(original),
                'finalSha256': SHA(final_read_back),
                'temporaryFilesRemoved': docker('sh', '-c', 'test ! -e ' + TMP).returncode == 0,
            })
    if (not restored or plan is None or run is None or target_metadata is None
            or observation_raw is None or wrong_certificate is None):
        raise RuntimeError('Campaign did not complete with restoration')
    inspect_end, runtime_end = inspect_product()
    (out / 'target-container-inspect-end.json').write_bytes(inspect_end)
    if runtime_end != runtime:
        raise RuntimeError('Product runtime changed during campaign')
    post_restore = fetch_metadata()
    (out / 'post-restore-target-metadata.xml').write_bytes(post_restore)
    if b'<ds:Signature' in post_restore or b'samlscope-rsa-sha1-capability-probe' in post_restore:
        raise RuntimeError('Target metadata remained signed after restoration')

    receipt = {
        'schema': 'samlscope-native-metadata-rsa-sha1-capability-v1',
        'runId': run,
        'caseId': 'IIP-MD05-ah-idp-01',
        'targetEntityId': TARGET_ENTITY,
        'targetMetadataSha256': SHA(target_metadata),
        'evidenceAdapter': 'simplesamlphp-native',
        'configuration': {
            'original': blob(original),
            'configuredReadBack': blob(configured_read_back),
            'restoredReadBack': blob(CONFIG.read_bytes()),
            'restored': True,
        },
        'runtime': {
            **runtime,
            'productVersion': product_version,
            'signerSource': blob(signer_source) | {'path': SIGNER_SOURCE},
            'parserSource': blob(parser_source) | {'path': PARSER_SOURCE},
            'verifierSource': blob(verifier_source) | {
                'path': '/tmp/samlscope-rsa-sha1-capability/verifier.php',
            },
            'versionSource': blob(version_source) | {'path': VERSION_SOURCE},
        },
        'nativeObservation': blob(observation_raw),
        'wrongCertificate': blob(wrong_certificate),
        'nativeVerifierExitCode': 0,
        'nativeVerifierStderr': blob((out / 'native-verifier.stderr').read_bytes()),
        'operationCounts': {
            'productConfigurationWrites': 2,
            'productRestarts': 0,
            'humanOperations': 0,
            'nativeVerificationExecutions': 1,
        },
    }
    save(out / 'receipt.json', receipt)
    save(out / 'operation-counts.json', receipt['operationCounts'] | {
        'runCreations': 1, 'preflightExecutions': 1, 'metadataHttpGets': 4,
        'restored': True,
    })
    print('Run', run, 'receipt', SHA((out / 'receipt.json').read_bytes()), 'restored', restored)


if __name__ == '__main__':
    main()
