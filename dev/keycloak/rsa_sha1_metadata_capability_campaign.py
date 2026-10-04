#!/usr/bin/env python3
"""Prepare a Run-bound Keycloak RSA-SHA1 metadata capability receipt.

The campaign executes the installed Keycloak SAML signer and verifier in an isolated JVM. It first
records the reference image's default Java policy rejecting RSA-SHA1, then runs the same verifier
with a process-local policy override. The live Keycloak server is never reconfigured or restarted.
All temporary private keys and container files are removed before the receipt is emitted.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.request

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import api, save

CONTAINER = 'samlscope-reference-keycloak'
TARGET_HOST = 'http://localhost:18180/realms/samlscope/protocol/saml/descriptor'
TARGET_ENTITY = 'http://localhost:18180/realms/samlscope'
SOURCE = REPO / 'dev/keycloak/KeycloakRsaSha1MetadataCapability.java'
CORE_JAR = '/opt/keycloak/lib/lib/main/org.keycloak.keycloak-saml-core-26.7.2.jar'
PUBLIC_JAR = '/opt/keycloak/lib/lib/main/org.keycloak.keycloak-saml-core-public-26.7.2.jar'
TMP = '/tmp/samlscope-keycloak-rsa-sha1-capability'
POLICY = b'jdk.xml.dsig.secureValidationPolicy=\n'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def command(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=kwargs.pop('timeout', 90), **kwargs)


def docker(*args, check=True):
    return subprocess.run(['docker', 'exec', CONTAINER, *args], check=check,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)


def inspect_product():
    raw = command(['docker', 'inspect', CONTAINER]).stdout
    parsed = json.loads(raw)
    if not isinstance(parsed, list) or len(parsed) != 1:
        raise RuntimeError('Ambiguous product container')
    item = parsed[0]
    state = item.get('State', {})
    if state.get('Running') is not True:
        raise RuntimeError('Product container is not running')
    protected = ('/opt/keycloak/lib', '/opt/keycloak/bin')
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


def fetch_target():
    with urllib.request.urlopen(TARGET_HOST, timeout=30) as response:
        if response.status != 200:
            raise RuntimeError('Keycloak metadata endpoint unavailable')
        return response.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--target-connection', help='Append a new immutable revision to this prior campaign target')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = SOURCE.read_bytes()
    inspect_start, runtime = inspect_product()
    (out / 'target-container-inspect-start.json').write_bytes(inspect_start)
    unsigned = fetch_target()
    (out / 'unsigned-target-metadata.xml').write_bytes(unsigned)
    temporary_removed = False

    with tempfile.TemporaryDirectory(prefix='samlscope-keycloak-md05ah-') as temporary:
        work = Path(temporary)
        core = work / 'keycloak-saml-core.jar'
        public = work / 'keycloak-saml-core-public.jar'
        command(['docker', 'cp', CONTAINER + ':' + CORE_JAR, str(core)])
        command(['docker', 'cp', CONTAINER + ':' + PUBLIC_JAR, str(public)])
        (out / 'target-keycloak-saml-core.jar').write_bytes(core.read_bytes())
        (out / 'target-keycloak-saml-core-public.jar').write_bytes(public.read_bytes())
        (out / 'native-verifier.java').write_bytes(source)
        classes = work / 'classes'
        classes.mkdir()
        command(['javac', '--release', '21', '-cp', str(core) + ':' + str(public),
                 '-d', str(classes), str(SOURCE)])
        (work / 'unsigned.xml').write_bytes(unsigned)
        command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                 '-subj', '/CN=samlscope-keycloak-rsa-sha1', '-keyout', str(work / 'key.pem'),
                 '-out', str(work / 'cert.pem')])
        command(['openssl', 'pkcs8', '-topk8', '-inform', 'PEM', '-outform', 'DER',
                 '-in', str(work / 'key.pem'), '-nocrypt', '-out', str(work / 'key.der')])
        command(['openssl', 'x509', '-in', str(work / 'cert.pem'), '-outform', 'DER',
                 '-out', str(work / 'cert.der')])
        command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                 '-subj', '/CN=samlscope-keycloak-rsa-sha1-wrong',
                 '-keyout', str(work / 'wrong-key.pem'), '-out', str(work / 'wrong-cert.pem')])
        command(['openssl', 'x509', '-in', str(work / 'wrong-cert.pem'), '-outform', 'DER',
                 '-out', str(work / 'wrong-cert.der')])
        (work / 'capability-security.properties').write_bytes(POLICY)

        docker('rm', '-rf', TMP, check=False)
        docker('mkdir', '-p', TMP)
        command(['docker', 'cp', str(classes) + '/.', CONTAINER + ':' + TMP + '/'])
        for name in ('unsigned.xml', 'key.der', 'cert.der', 'wrong-cert.der',
                     'capability-security.properties'):
            command(['docker', 'cp', str(work / name), CONTAINER + ':' + TMP + '/' + name])
        command(['docker', 'exec', '-u', '0', CONTAINER, 'chmod', '-R', 'a+rX', TMP])
        classpath = TMP + ':/opt/keycloak/lib/lib/main/*:/opt/keycloak/lib/lib/boot/*'
        policy_process = docker('java', '-XshowSettings:security:properties', '-version')
        default_security_policy = policy_process.stdout + policy_process.stderr
        if (b'jdk.xml.dsig.secureValidationPolicy=' not in default_security_policy
                or b'disallowAlg http://www.w3.org/2000/09/xmldsig#rsa-sha1'
                    not in default_security_policy):
            raise RuntimeError('Default JVM RSA-SHA1 policy could not be pinned')
        (out / 'default-security-properties.txt').write_bytes(default_security_policy)
        default = subprocess.run(['docker', 'exec', CONTAINER, 'java', '-cp', classpath,
            'KeycloakRsaSha1MetadataCapability', 'default', TMP + '/unsigned.xml', TMP + '/key.der',
            TMP + '/cert.der', TMP + '/wrong-cert.der'], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=90)
        (out / 'default-policy-verifier.stdout').write_bytes(default.stdout)
        (out / 'default-policy-verifier.stderr').write_bytes(default.stderr)
        save(out / 'default-policy-verifier-exit.json', {'exitCode': default.returncode})
        if default.returncode != 0:
            raise RuntimeError('Default-policy native verifier did not prove policy disablement')
        signed = docker('cat', TMP + '/unsigned.xml.signed').stdout
        (out / 'target-metadata.xml').write_bytes(signed)
        capability = subprocess.run(['docker', 'exec', CONTAINER, 'java',
            '-Djava.security.properties=' + TMP + '/capability-security.properties', '-cp', classpath,
            'KeycloakRsaSha1MetadataCapability', 'capability', TMP + '/unsigned.xml.signed',
            TMP + '/key.der', TMP + '/cert.der', TMP + '/wrong-cert.der'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        (out / 'native-verifier.stdout').write_bytes(capability.stdout)
        (out / 'native-verifier.stderr').write_bytes(capability.stderr)
        save(out / 'native-verifier-exit.json', {'exitCode': capability.returncode})
        if capability.returncode != 0:
            raise RuntimeError('Capability-policy native verifier controls failed')
        default_observation = json.loads(default.stdout)
        observation = json.loads(capability.stdout)
        if default_observation['inputSha256'] != SHA(signed) or observation['inputSha256'] != SHA(signed):
            raise RuntimeError('Native observations do not bind the signed target metadata')
        wrong_certificate = (work / 'wrong-cert.der').read_bytes()

        if args.target_connection:
            if not re.fullmatch(r'target_[0-9A-HJKMNP-TV-Z]{26}', args.target_connection):
                raise ValueError('Invalid prior target connection ID')
            target = api('/api/targets/' + args.target_connection + '/revisions', dict(
                entityId=TARGET_ENTITY, metadataXml=signed.decode(), authorizedTarget=True,
                expectedRole='IDP'))
        else:
            target = api('/api/targets', dict(
                name='Keycloak native RSA-SHA1 metadata capability', entityId=TARGET_ENTITY,
                metadataXml=signed.decode(), authorizedTarget=True, expectedRole='IDP'))
        save(out / 'target.json', target)
        connection = target['id']
        revision = target['revisions'][0]['id']
        if not re.fullmatch(r'target_[0-9A-HJKMNP-TV-Z]{26}', connection):
            raise RuntimeError('Invalid target connection ID')
        if not re.fullmatch(r'metadata_[0-9A-HJKMNP-TV-Z]{26}', revision):
            raise RuntimeError('Invalid target revision ID')
        created = api('/api/plans', dict(
            name='Keycloak native RSA-SHA1 metadata capability', profile='metadata_idp',
            suiteMetadataDelivery='HTTP_URL', targetConnectionId=connection,
            targetRevisionId=revision, declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
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
        if not any(row['code'] == 'target_metadata' and row['status'] == 'PASS'
                   for row in preflight['checks']):
            raise RuntimeError('Suite did not accept the product-signed target snapshot')

        receipt = {
            'schema': 'samlscope-native-metadata-rsa-sha1-capability-v1',
            'runId': run,
            'caseId': 'IIP-MD05-ah-idp-01',
            'targetEntityId': TARGET_ENTITY,
            'targetMetadataSha256': SHA(signed),
            'evidenceAdapter': 'keycloak-native-jvm',
            'configuration': {
                'defaultSecurityPolicy': blob(default_security_policy),
                'capabilitySecurityPolicy': blob(POLICY),
                'serverConfigurationUnchanged': True,
            },
            'runtime': {
                **runtime,
                'productVersion': '26.7.2',
                'coreLibrary': blob(core.read_bytes()) | {'path': CORE_JAR},
                'publicLibrary': blob(public.read_bytes()) | {'path': PUBLIC_JAR},
                'verifierSource': blob(source) | {
                    'path': TMP + '/KeycloakRsaSha1MetadataCapability.java',
                },
            },
            'defaultPolicyObservation': blob(default.stdout),
            'defaultPolicyVerifierExitCode': default.returncode,
            'defaultPolicyVerifierStderr': blob(default.stderr),
            'nativeObservation': blob(capability.stdout),
            'wrongCertificate': blob(wrong_certificate),
            'nativeVerifierExitCode': capability.returncode,
            'nativeVerifierStderr': blob(capability.stderr),
            'operationCounts': {
                'productConfigurationWrites': 0,
                'productRestarts': 0,
                'humanOperations': 0,
                'nativeVerificationExecutions': 2,
            },
        }
        save(out / 'receipt.json', receipt)
        save(out / 'operation-counts.json', receipt['operationCounts'] | {
            'runCreations': 1, 'preflightExecutions': 1,
            'targetConnectionRegistrations': 0 if args.target_connection else 1,
            'targetRevisionRegistrations': 1,
            'temporaryPrivateKeysPersisted': 0, 'serverConfigurationUnchanged': True,
        })
        docker('rm', '-rf', TMP)
        temporary_removed = docker('sh', '-c', 'test ! -e ' + TMP).returncode == 0

    inspect_end, runtime_end = inspect_product()
    (out / 'target-container-inspect-end.json').write_bytes(inspect_end)
    if runtime_end != runtime or not temporary_removed:
        raise RuntimeError('Product runtime changed or temporary files remain')
    if fetch_target() != unsigned:
        raise RuntimeError('Live Keycloak target metadata changed during isolated probe')
    save(out / 'restoration.json', {
        'serverConfigurationUnchanged': True,
        'containerRuntimeUnchanged': True,
        'temporaryFilesRemoved': True,
        'originalMetadataSha256': SHA(unsigned),
        'finalMetadataSha256': SHA(fetch_target()),
    })
    print('Run', run, 'receipt', SHA((out / 'receipt.json').read_bytes()), 'restored', True)


if __name__ == '__main__':
    main()
