#!/usr/bin/env python3
"""Record installed Shibboleth metadata signer/filter capability without changing IdP settings.

The existing private key stays inside the product container. Only its hash, public certificates,
native public library bytes and original observations leave it. This collector assigns no outcome.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.request
import zipfile

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import api, save

CONTAINER = 'samlscope-reference-shibboleth'
ENTITY = 'http://localhost:18280/idp/shibboleth'
LIB = '/opt/shibboleth-idp/dist/webapp/WEB-INF/lib/'
CREDENTIALS = '/opt/reference-idp/credentials/'
SOURCE = REPO / 'dev/shibboleth/ShibbolethRsaSha1MetadataCapability.java'
NATIVE = {
    'org.opensaml.core.config.InitializationService': 'opensaml-core-api-5.2.3.jar',
    'org.opensaml.saml.metadata.resolver.filter.impl.SignatureValidationFilter': 'opensaml-saml-impl-5.2.3.jar',
    'org.opensaml.xmlsec.signature.support.SignatureSupport': 'opensaml-xmlsec-api-5.2.3.jar',
    'org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine': 'opensaml-xmlsec-impl-5.2.3.jar',
    'net.shibboleth.idp.Version': 'idp-core-5.2.3.jar',
}
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def command(args, check=True):
    return subprocess.run(args, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=90)


def native(*args, check=True):
    return command(['docker', 'exec', CONTAINER, *args], check=check)


def blob(raw):
    return {'base64': base64.b64encode(raw).decode(), 'sha256': SHA(raw)}


def inspection():
    source = json.loads(command(['docker', 'inspect', CONTAINER]).stdout)[0]
    value = {'Id': source['Id'], 'Image': source['Image'], 'Name': source['Name'],
             'State': {k: source['State'][k] for k in ('Running', 'StartedAt')},
             'Mounts': [{'Destination': m['Destination']} for m in source['Mounts']]}
    if value['State']['Running'] is not True:
        raise RuntimeError('Native product is stopped')
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def configuration():
    key_sha = native('sha256sum', CREDENTIALS + 'idp-signing.key').stdout.decode().split()[0]
    cert = native('cat', CREDENTIALS + 'idp-signing.crt').stdout
    wrong = native('cat', CREDENTIALS + 'idp-encryption.crt').stdout
    value = dict(signingKeySha256=key_sha, signingCertificate=blob(cert), wrongCertificate=blob(wrong))
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode(), wrong


def observation(raw):
    return json.loads(raw.decode().strip().splitlines()[-1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    before = inspection()
    config_before, wrong = configuration()
    (out / 'target-container-inspect-start.json').write_bytes(before)
    (out / 'configuration-before.json').write_bytes(config_before)
    source = SOURCE.read_bytes()
    (out / SOURCE.name).write_bytes(source)
    # Silence incidental library diagnostics in this isolated JVM only; observations remain whole stdout.
    logging = b'<configuration><root level="OFF"/></configuration>\n'
    (out / 'native-logback.xml').write_bytes(logging)
    with urllib.request.urlopen(ENTITY, timeout=30) as response:
        unsigned = response.read()
    (out / 'unsigned-target-metadata.xml').write_bytes(unsigned)
    temporary = '/tmp/samlscope-rsa-sha1-capability-' + SHA(str(out).encode())[:16]
    native('mkdir', temporary)
    try:
        command(['docker', 'cp', str(SOURCE), CONTAINER + ':' + temporary + '/' + SOURCE.name])
        command(['docker', 'cp', str(out / 'unsigned-target-metadata.xml'), CONTAINER + ':' + temporary + '/unsigned.xml'])
        command(['docker', 'cp', str(out / 'native-logback.xml'), CONTAINER + ':' + temporary + '/logback.xml'])
        compiled = native('javac', '-cp', LIB + '*', '-d', temporary,
                          temporary + '/' + SOURCE.name, check=False)
        (out / 'compile.stdout').write_bytes(compiled.stdout)
        (out / 'compile.stderr').write_bytes(compiled.stderr)
        if compiled.returncode != 0:
            raise RuntimeError('Native helper compile failed')
        cp = temporary + ':' + LIB + '*'
        signer = native('java', '-Dlogback.configurationFile=' + temporary + '/logback.xml', '-cp', cp, 'ShibbolethRsaSha1MetadataCapability', 'sign-and-verify',
                        temporary + '/unsigned.xml', CREDENTIALS + 'idp-signing.key',
                        CREDENTIALS + 'idp-signing.crt', CREDENTIALS + 'idp-encryption.crt', check=False)
        (out / 'signer.stdout').write_bytes(signer.stdout)
        (out / 'signer.stderr').write_bytes(signer.stderr)
        if signer.returncode != 0:
            raise RuntimeError('Native metadata signer failed')
        signed = native('cat', temporary + '/unsigned.xml.signed').stdout
        (out / 'target-metadata.xml').write_bytes(signed)
        verifier = native('java', '-Dlogback.configurationFile=' + temporary + '/logback.xml', '-cp', cp, 'ShibbolethRsaSha1MetadataCapability', 'verify',
                          temporary + '/unsigned.xml.signed', '/dev/null',
                          CREDENTIALS + 'idp-signing.crt', CREDENTIALS + 'idp-encryption.crt', check=False)
        (out / 'native-verifier.stdout').write_bytes(verifier.stdout)
        (out / 'native-verifier.stderr').write_bytes(verifier.stderr)
        if verifier.returncode != 0:
            raise RuntimeError('Native metadata verifier failed')
        observations = [observation(signer.stdout), observation(verifier.stdout)]
        for item in observations:
            if item['signedSha256'] != SHA(signed) or item['productVersion'] != '5.2.3':
                raise RuntimeError('Native observation mismatches signed original')
            if not item['positive']['accepted'] or any(item[k]['accepted'] for k in ('tampered', 'wrongKey', 'unsigned')):
                raise RuntimeError('Native controls did not prove capability')
        classes = {}
        jars = out / 'native-libraries'; jars.mkdir()
        for name, jar in NATIVE.items():
            path = jars / jar
            command(['docker', 'cp', CONTAINER + ':' + LIB + jar, str(path)])
            class_file = name.replace('.', '/') + '.class'
            with zipfile.ZipFile(path) as archive:
                raw = archive.read(class_file)
            classes[name] = {'jar': LIB + jar, 'classFile': class_file, 'original': blob(raw)}
    finally:
        native('rm', '-rf', temporary)
    after = inspection()
    config_after, _ = configuration()
    (out / 'target-container-inspect-end.json').write_bytes(after)
    (out / 'configuration-after.json').write_bytes(config_after)
    if before != after or config_before != config_after:
        raise RuntimeError('Native runtime or credentials changed')
    target = api('/api/targets', dict(name='Shibboleth installed RSA-SHA1 metadata capability',
        entityId=ENTITY, metadataXml=signed.decode(), authorizedTarget=True, expectedRole='IDP'))
    save(out / 'target.json', target)
    created = api('/api/plans', dict(name='Shibboleth native RSA-SHA1 metadata capability',
        profile='metadata_idp', suiteMetadataDelivery='HTTP_URL', targetConnectionId=target['id'],
        targetRevisionId=target['revisions'][0]['id'], declaredFeatures={},
        parameters=dict(clockSkewToleranceSeconds=180, metadataRefreshWaitSeconds=300,
            testUserHint='samlscope-m0-user', requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    save(out / 'plan.json', created)
    plan = created['plan']['plan']['id']
    created = api('/api/plans/' + plan + '/runs', {})
    save(out / 'created.json', created)
    run = created['run']['id']
    preflight = api('/api/runs/' + run + '/preflight', {})
    save(out / 'preflight.json', preflight)
    if not any(row['code'] == 'target_metadata' and row['status'] == 'PASS' for row in preflight['checks']):
        raise RuntimeError('Suite did not accept the native-signed snapshot')
    counts = dict(productConfigurationWrites=0, productRestarts=0, humanOperations=0,
                  nativeVerificationExecutions=2)
    receipt = dict(schema='samlscope-native-metadata-rsa-sha1-capability-v1', runId=run,
        caseId='IIP-MD05-ah-idp-01', targetEntityId=ENTITY, targetMetadataSha256=SHA(signed),
        evidenceAdapter='shibboleth-native-jvm', configuration=dict(before=blob(config_before), after=blob(config_after)),
        runtime=dict(before=blob(before), after=blob(after), productVersion='5.2.3', verifierSource=blob(source), nativeClasses=classes),
        originalUnsignedMetadata=blob(unsigned), signerObservation=blob(signer.stdout), signerExitCode=signer.returncode,
        signerStderr=blob(signer.stderr), nativeObservation=blob(verifier.stdout), wrongCertificate=blob(wrong),
        nativeVerifierExitCode=verifier.returncode, nativeVerifierStderr=blob(verifier.stderr), operationCounts=counts)
    save(out / 'receipt.json', receipt)
    save(out / 'operation-counts.json', counts | dict(runCreations=1, preflightExecutions=1,
        nativeHelperCompiles=1, temporaryFilesRemoved=True, runtimeUnchanged=True, credentialsUnchanged=True,
        productPrivateKeyExported=False))
    save(out / 'restoration.json', dict(runtimeUnchanged=True, credentialsUnchanged=True,
        temporaryFilesRemoved=True, originalConfigurationSha256=SHA(config_before), finalConfigurationSha256=SHA(config_after)))
    print(json.dumps(dict(run=run, receiptSha256=SHA((out / 'receipt.json').read_bytes()), restored=True)))


if __name__ == '__main__':
    main()
