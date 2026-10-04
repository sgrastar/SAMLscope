#!/usr/bin/env python3
"""Verify the SimpleSAMLphp MD05.ah campaign without trusting receipt summary strings."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

SCHEMA = 'samlscope-native-metadata-rsa-sha1-capability-v1'
OBSERVATION_SCHEMA = 'samlscope-simplesamlphp-rsa-sha1-verification-v1'
CASE = 'IIP-MD05-ah-idp-01'
ENTITY = 'http://localhost:18380/idp'
RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
DS = 'http://www.w3.org/2000/09/xmldsig#'
CONTAINER = 'samlscope-reference-ssp'
SOURCE = Path(__file__).resolve().parents[1] / 'simplesamlphp/verify_rsa_sha1_metadata_capability.php'
SOURCE_SHA = '5f6a92c2d3af39391dbb7e7e063ae16ea7240ff4045d81562397159690803d20'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def decoded(node):
    raw = base64.b64decode(node['base64'], validate=True)
    assert node['sha256'] == SHA(raw)
    return raw


def certificate_der(root):
    values = root.findall('./{%s}Signature/{%s}KeyInfo/{%s}X509Data/{%s}X509Certificate' % (
        DS, DS, DS, DS))
    assert len(values) == 1 and values[0].text
    return base64.b64decode(''.join(values[0].text.split()), validate=True)


def validate_receipt(receipt, folder):
    target = (folder / 'target-metadata.xml').read_bytes()
    assert receipt['schema'] == SCHEMA and receipt['caseId'] == CASE
    assert re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', receipt['runId'])
    if (folder / 'created.json').exists():
        assert receipt['runId'] == json.loads((folder / 'created.json').read_text())['run']['id']
    assert receipt['targetEntityId'] == ENTITY and receipt['targetMetadataSha256'] == SHA(target)
    assert receipt['evidenceAdapter'] == 'simplesamlphp-native'
    root = ET.fromstring(target)
    assert root.tag == '{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor'
    assert root.attrib['entityID'] == ENTITY
    methods = root.findall('.//{%s}SignatureMethod' % DS)
    assert len(methods) == 1 and methods[0].attrib['Algorithm'] == RSA_SHA1
    cert_sha = SHA(certificate_der(root))

    config = receipt['configuration']
    original = decoded(config['original'])
    configured = decoded(config['configuredReadBack'])
    restored = decoded(config['restoredReadBack'])
    assert config['restored'] is True and original == restored and original != configured
    assert original == (folder / 'original-config.php').read_bytes()
    assert configured == (folder / 'configured-config.php').read_bytes()
    assert restored == (folder / 'final-config.php').read_bytes()
    for token in (b'samlscope-rsa-sha1-capability-probe', b"metadata.sign.enable'] = true",
                  b"metadata.sign.privatekey'] = 'server.pem'", b"metadata.sign.certificate'] = 'server.crt'",
                  RSA_SHA1.encode()):
        assert token in configured and token not in original

    runtime = receipt['runtime']
    assert runtime['runningAtCapture'] is True
    assert runtime['containerName'] == CONTAINER
    assert re.fullmatch(r'[0-9a-f]{64}', runtime['containerId'])
    assert re.fullmatch(r'sha256:[0-9a-f]{64}', runtime['imageId'])
    assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?', runtime['productVersion'])
    signer = decoded(runtime['signerSource'])
    parser = decoded(runtime['parserSource'])
    verifier = decoded(runtime['verifierSource'])
    version = decoded(runtime['versionSource'])
    assert runtime['signerSource']['path'] == '/var/simplesamlphp/src/SimpleSAML/Metadata/Signer.php'
    assert runtime['parserSource']['path'] == '/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php'
    assert runtime['verifierSource']['path'] == '/tmp/samlscope-rsa-sha1-capability/verifier.php'
    assert runtime['versionSource']['path'] == '/var/simplesamlphp/src/SimpleSAML/Configuration.php'
    assert SHA(verifier) == SOURCE_SHA and verifier == SOURCE.read_bytes()
    assert signer == (folder / 'target-signer-source.php').read_bytes()
    assert parser == (folder / 'target-parser-source.php').read_bytes()
    assert version == (folder / 'target-version-source.php').read_bytes()
    assert b'metadata.sign.algorithm' in signer and b'XMLSecurityKey::RSA_SHA1' in signer
    assert b'function validateSignature(array $certificates): bool' in parser
    assert b'$validator->validate($key)' in parser
    assert ("public const string VERSION = '%s';" % runtime['productVersion']).encode() in version

    observation_raw = decoded(receipt['nativeObservation'])
    assert observation_raw == (folder / 'native-verifier.stdout').read_bytes()
    observation = json.loads(observation_raw)
    assert observation == json.loads((folder / 'native-verifier.stdout').read_text())
    assert observation['schema'] == OBSERVATION_SCHEMA
    assert observation['inputSha256'] == SHA(target)
    assert observation['targetEntityId'] == ENTITY and observation['signatureAlgorithm'] == RSA_SHA1
    assert observation['trustedCertificateSha256'] == cert_sha
    wrong_certificate = decoded(receipt['wrongCertificate'])
    assert wrong_certificate == (folder / 'wrong-certificate.pem').read_bytes()
    wrong_der = base64.b64decode(b''.join(
        line for line in wrong_certificate.splitlines() if not line.startswith(b'-----')), validate=True)
    assert observation['wrongCertificateSha256'] == SHA(wrong_der) != cert_sha
    tampered = base64.b64decode(observation['tamperedInputBase64'], validate=True)
    unsigned = base64.b64decode(observation['unsignedInputBase64'], validate=True)
    assert observation['tamperedInputSha256'] == SHA(tampered)
    assert observation['unsignedInputSha256'] == SHA(unsigned)
    tampered_root = ET.fromstring(tampered)
    unsigned_root = ET.fromstring(unsigned)
    assert tampered_root.attrib['entityID'] == ENTITY + '#tampered'
    assert len(tampered_root.findall('./{%s}Signature' % DS)) == 1
    assert unsigned_root.attrib['entityID'] == ENTITY
    assert len(unsigned_root.findall('./{%s}Signature' % DS)) == 0
    assert observation['positiveAccepted'] is True
    assert observation['tamperedAccepted'] is False
    assert observation['wrongKeyAccepted'] is False
    assert observation['unsignedAccepted'] is False
    assert receipt['nativeVerifierExitCode'] == 0
    assert decoded(receipt['nativeVerifierStderr']) == b''
    assert receipt['operationCounts'] == {
        'productConfigurationWrites': 2, 'productRestarts': 0,
        'humanOperations': 0, 'nativeVerificationExecutions': 1,
    }
    return target, observation


def mutation_controls(receipt, folder):
    mutations = []
    def mutate(name, fn):
        changed = copy.deepcopy(receipt); fn(changed); mutations.append((name, changed))
    def replace_blob(node, raw):
        node['base64'] = base64.b64encode(raw).decode()
        node['sha256'] = SHA(raw)
    mutate('run', lambda x: x.__setitem__('runId', 'run_00000000000000000000000000'))
    mutate('target-hash', lambda x: x.__setitem__('targetMetadataSha256', '0' * 64))
    mutate('adapter', lambda x: x.__setitem__('evidenceAdapter', 'suite-native'))
    mutate('restore', lambda x: x['configuration'].__setitem__('restored', False))
    mutate('final-bytes', lambda x: replace_blob(x['configuration']['restoredReadBack'], b'changed'))
    mutate('source-hash', lambda x: x['runtime']['verifierSource'].__setitem__('sha256', '0' * 64))
    mutate('source-bytes', lambda x: replace_blob(x['runtime']['verifierSource'], b'<?php echo "forged";'))
    mutate('product-source', lambda x: replace_blob(x['runtime']['signerSource'], b'<?php // forged'))
    def false_positive(x):
        observation = json.loads(decoded(x['nativeObservation']))
        observation['positiveAccepted'] = False
        replace_blob(x['nativeObservation'], (json.dumps(observation, indent=4) + '\n').encode())
    mutate('positive', false_positive)
    for field in ('tamperedAccepted', 'wrongKeyAccepted', 'unsignedAccepted'):
        def accepted(x, field=field):
            observation = json.loads(decoded(x['nativeObservation']))
            observation[field] = True
            replace_blob(x['nativeObservation'], (json.dumps(observation, indent=4) + '\n').encode())
        mutate(field, accepted)
    mutate('observation-hash', lambda x: x['nativeObservation'].__setitem__('sha256', '0' * 64))
    mutate('wrong-certificate', lambda x: replace_blob(x['wrongCertificate'], b'forged'))
    rejected = {}
    for name, changed in mutations:
        try:
            validate_receipt(changed, folder)
            rejected[name] = False
        except (AssertionError, KeyError, ValueError, TypeError):
            rejected[name] = True
    assert all(rejected.values())
    return rejected


def verify(root, product='simplesamlphp'):
    assert product == 'simplesamlphp'
    folder = Path(root) / 'ssp-rsa-sha1-metadata-v151'
    receipt = json.loads((folder / 'receipt.json').read_text())
    target, observation = validate_receipt(receipt, folder)
    assert json.loads((folder / 'created.json').read_text())['run']['id'] == receipt['runId']
    preflight = json.loads((folder / 'preflight.json').read_text())
    assert any(row['code'] == 'target_metadata' and row['status'] == 'PASS' for row in preflight['checks'])
    restoration = json.loads((folder / 'restoration.json').read_text())
    assert restoration['restored'] and restoration['originalSha256'] == restoration['finalSha256']
    assert restoration['temporaryFilesRemoved']
    controls = mutation_controls(receipt, folder)
    verification = {
        'schema': 'samlscope-rsa-sha1-acceptance-verification-v1',
        'run': receipt['runId'],
        'receiptSha256': SHA((folder / 'receipt.json').read_bytes()),
        'targetMetadataSha256': SHA(target),
        'nativeObservationSha256': SHA((folder / 'native-verifier.stdout').read_bytes()),
        'mutationControls': controls,
        'observation': observation,
    }
    if (folder / 'result.json').exists():
        raw = (folder / 'result.json').read_bytes()
        result = json.loads(raw)
        cases = {case['id']: case for requirement in result['requirements'] for case in requirement['cases']}
        case = cases[CASE]
        assert result['run']['id'] == receipt['runId']
        assert result['target']['metadata_digest'] == 'sha256:' + SHA(target)
        assert (case['outcome'], case['verdict'], case['reason_code'], case['attested']) == (
            'SATISFIED', 'PASS', 'metadata.rsa-sha1.observed', False)
        verification['resultSha256'] = SHA(raw)
        verification['adoptable'] = True
        (folder / 'acceptance-verification.json').write_text(json.dumps(verification, indent=2) + '\n')
        return folder / 'result.json', {CASE: case}
    verification['adoptable'] = False
    (folder / 'acceptance-verification.json').write_text(json.dumps(verification, indent=2) + '\n')
    return None, {}


if __name__ == '__main__':
    import sys
    path, cases = verify(sys.argv[1])
    print('prepared' if path is None else cases[CASE]['verdict'])
