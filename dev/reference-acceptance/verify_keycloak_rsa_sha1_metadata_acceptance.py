#!/usr/bin/env python3
"""Independently verify the Keycloak MD05.ah native capability campaign."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

SCHEMA = 'samlscope-native-metadata-rsa-sha1-capability-v1'
OBSERVATION_SCHEMA = 'samlscope-keycloak-rsa-sha1-verification-v1'
CASE = 'IIP-MD05-ah-idp-01'
ENTITY = 'http://localhost:18180/realms/samlscope'
RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
DIGEST_SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1'
DS = 'http://www.w3.org/2000/09/xmldsig#'
IMAGE = 'sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067'
VERSION = '26.7.2'
CORE_SHA = '191794d8be9289121c628f5e69380771b67f72ea869207248c2bbda253979e84'
PUBLIC_SHA = 'e1262687b87e92edb759b02d568fed8518d5e00b32a70749bee61a787178bbb2'
SOURCE_SHA = '2589889c0bf09c720600bcda09a2856dd6cf02bf0fe05b0e882c17de05f22a1e'
CAPABILITY_POLICY = b'jdk.xml.dsig.secureValidationPolicy=\n'
SOURCE = Path(__file__).resolve().parents[1] / 'keycloak/KeycloakRsaSha1MetadataCapability.java'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def decoded(node):
    assert set(node) == {'base64', 'sha256'} or set(node) == {'base64', 'sha256', 'path'}
    raw = base64.b64decode(node['base64'], validate=True)
    assert node['sha256'] == SHA(raw)
    return raw


def certificate_der(root):
    values = root.findall('./{%s}Signature/{%s}KeyInfo/{%s}X509Data/{%s}X509Certificate' % (
        DS, DS, DS, DS))
    assert len(values) == 1 and values[0].text
    return base64.b64decode(''.join(values[0].text.split()), validate=True)


JAVA_VERIFIER = r'''
import java.io.*;
import java.nio.file.*;
import java.security.cert.*;
import java.util.Base64;
import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.*;
public final class IndependentXmlDsigVerifier {
  public static void main(String[] args) throws Exception {
    var factory = DocumentBuilderFactory.newInstance(); factory.setNamespaceAware(true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    var document = factory.newDocumentBuilder().parse(Path.of(args[0]).toFile());
    var root = document.getDocumentElement();
    if (root.hasAttribute("ID")) root.setIdAttribute("ID", true);
    var signatures = root.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    if (signatures.getLength() != 1) { System.out.print("false"); return; }
    var certificates = ((Element) signatures.item(0))
        .getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
    if (certificates.getLength() != 1) { System.out.print("false"); return; }
    var der = Base64.getMimeDecoder().decode(certificates.item(0).getTextContent());
    var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
        .generateCertificate(new ByteArrayInputStream(der));
    var context = new DOMValidateContext(certificate.getPublicKey(), signatures.item(0));
    context.setProperty("org.jcp.xml.dsig.secureValidation", false);
    var signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);
    System.out.print(signature.validate(context));
  }
}
'''


def independent_signature_controls(target, tampered, unsigned):
    with tempfile.TemporaryDirectory(prefix='samlscope-rsa-sha1-independent-') as directory:
        root = Path(directory)
        (root / 'IndependentXmlDsigVerifier.java').write_text(JAVA_VERIFIER)
        subprocess.run(['javac', str(root / 'IndependentXmlDsigVerifier.java')], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        results = {}
        for name, raw in {'positive': target, 'tampered': tampered, 'unsigned': unsigned}.items():
            path = root / (name + '.xml'); path.write_bytes(raw)
            run = subprocess.run(['java', '-cp', str(root), 'IndependentXmlDsigVerifier', str(path)],
                                 check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            results[name] = run.stdout.decode() == 'true'
        assert results == {'positive': True, 'tampered': False, 'unsigned': False}
        return results


def validate_observation(receipt, field, expected_mode, positive, target, cert_sha, wrong_sha):
    raw = decoded(receipt[field])
    observation = json.loads(raw)
    assert set(observation) == {
        'schema', 'policyMode', 'inputSha256', 'targetEntityId', 'signatureAlgorithm',
        'trustedCertificateSha256', 'wrongCertificateSha256', 'tamperedInputBase64',
        'tamperedInputSha256', 'unsignedInputBase64', 'unsignedInputSha256',
        'positiveAccepted', 'positiveError', 'tamperedAccepted', 'wrongKeyAccepted',
        'unsignedAccepted'}
    assert observation['schema'] == OBSERVATION_SCHEMA
    assert observation['policyMode'] == expected_mode
    assert observation['inputSha256'] == SHA(target)
    assert observation['targetEntityId'] == ENTITY
    assert observation['signatureAlgorithm'] == RSA_SHA1
    assert observation['trustedCertificateSha256'] == cert_sha
    assert observation['wrongCertificateSha256'] == wrong_sha != cert_sha
    assert observation['positiveAccepted'] is positive
    assert isinstance(observation['positiveError'], str)
    assert observation['tamperedAccepted'] is False
    assert observation['wrongKeyAccepted'] is False
    assert observation['unsignedAccepted'] is False
    tampered = base64.b64decode(observation['tamperedInputBase64'], validate=True)
    unsigned = base64.b64decode(observation['unsignedInputBase64'], validate=True)
    assert observation['tamperedInputSha256'] == SHA(tampered)
    assert observation['unsignedInputSha256'] == SHA(unsigned)
    assert ET.fromstring(tampered).attrib['entityID'] == ENTITY + '#tampered'
    assert len(ET.fromstring(tampered).findall('./{%s}Signature' % DS)) == 1
    assert ET.fromstring(unsigned).attrib['entityID'] == ENTITY
    assert len(ET.fromstring(unsigned).findall('./{%s}Signature' % DS)) == 0
    return raw, observation, tampered, unsigned


def validate_receipt(receipt, folder):
    assert set(receipt) == {
        'schema', 'runId', 'caseId', 'targetEntityId', 'targetMetadataSha256',
        'evidenceAdapter', 'configuration', 'runtime', 'defaultPolicyObservation',
        'defaultPolicyVerifierExitCode', 'defaultPolicyVerifierStderr', 'nativeObservation',
        'wrongCertificate', 'nativeVerifierExitCode', 'nativeVerifierStderr', 'operationCounts'}
    target = (folder / 'target-metadata.xml').read_bytes()
    assert receipt['schema'] == SCHEMA and receipt['caseId'] == CASE
    assert re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', receipt['runId'])
    assert receipt['runId'] == json.loads((folder / 'created.json').read_text())['run']['id']
    assert receipt['targetEntityId'] == ENTITY and receipt['targetMetadataSha256'] == SHA(target)
    assert receipt['evidenceAdapter'] == 'keycloak-native-jvm'
    root = ET.fromstring(target)
    assert root.tag == '{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor'
    assert root.attrib['entityID'] == ENTITY
    methods = root.findall('./{%s}Signature/{%s}SignedInfo/{%s}SignatureMethod' % (DS, DS, DS))
    digests = root.findall('./{%s}Signature/{%s}SignedInfo/{%s}Reference/{%s}DigestMethod' %
                           (DS, DS, DS, DS))
    assert len(methods) == 1 and methods[0].attrib['Algorithm'] == RSA_SHA1
    assert len(digests) == 1 and digests[0].attrib['Algorithm'] == DIGEST_SHA1
    cert_sha = SHA(certificate_der(root))

    config = receipt['configuration']
    assert set(config) == {'defaultSecurityPolicy', 'capabilitySecurityPolicy',
                           'serverConfigurationUnchanged'}
    default_policy = decoded(config['defaultSecurityPolicy'])
    assert b'jdk.xml.dsig.secureValidationPolicy=' in default_policy
    assert ('disallowAlg ' + RSA_SHA1).encode() in default_policy
    assert ('disallowAlg ' + DIGEST_SHA1).encode() in default_policy
    assert decoded(config['capabilitySecurityPolicy']) == CAPABILITY_POLICY
    assert config['serverConfigurationUnchanged'] is True
    assert default_policy == (folder / 'default-security-properties.txt').read_bytes()

    runtime = receipt['runtime']
    assert set(runtime) == {'containerName', 'containerId', 'imageId', 'startedAt',
                            'runningAtCapture', 'productVersion', 'coreLibrary',
                            'publicLibrary', 'verifierSource'}
    assert runtime['containerName'] == 'samlscope-reference-keycloak'
    assert re.fullmatch(r'[0-9a-f]{64}', runtime['containerId'])
    assert runtime['imageId'] == IMAGE and runtime['productVersion'] == VERSION
    assert runtime['runningAtCapture'] is True
    core = decoded(runtime['coreLibrary']); public = decoded(runtime['publicLibrary'])
    source = decoded(runtime['verifierSource'])
    assert runtime['coreLibrary']['path'].endswith('keycloak-saml-core-26.7.2.jar')
    assert runtime['publicLibrary']['path'].endswith('keycloak-saml-core-public-26.7.2.jar')
    assert runtime['verifierSource']['path'].endswith('KeycloakRsaSha1MetadataCapability.java')
    assert (SHA(core), SHA(public), SHA(source)) == (CORE_SHA, PUBLIC_SHA, SOURCE_SHA)
    assert core == (folder / 'target-keycloak-saml-core.jar').read_bytes()
    assert public == (folder / 'target-keycloak-saml-core-public.jar').read_bytes()
    assert source == SOURCE.read_bytes() == (folder / 'native-verifier.java').read_bytes()
    with zipfile.ZipFile(folder / 'target-keycloak-saml-core.jar') as archive:
        names = set(archive.namelist())
    assert {
        'org/keycloak/saml/SignatureAlgorithm.class', 'org/keycloak/rotation/KeyLocator.class',
        'org/keycloak/saml/processing/api/saml/v2/sig/SAML2Signature.class',
        'org/keycloak/saml/processing/core/saml/v2/util/DocumentUtil.class'} <= names
    for token in (b'SignatureAlgorithm.RSA_SHA1', b'new SAML2Signature().validate',
                  b'tamperedAccepted', b'wrongKeyAccepted', b'unsignedAccepted'):
        assert token in source

    wrong = decoded(receipt['wrongCertificate'])
    wrong_sha = SHA(wrong)
    default_raw, default, default_tampered, default_unsigned = validate_observation(
        receipt, 'defaultPolicyObservation', 'default', False, target, cert_sha, wrong_sha)
    native_raw, native, tampered, unsigned = validate_observation(
        receipt, 'nativeObservation', 'capability', True, target, cert_sha, wrong_sha)
    assert default_tampered == tampered and default_unsigned == unsigned
    assert default_raw == (folder / 'default-policy-verifier.stdout').read_bytes()
    assert native_raw == (folder / 'native-verifier.stdout').read_bytes()
    assert 'It is forbidden to use algorithm ' + RSA_SHA1 in default['positiveError']
    assert 'secure validation is enabled' in default['positiveError']
    assert native['positiveError'] == ''
    assert receipt['defaultPolicyVerifierExitCode'] == 0
    assert receipt['nativeVerifierExitCode'] == 0
    assert decoded(receipt['defaultPolicyVerifierStderr']) == (folder / 'default-policy-verifier.stderr').read_bytes()
    assert decoded(receipt['nativeVerifierStderr']) == (folder / 'native-verifier.stderr').read_bytes()
    assert receipt['operationCounts'] == {
        'productConfigurationWrites': 0, 'productRestarts': 0,
        'humanOperations': 0, 'nativeVerificationExecutions': 2}
    independent = independent_signature_controls(target, tampered, unsigned)
    return target, default, native, independent


def mutation_controls(receipt, folder):
    mutations = []
    def mutate(name, fn):
        changed = copy.deepcopy(receipt); fn(changed); mutations.append((name, changed))
    def replace_blob(node, raw):
        node['base64'] = base64.b64encode(raw).decode(); node['sha256'] = SHA(raw)
    def observation(field, key, value):
        def change(receipt):
            parsed = json.loads(decoded(receipt[field])); parsed[key] = value
            replace_blob(receipt[field], (json.dumps(parsed, indent=2) + '\n').encode())
        return change
    mutate('run', lambda x: x.__setitem__('runId', 'run_00000000000000000000000000'))
    mutate('target-hash', lambda x: x.__setitem__('targetMetadataSha256', '0' * 64))
    mutate('adapter', lambda x: x.__setitem__('evidenceAdapter', 'suite-native'))
    mutate('default-policy', lambda x: replace_blob(x['configuration']['defaultSecurityPolicy'], b'forged'))
    mutate('capability-policy', lambda x: replace_blob(x['configuration']['capabilitySecurityPolicy'], b'forged'))
    mutate('server-state', lambda x: x['configuration'].__setitem__('serverConfigurationUnchanged', False))
    mutate('image', lambda x: x['runtime'].__setitem__('imageId', 'sha256:' + '0' * 64))
    mutate('core', lambda x: replace_blob(x['runtime']['coreLibrary'], b'forged'))
    mutate('source', lambda x: replace_blob(x['runtime']['verifierSource'], b'class Forged {}'))
    mutate('default-positive', observation('defaultPolicyObservation', 'positiveAccepted', True))
    mutate('default-error', observation('defaultPolicyObservation', 'positiveError', ''))
    mutate('positive', observation('nativeObservation', 'positiveAccepted', False))
    mutate('tampered', observation('nativeObservation', 'tamperedAccepted', True))
    mutate('wrong-key', observation('nativeObservation', 'wrongKeyAccepted', True))
    mutate('unsigned', observation('nativeObservation', 'unsignedAccepted', True))
    mutate('policy-mode', observation('nativeObservation', 'policyMode', 'default'))
    mutate('operation-count', lambda x: x['operationCounts'].__setitem__('nativeVerificationExecutions', 1))
    mutate('native-exit', lambda x: x.__setitem__('nativeVerifierExitCode', 2))
    rejected = {}
    for name, changed in mutations:
        try:
            validate_receipt(changed, folder); rejected[name] = False
        except (AssertionError, KeyError, ValueError, TypeError, zipfile.BadZipFile,
                subprocess.CalledProcessError):
            rejected[name] = True
    assert all(rejected.values())
    return rejected


def verify(root, product='keycloak'):
    assert product == 'keycloak'
    folder = Path(root) / 'keycloak-rsa-sha1-metadata-v152'
    receipt = json.loads((folder / 'receipt.json').read_text())
    target, default, native, independent = validate_receipt(receipt, folder)
    preflight = json.loads((folder / 'preflight.json').read_text())
    assert any(row['code'] == 'target_metadata' and row['status'] == 'PASS' for row in preflight['checks'])
    restoration = json.loads((folder / 'restoration.json').read_text())
    assert restoration == {
        'serverConfigurationUnchanged': True, 'containerRuntimeUnchanged': True,
        'temporaryFilesRemoved': True,
        'originalMetadataSha256': restoration['finalMetadataSha256'],
        'finalMetadataSha256': restoration['finalMetadataSha256']}
    controls = mutation_controls(receipt, folder)
    verification = {
        'schema': 'samlscope-rsa-sha1-acceptance-verification-v1',
        'run': receipt['runId'],
        'receiptSha256': SHA((folder / 'receipt.json').read_bytes()),
        'targetMetadataSha256': SHA(target),
        'defaultObservationSha256': SHA((folder / 'default-policy-verifier.stdout').read_bytes()),
        'nativeObservationSha256': SHA((folder / 'native-verifier.stdout').read_bytes()),
        'independentSignatureControls': independent,
        'mutationControls': controls,
        'defaultPolicyObservation': default,
        'capabilityObservation': native,
    }
    if (folder / 'result.json').exists():
        raw = (folder / 'result.json').read_bytes(); result = json.loads(raw)
        cases = {case['id']: case for requirement in result['requirements'] for case in requirement['cases']}
        case = cases[CASE]
        assert result['run']['id'] == receipt['runId']
        assert result['target']['metadata_digest'] == 'sha256:' + SHA(target)
        assert (case['outcome'], case['verdict'], case['reason_code'], case['attested']) == (
            'SATISFIED', 'PASS', 'metadata.rsa-sha1.observed', False)
        verification['resultSha256'] = SHA(raw); verification['adoptable'] = True
        (folder / 'acceptance-verification.json').write_text(json.dumps(verification, indent=2) + '\n')
        return folder / 'result.json', {CASE: case}
    verification['adoptable'] = False
    (folder / 'acceptance-verification.json').write_text(json.dumps(verification, indent=2) + '\n')
    return None, {}


if __name__ == '__main__':
    import sys
    path, cases = verify(sys.argv[1])
    print('prepared' if path is None else cases[CASE]['verdict'])
