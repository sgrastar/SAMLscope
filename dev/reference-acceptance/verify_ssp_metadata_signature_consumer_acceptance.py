#!/usr/bin/env python3
"""Adopt the complete SSP native signature/transform campaign after production replay."""
import hashlib
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

from verify_ssp_metadata_signature_acceptance import replay_production_reader

if not __debug__:
    raise RuntimeError('acceptance verification must not run with Python optimization')

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CASES = {'IIP-MD03-a-idp-01', 'IIP-MD05-am-idp-01', 'IIP-MD05-an-idp-01', 'IIP-MD05-ao-idp-01'}
FOLDER = 'ssp-metadata-signature-consumer-v164/campaign-r3'
DS = 'http://www.w3.org/2000/09/xmldsig#'
MD = 'urn:oasis:names:tc:SAML:2.0:metadata'
SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'
EXPECTED = {
    'IIP-MD03-a-idp-01': ('SATISFIED', 'PASS', 'metadata.fixture-probe.satisfied'),
    'IIP-MD05-am-idp-01': ('SATISFIED_WITH_NOTE', 'WARNING', 'metadata.unauthorized-transform.safely-accepted'),
    'IIP-MD05-an-idp-01': ('VIOLATED', 'FAIL', 'metadata.excluded-content.accepted'),
    'IIP-MD05-ao-idp-01': ('SATISFIED', 'PASS', 'metadata.key-info-omission.accepted'),
}


def replay_helpers(folder, runtime):
    """Run the pinned production refusal reader and all four case implementations again."""
    repository = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix='samlscope-ssp-consumer-replay-') as temporary:
        temporary = Path(temporary)
        init = temporary / 'classpath.gradle'
        init.write_text('''gradle.projectsEvaluated {
  def p = gradle.rootProject.project(":api")
  p.tasks.register("printSignatureConsumerClasspath") {
    doLast { println(p.configurations.runtimeClasspath.asPath) }
  }
}
''')
        dependencies = subprocess.run([str(repository / 'gradlew'), '-q', '-I', str(init),
            ':api:printSignatureConsumerClasspath'], cwd=repository, capture_output=True,
            text=True, check=True).stdout.strip()
        assert dependencies
        classpath = str(runtime / 'runtime-runner.jar') + ':' + dependencies
        classes = temporary / 'classes'
        classes.mkdir()
        helpers = ['VerifyMetadataSignatureRejections', 'VerifyMetadataSignatureCampaign']
        subprocess.run(['javac', '-cp', classpath, '-d', str(classes), *[
            str(repository / 'dev/reference-acceptance' / (helper + '.java')) for helper in helpers]],
            cwd=repository, capture_output=True, check=True)
        results = {}
        for helper, filename in zip(helpers, ['native-signature-rejection-replay.json', 'production-case-replay.json']):
            report = temporary / filename
            arguments = [str(folder), str(report)]
            if helper.endswith('Campaign'):
                arguments.append(str(repository / 'tests/cases.yaml'))
            subprocess.run(['java', '-cp', str(classes) + ':' + classpath,
                'com.samlscope.runner.cases.' + helper, *arguments],
                cwd=repository, capture_output=True, check=True)
            raw = report.read_bytes()
            assert raw == (folder / filename).read_bytes(), 'retained production replay differs: ' + filename
            results[filename] = json.loads(raw)
        return results


def verify(root):
    folder = (Path(root) / FOLDER).resolve()
    load = lambda path: json.loads((folder / path).read_text())
    run = load('created.json')['run']['id']
    target = (folder / 'target-metadata.xml').read_bytes()
    receipt_raw = (folder / 'signature-verification-receipt.json').read_bytes()
    receipt = json.loads(receipt_raw)
    assert receipt['schema'] == 'samlscope-metadata-signature-verification-receipt-v4'
    assert receipt['runId'] == run and receipt['targetEntityId'] == 'http://localhost:18380/idp'
    assert receipt['campaignId'] == 'metadata-fixture-refresh' and receipt['evidenceAdapter'] == 'simplesamlphp-runtime'
    assert receipt['targetMetadataSha256'] == SHA(target)
    manifest = load('decoded-manifest.json')
    originals = {}
    for row in manifest:
        path = (folder / row['file']).resolve()
        assert path.parent == folder / 'decoded'
        raw = path.read_bytes()
        assert SHA(raw) == row['sha256'] and row['id'] not in originals
        originals[row['id']] = raw
    before = load('transcript-before-receipt.json')
    after = load('transcript-after-receipt.json')
    entries = {entry['id']: entry for entry in before}
    assert len(entries) == len(before) and before == after
    evaluation_folder = folder / 'evaluation-native-rejection'
    assert json.loads((evaluation_folder / 'transcript-before.json').read_text()) == before
    assert json.loads((evaluation_folder / 'transcript.json').read_text()) == before
    native_index = load('native-validation-index.json')
    configuration_index = load('configuration-index.json')
    prepared = {entry['samlSummary']['variant']: entry for entry in before
        if entry['direction'] == 'OUTBOUND' and entry.get('samlSummary', {}).get('type') == 'MetadataPrepared'}
    for variant in ['control', 'xpath-identity', 'xpath-exclude-role-descriptors',
                    'xpath-exclude-endpoints', 'xpath-exclude-key-descriptors', 'no-key-info']:
        fixture = (folder / variant / 'fixture.xml').read_bytes()
        assert originals[prepared[variant]['id']] == fixture
        native = native_index[variant]
        raw = originals[native['reference']]
        assert SHA(raw) == native['sha256'] and native['exit'] == 0
        assert raw == (folder / variant / native['stdout']).read_bytes()
        record = json.loads(raw)
        assert record['runId'] == run and record['variant'] == variant and record['fixtureSha256'] == SHA(fixture)
        assert record['outcome'] == 'accepted' and record['signatureVerified'] and record['exception'] is None
        assert record['entryPoint'] == 'SimpleSAML\\Metadata\\Sources\\MDQ::getMetaData'
        assert record['verifier'] == 'SimpleSAML\\Metadata\\SAMLParser::validateSignature'
        assert not record['genericParserOnly'] and record['validationCallCount'] == 1
        config = configuration_index[variant]
        assert record['configurationReference'] == config['reference']
        assert record['effectiveConfigurationReference'] == config['effectiveReference']
        assert originals[config['reference']] == (folder / variant / 'configured-configuration.stdout').read_bytes()
        assert SHA(originals[config['reference']]) == config['sha256'] == record['configurationSha256']
        certificate = originals[config['trustAnchorReference']]
        assert SHA(certificate) == config['trustAnchorOriginalSha256']
        assert SHA(ssl.PEM_cert_to_DER_cert(certificate.decode())) == record['trustAnchorCertificateSha256']
        for label, source in receipt['nativeSources'].items():
            assert SHA(originals[source['reference']]) == source['sha256'] == record['sourceSha256'][label]
        flow = load(variant + '/flow.json')
        assert flow['run'] == run and flow['variant'] == variant and flow['correlated_success']
        assert flow['positive_exchange']['success'] and flow['after_index'] == flow['before_index'] + 1
        request_reference, response_reference = flow['positive_exchange']['transcript_ids']
        request, response = entries[request_reference], entries[response_reference]
        assert request['direction'] == 'OUTBOUND' and request['samlSummary']['variant'] == variant
        request_id = request['samlSummary']['id']
        assert request_id == flow['positive_exchange']['request_id']
        assert response['direction'] == 'INBOUND' and response['samlSummary']['inResponseTo'] == request_id
        assert response['samlSummary']['statusCode'] == SUCCESS
        assert request['timestamp'] <= response['timestamp']
        xml = ET.fromstring(originals[response_reference])
        assert xml.attrib['InResponseTo'] == request_id
        assert xml.find('./{%s}Status/{%s}StatusCode' % ('urn:oasis:names:tc:SAML:2.0:protocol',
            'urn:oasis:names:tc:SAML:2.0:protocol')).attrib['Value'] == SUCCESS
    for variant in ['xpath-exclude-role-descriptors', 'xpath-exclude-endpoints', 'xpath-exclude-key-descriptors']:
        raw = (folder / variant / 'fixture.xml').read_text()
        assert 'xmlns:mdx="' + MD + '"' in raw and 'ancestor-or-self::mdx:' in raw
    root_xml = ET.fromstring((folder / 'no-key-info/fixture.xml').read_bytes())
    assert root_xml.find('./{%s}Signature/{%s}KeyInfo' % (DS, DS)) is None
    assert root_xml.find('./{%s}Signature' % DS) is not None
    assert (folder / 'original-config.php').read_bytes() == (folder / 'final-config.php').read_bytes()
    restoration = load('restoration.json')
    assert restoration['restored'] and restoration['temporary_files_removed'] and restoration['runtime_stable']
    assert restoration['original_sha256'] == restoration['final_sha256'] == SHA((folder / 'original-config.php').read_bytes())
    operations = load('operation-counts.json')
    assert (operations['product_configuration_writes'], operations['restoration_writes'],
        operations['native_validation_invocations'], operations['protocol_roundtrips'],
        operations['product_restarts'], operations['human_operations'], operations['restored']) == (15, 1, 15, 11, 0, 0, True)
    start, end = load('target-runtime-start.json'), load('target-runtime-end.json')
    assert start['binding'] == end['binding'] and start['version_source']['sha256'] == end['version_source']['sha256']
    assert start['binding']['container_name'] == 'samlscope-reference-ssp'
    assert start['runtime_version']['value'] == end['runtime_version']['value'] == '2.5.0'
    runtime = folder / 'runtime'
    runner = runtime / 'runtime-runner.jar'
    assert SHA(runner.read_bytes()) == (runtime / 'runner-jar-sha256.txt').read_text().strip()
    with zipfile.ZipFile(runner) as archive:
        assert SHA(archive.read('com/samlscope/runner/cases/MetadataSignatureVerificationEvidenceFile.class')) == \
            (runtime / 'reader-class-sha256.txt').read_text().strip()
    signature_replay = replay_production_reader(folder, runtime)
    replays = replay_helpers(folder, runtime)
    assert len(signature_replay['negative_controls']) >= 29
    assert set(signature_replay['negative_controls'].values()) == {'NOT_VERIFIED'}
    rejection_replay = replays['native-signature-rejection-replay.json']
    assert len(rejection_replay['negative_controls']) >= 27
    assert set(rejection_replay['proven_variants']) == {'unsigned', 'bad-signature', 'signed-other-key'}
    case_replay = replays['production-case-replay.json']
    assert set(case_replay['cases']) == CASES and len(case_replay['negative_controls']) >= 9
    result_path = evaluation_folder / 'result.json'
    result = json.loads(result_path.read_text())
    assert result['run']['id'] == run and result['target']['metadata_digest'] == 'sha256:' + SHA(target)
    cases = {case['id']: case for requirement in result['requirements'] for case in requirement['cases']}
    for case_id in CASES:
        case = cases[case_id]
        expected = EXPECTED[case_id]
        assert (case['outcome'], case['verdict'], case['reason_code']) == expected
        assert case['attested'] is False
        replay = case_replay['cases'][case_id]
        assert (replay['outcome'], replay['reason_code']) == (expected[0], expected[2])
        assert set(json.dumps(ref, sort_keys=True) for ref in replay['evidence']) == \
            set(json.dumps(ref, sort_keys=True) for ref in case['evidence'])
    installation = json.loads((evaluation_folder / 'receipt-installation.json').read_text())
    assert installation['run'] == run and installation['read_back']
    assert installation['sha256'] == SHA((folder / 'qualified-metadata-rejection-receipt.json').read_bytes())
    signature_installation = load('receipt-installation.json')
    assert signature_installation['run'] == run and signature_installation['read_back']
    assert signature_installation['sha256'] == SHA(receipt_raw)
    verification = dict(schema='samlscope-ssp-native-signature-consumer-acceptance-v1', run=run,
        acceptedCases=sorted(CASES), resultSha256=SHA(result_path.read_bytes()),
        signatureReceiptSha256=SHA(receipt_raw), rejectionReceiptSha256=installation['sha256'],
        runtimeRunnerSha256=SHA(runner.read_bytes()),
        signatureGateReplaySha256=SHA((folder / 'metadata-signature-replay.json').read_bytes()),
        nativeRejectionReplaySha256=SHA((folder / 'native-signature-rejection-replay.json').read_bytes()),
        productionCaseReplaySha256=SHA((folder / 'production-case-replay.json').read_bytes()),
        signatureGateMutationControls=len(signature_replay['negative_controls']),
        nativeRejectionMutationControls=len(rejection_replay['negative_controls']),
        caseMutationControls=len(case_replay['negative_controls']), operationCounts=operations,
        restored=True, transcriptUnchanged=True)
    (folder / 'acceptance-verification.json').write_text(json.dumps(verification, indent=2) + '\n')
    return result_path, {case_id: cases[case_id] for case_id in CASES}


if __name__ == '__main__':
    import sys
    path, cases = verify(sys.argv[1])
    print(path, sorted(cases))
