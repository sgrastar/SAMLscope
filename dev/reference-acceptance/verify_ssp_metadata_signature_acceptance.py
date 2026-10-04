#!/usr/bin/env python3
"""Adopt only SSP MD03.b/c proven by the native signature-validation campaign."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

from acceptance_dependency_discovery import runtime_classpath

if not __debug__:
    raise RuntimeError('acceptance verification must not run with Python optimization')

CASES = {'IIP-MD03-b-idp-01', 'IIP-MD03-c-idp-01'}
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def replay_production_reader(folder, runtime):
    """Regenerate the retained replay with the pinned production reader.

    The stored replay is useful evidence only after the verifier has reproduced it.  Keep the
    captured Runner JAR first on the class path so the current worktree cannot replace the
    evidence reader that evaluated this Run.
    """
    repository = Path(__file__).resolve().parents[2]
    runner = runtime / 'runtime-runner.jar'
    helper = repository / 'dev/reference-acceptance/VerifyMetadataSignatureEvidence.java'
    with tempfile.TemporaryDirectory(prefix='samlscope-ssp-signature-replay-') as temporary:
        temporary = Path(temporary)
        dependency_classpath = runtime_classpath(repository, project=':runner')
        assert dependency_classpath
        classpath = str(runner) + ':' + dependency_classpath
        classes = temporary / 'classes'
        classes.mkdir()
        subprocess.run(
            ['javac', '-cp', classpath, '-d', str(classes), str(helper)],
            cwd=repository, check=True, text=True, capture_output=True)
        report = temporary / 'replay.json'
        subprocess.run(
            ['java', '-cp', str(classes) + ':' + classpath,
             'com.samlscope.runner.cases.VerifyMetadataSignatureEvidence',
             str(folder), str(report)],
            cwd=repository, check=True, text=True, capture_output=True)
        regenerated = report.read_bytes()
    retained = (folder / 'metadata-signature-replay.json').read_bytes()
    assert regenerated == retained, 'retained replay differs from production-reader replay'
    return json.loads(regenerated)


def verify(root):
    folder = Path(root) / 'ssp-metadata-signature-v162' / 'campaign-v3'
    result_path = folder / 'repair-invalid-control' / 'result.json'
    receipt_raw = (folder / 'signature-verification-receipt-repaired-v2.json').read_bytes()
    receipt = json.loads(receipt_raw)
    result_raw = result_path.read_bytes()
    result = json.loads(result_raw)
    run = json.loads((folder / 'created.json').read_text())['run']['id']
    assert receipt['schema'] == 'samlscope-metadata-signature-verification-receipt-v4'
    assert receipt['runId'] == run == result['run']['id']
    assert receipt['campaignId'] == 'metadata-fixture-refresh'
    assert receipt['targetEntityId'] == 'http://localhost:18380/idp'
    assert receipt['evidenceAdapter'] == 'simplesamlphp-runtime'
    target = (folder / 'target-metadata.xml').read_bytes()
    assert receipt['targetMetadataSha256'] == SHA(target)
    assert result['target']['metadata_digest'] == 'sha256:' + SHA(target)

    manifest = json.loads((folder / 'decoded-manifest.json').read_text())
    originals = {}
    for row in manifest:
        path = (folder / row['file']).resolve()
        assert path.parent == (folder / 'decoded').resolve()
        raw = path.read_bytes()
        assert row['id'] not in originals and row['sha256'] == SHA(raw)
        originals[row['id']] = raw

    def original(node, ref='reference', digest='sha256'):
        raw = originals[node[ref]]
        assert SHA(raw) == node[digest]
        return raw

    config = receipt['configurationReadBack']
    assert original(config) == (folder / 'signed-other-key-primary-keyinfo/out-of-band-configuration.stdout').read_bytes()
    assert original(config, 'effectiveReference', 'effectiveSha256') == \
        (folder / 'signed-other-key-primary-keyinfo/out-of-band-effective.stdout').read_bytes()
    assert original(config, 'trustAnchorReference', 'trustAnchorOriginalSha256') == \
        (folder / 'signed-other-key-primary-keyinfo/out-of-band-anchor.stdout').read_bytes()
    restoration = receipt['restorationReadBack']
    assert original(restoration, 'originalReference', 'originalSha256') == \
        original(restoration, 'finalReference', 'finalSha256')
    assert (folder / 'original-config.php').read_bytes() == (folder / 'final-config.php').read_bytes()
    assert (folder / 'repair-embedded-control/original-config.php').read_bytes() == \
        (folder / 'repair-embedded-control/final-config.php').read_bytes()
    assert (folder / 'repair-invalid-control/original-config.php').read_bytes() == \
        (folder / 'repair-invalid-control/final-config.php').read_bytes()

    source_files = {
        'samlParser': 'source-samlParser.stdout', 'mdq': 'source-mdq.stdout',
        'metaLoader': 'source-metaLoader.stdout', 'configuration': 'source-configuration.stdout',
        'adapter': 'source-adapter.stdout',
    }
    for name, filename in source_files.items():
        assert original(receipt['nativeSources'][name]) == (folder / filename).read_bytes()
    assert original(receipt['positive'], 'nativeValidationReference', 'nativeValidationSha256') == \
        (folder / 'signed-other-key-primary-keyinfo/out-of-band-native.stdout').read_bytes()

    controls = {row['kind']: row for row in receipt['negativeControls']}
    assert set(controls) == {'invalid-signature', 'embedded-anchor'}
    invalid = controls['invalid-signature']
    embedded = controls['embedded-anchor']
    assert original(invalid, 'nativeRejectionReference', 'nativeRejectionSha256') == \
        (folder / 'repair-invalid-control/invalid-signature-native.stdout').read_bytes()
    assert original(invalid['configurationReadBack']) == \
        (folder / 'repair-invalid-control/invalid-signature-configuration.stdout').read_bytes()
    assert original(invalid['configurationReadBack'], 'effectiveReference', 'effectiveSha256') == \
        (folder / 'repair-invalid-control/invalid-signature-effective.stdout').read_bytes()
    assert original(invalid['configurationReadBack'], 'trustAnchorReference', 'trustAnchorOriginalSha256') == \
        (folder / 'repair-invalid-control/invalid-signature-anchor.stdout').read_bytes()
    assert invalid['configurationReadBack']['trustAnchorCertificateSha256'] == \
        'cc2a617a23b288296b853a9df19499f3b0246f73e179f46bf26697248046d626'
    assert original(embedded, 'nativeRejectionReference', 'nativeRejectionSha256') == \
        (folder / 'repair-embedded-control/positive-embedded-native.stdout').read_bytes()
    assert original(embedded['configurationReadBack']) == \
        (folder / 'repair-embedded-control/positive-embedded-configuration.stdout').read_bytes()
    assert embedded['configurationReadBack']['trustAnchorCertificateSha256'] == \
        receipt['positive']['embeddedKeyInfoCertificateSha256'] == \
        'a95ceedffdb65b86be61b1c92982ff8a8cced46a7611be02211dc41ef701efac'
    assert config['trustAnchorCertificateSha256'] not in {
        invalid['configurationReadBack']['trustAnchorCertificateSha256'],
        embedded['configurationReadBack']['trustAnchorCertificateSha256'],
    }

    runtime = folder.parent / 'runtime'
    replay = replay_production_reader(folder, runtime)
    assert replay['run'] == run and replay['receipt_sha256'] == SHA(receipt_raw)
    assert replay['target_metadata_sha256'] == SHA(target)
    assert len(replay['negative_controls']) >= 29
    assert set(replay['negative_controls'].values()) == {'NOT_VERIFIED'}
    assert replay['verdict_adopted'] is False

    operations = json.loads((folder / 'operation-counts.json').read_text())
    repair_embedded = json.loads((folder / 'repair-embedded-control/operations.json').read_text())
    repair_invalid = json.loads((folder / 'repair-invalid-control/operations.json').read_text())
    assert (operations['product_configuration_writes'], operations['restoration_writes'],
            operations['native_validation_invocations'], operations['protocol_roundtrips'],
            operations['product_restarts'], operations['human_operations'], operations['restored']) == \
           (10, 1, 10, 6, 0, 0, True)
    for repair in (repair_embedded, repair_invalid):
        assert (repair['product_configuration_writes'], repair['restoration_writes'],
                repair['native_validation_invocations'], repair['product_restarts'],
                repair['human_operations'], repair['restored'], repair['runtime_stable']) == \
               (1, 1, 1, 0, 0, True, True)
    for part in (folder, folder / 'repair-embedded-control', folder / 'repair-invalid-control'):
        start = json.loads((part / 'target-runtime-start.json').read_text())['binding']
        end = json.loads((part / 'target-runtime-end.json').read_text())['binding']
        assert start == end
        assert start['container_name'] == 'samlscope-reference-ssp'
        assert re.fullmatch(r'[0-9a-f]{64}', start['container_id'])
        assert re.fullmatch(r'sha256:[0-9a-f]{64}', start['image_id'])

    jar = runtime / 'runtime-runner.jar'
    jar_sha = (runtime / 'runner-jar-sha256.txt').read_text().split()[0]
    class_sha = (runtime / 'reader-class-sha256.txt').read_text().split()[0]
    assert jar_sha == SHA(jar.read_bytes()) == '74a1750a46caaff558f624ad7b6bb9adb0ea05165c83e65e2fa45ea3d7494d06'
    with zipfile.ZipFile(jar) as archive:
        assert class_sha == SHA(archive.read(
            'com/samlscope/runner/cases/MetadataSignatureVerificationEvidenceFile.class'))

    cases = {case['id']: case for requirement in result['requirements'] for case in requirement['cases']}
    for case_id in CASES:
        case = cases[case_id]
        assert (case['outcome'], case['verdict'], case['reason_code'], case['attested']) == \
               ('SATISFIED', 'PASS', 'metadata.fixture-probe.satisfied', False)
    assert cases['IIP-MD03-a-idp-01']['verdict'] == 'NOT_VERIFIED'
    verification = {
        'schema': 'samlscope-ssp-metadata-signature-acceptance-v1', 'run': run,
        'receiptSha256': SHA(receipt_raw), 'resultSha256': SHA(result_raw),
        'replaySha256': SHA((folder / 'metadata-signature-replay.json').read_bytes()),
        'acceptedCases': sorted(CASES), 'mutationControls': replay['negative_controls'],
        'operationCounts': {'productConfigurationWrites': 12, 'restorationWrites': 3,
                            'nativeValidationInvocations': 12, 'protocolRoundtrips': 6,
                            'productRestarts': 0, 'humanOperations': 0},
    }
    (folder / 'acceptance-verification.json').write_text(json.dumps(verification, indent=2) + '\n')
    return result_path, {case_id: cases[case_id] for case_id in CASES}


if __name__ == '__main__':
    import sys
    path, cases = verify(sys.argv[1])
    print(path, sorted(cases))
