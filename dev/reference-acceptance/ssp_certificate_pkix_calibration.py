#!/usr/bin/env python3
"""Calibrate revoked and declared unreachable mutants with native public-only OpenSSL.

This runs no SAML or authentication operation and changes no product setting.
The result describes a counterfactual extra-check producer, never stock SSP behavior.
"""
import argparse
import base64
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
PHP = Path(__file__).with_name('SimpleSamlPhpCertificatePkixCalibration.php')
CONTAINER = 'samlscope-reference-ssp'
SOURCE_PATHS = {
    'native-message.php': '/var/simplesamlphp/modules/saml/src/Message.php',
    'native-parser.php': '/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php',
    'native-configuration.php': '/var/simplesamlphp/src/SimpleSAML/Configuration.php',
    'native-signed-helper.php': '/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/SignedElementHelper.php',
    'native-utils.php': '/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/Utils.php',
    'native-xml-security-key.php': '/var/simplesamlphp/vendor/robrichards/xmlseclibs/src/XMLSecurityKey.php',
}
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
NOW = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()


def command(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=45, **kwargs)


def read(path):
    return json.loads(Path(path).read_bytes())


def locate(folder, variant='certificate-revoked'):
    receipt = folder / 'receipt' if (folder / 'receipt').is_dir() else folder
    manifest = read(receipt / 'manifest.json')
    epochs = [e for e in manifest['epochs'] if e['variant'] == variant]
    if len(epochs) != 1 or len(epochs[0]['probes']) != 1:
        raise ValueError('Non-unique certificate condition original')
    ref = epochs[0]['probes'][0]['requestReference']
    transcript_path = receipt / 'transcript.json'
    history = read(transcript_path if transcript_path.exists() else folder / 'transcript.json')
    entries = [e for e in history if e['id'] == ref]
    if len(entries) != 1 or entries[0]['runId'] != manifest['runId']:
        raise ValueError('Foreign or duplicate request original')
    entry = entries[0]
    decoded_path = receipt / 'decoded-manifest.json'
    decoded_root = receipt if decoded_path.exists() else folder
    decoded = [r for r in read(decoded_root / 'decoded-manifest.json') if r['id'] == ref]
    if len(decoded) != 1:
        raise ValueError('Missing decoded request')
    request = (decoded_root / decoded[0]['file']).read_bytes()
    if SHA(request) != decoded[0]['sha256']:
        raise ValueError('Decoded original changed')
    fixture_name = variant + '-fixture.xml'
    fixture = (receipt / fixture_name).read_bytes()
    if SHA(fixture) != manifest['files'][fixture_name]:
        raise ValueError('Fixture original changed')
    request_id = ET.fromstring(request).get('ID')
    if not request_id or entry['direction'] != 'OUTBOUND':
        raise ValueError('Not an original Suite request')
    return receipt, manifest, ref, request_id, request, fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    inputs = [locate(args.input.resolve(), variant) for variant in
              ('certificate-revoked', 'certificate-revocation-unreachable')]
    receipt, manifest, _, _, _, _ = inputs[0]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = PHP.read_bytes()
    (out / PHP.name).write_bytes(source)
    runtime_command = ['docker', 'inspect', '--format',
                       '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}}}', CONTAINER]
    before = command(runtime_command).stdout
    (out / 'runtime-before.json').write_bytes(before)
    start = NOW()
    native_command = ['docker', 'exec', '-i', CONTAINER, 'php', '-r', source.decode().removeprefix('<?php').lstrip()]
    report = None
    rows = []
    native_reports = []
    for variant, original in zip(('certificate-revoked', 'certificate-revocation-unreachable'), inputs):
        _, selected_manifest, ref, request_id, request, fixture = original
        assert selected_manifest == manifest
        payload = dict(schema='samlscope-ssp-openssl-calibration-input-v1', variant=variant,
                       runId=manifest['runId'], targetMetadataSha256=manifest['targetMetadataSha256'],
                       requestReference=ref, requestId=request_id, requestSha256=SHA(request),
                       fixtureSha256=SHA(fixture), requestBase64=base64.b64encode(request).decode(),
                       fixtureBase64=base64.b64encode(fixture).decode(), checkerSourceSha256=SHA(source),
                       sourcePaths=SOURCE_PATHS)
        result = command(native_command, input=json.dumps(payload).encode())
        stdout_name = variant + '-native-producer-stdout.json'
        stderr_name = variant + '-native-producer-stderr.txt'
        (out / stdout_name).write_bytes(result.stdout)
        (out / stderr_name).write_bytes(result.stderr)
        current = json.loads(result.stdout)
        assert current['counterfactualCalibrationOnly'] is True
        assert current['controlsAdopted'] is False and current['actualProductFinding'] is False
        assert current['runId'] == manifest['runId'] and current['checkerSourceSha256'] == SHA(source)
        assert len(current['records']) == 1
        row = current['records'][0]
        assert row['variant'] == variant and row['requestId'] == request_id and row['requestSha256'] == SHA(request)
        assert row['fixtureSha256'] == SHA(fixture) and row['nativeSignatureVerified'] is True
        assert row['setup']['exitCode'] == 0 and row['failure']['exitCode'] == 2
        if variant == 'certificate-revoked':
            assert row['errorCode'] == 23 and re.search(r'\berror 23 at 0 depth lookup: certificate revoked\b', row['failure']['stderr'], re.I)
            assert row['network'] == []
        else:
            assert row['errorCode'] == 3 and re.search(r'\berror 3 at 0 depth lookup: unable to get certificate CRL\b', row['failure']['stderr'], re.I)
            assert '-crl_check' in row['selectedOperation'] and len(row['network']) == 2
            assert row['revocationPolicy'] == dict(lookupSource='native-curl-certificate-CDP/AIA',
                                                  lookupOutcome='UNAVAILABLE', requireRevocationEvidence=True,
                                                  failureMode='fail-closed')
            assert all(n['exitCode'] == 7 and 'curl: (7)' in n['stderr'] for n in row['network'])
            assert all(row['setup']['completedAt'] <= n['startedAt'] <= n['completedAt'] <= row['failure']['startedAt'] for n in row['network'])
        assert row['signatureVerifiedAt'] <= row['setup']['startedAt'] <= row['setup']['completedAt'] <= row['failure']['startedAt'] <= row['failure']['completedAt']
        for name in SOURCE_PATHS:
            expected = receipt / 'native-source' / name
            assert expected.is_file() and SHA(expected.read_bytes()) == current['nativeSourceHashes'][name]
        if report is None:
            report = current
        else:
            for name in ['nativeSourceHashes', 'nativeOpenSslBinarySha256', 'nativePhpOpenSslVersion']:
                assert report[name] == current[name]
        phases = [('setup', row['setup']), ('failure', row['failure'])]
        phases += [(f'network-{i}', n) for i, n in enumerate(row['network'])]
        for phase, value in phases:
            for stream in ('stdout', 'stderr'):
                raw = value.pop(stream).encode()
                name = f'{variant}-{phase}-{stream}.txt'
                (out / name).write_bytes(raw)
                value[stream + 'File'] = name
                value[stream + 'Sha256'] = SHA(raw)
        for stream in ('stdout', 'stderr'):
            row[stream + 'File'] = row['failure'][stream + 'File']
            row[stream + 'Sha256'] = row['failure'][stream + 'Sha256']
        row['nativeProducerReportFile'] = stdout_name
        row['nativeProducerReportSha256'] = SHA(result.stdout)
        rows.append(row)
        native_reports.append(dict(variant=variant, file=stdout_name, sha256=SHA(result.stdout)))
    finish = NOW()
    report['records'] = rows
    report['nativeProducerReports'] = native_reports
    report['checkerSourceFile'] = PHP.name
    after = command(runtime_command).stdout
    (out / 'runtime-after.json').write_bytes(after)
    assert before == after and json.loads(before)['running'] is True
    report['operations'] = dict(nativeProducerInvocations=2, nativeCompilerInvocations=0,
                                nativeOpenSslCliInvocations=6, nativeCurlInvocations=2, nativeSignatureVerifications=2,
                                productConfigurationWrites=0, protocolSubmissions=0,
                                credentialPosts=0, personOperations=0, productRestarts=0,
                                publicTemporaryFilesRemoved=True)
    report['hostStartedAt'], report['hostCompletedAt'] = start, finish
    report['runtimeBeforeSha256'], report['runtimeAfterSha256'] = SHA(before), SHA(after)
    report['inputManifestSha256'] = SHA((receipt / 'manifest.json').read_bytes())
    report['outputOriginals'] = {p.name: SHA(p.read_bytes()) for p in out.iterdir() if p.is_file()}
    (out / 'native-openssl-calibration.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(status='diagnostic-only', records=2, runId=manifest['runId'], operations=report['operations'])))


if __name__ == '__main__':
    main()
