#!/usr/bin/env python3
"""Verify native Shibboleth RSA-SHA1 originals, archived production replay and formal result."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request
import zipfile

from verify_keycloak_rsa_sha1_metadata_acceptance import independent_signature_controls

REPO = Path(__file__).resolve().parents[2]
FOLDER = 'shibboleth-rsa-sha1-metadata-v171-r5'
CASE = 'IIP-MD05-ah-idp-01'
HELPER = 'VerifyShibbolethRsaSha1CapabilityEvidence'
JARS = ('runner', 'core', 'saml', 'store', 'peer', 'api')
CLASSES = ('MetadataRsaSha1CapabilityEvidenceFile', 'ShibbolethRsaSha1CapabilityProof', 'MetadataSignatureTestCase')
SOURCE_SHA = 'e761d0b982c9dd94b12f8e88a78534b0e828f733d892b8214c6d4a30bce46628'
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def require(value, detail):
    if not value:
        raise ValueError(detail)


def decoded(value):
    require(set(value) == {'base64', 'sha256'}, 'Original blob fields differ')
    raw = base64.b64decode(value['base64'], validate=True)
    require(sha(raw) == value['sha256'], 'Original hash differs')
    return raw


def locate(root):
    root = Path(root).resolve()
    return root if root.name == FOLDER else root / FOLDER


def capture_runtime(folder):
    runtime = folder / 'runtime'; runtime.mkdir(exist_ok=False)
    subprocess.run(['docker', 'cp', 'samlscope-reference-suite:/opt/samlscope/lib', str(runtime / 'lib')],
                   check=True, capture_output=True)
    pins = {'files': {p.name: sha(p.read_bytes()) for p in sorted((runtime / 'lib').glob('*.jar'))}}
    for name in JARS:
        require(name + '-0.1.0.jar' in pins['files'], 'Missing deployed module JAR')
    with zipfile.ZipFile(runtime / 'lib/runner-0.1.0.jar') as archive:
        pins['classes'] = {name: sha(archive.read('com/samlscope/runner/cases/' + name + '.class')) for name in CLASSES}
    source = Path(__file__).with_name(HELPER + '.java').read_bytes()
    (runtime / (HELPER + '.java')).write_bytes(source)
    pins['helperSha256'] = sha(source)
    pins['suiteImageId'] = subprocess.check_output(['docker', 'inspect', '--format', '{{.Image}}', 'samlscope-reference-suite']).decode().strip()
    (runtime / 'pins.json').write_text(json.dumps(pins, indent=2) + '\n')


def replay(folder):
    runtime = folder / 'runtime'; pins = read(runtime / 'pins.json')
    require({p.name: sha(p.read_bytes()) for p in (runtime / 'lib').glob('*.jar')} == pins['files'], 'Archived runtime differs')
    require(sha((runtime / (HELPER + '.java')).read_bytes()) == pins['helperSha256'], 'Archived helper differs')
    with zipfile.ZipFile(runtime / 'lib/runner-0.1.0.jar') as archive:
        require(pins['classes'] == {name: sha(archive.read('com/samlscope/runner/cases/' + name + '.class')) for name in CLASSES}, 'Production class bytes differ')
    cp = str(runtime / 'lib/*')
    with tempfile.TemporaryDirectory(prefix='shibboleth-rsa-sha1-production-') as name:
        temporary = Path(name); classes = temporary / 'classes'
        result = subprocess.run(['javac', '-sourcepath', '', '-cp', cp, '-d', str(classes), str(runtime / (HELPER + '.java'))], capture_output=True, timeout=30)
        require(result.returncode == 0, 'Archived helper compile failed: ' + result.stderr.decode()[-1200:])
        require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')), 'Helper shadows production classes')
        result = subprocess.run(['java', '-cp', str(classes) + ':' + cp, 'com.samlscope.runner.cases.' + HELPER,
                                 str(folder), str(temporary / 'report.json')], capture_output=True, timeout=60)
        require(result.returncode == 0, 'Archived production replay failed: ' + result.stderr.decode()[-1600:])
        return read(temporary / 'report.json')


def verify(root, live=False):
    folder = locate(root); receipt = read(folder / 'receipt.json'); run = read(folder / 'created.json')['run']['id']
    require(receipt['runId'] == run and receipt['caseId'] == CASE, 'Run/case differs')
    require(receipt['evidenceAdapter'] == 'shibboleth-native-jvm', 'Native adapter differs')
    target = (folder / 'target-metadata.xml').read_bytes()
    require(receipt['targetMetadataSha256'] == sha(target), 'Target digest differs')
    require(decoded(receipt['originalUnsignedMetadata']) == (folder / 'unsigned-target-metadata.xml').read_bytes(), 'Unsigned original differs')
    require(sha(decoded(receipt['runtime']['verifierSource'])) == SOURCE_SHA
            and decoded(receipt['runtime']['verifierSource']) == (folder / 'ShibbolethRsaSha1MetadataCapability.java').read_bytes(), 'Native helper source differs')
    for name, node in receipt['runtime']['nativeClasses'].items():
        with zipfile.ZipFile(folder / 'native-libraries' / Path(node['jar']).name) as archive:
            require(decoded(node['original']) == archive.read(node['classFile']), 'Installed native class differs: ' + name)
    for field, name in [('before', 'target-container-inspect-start.json'), ('after', 'target-container-inspect-end.json')]:
        require(decoded(receipt['runtime'][field]) == (folder / name).read_bytes(), 'Native inspection original differs')
    for field in ('before', 'after'):
        require(decoded(receipt['configuration'][field]) == (folder / ('configuration-' + field + '.json')).read_bytes(), 'Configuration original differs')
    require(decoded(receipt['configuration']['before']) == decoded(receipt['configuration']['after']), 'Native credential state changed')
    for field, name in [('signerObservation', 'signer.stdout'), ('signerStderr', 'signer.stderr'),
                        ('nativeObservation', 'native-verifier.stdout'), ('nativeVerifierStderr', 'native-verifier.stderr')]:
        require(decoded(receipt[field]) == (folder / name).read_bytes(), 'Native observation original differs')
    original = json.loads(decoded(receipt['nativeObservation']).decode().strip().splitlines()[-1])
    independent = independent_signature_controls(target, base64.b64decode(original['tamperedInputBase64'], validate=True),
                                                  base64.b64decode(original['unsignedInputBase64'], validate=True))
    recorded = read(folder / 'production-reader-replay.json')
    require(replay(folder) == recorded and len(recorded['checks']) == 23, 'Production replay differs')
    require(recorded['checks']['complete-native-originals'] == 'SATISFIED'
            and all(v == 'NOT_VERIFIED' for k, v in recorded['checks'].items() if k != 'complete-native-originals'), 'Invalid evidence was accepted')
    expected_counts = dict(productConfigurationWrites=0, productRestarts=0, humanOperations=0, nativeVerificationExecutions=2)
    require(receipt['operationCounts'] == expected_counts, 'Native operation counts differ')
    restoration = read(folder / 'restoration.json')
    require(restoration['runtimeUnchanged'] is True and restoration['credentialsUnchanged'] is True
            and restoration['temporaryFilesRemoved'] is True
            and restoration['originalConfigurationSha256'] == restoration['finalConfigurationSha256'], 'Restoration differs')
    baseline = read(folder / 'baseline-login/operations.json')
    require(baseline['run'] == run and baseline['restored'] is True and baseline['failures'] == []
            and baseline['temporary_removed'] is True and baseline['original_sha256'] == baseline['final_sha256'], 'Baseline native restoration differs')
    baseline_ops = baseline['operations']
    require(sum(x['operation'] == 'write' for x in baseline_ops) == 3
            and sum(x['operation'] == 'reload' for x in baseline_ops) == 2
            and sum(x['operation'] == 'ordinary-login' for x in baseline_ops) == 1
            and all(x.get('read_back') is True for x in baseline_ops if x['operation'] == 'write'), 'Baseline native operation counts differ')
    require(any(row['code'] == 'target_metadata' and row['status'] == 'PASS' for row in read(folder / 'preflight.json')['checks']), 'Preflight target was not accepted')
    formal = folder / 'evaluation'; result = read(formal / 'result.json')
    rows = {c['id']: c for q in result['requirements'] for c in q['cases']}; row = rows[CASE]
    require((row['outcome'], row['verdict'], row['reason_code'], row['attested']) == ('SATISFIED', 'PASS', 'metadata.rsa-sha1.observed', False), 'Formal result differs')
    require(result['run']['id'] == run and result['target']['metadata_digest'] == 'sha256:' + sha(target), 'Formal Run/target differs')
    require(read(formal / 'transcript-before.json') == read(formal / 'transcript.json'), 'Formal measurement altered transcript')
    execution = next(x for x in read(formal / 'milestone-start.json') if x['caseId'] == CASE)
    details = execution['outcome']['details']
    require(execution['runId'] == run and execution['status'] == 'FINISHED'
            and execution['outcome']['outcome'] == 'SATISFIED'
            and details['native_receipt_sha256'] == sha((folder / 'receipt.json').read_bytes())
            and details['producer_variant_proven'] is True and details['verifier_variant_proven'] is True
            and details['product_version'] == '5.2.3', 'Formal native proof details differ')
    require(execution['outcome']['evidence'] == row['evidence']
            == [{'kind': 'target_metadata', 'reference': 'sha256:' + sha(target)}], 'Formal native evidence differs')
    readback = read(folder / 'receipt-placement.json')
    require(readback['readBackSha256'] == sha((folder / 'receipt.json').read_bytes()) and readback['bytesIdentical'] is True, 'Receipt placement differs')
    if live:
        for suffix, expected in [('result.json', result), ('transcript', read(formal / 'transcript.json'))]:
            with urllib.request.urlopen('http://localhost:18080/api/runs/' + run + '/' + suffix, timeout=30) as response:
                current = json.load(response)
            require(current == expected, 'Live formal result/transcript differs')
    return formal / 'result.json', {CASE: row}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('root', type=Path)
    parser.add_argument('--capture-runtime', action='store_true'); parser.add_argument('--record-replay', action='store_true')
    parser.add_argument('--live', action='store_true'); args = parser.parse_args(); folder = locate(args.root)
    if args.capture_runtime: capture_runtime(folder)
    if args.record_replay:
        output = folder / 'production-reader-replay.json'; require(not output.exists(), 'Refusing replay replacement')
        output.write_text(json.dumps(replay(folder), indent=2) + '\n')
    if not args.capture_runtime and not args.record_replay:
        path, rows = verify(args.root, args.live); print(json.dumps(dict(result=str(path), verdict=rows[CASE]['verdict'], verified=True)))
