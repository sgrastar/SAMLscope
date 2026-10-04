#!/usr/bin/env python3
"""Adopt three persistent NameID observations from unchanged native two-peer originals."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import uuid
import zipfile

from verify_shibboleth_metadata_refresh_acceptance import decoded_originals
from verify_terminal_http_acceptance import _verify_target_runtime, _verify_suite_runtime, find_case, parsed_time
from acceptance_dependency_discovery import runtime_classpath as discover_runtime_classpath

REPO = Path(__file__).resolve().parents[2]
FOLDER = 'shibboleth-persistent-pairwise-v165-r1'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
READ = lambda path: json.loads(Path(path).read_text())
EXPECTED = {
    'IIP-SSO05-a-idp-01': 'browser.normal-flow.persistent-nameid-returned',
    'IIP-SSO05-a2-idp-01': 'browser.normal-flow.persistent-nameid-length',
    'IIP-SSO05-a3-idp-01': 'idp.persistent-pairwise.observed',
}
PINS = {
    'image_id': 'sha256:e781d6d9f7c417af36705a4abe06030212acb0a02a915f9e112a07214583a7e4',
    'jars': {
        'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe',
        'runner': '549b523ff3a60da56aa514f68fbf369ecd708199218aa21610e1661803fe2fb3',
        'saml': '49c87837124dc6ebcf3b94e9221df7a08cf577f37b2bb98b9744c3085a019d97',
    },
}
CONTROLS = {'equal-persistent-values', 'wrong-name-qualifier', 'wrong-sp-name-qualifier',
    'unexpected-sp-provided-id', 'wrong-audience', 'different-principal', 'forged-audit-request',
    'wrong-target', 'wrong-run', 'wrong-decryption-key', 'missing-peer', 'wrong-request-reference',
    'wrong-native-sp-metadata', 'wrong-restoration', 'missing-readback', 'late-before-readback',
    'wrong-readback', 'missing-original', 'wrong-uid-resolver-qname', 'disabled-generator', 'foreign-run-transcript'}


def require(value, detail):
    if not value:
        raise ValueError(detail)


def runtime_classpath():
    # This is dependency discovery only; production JARs always precede these entries.
    return discover_runtime_classpath(REPO)


def replay(folder, retain=False, live=False):
    folder = Path(folder)
    primary = folder / 'primary'
    manifest = READ(folder / 'receipt-v1/manifest.json')
    run = manifest['runId']
    runtime = READ(primary / 'suite-runtime-terminal-http.json')
    for name, digest in PINS['jars'].items():
        require(digest == SHA((primary / runtime['jars'][name]['file']).read_bytes()), 'Captured production JAR differs: ' + name)
        if live:
            native = subprocess.check_output(['docker', 'exec', 'samlscope-reference-suite', 'cat', runtime['jars'][name]['path']])
            require(SHA(native) == digest, 'Live production JAR differs: ' + name)
    store = READ(primary / 'store-runtime.json')
    require(store['sha256'] == SHA((primary / store['file']).read_bytes()), 'Store original changed')
    helper = folder / 'replay-helper-original.java'
    provenance = READ(folder / 'replay-helper-original.json')
    require(provenance['sha256'] == SHA(helper.read_bytes()) and provenance['file'] == helper.name, 'Archived helper changed')
    jars = [primary / runtime['jars'][name]['file'] for name in ('runner', 'core', 'saml')]
    classpath = ':'.join(map(str, jars + [primary / store['file']])) + ':' + runtime_classpath()
    remote = '/tmp/shib-persistent-adoption-' + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='samlscope-persistent-production-') as temporary:
        classes = Path(temporary) / 'classes'
        classes.mkdir()
        named_helper = Path(temporary) / 'VerifyShibbolethPersistentPairwiseEvidence.java'
        named_helper.write_bytes(helper.read_bytes())
        subprocess.run(['javac', '-cp', classpath, '-d', str(classes), str(named_helper)], check=True, capture_output=True)
        require(all(path.name.startswith('VerifyShibbolethPersistentPairwiseEvidence')
                    for path in classes.rglob('*.class')), 'Helper would shadow a production class')
        try:
            subprocess.run(['docker', 'exec', 'samlscope-reference-suite', 'mkdir', '-p', remote], check=True, capture_output=True)
            subprocess.run(['docker', 'cp', str(classes), 'samlscope-reference-suite:' + remote + '/classes'], check=True, capture_output=True)
            archived_jars = []
            for jar in jars + [primary / store['file']]:
                destination = remote + '/' + jar.name
                subprocess.run(['docker', 'cp', str(jar), 'samlscope-reference-suite:' + destination], check=True, capture_output=True)
                archived_jars.append(destination)
            subprocess.run(['docker', 'cp', str(folder / 'receipt-v1'), 'samlscope-reference-suite:' + remote + '/receipt'], check=True, capture_output=True)
            java_classpath = '/opt/samlscope/lib/runner-0.1.0.jar' if live else ':'.join(archived_jars)
            command = ['docker', 'exec', 'samlscope-reference-suite', 'java', '-cp',
                java_classpath + ':' + remote + '/classes:/opt/samlscope/lib/*',
                'com.samlscope.runner.cases.VerifyShibbolethPersistentPairwiseEvidence',
                ('/data/persistent-nameid-evidence/' + run) if live else remote + '/receipt', remote + '/report.json']
            executed = subprocess.run(command, capture_output=True)
            require(executed.returncode == 0, 'Production replay failed: ' + executed.stderr.decode(errors='replace')[-2000:])
            regenerated = subprocess.check_output(['docker', 'exec', 'samlscope-reference-suite', 'cat', remote + '/report.json'])
        finally:
            subprocess.run(['docker', 'exec', '-u', '0', 'samlscope-reference-suite', 'rm', '-rf', remote], check=True, capture_output=True)
    retained = folder / 'production-replay-v166.json'
    if retain:
        require(not retained.exists(), 'Refusing to replace production replay')
        retained.write_bytes(regenerated)
    else:
        require(retained.read_bytes() == regenerated, 'Production reader replay differs')
    report = json.loads(regenerated)
    require(report['runId'] == run and report['nativeOriginals'] == report['memoryOnlySemanticBaseline'] == 'SATISFIED'
            and set(report['controls']) == CONTROLS and set(report['controls'].values()) == {'NOT_VERIFIED'},
            'Native/semantic controls incomplete')
    return report


def verify(root):
    folder = Path(root) / FOLDER
    receipt = folder / 'receipt-v1'
    manifest = READ(receipt / 'manifest.json')
    primary = folder / 'primary'
    run = READ(primary / 'created.json')['run']['id']
    require(manifest['schema'] == 'samlscope-shibboleth-persistent-pairwise-v1'
            and manifest['runId'] == run and len(manifest['peers']) == 2, 'Wrong native pairwise receipt')
    placement = READ(folder / 'receipt-placement-readback.json')
    require(placement['destination'] == '/data/persistent-nameid-evidence/' + run
            and {row['file']: row['sha256'] for row in placement['files']}
            == {path.name: SHA(path.read_bytes()) for path in receipt.iterdir() if path.is_file()},
            'Original placement read-back differs')
    peer_runs = set()
    for label, peer in zip(('primary', 'secondary'), manifest['peers']):
        child = folder / label
        created = READ(child / 'created.json')['run']
        require(peer['runId'] == created['id'] and peer['runId'] not in peer_runs
                and peer['entityId'] == 'http://localhost:18080/p/' + created['planId']
                and manifest['targetMetadataSha256'] == SHA((child / 'target-metadata.xml').read_bytes()),
                'Peer Run/entity/target identity differs')
        peer_runs.add(peer['runId'])
        transcript = READ(child / 'transcript.json')
        require((receipt / (label + '-transcript.json')).read_bytes() == (child / 'transcript.json').read_bytes()
                and (receipt / (label + '-decoded-manifest.json')).read_bytes() == (child / 'decoded-manifest.json').read_bytes(),
                'Peer transcript/original hash manifest differs')
        decoded_originals(child, transcript)
        _verify_target_runtime(child, 'shibboleth', float(created['createdAt']))
        for field in ('nativeMetadata', 'audit', 'nativeMetadataRead'):
            require(peer[field + 'Sha256'] == SHA((receipt / peer[field + 'File']).read_bytes()), 'Native peer original changed')
        native = READ(receipt / peer['nativeMetadataReadFile'])
        require(native['runId'] == peer['runId'] and native['entityId'] == peer['entityId']
                and native['container'] == 'samlscope-reference-shibboleth'
                and native['command'] == ['/opt/reference-idp/bin/mdquery.sh', '-u', 'http://localhost:8080/idp', '-e', peer['entityId']]
                and native['exitCode'] == 0 and native['sha256'] == peer['nativeMetadataSha256'],
                'SP metadata did not come from native effective provider')
        require((receipt / peer['nativeMetadataFile']).read_bytes() == (child / 'native-effective-peer-metadata.xml').read_bytes()
                and (receipt / peer['auditFile']).read_bytes() == (folder / 'native-principal-audit.log').read_bytes(),
                'Native metadata/audit originals differ')
        counts = READ(child / 'operation-counts.json')
        require(all(counts[field] == 0 for field in ('configuration_write_attempts', 'restoration_write_attempts',
                'reloads', 'product_restarts', 'human_operations')) and counts['restored'] is True,
                'Child changed target configuration')
    require({row['kind'] for row in manifest['configurationFiles']} == {'nameid-xml', 'nameid-properties',
            'audit-xml', 'metadata-provider-xml', 'attribute-resolver-xml'}, 'Native configuration inventory incomplete')
    for row in manifest['configurationFiles']:
        for phase in ('original', 'configured', 'final'):
            require(row[phase + 'Sha256'] == SHA((receipt / row[phase + 'File']).read_bytes()), 'Configuration original changed')
        require((receipt / row['originalFile']).read_bytes() == (receipt / row['finalFile']).read_bytes(), 'Configuration not restored')
        require({item['phase'] for item in row['readBacks']} == {'primary-before', 'primary-after', 'secondary-before', 'secondary-after'},
                'Missing unchanged native read-back')
        for item in row['readBacks']:
            raw = (receipt / item['file']).read_bytes()
            require(item['sha256'] == SHA(raw) and raw == (receipt / row['configuredFile']).read_bytes(), 'Native configuration changed between peers')
    counts = READ(folder / 'operation-counts.json')
    operations = READ(folder / 'operations.json')
    require(READ(folder / 'restoration.json')['restored'] is True and counts['restored'] is True
            and counts['human_operations'] == counts['product_reloads'] == 0
            and counts['run_creations'] == 2
            and counts['product_configuration_writes'] == sum(item['operation'] == 'product-config-write' for item in operations) == 8
            and counts['restoration_writes'] == sum(item['label'].startswith('restore-') and item['operation'] == 'product-config-write' for item in operations) == 4
            and counts['product_restarts'] == sum(item['operation'] == 'product-restart' for item in operations) == 2
            and all(item.get('readBack') is True for item in operations if item['operation'] == 'product-config-write'),
            'Native operation counts/read-back/restoration differ')
    formal = READ(primary / 'formal-persistent-evaluation.json')
    require(formal['runId'] == run and formal['transcriptUnchanged'] is True, 'Formal Run/transcript changed')
    _verify_suite_runtime(primary, run, parsed_time(formal['startedAt']), PINS)
    with zipfile.ZipFile(primary / READ(primary / 'suite-runtime-terminal-http.json')['jars']['runner']['file']) as archive:
        require(b'samlscope-shibboleth-persistent-pairwise-v1' in archive.read('com/samlscope/runner/cases/PersistentPairwiseNameIdEvidence.class'),
                'Production persistent reader missing')
    evaluation = primary / 'evaluation-terminal-http-v1'
    require(READ(evaluation / 'transcript-before.json') == READ(evaluation / 'transcript.json') == READ(primary / 'transcript.json'),
            'Re-evaluation changed Recorder originals')
    result_path = evaluation / 'result.json'
    result = READ(result_path)
    require(result['run']['id'] == run, 'Result belongs to another Run')
    cases = {case: find_case(result, case) for case in EXPECTED}
    for case, reason in EXPECTED.items():
        found = cases[case]
        require((found['outcome'], found['verdict'], found['reason_code'], found['attested']) == ('SATISFIED', 'PASS', reason, False)
                and formal['cases'][case] == found, 'Persistent conclusion changed: ' + case)
    expected_refs = {exchange[field] for peer in manifest['peers'] for exchange in peer['exchanges']
                     for field in ('requestReference', 'responseReference')}
    require({row['reference'] for row in cases['IIP-SSO05-a3-idp-01']['evidence']} == expected_refs,
            'Pairwise evidence references differ')
    replay(folder)
    return result_path, cases


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--retain-replay', action='store_true')
    parser.add_argument('--live', action='store_true', help='Also require and replay the current deployed v166 Runner')
    args = parser.parse_args()
    if args.retain_replay:
        print(replay(args.root / FOLDER, retain=True, live=args.live))
    elif args.live:
        print(replay(args.root / FOLDER, live=True))
    else:
        path, cases = verify(args.root)
        print(path, {name: case['verdict'] for name, case in cases.items()})
