#!/usr/bin/env python3
"""Adopt SSO01.ae only from native originals and archived production-reader replay.

Default verification does not depend on current product settings or the deployed Reader.
The captured production JARs precede all current dependencies in an ephemeral Suite JVM;
the Suite's existing Run private key is used only in memory. --live is an explicit extra check.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid
import zipfile

from verify_shibboleth_metadata_refresh_acceptance import decoded_originals
from verify_shibboleth_persistent_pairwise_acceptance import runtime_classpath
from verify_terminal_http_acceptance import _verify_suite_runtime, find_case, parsed_time

REPO = Path(__file__).resolve().parents[2]
FOLDER = 'shibboleth-identity-v170-r3'
CASE = 'IIP-SSO01-ae-idp-01'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
READ = lambda path: json.loads(Path(path).read_text())
PINS = {'image_id': 'sha256:1b1562f0e47e057432521a0248bd8d48d040d7b6e17e1b5b3d088a73d4143395', 'jars': {'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe', 'runner': '4bed31dce80c37002779be9ec7405be7940f7870d116199289214774fe94ef91', 'saml': '0b83d6813246e0138bcd77e0118a0fae7b2f56f76044b7440db39e69788eb818'}}
NATIVE_JAR_SHA256 = '428e389d88bb2abcad19d69bcf759af29f7ce6beb776ccfaa5a6ea76751682ba'
HELPER_SHA256 = '91e7753cd501d9cfcfbb70c5269e020e5374813780ba79b6f87f8c27712a80aa'  # Filled after the complete negative-control helper is frozen.
CONTROLS = {'always-success', 'positive-error', 'non-password-method', 'error-with-assertion',
    'wrong-correlation', 'wrong-destination', 'wrong-audience', 'unsigned-response',
    'ambient-flow-enabled', 'session-enabled', 'session-reuse-enabled', 'native-sso-reuse',
    'wrong-principal', 'forged-native-request', 'wrong-restoration', 'missing-readback',
    'late-before-readback', 'missing-native-source', 'wrong-target', 'missing-error-original',
    'foreign-run-transcript', 'declaration-only', 'missing-native-challenge',
    'wrong-challenge-request', 'wrong-challenge-source', 'credential-before-challenge',
    'challenge-password-input-missing', 'challenge-after-success', 'altered-custom-condition-flow',
    'custom-global-authentication-override'}
KINDS = {'authn-properties', 'password-validator', 'global', 'relying-party', 'providers', 'audit',
    'condition-base', 'condition-locked', 'condition-expired', 'condition-expiring'}


def require(value, detail):
    if not value:
        raise ValueError(detail)


def replay(folder, retain=False, live=False):
    folder = Path(folder)
    child = folder / 'browser'
    runtime = READ(child / 'suite-runtime-terminal-http.json')
    store = READ(child / 'store-runtime.json')
    jars = [child / runtime['jars'][name]['file'] for name in ('runner', 'core', 'saml')]
    for name, digest in PINS['jars'].items():
        require(SHA((child / runtime['jars'][name]['file']).read_bytes()) == digest,
                'Archived production JAR changed: ' + name)
        if live:
            actual = subprocess.check_output(['docker', 'exec', 'samlscope-reference-suite',
                'cat', runtime['jars'][name]['path']])
            require(SHA(actual) == digest, 'Live production JAR changed: ' + name)
    require(store['path'] == '/opt/samlscope/lib/store-0.1.0.jar'
            and store['sha256'] == SHA((child / store['file']).read_bytes()), 'Store original changed')
    jars.append(child / store['file'])
    helper = folder / 'replay-helper-original.java'
    provenance = READ(folder / 'replay-helper-original.json')
    require(provenance['file'] == helper.name and SHA(helper.read_bytes()) == provenance['sha256']
            == HELPER_SHA256, 'Archived helper changed')
    remote = '/tmp/shib-authentication-identity-adoption-' + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='samlscope-identity-production-') as temporary:
        temp = Path(temporary)
        named = temp / 'VerifyShibbolethAuthenticationIdentityEvidence.java'
        named.write_bytes(helper.read_bytes())
        classes = temp / 'classes'; classes.mkdir()
        subprocess.run(['javac', '-cp', ':'.join(map(str, jars)) + ':' + runtime_classpath(),
            '-d', str(classes), str(named)], check=True, capture_output=True)
        require(all(path.name.startswith('VerifyShibbolethAuthenticationIdentityEvidence')
                    for path in classes.rglob('*.class')), 'Helper would shadow a production class')
        originals = temp / 'originals'
        shutil.copytree(folder / 'receipt', originals)
        for name in ('transcript.json', 'target-metadata.xml', 'plan.json'):
            shutil.copyfile(child / name, originals / name)
        shutil.copyfile(folder / 'context-parameters.json', originals / 'context-parameters.json')
        shutil.copytree(child / 'decoded', originals / 'decoded')
        try:
            subprocess.run(['docker', 'exec', 'samlscope-reference-suite', 'mkdir', '-p', remote],
                check=True, capture_output=True)
            for path, destination in ((classes, 'classes'), (originals, 'originals')):
                subprocess.run(['docker', 'cp', str(path), 'samlscope-reference-suite:' + remote + '/' + destination],
                    check=True, capture_output=True)
            remote_jars = []
            for index, jar in enumerate(jars):
                destination = remote + '/production-' + str(index) + '.jar'
                subprocess.run(['docker', 'cp', str(jar), 'samlscope-reference-suite:' + destination],
                    check=True, capture_output=True)
                remote_jars.append(destination)
            subprocess.run(['docker', 'exec', '-u', '0', 'samlscope-reference-suite', 'chown',
                '-R', '10001:10001', remote], check=True, capture_output=True)
            executed = subprocess.run(['docker', 'exec', 'samlscope-reference-suite', 'java', '-cp',
                ':'.join(remote_jars) + ':' + remote + '/classes:/opt/samlscope/lib/*',
                'com.samlscope.runner.cases.VerifyShibbolethAuthenticationIdentityEvidence',
                remote + '/originals', remote + '/report.json'], capture_output=True)
            require(executed.returncode == 0, 'Production replay failed: ' + executed.stderr.decode(errors='replace')[-2000:])
            regenerated = subprocess.check_output(['docker', 'exec', 'samlscope-reference-suite', 'cat', remote + '/report.json'])
        finally:
            subprocess.run(['docker', 'exec', '-u', '0', 'samlscope-reference-suite', 'rm', '-rf', remote],
                check=True, capture_output=True)
    retained = folder / 'production-replay-v171.json'
    if retain:
        require(not retained.exists(), 'Refusing to replace retained production replay')
        retained.write_bytes(regenerated)
    else:
        require(regenerated == retained.read_bytes(), 'Archived production Reader replay differs')
    report = json.loads(regenerated)
    require(report['runId'] == READ(folder / 'campaign.json')['runId']
            and report['nativeOriginals'] == report['memoryOnlySignedBaseline'] == 'SATISFIED'
            and set(report['controls']) == CONTROLS and set(report['controls'].values()) == {'NOT_VERIFIED'},
            'Native/semantic detection controls incomplete')
    return report


def native_runtime(folder, entries, operations):
    snapshots = []
    for phase in ('start', 'end'):
        summary = READ(folder / ('target-runtime-' + phase + '.json'))
        raw = (folder / ('target-container-inspect-' + phase + '.json')).read_bytes()
        image_raw = (folder / ('target-image-inspect-' + phase + '.json')).read_bytes()
        inspected = json.loads(raw); images = json.loads(image_raw)
        require(len(inspected) == len(images) == 1 and summary['docker_inspect_sha256'] == SHA(raw)
                and summary['image_inspect_sha256'] == SHA(image_raw), 'Native runtime original changed')
        item = inspected[0]; binding = summary['binding']; image = images[0]
        ports = item['NetworkSettings']['Ports']['8080/tcp']
        require(summary['product'] == 'shibboleth' and summary['phase'] == phase
                and binding['container_name'] == item['Name'].removeprefix('/') == 'samlscope-reference-shibboleth'
                and binding['container_id'] == item['Id'] and binding['image_id'] == item['Image'] == image['Id']
                and binding['configured_image'] == item['Config']['Image']
                and binding['container_started_at'] == item['State']['StartedAt']
                and item['State']['Running'] is binding['running_at_capture'] is True
                and binding['host_port_bound'] is True and binding['host_port'] == 18280
                and any(p['HostIp'] == '127.0.0.1' and p['HostPort'] == '18280' for p in ports),
                'Native product runtime binding differs')
        version = summary['runtime_version']; source = summary['version_source']
        require(version['value'] == source['value'] == '5.2.3'
                and SHA((folder / version['file']).read_bytes()) == version['sha256']
                and SHA((folder / source['file']).read_bytes()) == source['sha256'], 'Native runtime version changed')
        snapshots.append(binding)
    first = min(e['timestamp'] for e in entries.values())
    last = max(e['timestamp'] for e in entries.values())
    prep = [r for r in operations if r['operation'] == 'product-restart' and r['label'].startswith('prepare-')]
    final = [r for r in operations if r['operation'] == 'product-restart' and r['label'].startswith('restore-')]
    require(len(prep) == len(final) == 1 and prep[0]['completed'] is final[0]['completed'] is True
            and parsed_time(prep[0]['recordedAt']) <= parsed_time(snapshots[0]['container_started_at'])
            <= parsed_time(prep[0]['completedAt']) < first <= last
            < parsed_time(final[0]['recordedAt']) <= parsed_time(snapshots[1]['container_started_at'])
            <= parsed_time(final[0]['completedAt']), 'Native restart lifecycle does not bracket controls')
    require({k: v for k, v in snapshots[0].items() if k != 'container_started_at'}
            == {k: v for k, v in snapshots[1].items() if k != 'container_started_at'},
            'Native product identity changed between preparation and exact restoration')


def verify(root):
    folder = Path(root) / FOLDER; child = folder / 'browser'; receipt = folder / 'receipt'
    manifest = READ(receipt / 'manifest.json'); run = READ(child / 'created.json')['run']['id']
    require(manifest['schema'] == 'samlscope-shibboleth-authentication-identity-v1'
            and manifest['runId'] == run == READ(folder / 'campaign.json')['runId']
            and manifest['targetEntityId'] == 'http://localhost:18280/idp/shibboleth'
            and manifest['targetMetadataSha256'] == SHA((child / 'target-metadata.xml').read_bytes()), 'Wrong native identity receipt')
    actual = {p.name: SHA(p.read_bytes()) for p in receipt.iterdir() if p.is_file() and not p.is_symlink()}
    placement = READ(folder / 'receipt-installation.json')
    require(actual == READ(folder / 'receipt-originals.json') == placement['files']
            and placement['runId'] == run and placement['readBackMatched'] is True, 'Original placement differs')
    entries = {e['id']: e for e in READ(child / 'transcript.json')}
    require(len(entries) == len(READ(child / 'transcript.json'))
            and all(e['runId'] == run for e in entries.values()), 'Recorder original Run mixing')
    decoded_originals(child, list(entries.values()))
    operations = READ(folder / 'operations.json'); counts = READ(folder / 'operation-counts.json')
    require(READ(folder / 'restoration.json')['restored'] is counts['restored'] is True
            and counts['humanOperations'] == 0
            and counts['productConfigWrites'] == sum(r['operation'] == 'product-config-write' for r in operations) == 6
            and counts['restorationWrites'] == sum(r['operation'] == 'product-config-write' and r['label'].startswith('restore-') for r in operations) == 3
            and counts['productRestarts'] == sum(r['operation'] == 'product-restart' for r in operations) == 2
            and counts['protocolSubmissions'] == 2 and counts['preparedActions'] == 71 and counts['skippedBeforeTarget'] == 70
            and all(r['readBack'] is True for r in operations if r['operation'] == 'product-config-write'),
            'Native operation counts/restoration differ')
    native_runtime(folder, entries, operations)
    require({r['kind'] for r in manifest['configurationFiles']} == KINDS
            and len(manifest['configurationFiles']) == len(KINDS), 'Native configuration inventory incomplete')
    for row in manifest['configurationFiles']:
        for phase in ('original', 'configured', 'final'):
            require(SHA((receipt / row[phase + 'File']).read_bytes()) == row[phase + 'Sha256'], 'Native configuration hash differs')
        require((receipt / row['originalFile']).read_bytes() == (receipt / row['finalFile']).read_bytes(), 'Configuration restoration differs')
        require({r['phase'] for r in row['readBacks']} == {'before', 'after'} and len(row['readBacks']) == 2,
                'Unchanged native read-back missing')
        for back in row['readBacks']:
            require(SHA((receipt / back['file']).read_bytes()) == back['sha256'] == row['configuredSha256'], 'Native settings changed during controls')
    provenance = READ(folder / 'native-source-provenance.json')
    require(provenance['container'] == 'samlscope-reference-shibboleth'
            and provenance['nativeJar'] == '/usr/local/tomcat/webapps/idp/WEB-INF/lib/idp-conf-impl-5.2.3.jar'
            and provenance['jarFile'] == 'native-idp-conf-impl.jar'
            and provenance['jarSha256'] == SHA((folder / provenance['jarFile']).read_bytes()) == NATIVE_JAR_SHA256,
            'Native configuration module identity differs')
    with zipfile.ZipFile(folder / provenance['jarFile']) as archive:
        for kind, member in provenance['sources'].items():
            require(archive.read(member) == (folder / ('native-' + kind + '.xml')).read_bytes()
                    == (receipt / ('native-' + kind + '.xml')).read_bytes(), 'Native packaged source original differs')
    native = READ(receipt / manifest['spMetadataReadFile'])
    plan = READ(child / 'created.json')['run']['planId']; entity = 'http://localhost:18080/p/' + plan
    require(SHA((receipt / manifest['spMetadataReadFile']).read_bytes()) == manifest['spMetadataReadSha256']
            and native['runId'] == run and native['entityId'] == entity
            and native['container'] == 'samlscope-reference-shibboleth' and native['exitCode'] == 0
            and native['command'] == ['/opt/reference-idp/bin/mdquery.sh', '-u', 'http://localhost:8080/idp', '-e', entity]
            and native['sha256'] == manifest['spMetadataSha256'] == SHA((receipt / manifest['spMetadataFile']).read_bytes())
            and (receipt / manifest['spMetadataFile']).read_bytes() == (folder / 'native-effective-sp-metadata.xml').read_bytes(),
            'SP metadata did not come from the native effective resolver')
    formal = READ(child / 'formal-authentication-identity-evaluation.json')
    require(formal['runId'] == run and formal['transcriptUnchanged'] is True, 'Formal Recorder changed')
    _verify_suite_runtime(child, run, parsed_time(formal['startedAt']), PINS)
    with zipfile.ZipFile(child / READ(child / 'suite-runtime-terminal-http.json')['jars']['runner']['file']) as archive:
        require(b'samlscope-shibboleth-authentication-identity-v1' in archive.read('com/samlscope/runner/cases/ShibbolethAuthenticationIdentityEvidenceFile.class'),
                'Production identity Reader absent')
    evaluation = child / 'evaluation-terminal-http-v1'
    require(READ(evaluation / 'transcript-before.json') == READ(evaluation / 'transcript.json') == list(entries.values()),
            'Formal evaluation changed Recorder originals')
    result_path = evaluation / 'result.json'; case = find_case(READ(result_path), CASE)
    require((case['outcome'], case['verdict'], case['reason_code'], case['attested'])
            == ('SATISFIED', 'PASS', 'configuration.identity.native-controls-observed', False)
            and formal['case'] == case, 'Formal native identity conclusion differs')
    expected = {manifest[k][f] for k in ('positive', 'unable') for f in ('requestReference', 'responseReference')}
    require({e['reference'] for e in case['evidence'] if e['kind'] == 'transcript'} == expected, 'Conclusion references differ')
    replay(folder)
    return result_path, {CASE: case}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--retain-replay', action='store_true')
    parser.add_argument('--live', action='store_true', help='Additionally compare current installed production JARs')
    args = parser.parse_args()
    if args.retain_replay or args.live:
        print(replay(args.root / FOLDER, retain=args.retain_replay, live=args.live))
    else:
        path, cases = verify(args.root)
        print(path, {name: case['verdict'] for name, case in cases.items()})
