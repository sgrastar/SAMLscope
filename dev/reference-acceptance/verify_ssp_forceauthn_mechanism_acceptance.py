#!/usr/bin/env python3
"""Replay native internal-state originals, all controls, and central stored conclusions."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import native_publisher_stored_outcome as stored
from capture_terminal_http_runtime import api
from verify_native_publisher_key_inventory_acceptance import readback_inventory, public_cases

REPO = Path(__file__).resolve().parents[2]
FOLDER = 'ssp-forceauthn-mechanism-r3'
RUNTIME = 'reader-native-mechanism-v230'
DEPLOYMENT = 'deployment-v230'
CASE = 'IIP-IDP06-b-idp-01'
HELPER = 'VerifySimpleSamlPhpForceAuthnMechanism'
STORED = 'ReadNativePublisherKeyStoredConclusions'
JARS = ('runner', 'core', 'saml', 'store', 'peer', 'api')
SUITE = 'samlscope-reference-suite'
PINS = {
    'runner': 'c66778bafc59968b4676fdae9868075c2ce30235621404836f92c6837e2e5092',
    'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe',
    'saml': 'db9f6e715f87b965020311507b56e9a990d30741d5047e8fab35d85aa1de3ab5',
    'store': 'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece',
    'peer': '133703391229d9ce4247af5bb3d39a1853b9caa816307fe56a17148ff4a3242c',
    'api': '24cb469496204e912e496ec317e4066fa434d0270a951617277f0b349259de8b',
    'dependencyPrioritySha256': '2f4464628c25eebd64c84a432e745c634d3daff60dd8064c289e039b9691b5a9',
    'VerifySimpleSamlPhpForceAuthnMechanism': '3008a9b3413487984f9bb605b1ea1a5f31d5e7393dc681ca17792029874c849e',
    'ReadNativePublisherKeyStoredConclusions': 'b4887c7dd1137ea02b7c75d3bf7405e5669e56f0f4971de26ca80a66b8b593fd',
}
CONTROLS = {'lost-true', 'always-true', 'missing-flag', 'wrong-request', 'wrong-mechanism', 'wrong-stage',
            'wrong-source', 'state-after-response', 'credentials-persisted', 'state-handle-persisted',
            'duplicate-state', 'restore-mismatch', 'wrong-run', 'wrong-target', 'wrong-command'}
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
READ = lambda path: json.loads(Path(path).read_bytes())


def require(value, message):
    if not value:
        raise ValueError(message)


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def folder_from(root):
    root = Path(root)
    return root if root.name == FOLDER else root / FOLDER


def original_contract(folder):
    browser = folder / 'browser'
    run = READ(browser / 'created.json')['run']['id']
    receipt = folder / 'receipt' / (run + '.simplesamlphp-forceauthn-mechanism')
    manifest = READ(receipt / 'manifest.json')
    require(manifest['runId'] == run and manifest['caseId'] == CASE, 'Foreign native receipt')
    for name, digest in manifest['files'].items():
        path = receipt / name
        require(path.parent == receipt and path.is_file() and not path.is_symlink()
                and SHA(path.read_bytes()) == digest, 'Changed native original')
    require(SHA((browser / 'target-metadata.xml').read_bytes()) == manifest['targetMetadataSha256'], 'Target mismatch')
    restored = READ(browser / 'restoration.json')
    require(restored['restored'] is True and restored['failures'] == []
            and restored['original_sha256'] == restored['final_sha256'], 'Native restoration incomplete')
    operations = READ(browser / 'operation-counts.json')
    require(operations['human_operations'] == operations['product_restarts'] == 0
            and operations['configuration_write_attempts'] == 2 and operations['restoration_write_attempts'] == 1
            and operations['reloads'] == 2 and operations['login_submission_attempts'] == 3
            and operations['target_submissions'] == 4 and operations['initial_baseline_submissions'] == 1,
            'Actual configuration and interaction counts differ')
    native = READ(folder / 'mechanism-operation-counts.json')
    require(native == dict(nativeStateReadbacks=3, credentialPosts=3, protocolOperations=4,
                           humanOperations=0, nativeCodeWrites=0, outcomeAssigned=False), 'Native collector counts differ')
    entries = READ(browser / 'transcript.json')
    require(len(entries) == len({e['id'] for e in entries}) and all(e['runId'] == run for e in entries), 'Foreign protocol original')
    for row in READ(browser / 'decoded-manifest.json'):
        path = browser / row['file']
        require(path.parent == browser / 'decoded' and SHA(path.read_bytes()) == row['sha256'], 'Decoded original changed')
    return run, receipt, manifest, entries


def archive(folder):
    dest = folder / RUNTIME
    dest.mkdir()
    qualification = folder.parent / DEPLOYMENT / 'isolated-test-overlay.json'
    qualified = READ(qualification)
    live_proof = READ(folder.parent / DEPLOYMENT / 'runtime-live-verification.json')
    require(qualified['projectJars'] == live_proof['projectJars'] and live_proof['healthStatus'] == 200,
            'Deployment not qualified')
    pins = {}
    for name in JARS:
        remote = '/opt/samlscope/lib/' + name + '-0.1.0.jar'
        before = subprocess.check_output(['docker', 'exec', SUITE, 'sha256sum', remote]).decode().split()[0]
        subprocess.run(['docker', 'cp', SUITE + ':' + remote, str(dest / (name + '.jar'))], check=True, capture_output=True)
        after = subprocess.check_output(['docker', 'exec', SUITE, 'sha256sum', remote]).decode().split()[0]
        require(before == after == SHA((dest / (name + '.jar')).read_bytes())
                == qualified['projectJars'][name + '-0.1.0.jar'], 'Runtime changed during archive')
        pins[name] = before
    dependency_folder = dest / 'dependencies'
    dependency_folder.mkdir()
    priorities = []
    for source, digest in qualified['dependencySha256'].items():
        source = Path(source)
        require(source.name not in {n + '-0.1.0.jar' for n in JARS} and SHA(source.read_bytes()) == digest,
                'Qualified dependency changed')
        target = dependency_folder / source.name
        require(not target.exists(), 'Duplicate dependency')
        shutil.copyfile(source, target)
        priorities.append(dict(file='dependencies/' + source.name, sha256=digest))
    save(dest / 'dependency-priority.json', dict(mutableProjectEntriesExcluded=True, entries=priorities,
                                               qualifiedSourceSha256=SHA(qualification.read_bytes())))
    pins['dependencyPrioritySha256'] = SHA((dest / 'dependency-priority.json').read_bytes())
    for name in (HELPER, STORED):
        source = Path(__file__).with_name(name + '.java')
        shutil.copyfile(source, dest / source.name)
        pins[name] = SHA(source.read_bytes())
    save(dest / 'pins.json', pins)
    save(dest / 'archive-provenance.json', dict(actualDeployedByteCopy=True, mutableProjectHardlinks=False,
                                               qualifiedDeployment=DEPLOYMENT, productOperations=0))
    return pins


def replay(folder):
    runtime = folder / RUNTIME
    pins = READ(runtime / 'pins.json')
    require(PINS and pins == PINS, 'Runtime pins not independently finalized')
    for name in JARS:
        path = runtime / (name + '.jar')
        require(path.stat().st_nlink == 1 and SHA(path.read_bytes()) == pins[name], 'Archived project changed')
    for name in (HELPER, STORED):
        require(SHA((runtime / (name + '.java')).read_bytes()) == pins[name], 'Archived helper changed')
    require(SHA((runtime / 'dependency-priority.json').read_bytes()) == pins['dependencyPrioritySha256'], 'Dependency order changed')
    cp = stored.archived_classpath(runtime)
    with tempfile.TemporaryDirectory(prefix='ssp-native-mechanism-replay-') as name:
        temporary = Path(name)
        classes = temporary / 'classes'
        subprocess.run(['javac', '-sourcepath', '', '-cp', cp, '-d', str(classes), str(runtime / (HELPER + '.java'))],
                       check=True, capture_output=True, timeout=60)
        require(all(p.name.startswith(HELPER) for p in classes.rglob('*.class')), 'Replay helper shadows production')
        subprocess.run(['java', '-cp', str(classes) + ':' + cp, 'com.samlscope.runner.cases.' + HELPER,
                        str(folder.resolve()), str((folder / 'receipt').resolve()), str(temporary / 'report.json')],
                       check=True, capture_output=True, timeout=90)
        return READ(temporary / 'report.json')


def install(folder):
    run, receipt, manifest, entries = original_contract(folder)
    require(replay(folder) == READ(folder / 'native-reader-replay.json'), 'Production replay must precede installation')
    evaluation = folder / 'evaluation'
    evaluation.mkdir()
    shutil.copyfile(folder / 'browser/created.json', folder / 'created.json')
    stored.capture(folder, RUNTIME, 'evaluation/stored-before.json', run, CASE)
    save(evaluation / 'result-before.json', api('/api/runs/' + run + '/result.json'))
    save(evaluation / 'transcript-before.json', api('/api/runs/' + run + '/transcript'))
    require(READ(evaluation / 'transcript-before.json') == entries, 'History changed before adoption')
    base = '/data/force-authn-mechanism-evidence'
    destination = base + '/' + receipt.name
    stage = base + '/.stage-' + receipt.name
    for path in (destination, stage):
        require(subprocess.run(['docker', 'exec', SUITE, 'test', '-e', path], capture_output=True).returncode == 1,
                'Refusing to overwrite installed evidence')
    expected = manifest['files'] | {'manifest.json': SHA((receipt / 'manifest.json').read_bytes())}
    with tempfile.TemporaryDirectory(prefix='ssp-native-mechanism-install-') as name:
        temporary = Path(name) / 'receipt'
        shutil.copytree(receipt, temporary)
        for path in [temporary, *temporary.rglob('*')]:
            path.chmod(0o755 if path.is_dir() else 0o644)
        subprocess.run(['docker', 'exec', '--user', '0', SUITE, 'mkdir', '-p', base], check=True, capture_output=True)
        subprocess.run(['docker', 'cp', str(temporary), SUITE + ':' + stage], check=True, capture_output=True)
        require(readback_inventory(stage) == expected, 'Staged receipt readback differs')
        subprocess.run(['docker', 'exec', '--user', '0', SUITE, 'mv', stage, destination], check=True, capture_output=True)
    require(readback_inventory(destination) == expected, 'Installed receipt differs')
    save(folder / 'receipt-installation.json', dict(path=destination, records=expected, atomicSameDataFilesystem=True,
                                                   publicFiles0644=True, productOperations=0))


def formal(folder):
    run, _, _, _ = original_contract(folder)
    evaluation = folder / 'evaluation'
    require((evaluation / 'stored-before.json').is_file(), 'Original stored conclusion missing')
    save(evaluation / 'evaluate.json', api('/api/runs/' + run + '/protocol-evidence/evaluate', {}))
    save(evaluation / 'result.json', api('/api/runs/' + run + '/result.json'))
    save(evaluation / 'transcript.json', api('/api/runs/' + run + '/transcript'))
    stored.capture(folder, RUNTIME, 'evaluation/stored-after.json', run, CASE)


def verify(root):
    folder = folder_from(root)
    run, receipt, manifest, entries = original_contract(folder)
    observed = replay(folder)
    require(observed == READ(folder / 'native-reader-replay.json') and set(observed['negativeControls']) == CONTROLS
            and set(observed['negativeControls'].values()) == {'NOT_VERIFIED'} and observed['productOperations'] == 0
            and observed['operatorAttestationSupplied'] is False and observed['privateCredentialsPersisted'] is False,
            'Production controls/provenance differ')
    outcome = observed['outcome']
    require(outcome['outcome'] == 'SATISFIED' and outcome['reasonCode'] == 'idp.force-authn.mechanism-reachability.native-proven',
            'Native mechanism conclusion differs')
    installed = READ(folder / 'receipt-installation.json')
    require(installed['records'] == manifest['files'] | {'manifest.json': SHA((receipt / 'manifest.json').read_bytes())}
            and installed['atomicSameDataFilesystem'] and installed['productOperations'] == 0, 'Installation proof differs')
    evaluation = folder / 'evaluation'
    result = READ(evaluation / 'result.json')
    require(result['run']['id'] == run and result['target']['metadata_digest'] == 'sha256:' + manifest['targetMetadataSha256']
            and READ(evaluation / 'transcript-before.json') == READ(evaluation / 'transcript.json') == entries,
            'Formal Run identity/history differs')
    after = stored.compare_stored(folder, RUNTIME, CASE, outcome)
    case = public_cases(result)[CASE]
    require((case['mode'], case['outcome'], case['verdict'], case['attested'], case['reason_code'])
            == ('ATTESTED', 'SATISFIED', 'PASS', False, outcome['reasonCode'])
            and case['evidence'] == outcome['evidence'] and after['verdict'] == 'PASS', 'Central determination differs')
    return evaluation / 'result.json', {CASE: case}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--mode', choices=('archive', 'replay', 'install', 'formal', 'verify'), default='verify')
    args = parser.parse_args()
    folder = folder_from(args.root)
    if args.mode == 'archive':
        print(json.dumps(archive(folder), indent=2))
    elif args.mode == 'replay':
        result = replay(folder)
        destination = folder / 'native-reader-replay.json'
        require(not destination.exists(), 'Refusing to replace production replay')
        save(destination, result)
        print(result['runId'])
    elif args.mode == 'install':
        install(folder)
    elif args.mode == 'formal':
        formal(folder)
    else:
        print(verify(args.root)[0])
