#!/usr/bin/env python3
"""Bind a tested Runner overlay to the actual Suite and host test distribution."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', required=True, type=pathlib.Path)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    parent, output = args.parent.resolve(), args.output.resolve()
    check(output.is_relative_to(ROOT / 'build/acceptance'), 'Unexpected artifact directory')
    check(not (output / 'runtime-live-verification.json').exists(), 'Runtime already qualified')
    proof = json.loads((output / 'isolated-test-overlay.json').read_text())
    expected = proof['projectJars']
    prior = json.loads((parent / 'runtime-live-verification.json').read_text())['projectJars']
    check(proof['testCount'] > 0 and proof['packagedReplayExitCode'] == 0
          and proof['unrelatedWorktreeSourcesIncluded'] is False, 'Packaged test qualification unavailable')
    archive = output / 'runtime-built'
    for name, digest in expected.items():
        check((archive / name).stat().st_nlink == 1 and sha(archive / name) == digest, 'Archive changed: ' + name)
        if name != 'runner-0.1.0.jar':
            check(digest == prior[name], 'Non-Runner module changed')
    deployment = json.loads((output / 'deployment.json').read_text())
    def command(argv):
        return subprocess.run(argv, check=True, capture_output=True).stdout.decode()
    container = json.loads(command(['docker', 'inspect', 'samlscope-reference-suite']))[0]
    check(container['State']['Running'] and container['Image'] == deployment['imageId']
          and container['Id'] == deployment['suiteContainerId'], 'Unexpected deployed runtime')
    raw = command(['docker', 'exec', 'samlscope-reference-suite', 'sha256sum',
                   *('/opt/samlscope/lib/' + name for name in expected)])
    live = {pathlib.Path(line.split()[1]).name: line.split()[0] for line in raw.splitlines()}
    check(live == expected, 'Live project JARs differ from qualified archive')
    (output / 'runtime-live-project-sha256.txt').write_text(raw)
    gates = {'g1-docgen.log': 'docs/04 matches coverage.yaml',
             'g1-structural.log': '46/46 PASS', 'g2.log': '21/21 PASS'}
    for name, message in gates.items():
        check(message in (output / name).read_text(), 'Gate unavailable: ' + name)
    lib = ROOT / 'api/build/install/samlscope/lib'
    runner = lib / 'runner-0.1.0.jar'
    before = sha(runner)
    check(before == prior['runner-0.1.0.jar'], 'Unexpected host distribution')
    for name in expected:
        if name != runner.name:
            check(sha(lib / name) == expected[name], 'Host dependency changed: ' + name)
    stage = lib / ('.runner-' + output.name + '-qualified.tmp')
    check(not stage.exists(), 'Unresolved prior host update')
    stage.write_bytes((archive / runner.name).read_bytes())
    stage.chmod(0o644)
    check(sha(stage) == expected[runner.name], 'Host copy failed')
    os.replace(stage, runner)
    check({name: sha(lib / name) for name in expected} == expected, 'Host distribution read-back mismatch')
    with urllib.request.urlopen('http://localhost:18080/api/health', timeout=5) as response:
        check(response.status == 200, 'Suite health failed')
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    host = {'schema': 'samlscope-host-distribution-overlay-v1', 'recordedAt': stamp,
            'runnerBeforeSha256': before, 'runnerAfterSha256': sha(runner), 'projectJars': expected,
            'fiveOtherProjectJarsUnchanged': True, 'immutableArchivesIndependent': True,
            'fullGradleInstallDistRebuild': False, 'testedClassOverlayOnly': True,
            'sourceQualification': str((output / 'isolated-test-overlay.json').relative_to(ROOT))}
    (output / 'host-distribution-overlay.json').write_text(json.dumps(host, indent=2) + '\n')
    result = {'schema': 'samlscope-live-runner-overlay-verification-v1', 'recordedAt': stamp,
              'image': deployment['image'], 'imageId': deployment['imageId'],
              'suiteContainerId': container['Id'], 'healthStatus': 200, 'projectJars': live,
              'liveMatchesIndependentArchive': True, 'liveMatchesHostDistribution': True,
              'fiveOtherProjectJarsUnchanged': True, 'protectedApiJarUnchanged': True,
              'packagedTestCount': proof['testCount'], 'personOperations': 0,
              'nativeCampaignMayResume': True, 'runtimeQualifierSha256': sha(pathlib.Path(__file__))}
    (output / 'runtime-live-verification.json').write_text(json.dumps(result, indent=2) + '\n')
    (output / 'runtime-qualifier-source.py').write_bytes(pathlib.Path(__file__).read_bytes())
    (output / 'gates.json').write_text(json.dumps({'g1Docgen': 'PASS', 'g1Structural': '46/46 PASS',
                                                 'g2': '21/21 PASS',
                                                 'logs': {name: sha(output / name) for name in gates}}, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
