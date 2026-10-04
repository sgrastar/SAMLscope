#!/usr/bin/env python3
"""Qualify a tested multi-module overlay without replacing unrelated host JARs."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
PROJECT_JARS = {n + '-0.1.0.jar' for n in ('api', 'core', 'peer', 'runner', 'saml', 'store')}
ALLOWED_CHANGED = {n + '-0.1.0.jar' for n in ('peer', 'runner', 'saml')}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise RuntimeError(message)


def command(argv):
    return subprocess.run(argv, check=True, capture_output=True).stdout.decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    parent, output = args.parent.resolve(), args.output.resolve()
    require(output.is_relative_to(ROOT / 'build/acceptance') and not (output / 'runtime-live-verification.json').exists(),
            'Unexpected or already qualified output')
    proof = json.loads((output / 'isolated-test-overlay.json').read_text())
    require(proof['schema'] == 'samlscope-project-isolated-overlay-qualification-v1'
            and proof['testCount'] > 0 and proof['packagedReplayExitCode'] == 0
            and proof['signedProtectedSourcesIncluded'] is False
            and proof['unrelatedWorktreeSourcesIncluded'] is False
            and proof['mainClassSourcesBoundToArchive'] is True, 'Packaged qualification unavailable')
    expected = proof['projectJars']
    parent_runtime = json.loads((parent / 'runtime-live-verification.json').read_text())
    prior = parent_runtime['projectJars']
    require(proof['parentImageId'] == parent_runtime['imageId']
            and proof['testedArchiveSha256'] == expected and proof['archiveUnchangedAfterTesting'] is True,
            'Parent image or tested archive binding unavailable')
    dependencies = proof['runtimeDependencySha256']
    require(dependencies and dependencies == proof['parentRuntimeDependencySha256'], 'Runtime dependency binding unavailable')
    require(set(expected) == set(prior) == PROJECT_JARS, 'Project JAR scope changed')
    changed = {n for n in PROJECT_JARS if expected[n] != prior[n]}
    require(changed and changed <= ALLOWED_CHANGED and changed == set(proof['changedProjectJars']), 'Unqualified module change')
    archive = output / 'runtime-built'
    for name, digest in expected.items():
        require((archive / name).stat().st_nlink == 1 and sha(archive / name) == digest, 'Archive changed')
    for path, digest in proof['sourceSha256'].items():
        require(sha(ROOT / path) == digest, 'Source changed since packaged qualification')
    deployment = json.loads((output / 'deployment.json').read_text())
    container = json.loads(command(['docker', 'inspect', 'samlscope-reference-suite']))[0]
    require(container['State']['Running'] and container['Image'] == deployment['imageId']
            and container['Id'] == deployment['suiteContainerId'], 'Unexpected live runtime')
    public_inputs = deployment.get('allowedEnvironmentChange', {})
    require(public_inputs == {'SAMLSCOPE_SLO_BACKCHANNEL_BASE': 'http://host.docker.internal:18080'}
            or (public_inputs == {'SAMLSCOPE_IMAGE_DIGEST': deployment['imageId']}
                and deployment.get('effectiveEnvironmentComparedInMemory') is True),
            'Unqualified public runtime input')
    environment = {value.split('=', 1)[0]: value.split('=', 1)[1]
                   for value in container['Config'].get('Env', []) if '=' in value}
    require(all(environment.get(name) == value for name, value in public_inputs.items()),
            'Live public runtime input differs')
    raw = command(['docker', 'exec', 'samlscope-reference-suite', 'sha256sum',
                   *('/opt/samlscope/lib/' + n for n in sorted(PROJECT_JARS))])
    live = {Path(line.split()[1]).name: line.split()[0] for line in raw.splitlines()}
    require(live == expected, 'Live JARs differ from tested archive')
    dependency_raw = command(['docker', 'exec', 'samlscope-reference-suite', 'sh', '-c',
                              'sha256sum /opt/samlscope/lib/*.jar'])
    all_jars = {Path(line.split()[1]).name: line.split()[0] for line in dependency_raw.splitlines()}
    require(all_jars == expected | dependencies, 'Live dependency inventory differs from qualified parent')
    for name, digest in dependencies.items():
        require(sha(ROOT / 'api/build/install/samlscope/lib' / name) == digest, 'Host dependency differs')
    gates = {'g1-docgen.log': 'docs/04 matches coverage.yaml', 'g1-structural.log': '46/46 PASS', 'g2.log': '21/21 PASS'}
    for name, message in gates.items():
        require(message in (output / name).read_text(), 'Gate unavailable: ' + name)
    with urllib.request.urlopen('http://localhost:18080/api/health', timeout=5) as response:
        require(response.status == 200, 'Suite health failed')
    lib = ROOT / 'api/build/install/samlscope/lib'
    before = {n: sha(lib / n) for n in PROJECT_JARS}
    require(before == prior, 'Unexpected host distribution before update')
    stages, installed = {}, []
    try:
        for name in sorted(changed):
            stage = lib / ('.' + name + '-' + output.name + '-qualified.tmp')
            require(not stage.exists(), 'Unresolved prior host update')
            stage.write_bytes((archive / name).read_bytes()); stage.chmod(0o644)
            require(sha(stage) == expected[name], 'Host staging differs')
            stages[name] = stage
        for name, stage in stages.items():
            os.replace(stage, lib / name); installed.append(name)
        require({n: sha(lib / n) for n in PROJECT_JARS} == expected, 'Host read-back differs')
    except BaseException:
        for name in installed:
            stage = lib / ('.' + name + '-' + output.name + '-rollback.tmp')
            stage.write_bytes((parent / 'runtime-built' / name).read_bytes()); stage.chmod(0o644)
            require(sha(stage) == prior[name], 'Host rollback staging differs')
            os.replace(stage, lib / name)
        for stage in stages.values():
            if stage.exists(): stage.unlink()
        require({n: sha(lib / n) for n in PROJECT_JARS} == prior, 'Host rollback differs')
        raise
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (output / 'runtime-live-project-sha256.txt').write_text(raw)
    host = {'schema': 'samlscope-host-project-overlay-v1', 'recordedAt': stamp,
            'beforeProjectJars': before, 'projectJars': expected,
            'changedProjectJars': sorted(changed), 'immutableArchivesIndependent': True,
            'fullGradleInstallDistRebuild': False, 'testedClassOverlayOnly': True,
            'sourceQualification': str((output / 'isolated-test-overlay.json').relative_to(ROOT))}
    (output / 'host-distribution-overlay.json').write_text(json.dumps(host, indent=2) + '\n')
    result = {'schema': 'samlscope-live-project-overlay-verification-v1', 'recordedAt': stamp,
              'image': deployment['image'], 'imageId': deployment['imageId'],
              'suiteContainerId': container['Id'], 'healthStatus': 200, 'projectJars': live,
              'changedProjectJars': sorted(changed), 'liveMatchesIndependentArchive': True,
              'liveMatchesHostDistribution': True, 'protectedApiJarUnchanged': True,
              'packagedTestCount': proof['testCount'], 'personOperations': 0,
              'runtimeDependencySha256': dependencies, 'liveDependenciesMatchQualifiedParent': True,
              'publicRuntimeInputs': public_inputs,
              'nativeCampaignMayResume': True, 'runtimeQualifierSha256': sha(Path(__file__))}
    (output / 'runtime-live-verification.json').write_text(json.dumps(result, indent=2) + '\n')
    third_party = {'schema': 'samlscope-runtime-third-party-verification-v1', 'recordedAt': stamp,
                   'imageId': deployment['imageId'], 'suiteContainerId': container['Id'],
                   'parentRuntimeVerificationSha256': sha(output / 'runtime-live-verification.json'),
                   'thirdPartyJars': dependencies, 'liveEqualsHostAndQualifiedParent': True,
                   'containerMutations': 0, 'productOperations': 0}
    (output / 'runtime-third-party-verification.json').write_text(json.dumps(third_party, indent=2) + '\n')
    (output / 'runtime-qualifier-source.py').write_bytes(Path(__file__).read_bytes())
    (output / 'gates.json').write_text(json.dumps({'g1Docgen': 'PASS', 'g1Structural': '46/46 PASS',
                                                 'g2': '21/21 PASS',
                                                 'logs': {n: sha(output / n) for n in gates}}, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
