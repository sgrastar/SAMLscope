#!/usr/bin/env python3
"""Deploy qualified unprotected project overlays while preserving live inputs in memory.

The application volume is retained. Public runtime identities and operation
hashes are recorded; Docker environment values are neither printed nor saved.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import time
import urllib.request

REPO = Path(__file__).resolve().parents[2]
SUITE = 'samlscope-reference-suite'
FORWARD = 'samlscope-reference-local-forward-v116'
PROJECT_JARS = tuple(name + '-0.1.0.jar' for name in ('api', 'core', 'peer', 'runner', 'saml', 'store'))
OVERLAY_JARS = {'core-0.1.0.jar', 'store-0.1.0.jar', 'runner-0.1.0.jar', 'saml-0.1.0.jar', 'peer-0.1.0.jar'}
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def inspect(name):
    values = json.loads(subprocess.check_output(['docker', 'inspect', name]))
    require(len(values) == 1, 'Ambiguous container')
    return values[0]


def public(item):
    return dict(id=item['Id'], image=item['Image'], running=item['State']['Running'],
                startedAt=item['State']['StartedAt'], mounts=item['Mounts'],
                network=item['HostConfig']['NetworkMode'], ports=item['HostConfig']['PortBindings'])


def mount_identity(item):
    return sorted(item['Mounts'], key=lambda mount: (mount['Destination'], mount['Type'], mount['Source']))


def environment(item):
    values = item['Config'].get('Env') or []
    require(all('=' in value for value in values), 'Malformed environment')
    result = dict(value.split('=', 1) for value in values)
    require(len(result) == len(values), 'Ambiguous environment')
    return result


def launch_identity(item):
    # Health counters and exec IDs change while the same qualified runtime is running.
    return {key: item[key] for key in ('Id', 'Image', 'Config', 'HostConfig')} | {
        'mounts': mount_identity(item), 'running': item['State']['Running'], 'startedAt': item['State']['StartedAt']}


def require_persistent_data(item):
    values = environment(item)
    current, legacy = values.get('SAMLSCOPE_DATA_DIR'), values.get('SAMLIER_DATA_DIR')
    require(current is None or legacy is None or current == legacy, 'Conflicting data directories')
    raw = current if current is not None else legacy if legacy is not None else '/data'
    data = PurePosixPath(raw)
    require(data.is_absolute() and '..' not in data.parts and str(data) != '/', 'Unsafe data directory')
    covering = []
    for mount in item['Mounts']:
        destination = PurePosixPath(mount['Destination'])
        require(destination.is_absolute() and '..' not in destination.parts, 'Unsafe mount destination')
        if data.is_relative_to(destination):
            covering.append(mount)
        if destination.is_relative_to(data):
            require(mount['Type'] in ('volume', 'bind') and mount['RW'], 'Nonpersistent nested data mount')
    require(covering, 'Application data is in the disposable container layer')
    effective = max(covering, key=lambda mount: len(PurePosixPath(mount['Destination']).parts))
    require(effective['Type'] in ('volume', 'bind') and effective['RW']
            and (effective.get('Name') if effective['Type'] == 'volume' else effective.get('Source')),
            'Application data requires a writable persistent mount')


def preflight_launch(before, forward, image):
    """Validate both directions before any stop or removal can happen."""
    require_persistent_data(before)
    require('SAMLSCOPE_IMAGE_DIGEST' in environment(before), 'Image digest input unavailable')
    require('SAMLIER_IMAGE_DIGEST' not in environment(before), 'Legacy image digest needs explicit migration')
    return {
        'newSuite': run_arguments(before, SUITE, image, digest=image),
        'oldSuite': run_arguments(before, SUITE, before['Image']),
        'newForward': run_arguments(forward, FORWARD, forward['Image'], network='container:pending-suite'),
        'oldForward': run_arguments(forward, FORWARD, forward['Image'], network='container:pending-suite'),
    }


def bind_forward(template, suite_id):
    require(len(suite_id) == 64 and all(c in '0123456789abcdef' for c in suite_id), 'Invalid Suite identity')
    result = list(template)
    index = result.index('--network') + 1
    require(result[index] == 'container:pending-suite', 'Unqualified network template')
    result[index] = 'container:' + suite_id
    return result


def wait_health():
    for attempt in range(30):
        try:
            with urllib.request.urlopen('http://localhost:18080/api/health', timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(1)
    raise ValueError('Suite health unavailable')


def runtime_hashes(execute):
    rows = execute(['docker', 'exec', SUITE, 'sha256sum',
                    *('/opt/samlscope/lib/' + name for name in PROJECT_JARS)]).splitlines()
    result = {}
    for row in rows:
        digest, path = row.split('  ', 1)
        require(path.startswith('/opt/samlscope/lib/') and Path(path).name in PROJECT_JARS
                and Path(path).name not in result, 'Unexpected running JAR identity')
        result[Path(path).name] = digest
    return result


def verify_live(before, forward, live, live_forward, image):
    require(live['State']['Running'] and live_forward['State']['Running'] and live['Image'] == image
            and live_forward['Image'] == forward['Image']
            and live_forward['HostConfig']['NetworkMode'] == 'container:' + live['Id'], 'Live identity changed')
    require(mount_identity(live) == mount_identity(before)
            and mount_identity(live_forward) == mount_identity(forward), 'Mounts changed')
    old_environment = environment(before)
    if image != before['Image']:
        old_environment['SAMLSCOPE_IMAGE_DIGEST'] = image
    require(old_environment == environment(live) and environment(forward) == environment(live_forward),
            'Live inputs changed')
    require_persistent_data(live)


def run_arguments(item, name, image, network=None, digest=None):
    host, config = item['HostConfig'], item['Config']
    require(host['RestartPolicy']['Name'] == 'no' and not host['AutoRemove'] and not host['ExtraHosts'],
            'Unsupported live launch configuration')
    args = ['docker', 'run', '-d', '--name', name, '--network', network or host['NetworkMode']]
    for container_port, bindings in (host['PortBindings'] or {}).items():
        for binding in bindings or []:
            args += ['-p', binding['HostIp'] + ':' + binding['HostPort'] + ':' + container_port]
    for mount in item['Mounts']:
        require(mount['Type'] in ('volume', 'bind'), 'Unsupported mount')
        source = mount['Name'] if mount['Type'] == 'volume' else mount['Source']
        spec = 'type=' + mount['Type'] + ',source=' + source + ',target=' + mount['Destination']
        if not mount['RW']:
            spec += ',readonly'
        args += ['--mount', spec]
    for value in config.get('Env') or []:
        if value.startswith('SAMLSCOPE_IMAGE_DIGEST=') and digest is not None:
            value = 'SAMLSCOPE_IMAGE_DIGEST=' + digest
        args += ['-e', value]
    if config['User']:
        args += ['--user', config['User']]
    if config['WorkingDir']:
        args += ['--workdir', config['WorkingDir']]
    entrypoint = config.get('Entrypoint') or []
    require(len(entrypoint) <= 1, 'Unsupported entrypoint vector')
    if entrypoint:
        args += ['--entrypoint', entrypoint[0]]
    args += [image, *(config.get('Cmd') or [])]
    return args


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    folder, parent = args.output.resolve(), args.parent.resolve()
    require(folder.is_relative_to(REPO / 'build/acceptance') and not (folder / 'deployment.json').exists(), 'Unsafe generation')
    qualification = json.loads((folder / 'isolated-test-overlay.json').read_bytes())
    prior = json.loads((parent / 'runtime-live-verification.json').read_bytes())
    changed = qualification['changedProjectJars']
    require(qualification['packagedReplayExitCode'] == 0 and qualification['testCount'] > 0
            and changed and len(set(changed)) == len(changed) and set(changed) <= OVERLAY_JARS
            and qualification['mainClassSourcesBoundToArchive'] is True
            and qualification['signedProtectedSourcesIncluded'] is False,
            'Only qualified unprotected project changes allowed')
    require(set(qualification['projectJars']) == set(PROJECT_JARS)
            and set(prior['projectJars']) == set(PROJECT_JARS), 'Incomplete runtime identity')
    require(qualification['parentImageId'] == prior['imageId']
            and qualification['testedArchiveSha256'] == qualification['projectJars']
            and qualification['archiveUnchangedAfterTesting'] is True,
            'Tested archive or parent image binding unavailable')
    for name in PROJECT_JARS:
        source = folder / 'runtime-built' / name
        original = parent / 'runtime-built' / name
        require(source.stat().st_nlink == 1 and not source.is_symlink()
                and SHA(source.read_bytes()) == qualification['projectJars'][name], 'Qualified archive differs')
        require(original.stat().st_nlink == 1 and not original.is_symlink()
                and SHA(original.read_bytes()) == prior['projectJars'][name], 'Parent archive differs')
    require(set(changed) == {name for name in PROJECT_JARS
                            if qualification['projectJars'][name] != prior['projectJars'][name]},
            'Declared JAR changes differ from the qualified archive')
    before, forward = inspect(SUITE), inspect(FORWARD)
    require(before['State']['Running'] and forward['State']['Running'] and before['Image'] == prior['imageId']
            and forward['HostConfig']['NetworkMode'] == 'container:' + before['Id'], 'Current runtime differs')
    # Validate recovery too: an unsupported original launch cannot be repaired after removal.
    preflight_launch(before, forward, 'sha256:' + '0' * 64)
    context = folder / 'docker-context'
    operations = []

    def execute(argv):
        result = subprocess.run(argv, capture_output=True)
        operations.append(dict(operation=argv[:3], exitCode=result.returncode,
                               stdoutSha256=SHA(result.stdout), stderrSha256=SHA(result.stderr)))
        (folder / 'operations.json').write_text(json.dumps(operations, indent=2) + '\n')
        require(result.returncode == 0, 'Runtime operation failed; diagnostics retained by hash')
        return result.stdout.decode().strip()

    context_owned = False
    alias_created = False
    parent_alias = 'samlscope-overlay-parent:' + prior['imageId'].removeprefix('sha256:') + '-' + SHA(str(folder).encode())[:16]
    mutation_started = False
    try:
        if context.exists():
            require(not context.is_symlink() and {p.name for p in context.iterdir()} == {'Dockerfile', *changed},
                    'Unexpected build context')
            require(all(p.is_file() and not p.is_symlink() for p in context.iterdir()), 'Unsafe context file')
            context_owned = True
        else:
            context.mkdir()
            context_owned = True
            for name in changed:
                shutil.copyfile(folder / 'runtime-built' / name, context / name)
        require(all(not (context / name).is_symlink()
                    and SHA((context / name).read_bytes()) == qualification['projectJars'][name]
                    for name in changed), 'Build context differs from the qualified archives')
        base_image = prior['image']
        require(subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', base_image]).decode().strip()
                == before['Image'], 'Local base image tag changed')
        alias_check = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', parent_alias], capture_output=True)
        if alias_check.returncode == 0:
            require(alias_check.stdout.decode().strip() == before['Image'], 'Qualified parent alias differs')
        else:
            require(alias_check.returncode == 1, 'Parent alias lookup failed')
            execute(['docker', 'tag', before['Image'], parent_alias])
            alias_created = True
        require(subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', parent_alias]).decode().strip()
                == before['Image'], 'Parent alias not bound to the qualified image')
        (context / 'Dockerfile').write_text('FROM ' + parent_alias + '\nCOPY --chown=10001:10001 '
                                           + ' '.join(changed) + ' /opt/samlscope/lib/\n')
        with (folder / 'build.log').open('wb') as log:
            subprocess.run(['docker', 'build', '-t', args.image, str(context)], check=True, stdout=log, stderr=subprocess.STDOUT)
        image = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', args.image]).decode().strip()
        require(subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', base_image]).decode().strip()
                == before['Image']
                and subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', parent_alias]).decode().strip()
                == before['Image'], 'Base image changed during build')
        launches = preflight_launch(before, forward, image)
        # Re-read just before mutation to reject stale launch inputs or a replaced container.
        require(launch_identity(inspect(SUITE)) == launch_identity(before)
                and launch_identity(inspect(FORWARD)) == launch_identity(forward), 'Runtime changed during qualification')
        (folder / 'before-containers.json').write_text(json.dumps([public(before), public(forward)], indent=2) + '\n')
        mutation_started = True
        execute(['docker', 'stop', FORWARD]); execute(['docker', 'stop', SUITE])
        execute(['docker', 'rm', FORWARD]); execute(['docker', 'rm', SUITE])
        execute(launches['newSuite'])
        live = inspect(SUITE)
        execute(bind_forward(launches['newForward'], live['Id']))
        wait_health()
        live, live_forward = inspect(SUITE), inspect(FORWARD)
        verify_live(before, forward, live, live_forward, image)
        hashes = runtime_hashes(execute)
        require(hashes == qualification['projectJars'], 'Running JARs differ from qualified archives')
        (folder / 'after-containers.json').write_text(json.dumps([public(live), public(live_forward)], indent=2) + '\n')
        deployment = dict(recordedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(), image=args.image, imageId=image,
                          suiteContainerId=live['Id'], forwarderContainerId=live_forward['Id'], healthStatus=200,
                          mountsUnchanged=True, writablePersistentDataVerified=True, launchValidatedBeforeMutation=True,
                          parentAliasBoundToImageId=prior['imageId'],
                          suiteRecreated=1, forwarderRecreated=1, imageDigestEnvironmentUpdated=True,
                          effectiveEnvironmentComparedInMemory=True,
                          allowedEnvironmentChange={'SAMLSCOPE_IMAGE_DIGEST': image},
                          changedProjectJars=changed, projectJars=hashes,
                          productRecreated=0, productSettings=0, protocolSubmissions=0, personOperations=0)
        (folder / 'deployment.json').write_text(json.dumps(deployment, indent=2) + '\n')
    except Exception:
        if mutation_started:
            rollback = dict(originalImageRestored=False, applicationVolumeRetained=False,
                            credentialsPersisted=False, recoveryVerified=False)
            try:
                for name in (FORWARD, SUITE):
                    if subprocess.run(['docker', 'inspect', name], capture_output=True).returncode == 0:
                        execute(['docker', 'rm', '-f', name])
                execute(launches['oldSuite'])
                recovered = inspect(SUITE)
                execute(bind_forward(launches['oldForward'], recovered['Id']))
                wait_health()
                recovered, recovered_forward = inspect(SUITE), inspect(FORWARD)
                verify_live(before, forward, recovered, recovered_forward, before['Image'])
                require(runtime_hashes(execute) == prior['projectJars'], 'Recovered JARs differ')
                rollback.update(originalImageRestored=True, applicationVolumeRetained=True, recoveryVerified=True,
                                suiteContainerId=recovered['Id'], forwarderContainerId=recovered_forward['Id'], healthStatus=200)
            finally:
                (folder / 'rollback.json').write_text(json.dumps(rollback, indent=2) + '\n')
        raise
    finally:
        # Only the validated owned context is disposable; archives and diagnostic logs remain.
        if context_owned:
            shutil.rmtree(context)
        if alias_created:
            execute(['docker', 'image', 'rm', parent_alias])
    print('Qualified project overlay deployed; target products and application volume retained.')


if __name__ == '__main__':
    main()
