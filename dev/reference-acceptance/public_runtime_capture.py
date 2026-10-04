"""Capture native runtime identity without persisting Docker environment credentials.

The existing runtime recorder receives Docker's own JSON projection rather than a full inspect
record. This is deliberately a public identity/port read-back, not a configuration inventory.
"""
import contextlib
import json
from pathlib import Path
import capture_terminal_http_runtime as runtime

CONTAINER_FORMAT = ('[{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
                    '"State":{"Running":{{json .State.Running}},"StartedAt":{{json .State.StartedAt}}},'
                    '"Config":{"Image":{{json .Config.Image}}},'
                    '"NetworkSettings":{"Ports":{{json .NetworkSettings.Ports}}}}]')
IMAGE_FORMAT = '[{"Id":{{json .Id}},"RepoDigests":{{json .RepoDigests}}}]'


@contextlib.contextmanager
def public_inspection(output_dir):
    original = runtime.output
    commands = []

    def output(command):
        if command[:2] == ['docker', 'inspect']:
            command = ['docker', 'inspect', '--format', CONTAINER_FORMAT, *command[2:]]
            commands.append(command)
        elif command[:3] == ['docker', 'image', 'inspect']:
            command = ['docker', 'image', 'inspect', '--format', IMAGE_FORMAT, *command[3:]]
            commands.append(command)
        return original(command)

    runtime.output = output
    try:
        yield
    finally:
        runtime.output = original
        path = Path(output_dir) / 'public-runtime-inspection-scope.json'
        previous = json.loads(path.read_text()) if path.exists() else []
        previous.append(dict(scope='native-public-identity-and-port-projection', commands=commands,
                             environment_captured=False, credentials_captured=False))
        path.write_text(json.dumps(previous, indent=2) + '\n')


def capture_target(output_dir, product, phase):
    with public_inspection(output_dir):
        return runtime.capture_target(output_dir, product, phase)


def capture_suite(output_dir):
    with public_inspection(output_dir):
        return runtime.capture_suite(output_dir)
