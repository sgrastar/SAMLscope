"""Pre-mutation and recovery guards; these tests never operate Docker."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('deployment', Path(__file__).with_name('deploy_project_overlay.py'))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


def container():
    return {'Id': 'a' * 64, 'Image': 'sha256:original',
            'State': {'Running': True, 'StartedAt': '2026-10-04T00:00:00Z'},
            'HostConfig': {'RestartPolicy': {'Name': 'no'}, 'AutoRemove': False, 'ExtraHosts': [],
                           'PortBindings': {}, 'NetworkMode': 'bridge'},
            'Config': {'Env': ['SAMLSCOPE_IMAGE_DIGEST=sha256:original'], 'User': '10001',
                       'WorkingDir': '/opt/samlscope', 'Entrypoint': [], 'Cmd': ['java']},
            'Mounts': [{'Type': 'volume', 'Name': 'retained-data', 'Source': '/volumes/data',
                        'Destination': '/data', 'RW': True}]}


class DeploymentGuards(unittest.TestCase):
    def test_unsupported_original_or_forward_launch_rejected_without_docker(self):
        for role, attribute, value in [('suite', 'RestartPolicy', {'Name': 'always'}),
                                       ('forward', 'ExtraHosts', ['unexpected:127.0.0.1'])]:
            suite, forward = container(), container()
            (suite if role == 'suite' else forward)['HostConfig'][attribute] = value
            with patch.object(d.subprocess, 'run') as run, patch.object(d.subprocess, 'check_output') as output:
                with self.assertRaises(ValueError):
                    d.preflight_launch(suite, forward, 'sha256:new')
                run.assert_not_called(); output.assert_not_called()

    def test_disposable_or_readonly_data_never_enters_launch(self):
        for mounts in ([], [dict(container()['Mounts'][0], RW=False)],
                       [dict(container()['Mounts'][0], Type='tmpfs')]):
            suite = container(); suite['Mounts'] = mounts
            with self.assertRaises(ValueError):
                d.preflight_launch(suite, container(), 'sha256:new')

    def test_longest_mount_wins_and_legacy_data_dir_is_preserved(self):
        suite = container()
        suite['Config']['Env'].append('SAMLIER_DATA_DIR=/data/custom')
        d.require_persistent_data(suite)
        suite['Mounts'].append(dict(suite['Mounts'][0], Destination='/data/custom', RW=False))
        with self.assertRaises(ValueError): d.require_persistent_data(suite)
        suite['Mounts'][-1]['RW'] = True
        d.require_persistent_data(suite)
        suite['Config']['Env'].append('SAMLSCOPE_DATA_DIR=/other')
        with self.assertRaises(ValueError): d.require_persistent_data(suite)

    def test_both_launch_directions_are_frozen_and_only_network_identity_is_bound(self):
        suite, forward = container(), container()
        launches = d.preflight_launch(suite, forward, 'sha256:new')
        self.assertIn('SAMLSCOPE_IMAGE_DIGEST=sha256:new', launches['newSuite'])
        self.assertIn('SAMLSCOPE_IMAGE_DIGEST=sha256:original', launches['oldSuite'])
        bound = d.bind_forward(launches['oldForward'], 'b' * 64)
        self.assertIn('container:' + 'b' * 64, bound)
        self.assertIn('container:pending-suite', launches['oldForward'])
        with self.assertRaises(ValueError): d.bind_forward(launches['newForward'], 'not-an-id')

    def test_mount_order_is_irrelevant_but_recovery_environment_is_not(self):
        old, forward = container(), container()
        old['Mounts'].append(dict(old['Mounts'][0], Name='config', Source='/volumes/config', Destination='/config'))
        live = copy.deepcopy(old); live['Mounts'].reverse()
        lf = copy.deepcopy(forward); lf['HostConfig']['NetworkMode'] = 'container:' + live['Id']
        d.verify_live(old, forward, live, lf, old['Image'])
        live['Config']['Env'].append('UNEXPECTED_INPUT=value')
        with self.assertRaises(ValueError): d.verify_live(old, forward, live, lf, old['Image'])

    def test_health_counter_changes_do_not_mask_changed_launch_or_epoch(self):
        old, same = container(), container()
        same['State']['Health'] = {'FailingStreak': 2}
        self.assertEqual(d.launch_identity(old), d.launch_identity(same))
        same['State']['StartedAt'] = '2026-10-04T01:00:00Z'
        self.assertNotEqual(d.launch_identity(old), d.launch_identity(same))


if __name__ == '__main__': unittest.main()
