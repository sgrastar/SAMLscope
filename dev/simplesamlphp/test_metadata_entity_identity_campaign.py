"""Offline collector tests. Every external action is replaced by a recording fake."""
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ssp_md05_campaign', Path(__file__).with_name('metadata_entity_identity_campaign.py'))
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)
REPO = Path(__file__).resolve().parents[4]
# The output tree is not a checkout. Tests receive the actual read-only repository.
import os
REPO = Path(os.environ['SSP_MD05_REPO'])
spec = importlib.util.spec_from_file_location('ssp_md05_batch', REPO/'dev/simplesamlphp/configuration_batch.py')
batch_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch_module)


class FakeProduct:
    def __init__(self, root, defect=None):
        self.root, self.defect = root, defect
        self.config = root/'config-override.php'
        self.original = b"<?php\n$unrelated = 'synthetic-sensitive-value';\n"
        self.config.write_bytes(self.original)
        self.inode = self.config.stat().st_ino
        self.remote_files = {}
        self.run_count = 0
        self.actions = []
        self.refs = 0
        self.fixture = b'<EntityDescriptor entityID="offline"/>'

    def save(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value)+'\n')

    def api(self, path, body=None):
        self.actions.append(('api', path))
        if path == '/api/plans':
            self.run_count += 1
            plan = 'plan_'+str(self.run_count).zfill(26)
            return dict(plan=dict(plan=dict(id=plan, profile='metadata_idp')))
        if path.endswith('/runs'):
            run = 'run_'+str(self.run_count).zfill(26)
            return dict(run=dict(id=run, planId=path.split('/')[3]))
        if path.endswith('/result.json'):
            cases = list(campaign.CASES)
            if self.defect == 'missing-case':
                cases.pop()
            return dict(requirements=[dict(cases=[dict(id=c) for c in cases])])
        if path.endswith('/transcript'):
            run = path.split('/')[3]
            if any(a == ('flow', run) for a in self.actions):
                return [dict(id='request-'+run, direction='OUTBOUND', samlSummary=dict(type='AuthnRequest', id='rq-'+run)),
                        dict(id='response-'+run, direction='INBOUND', samlSummary=dict(normalFlowAccepted=True, inResponseTo='rq-'+run))]
            return []
        if path.endswith('/metadata-lab'):
            return dict(automaticStartUrl='http://localhost/gate', metadataUrl='http://localhost/metadata')
        return {}

    def capture(self, folder, run, entries):
        (folder/'target-metadata.xml').write_bytes(b'<metadata>offline-target</metadata>')
        self.save(folder/'decoded-manifest.json', [])

    def recorded(self, folder, created, value, label):
        self.refs += 1
        (folder/'native-originals').mkdir(exist_ok=True)
        (folder/'native-originals'/(label+'.json')).write_bytes(campaign.canonical(value))
        return dict(reference='tx_'+str(self.refs).zfill(26), sha256=campaign.SHA(campaign.canonical(value)))

    def urlopen(self, url, **kwargs):
        return types.SimpleNamespace(__enter__=lambda x: x)

    def run(self, argv, **kwargs):
        self.actions.append(('docker', tuple(argv)))
        if argv[1] == 'inspect':
            output = campaign.canonical(dict(id='fake-container', image='sha256:'+'1'*64, running=True, startedAt='offline'))
        else:
            command = argv[4:]
            operation = command[0]
            if operation == 'cat':
                if command[1] == campaign.REMOTE:
                    output = self.config.read_bytes()
                    if self.defect == 'stale-mount' and output != self.original:
                        output = self.original
                else:
                    output = self.remote_files.get(command[1], b'public-native-source')
            elif operation == 'php':
                php = command[2]
                if php == 'fake-native-parser':
                    if self.defect == 'parser-failed':
                        return subprocess.CompletedProcess(argv, 1, b'', b'not-persisted-sensitive-error')
                    output = campaign.canonical(dict(entity_id=command[3], validate_authnrequest=True, php="$metadata['offline'] = [];"))
                elif php == campaign.READBACK:
                    value = json.loads(kwargs['input'])
                    if value['phase'] == 'restored':
                        output = campaign.canonical(dict(sources=[dict(type='flatfile')], ownedPeersAbsent=not (self.defect == 'restoration-failed' and any(a[0] == 'flow' for a in self.actions))))
                    else:
                        sources, _ = campaign.overlay('/tmp/samlscope-md05-run_'+str(1).zfill(26))
                        output = campaign.canonical(dict(sources=sources, version='2.5.0', sourceHashes={k: campaign.SHA(b'public-native-source') for k in campaign.NATIVE_FILES}, configurationSha256=campaign.SHA(self.config.read_bytes())))
                        if self.defect == 'unsupported-native-source':
                            return subprocess.CompletedProcess(argv, 1, b'', b'native-source-not-supported')
                elif 'file_put_contents' in php:
                    self.remote_files[command[3]] = kwargs['input']
                    output = b''
                else:
                    output = b'[{"type":"flatfile"}]'
            else:
                output = b''
        return subprocess.CompletedProcess(argv, 0, output, b'')

    def helpers(self):
        owner = self
        class Client:
            def __init__(self):
                pass
            def request(self, url, fields=None):
                return ('', '', 200)
            def flow(self, url, *args):
                run = url.split('run=')[1]
                owner.actions.append(('flow', run))
                return 'recorded'
        parser = types.SimpleNamespace(api=self.api, save=self.save, BASE='http://localhost:18080', PHP='fake-native-parser')
        return batch_module.ConfigurationBatch, Client, self.capture, self.recorded, parser


class Response:
    status = 202
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self):
        return b'<EntityDescriptor entityID="offline"/>'


class CampaignTests(unittest.TestCase):
    def test_dry_run_is_pure_and_prints_fixtures_and_counts(self):
        with patch.object(campaign, 'load_helpers', side_effect=AssertionError('live import')), \
             patch.object(campaign.subprocess, 'run', side_effect=AssertionError('Docker')), \
             patch.object(campaign.urllib.request, 'urlopen', side_effect=AssertionError('network')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            campaign.main(['--dry-run', '--configuration', '/does/not/exist'])
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['executedCounts'], dict(docker=0, network=0, productWrites=0, protocolSubmissions=0))
        self.assertEqual(len(plan['fixtures']), 3)
        self.assertEqual(plan['plannedCounts']['configurationApplyWrites'], 1)
        self.assertEqual(plan['plannedCounts']['restorationWrites'], 1)

    def test_profile_requires_both_exact_approved_case_digests(self):
        profile = dict(profile='metadata_idp', cases=[dict(id=k, digest=v) for k, v in campaign.CASES.items()])
        campaign.approved_profile(profile)
        profile['cases'][0]['digest'] = 'sha256:'+'0'*64
        with self.assertRaises(ValueError):
            campaign.approved_profile(profile)

    def test_run_inventory_and_duplicates_fail_closed(self):
        for rows in [[], [dict(id=next(iter(campaign.CASES)))]*2]:
            with self.assertRaises(ValueError):
                campaign.inventory(dict(requirements=[dict(cases=rows)]))

    def test_sensitive_native_fields_are_refused_recursively(self):
        for key in ('Authorization', 'Cookie', 'password', 'privatekey', 'token'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                campaign.reject_sensitive(dict(wrapper=[{key: 'value'}]))

    def test_overlay_has_two_separate_sources_and_no_key_overwrite(self):
        sources, code = campaign.overlay('/tmp/samlscope-md05-run_'+'1'*26)
        self.assertEqual(len(sources), 3)
        self.assertNotEqual(sources[1]['directory'], sources[2]['directory'])
        self.assertNotIn(b'$metadata[', code)
        with self.assertRaises(ValueError):
            campaign.overlay('/tmp/../unsafe')

    def exercise(self, defect=None):
        with tempfile.TemporaryDirectory(prefix='ssp-live-fake-') as name:
            root = Path(name).resolve()
            fake = FakeProduct(root, defect)
            args = argparse.Namespace(repo=REPO, configuration=fake.config, output=root/'output')
            with patch.dict(campaign.os.environ, {'REFERENCE_PASSWORD': 'ephemeral-test-password'}), \
                 patch('yaml.safe_load', return_value={'cases': [dict(id=k, case_digest=v) for k, v in campaign.CASES.items()]}), \
                 patch.object(campaign, 'load_helpers', return_value=fake.helpers()), \
                 patch.object(campaign.subprocess, 'run', side_effect=fake.run), \
                 patch.object(campaign.urllib.request, 'urlopen', return_value=Response()), \
                 contextlib.redirect_stdout(io.StringIO()):
                if defect:
                    with self.assertRaises(ValueError):
                        campaign.live(args)
                else:
                    campaign.live(args)
            self.assertEqual(fake.config.read_bytes(), fake.original)
            self.assertEqual(fake.config.stat().st_ino, fake.inode)
            for path in args.output.rglob('*'):
                if path.is_file():
                    self.assertNotIn(b'synthetic-sensitive-value', path.read_bytes())
                    self.assertNotIn(b'ephemeral-test-password', path.read_bytes())
                    self.assertNotIn(b'not-persisted-sensitive-error', path.read_bytes())
            return json.loads((args.output/'receipt/operation-counts.json').read_bytes()), fake.actions

    def test_live_uses_one_overlay_and_one_inode_preserving_restoration(self):
        counts, actions = self.exercise()
        self.assertEqual((counts['configurationApplyWrites'], counts['restorationWrites'], counts['successfulHostWrites']), (1, 1, 2))
        self.assertEqual(counts['fixtureFileWrites'], 2)
        self.assertEqual(counts['protocolSubmissions'], 2)
        self.assertTrue(counts['restored'])

    def test_stale_bind_mount_restores_without_retrying_protocol(self):
        counts, actions = self.exercise('stale-mount')
        self.assertEqual(counts['restorationWrites'], 1)
        self.assertFalse(any(a[0] == 'flow' for a in actions))

    def test_unsupported_source_is_not_fabricated(self):
        counts, actions = self.exercise('unsupported-native-source')
        self.assertEqual(counts['nativeApplications'], 0)
        self.assertEqual(counts['restorationWrites'], 1)

    def test_parser_failure_performs_no_configuration_write(self):
        counts, actions = self.exercise('parser-failed')
        self.assertEqual(counts['configurationApplyWrites'], 0)
        self.assertFalse(any(a[0] == 'flow' for a in actions))

    def test_missing_saved_case_stops_before_native_parser_or_overlay(self):
        counts, actions = self.exercise('missing-case')
        self.assertEqual(counts['nativeParserInvocations'], 0)
        self.assertEqual(counts['configurationApplyWrites'], 0)

    def test_failed_restoration_is_not_adoptable(self):
        counts, _ = self.exercise('restoration-failed')
        self.assertFalse(counts['restored'])


if __name__ == '__main__':
    unittest.main()
