"""No live product, listener, browser, network, credentials, or Docker required."""
import copy
import io
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.request

from campaign import (CASES, JOB, OUT, REQUIRED_PROOFS, Counters, cli, conditions,
                      digest, fixtures, output_path, plan, run_campaign)
from keycloak_campaign import NativeSettingBatch
from simplesamlphp_campaign import PublicOverlayBatch


def fingerprint(value):
    return dict(origin='product-runtime', sha256=digest(value))


class MemoryDriver:
    """A deterministic fixture, NOT product evidence or an adapter for real targets."""
    def __init__(self, product='keycloak'):
        self.product = product
        self.current = 'original'
        self.calls = []
        self.receipts = 0
        self.mode = None
        self.edit_receipt = lambda row: row
        self.scope = dict(product=product, profile='browser_sso_idp', role='idp',
            caseDigests=CASES.copy(), runId='run_' + '0' * 26,
            targetMetadataSha256='a' * 64, loginInputBindingSha256='b' * 64,
            **dict.fromkeys(REQUIRED_PROOFS, True))

    def preflight(self, product, cases):
        self.calls.append('preflight')
        return copy.deepcopy(self.scope)

    def capture(self):
        self.calls.append('capture')
        return self.current

    def read_effective(self):
        self.calls.append('read-effective')
        return fingerprint(self.current)

    def apply(self, mode, counters):
        self.mode = mode
        self.calls.append('apply-' + mode)
        counters.write(lambda: setattr(self, 'current', mode), location='native')
        return fingerprint(mode)

    def collect_existing_outbox(self, row):
        self.receipts += 1
        self.calls.append('collect-' + row['id'])
        serial = str(self.receipts)
        receipt = dict(runId=self.scope['runId'], condition=row['id'], mode=self.mode,
            targetMetadataSha256=self.scope['targetMetadataSha256'],
            transport='persisted-outbox-recorder', delivery='observed',
            requestId='_request' + serial, actionId='action' + serial,
            requestReference='request' + serial, responseReference='response' + serial,
            requestSha256=digest(['request', serial]), responseSha256=digest(['response', serial]))
        return self.edit_receipt(receipt)

    def restore(self, original, counters):
        self.calls.append('restore')
        counters.write(lambda: setattr(self, 'current', original), location='native', restoring=True)

    def collect_restored_normal_outbox(self):
        self.mode = 'restored'
        return self.collect_existing_outbox(dict(id='M0_RESTORED'))


class CampaignTest(unittest.TestCase):
    def test_case_digest_pins_match_read_only_case_catalog(self):
        # Deliberately no coverage/specs/predicates/approval-file reads.
        raw = (OUT.parents[2] / 'tests/cases.yaml').read_text()
        blocks = re.split(r'(?m)^- id: ', raw)
        actual = {}
        for block in blocks:
            case = block.split('\n', 1)[0]
            if case in CASES:
                actual[case] = re.search(r'(?m)^  case_digest: (\S+)$', block).group(1)
        self.assertEqual(CASES, actual)

    def test_matrix_reuses_shibboleth_inputs_and_has_native_availability_controls(self):
        rows = conditions()
        self.assertEqual(24, len(rows))
        self.assertEqual(20, len(fixtures.inputs()))
        self.assertEqual(16, sum(r['mode'] == 'normal' for r in rows))
        self.assertEqual(8, sum(r['mode'] == 'maximum' for r in rows))
        self.assertEqual(24, len({(r['mode'], r['id']) for r in rows}))
        # Input-file IDs remain legal for AuthnContextCampaignInputs; an existing
        # control-low input is consumed once per DIFFERENT native mode/operation.
        for row in rows:
            self.assertRegex(row['id'], r'^(ga|gb|gc|gj|control)-(class|declaration)-(selection|unachievable|forward|reverse|low|medium|high)$')
        for case in ('ga', 'gb', 'gc', 'gj'):
            chosen = [r for r in rows if r['id'].startswith(case + '-')]
            self.assertEqual(4, len(chosen))
            self.assertEqual({'CLASS', 'DECLARATION'}, {r['kind'] for r in chosen})
        for kind in ('CLASS', 'DECLARATION'):
            forward, reverse = [r for r in rows if r['id'].startswith('gj-') and r['kind'] == kind]
            self.assertEqual(forward['references'], list(reversed(reverse['references'])))

    def test_full_lifecycle_collects_unqualified_only_and_counts_each_stage(self):
        driver = MemoryDriver()
        report = run_campaign('keycloak', driver)
        self.assertEqual('collected-unqualified', report['status'])
        self.assertTrue(report['restored'])
        self.assertEqual('original', driver.current)
        self.assertEqual([], report['errors'])
        counts = report['counts']
        self.assertEqual(3, counts['setting_write_attempts'])
        self.assertEqual(0, counts['host_write_successes'])
        self.assertEqual(3, counts['native_write_successes'])
        self.assertEqual(2, counts['product_effective_applications'])
        self.assertEqual(1, counts['restoration_write_attempts'])
        self.assertEqual(1, counts['product_effective_restorations'])
        self.assertEqual(24, counts['condition_receipts'])
        self.assertEqual(1, counts['restored_normal_dispatch_attempts'])
        self.assertEqual(53, counts['effective_readbacks'])
        self.assertNotIn('outcome', report)
        self.assertNotIn('verdict', report)

    def test_preflight_fails_before_capture_or_writes_for_each_unproven_requirement(self):
        for key in REQUIRED_PROOFS:
            with self.subTest(key=key):
                driver = MemoryDriver()
                driver.scope[key] = False
                report = run_campaign('keycloak', driver)
                self.assertEqual(['preflight'], driver.calls)
                self.assertEqual('incomplete', report['status'])
                self.assertEqual(0, report['counts']['setting_write_attempts'])

    def test_missing_case_wrong_profile_or_digest_cannot_modify_saved_run(self):
        for key, value in [('caseDigests', {}), ('profile', 'ecp_idp'), ('role', 'sp'),
                           ('product', 'simplesamlphp'), ('targetMetadataSha256', ''),
                           ('runId', 'foreign'), ('loginInputBindingSha256', '')]:
            with self.subTest(key=key):
                driver = MemoryDriver()
                driver.scope[key] = value
                report = run_campaign('keycloak', driver)
                self.assertEqual(0, report['counts']['setting_write_attempts'])

    def test_partial_apply_failure_is_restored(self):
        driver = MemoryDriver()
        original_apply = driver.apply
        def fail(mode, counts):
            original_apply(mode, counts)
            raise OSError('private details must not reach report')
        driver.apply = fail
        report = run_campaign('keycloak', driver)
        self.assertTrue(report['restored'])
        self.assertEqual(1, report['counts']['restoration_write_attempts'])
        self.assertEqual(0, report['counts']['condition_dispatch_attempts'])
        self.assertNotIn('private details', json.dumps(report))

    def test_acknowledged_setting_without_effective_product_application_never_sends(self):
        driver = MemoryDriver()
        def stale(mode, counts):
            counts.write(lambda: None, location='native')
            return fingerprint(mode)
        driver.apply = stale
        report = run_campaign('keycloak', driver)
        self.assertTrue(report['restored'])
        self.assertEqual(0, report['counts']['product_effective_applications'])
        self.assertEqual(0, report['counts']['condition_dispatch_attempts'])

    def test_host_readback_cannot_substitute_product_runtime(self):
        driver = MemoryDriver()
        driver.read_effective = lambda: dict(origin='host-file', sha256='c' * 64)
        report = run_campaign('keycloak', driver)
        self.assertEqual(0, report['counts']['setting_write_attempts'])

    def test_foreign_uncertain_or_missing_original_receipts_stop_without_retry(self):
        for key, value in [('runId', 'run_' + '1' * 26), ('condition', 'other'),
                           ('mode', 'maximum'), ('delivery', 'UNKNOWN_DELIVERY'),
                           ('transport', 'preloaded-recorder-only'), ('responseSha256', ''),
                           ('requestReference', ''), ('targetMetadataSha256', 'c' * 64)]:
            with self.subTest(key=key):
                driver = MemoryDriver()
                driver.edit_receipt = lambda row: dict(row, **{key: value})
                report = run_campaign('keycloak', driver)
                self.assertEqual('incomplete', report['status'])
                self.assertTrue(report['restored'])
                self.assertEqual(1, report['counts']['condition_dispatch_attempts'])
                self.assertEqual(0, report['counts']['condition_receipts'])

    def test_duplicate_action_or_originals_cannot_create_additional_observations(self):
        for key in ('requestId', 'actionId', 'requestReference', 'responseReference'):
            with self.subTest(key=key):
                driver = MemoryDriver()
                driver.edit_receipt = lambda row: dict(row, **{key: '_same'})
                report = run_campaign('keycloak', driver)
                self.assertEqual(1, report['counts']['condition_receipts'])
                self.assertEqual(2, report['counts']['condition_dispatch_attempts'])

    def test_timeout_and_http_error_are_incomplete_and_never_retried(self):
        for error in (TimeoutError(), OSError('HTTP500'), OSError('silence')):
            with self.subTest(error=error):
                driver = MemoryDriver()
                def fail(_):
                    raise error
                driver.collect_existing_outbox = fail
                report = run_campaign('keycloak', driver)
                self.assertEqual('incomplete', report['status'])
                self.assertTrue(report['restored'])
                self.assertEqual(1, report['counts']['condition_dispatch_attempts'])
                self.assertEqual(0, report['counts']['restored_normal_dispatch_attempts'])

    def test_drift_after_exchange_is_not_accepted(self):
        driver = MemoryDriver()
        def mutate(row):
            driver.current = 'other'
            return row
        driver.edit_receipt = mutate
        report = run_campaign('keycloak', driver)
        self.assertEqual(0, report['counts']['condition_receipts'])
        self.assertEqual('incomplete', report['status'])

    def test_failed_or_mismatched_restoration_prevents_completion(self):
        for raises in (True, False):
            with self.subTest(raises=raises):
                driver = MemoryDriver()
                def restore(original, counts):
                    if raises:
                        raise OSError('restore failed')
                driver.restore = restore
                report = run_campaign('keycloak', driver)
                self.assertFalse(report['restored'])
                self.assertEqual('incomplete', report['status'])
                self.assertEqual(0, report['counts']['restored_normal_dispatch_attempts'])

    def test_arbitrary_driver_fields_are_never_persisted(self):
        driver = MemoryDriver()
        driver.edit_receipt = lambda row: dict(row, html='do not persist', Cookie='do not persist')
        report = run_campaign('keycloak', driver)
        self.assertNotIn('do not persist', json.dumps(report))

    def test_error_only_envelopes_do_not_become_success_or_outcome(self):
        driver = MemoryDriver()
        driver.edit_receipt = lambda row: dict(row, samlStatus='error')
        report = run_campaign('keycloak', driver)
        self.assertEqual('collected-unqualified', report['status'])
        self.assertEqual('supplemental-unadopted', report['evidenceStatus'])
        self.assertNotIn('outcome', report)
        self.assertNotIn('verdict', report)


class BatchesTest(unittest.TestCase):
    def test_host_overlay_keeps_inode_restores_original_and_does_not_count_as_native(self):
        with tempfile.TemporaryDirectory(dir=JOB) as folder:
            path = Path(folder) / 'public.php'
            path.write_bytes(b'<?php // credential-free fixture\n')
            original, inode = path.read_bytes(), path.stat().st_ino
            counts = Counters()
            batch = PublicOverlayBatch(path, counts)
            batch.apply(b'// normal')
            batch.apply(b'// maximum')
            self.assertNotIn(b'normal', path.read_bytes())
            batch.restore()
            batch.restore()
            self.assertEqual(original, path.read_bytes())
            self.assertEqual(inode, path.stat().st_ino)
            self.assertEqual(3, counts.host_write_successes)
            self.assertEqual(1, counts.restoration_host_write_successes)
            self.assertEqual(0, counts.product_effective_applications)

    def test_host_external_edit_is_preserved(self):
        with tempfile.TemporaryDirectory(dir=JOB) as folder:
            path = Path(folder) / 'public.php'
            path.write_bytes(b'original')
            batch = PublicOverlayBatch(path, Counters())
            batch.apply(b'normal')
            path.write_bytes(b'operator edit')
            with self.assertRaises(RuntimeError):
                batch.restore()
            self.assertEqual(b'operator edit', path.read_bytes())

    def test_host_batch_prohibits_docker_fallback(self):
        with tempfile.TemporaryDirectory(dir=JOB) as folder:
            path = Path(folder) / 'public.php'
            path.write_bytes(b'original')
            batch = PublicOverlayBatch(path, Counters())
            batch.container = 'never-used'
            with self.assertRaises(ValueError):
                batch.apply(b'next')
            self.assertEqual(b'original', path.read_bytes())

    def test_native_resource_handles_failed_write_that_already_applied(self):
        state, counts = dict(level='original'), Counters()
        def write(value):
            state.clear()
            state.update(value)
            if value['level'] != 'original':
                raise OSError('acknowledgment lost')
        batch = NativeSettingBatch(lambda: state.copy(), write, counts)
        with self.assertRaises(OSError):
            batch.apply(dict(level='normal'))
        batch.restore()
        self.assertEqual(dict(level='original'), state)
        self.assertEqual(2, counts.setting_write_attempts)
        self.assertEqual(1, counts.native_write_successes)
        self.assertEqual(1, counts.restoration_native_write_successes)

    def test_native_concurrent_edit_is_preserved_on_apply_and_restore(self):
        state, counts = dict(level='original'), Counters()
        def write(value):
            state.clear()
            state.update(value)
        batch = NativeSettingBatch(lambda: state.copy(), write, counts)
        batch.apply(dict(level='normal'))
        state['level'] = 'operator edit'
        with self.assertRaises(RuntimeError):
            batch.apply(dict(level='maximum'))
        with self.assertRaises(RuntimeError):
            batch.restore()
        self.assertEqual(dict(level='operator edit'), state)

    def test_native_success_and_failed_readback_are_counted_separately(self):
        counts = Counters()
        batch = NativeSettingBatch(lambda: dict(level='original'), lambda value: None, counts)
        with self.assertRaises(RuntimeError):
            batch.apply(dict(level='normal'))
        batch.restore()
        self.assertEqual(1, counts.native_write_successes)
        self.assertEqual(0, counts.product_effective_applications)
        self.assertEqual(0, counts.restoration_write_attempts)


class DryRunTest(unittest.TestCase):
    def test_cli_dry_run_has_no_external_access_and_no_implicit_live_mode(self):
        for product in ('keycloak', 'simplesamlphp'):
            with self.subTest(product=product), tempfile.TemporaryDirectory(dir=JOB) as folder:
                with patch.object(socket, 'socket', side_effect=AssertionError('network')), \
                     patch.object(subprocess, 'run', side_effect=AssertionError('process')), \
                     patch.object(urllib.request, 'urlopen', side_effect=AssertionError('HTTP')), \
                     patch.object(sys, 'argv', ['campaign', '--dry-run', '--out', folder]), \
                     patch('sys.stdout', new_callable=io.StringIO):
                    cli(product)
                data = json.loads((Path(folder) / 'plan.json').read_text())
                self.assertEqual(0, data['plannedExternalOperationsNow'])
                self.assertFalse(data['liveExecutionAvailable'])
                self.assertTrue(data['blockers'])
                self.assertEqual(24, data['conditionalEstimates']['conditionExchanges'])
                with patch.object(sys, 'argv', ['campaign', '--dry-run', '--out', folder]):
                    with self.assertRaises(FileExistsError):
                        cli(product)

    def test_no_dry_run_flag_refuses_before_output_write(self):
        with patch.object(sys, 'argv', ['campaign', '--out', str(OUT / 'must-not-exist')]), \
             patch('sys.stderr', new_callable=io.StringIO):
            with self.assertRaises(SystemExit):
                cli('keycloak')

    def test_output_must_remain_in_authorized_roots(self):
        for path in ('/tmp/not-authorized', str(OUT.parent / 'other'), str(OUT), str(JOB)):
            with self.subTest(path=path), self.assertRaises(ValueError):
                output_path(Path(path))
        with tempfile.TemporaryDirectory(dir=JOB) as folder:
            link = Path(folder) / 'alias'
            link.symlink_to(OUT, target_is_directory=True)
            with self.assertRaises(ValueError):
                output_path(link / 'aliased')

    def test_unknown_product_is_rejected(self):
        with self.assertRaises(ValueError):
            plan('shibboleth')


if __name__ == '__main__':
    unittest.main()
