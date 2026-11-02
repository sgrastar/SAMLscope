"""Offline trust, replay and formal adoption boundary tests."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('ssp_adopter', Path(__file__).with_name('verify_ssp_metadata_entity_identity_acceptance.py'))
adopter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adopter)


class AdopterTests(unittest.TestCase):
    def test_duplicate_json_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)/'data.json'
            path.write_text('{"runId":"first","runId":"second"}')
            with self.assertRaises(ValueError):
                adopter.load(path)

    def test_safe_path_refuses_escape_absolute_symlink_and_missing(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            (root/'original').write_text('original')
            (root/'link').symlink_to(root/'original')
            for candidate in ('../original', '/original', 'link', 'absent'):
                with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                    adopter.safe(root, candidate)

    def runtime(self, root):
        source = root/'deployed'
        source.mkdir()
        with zipfile.ZipFile(source/'runner.jar', 'w') as archive:
            for name in adopter.CLASSES:
                archive.writestr('com/samlscope/runner/cases/'+name+'.class', b'offline-public-class-'+name.encode())
        helpers = root/'helpers'
        helpers.mkdir()
        for name in (adopter.HELPER, adopter.STORED):
            (helpers/(name+'.java')).write_text('public class '+name+' {}\n')
        runtime = root/'runtime'
        digest = adopter.pin_runtime(source, runtime, helpers)
        return runtime, digest

    def test_runtime_copies_bytes_and_checks_actual_reader_classes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            runtime, digest = self.runtime(root)
            self.assertIn('runner.jar', adopter.verify_runtime(runtime, digest))
            original = (runtime/'lib/runner.jar').read_bytes()
            (root/'deployed/runner.jar').write_bytes(b'rebuilt')
            self.assertEqual((runtime/'lib/runner.jar').read_bytes(), original)
            (runtime/'lib/runner.jar').write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                adopter.verify_runtime(runtime, digest)

    def test_runtime_manifest_itself_needs_external_trust_anchor(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            runtime, digest = self.runtime(root)
            pins = adopter.load(runtime/'pins.json')
            pins['files'][adopter.HELPER+'.java'] = '0'*64
            (runtime/'pins.json').write_text(json.dumps(pins))
            with self.assertRaises(ValueError):
                adopter.verify_runtime(runtime, digest)

    def test_runtime_rejects_extra_files_and_duplicate_class_shadowing(self):
        for defect in ('extra', 'shadow'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as name:
                root = Path(name).resolve()
                runtime, digest = self.runtime(root)
                if defect == 'extra':
                    (runtime/'extra').write_text('extra')
                else:
                    path = runtime/'lib/dependency.jar'
                    with zipfile.ZipFile(path, 'w') as archive:
                        archive.writestr('com/samlscope/runner/cases/'+adopter.CLASSES[0]+'.class', b'shadow')
                    pins = adopter.load(runtime/'pins.json')
                    pins['files']['lib/dependency.jar'] = adopter.SHA(path.read_bytes())
                    (runtime/'pins.json').write_text(json.dumps(pins))
                    digest = adopter.SHA((runtime/'pins.json').read_bytes())
                with self.assertRaises(ValueError):
                    adopter.verify_runtime(runtime, digest)

    def observed(self, outcome='NOT_VERIFIED'):
        run = 'run_'+'1'*26
        result = {identity: dict(outcome=outcome, notVerifiedReason='duplicate-conflict-unqualified' if outcome == 'NOT_VERIFIED' else None,
            details=dict(evidence_adapter=adopter.ADAPTER, native_run_id=run, case_id=identity)) for identity in adopter.CASES}
        controls = {name: {identity: dict(outcome='VIOLATED' if name.startswith('mut-') else 'NOT_VERIFIED')
                           for identity in adopter.CASES} for name in adopter.CONTROLS}
        return dict(runId=run, production_outcomes=result, checks=controls, shared_native_lifecycle=True,
                    privateMaterialExported=False, additionalProductOperations=0, calibrationOnly=True), dict(runId=run)

    def test_shadowing_only_qualifies_for_diagnostics(self):
        observed, manifest = self.observed()
        adopter.verify_replay(observed, manifest, False)
        with self.assertRaises(ValueError):
            adopter.verify_replay(observed, manifest, True)

    def test_detected_merge_can_be_conclusive_but_unqualified_success_cannot(self):
        observed, manifest = self.observed('VIOLATED')
        adopter.verify_replay(observed, manifest, True)
        for result in observed['production_outcomes'].values():
            result['outcome'] = 'SATISFIED'
        with self.assertRaises(ValueError):
            adopter.verify_replay(observed, manifest, True)

    def test_wrong_run_control_failure_missing_control_and_extra_control(self):
        for defect in ('run', 'negative', 'missing', 'extra', 'positive'):
            with self.subTest(defect=defect):
                observed, manifest = self.observed('VIOLATED')
                if defect == 'run':
                    manifest['runId'] = 'foreign'
                elif defect == 'negative':
                    observed['checks']['mut-iip-md05-a1-idp'][next(iter(adopter.CASES))]['outcome'] = 'SATISFIED'
                elif defect == 'missing':
                    observed['checks'].pop('missing-normal')
                elif defect == 'extra':
                    observed['checks']['extra'] = {}
                else:
                    observed['checks']['positive-control-failed'][next(iter(adopter.CASES))]['outcome'] = 'VIOLATED'
                with self.assertRaises(ValueError):
                    adopter.verify_replay(observed, manifest, True)

    def test_missing_receipt_restoration_or_trust_anchor_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            receipt = root/'receipt'
            receipt.mkdir()
            (receipt/'manifest.json').write_text('{}')
            with self.assertRaises(ValueError):
                adopter.verify_receipt(root, '0'*64)

    def test_java_failure_is_not_treated_as_a_calibration_result(self):
        import subprocess
        with patch.object(adopter, 'verify_runtime', return_value='pinned.jar'), \
             patch.object(adopter.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'javac')):
            with self.assertRaises(subprocess.CalledProcessError):
                adopter.java(Path('/missing'), '0'*64, adopter.HELPER, [])

    def test_replay_is_recomputed_instead_of_trusting_saved_outcomes(self):
        observed, manifest = self.observed('VIOLATED')
        with patch.object(adopter, 'verify_receipt', return_value=manifest), \
             patch.object(adopter, 'replay', return_value=observed) as replay, \
             patch.object(adopter, 'load', return_value={'tampered': True}):
            with self.assertRaises(ValueError):
                adopter.verify(Path('/offline'), Path('/runtime'), Path('/data'), '0'*64, '1'*64, True)
            replay.assert_called_once()

class AdoptionActionTests(unittest.TestCase):
    observed = AdopterTests.observed
    # Reuse only the synthetic replay factory; do not repeat the inherited tests.
    def test_install_refuses_unqualified_result_before_any_install_or_api_action(self):
        observed, manifest = self.observed()
        with patch.object(adopter, 'verify_receipt', return_value=manifest), \
             patch.object(adopter, 'suite_java', return_value=observed), \
             patch.object(adopter, 'verify_deployed_runtime', side_effect=AssertionError('installation gate bypassed')), \
             patch.object(adopter, 'api', side_effect=AssertionError('network')), \
             patch.object(adopter.subprocess, 'run', side_effect=AssertionError('Docker')):
            with self.assertRaises(ValueError):
                adopter.install(Path('/offline'), Path('/runtime'), '0'*64, '1'*64)

    def test_immutable_capture_does_not_overwrite_existing_original(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)/'original.json'
            adopter.immutable(path, {'original': True})
            with self.assertRaises(FileExistsError):
                adopter.immutable(path, {'original': False})
            self.assertEqual(adopter.load(path), {'original': True})

class ReceiptTests(unittest.TestCase):
    def build(self, root):
        receipt = root/'receipt'
        receipt.mkdir()
        peers = []
        for index, label in enumerate(('primary', 'secondary'), 1):
            run = 'run_'+str(index).zfill(26)
            identity = 'tx_'+str(index).zfill(26)
            child = receipt/label
            (child/'decoded').mkdir(parents=True)
            raw = b'<public-original/>'
            (child/'decoded'/(identity+'.xml')).write_bytes(raw)
            (child/'transcript.json').write_text(json.dumps([dict(id=identity, runId=run, headers={},
                decodedSamlRef='transcripts/'+run+'/'+identity+'.saml.xml', decodedSamlBytes=len(raw))]))
            (child/'decoded-manifest.json').write_text(json.dumps([dict(id=identity, file='decoded/'+identity+'.xml', sha256=adopter.SHA(raw))]))
            peers.append(dict(label=label, runId=run))
        (receipt/'restoration.json').write_text('{"restored":true}')
        manifest = dict(runId=peers[0]['runId'], adapter=adopter.ADAPTER, peers=peers)
        return receipt, manifest

    def rehash(self, receipt, manifest):
        manifest['files'] = {str(p.relative_to(receipt)): adopter.SHA(p.read_bytes()) for p in receipt.rglob('*')
                             if p.is_file() and p.name != 'manifest.json'}
        (receipt/'manifest.json').write_text(json.dumps(manifest))
        return adopter.SHA((receipt/'manifest.json').read_bytes())

    def test_complete_original_inventory_is_verified(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            receipt, manifest = self.build(root)
            digest = self.rehash(receipt, manifest)
            self.assertEqual(adopter.verify_receipt(root, digest), manifest)

    def test_semantic_foreign_duplicate_and_restoration_edits_fail_even_when_rehashed(self):
        for defect in ('foreign-run', 'duplicate', 'foreign-decoded', 'duplicate-decoded', 'restoration', 'missing-original'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as name:
                root = Path(name).resolve()
                receipt, manifest = self.build(root)
                history = receipt/'secondary/transcript.json'
                rows = adopter.load(history)
                if defect == 'foreign-run':
                    rows[0]['runId'] = manifest['runId']
                elif defect == 'duplicate':
                    rows.append(copy.deepcopy(rows[0]))
                elif defect == 'foreign-decoded':
                    rows[0]['decodedSamlRef'] = 'transcripts/'+manifest['runId']+'/'+rows[0]['id']+'.saml.xml'
                elif defect == 'duplicate-decoded':
                    path = receipt/'secondary/decoded-manifest.json'
                    decoded = adopter.load(path)
                    path.write_text(json.dumps(decoded+decoded))
                elif defect == 'restoration':
                    (receipt/'restoration.json').write_text('{"restored":false}')
                else:
                    next((receipt/'secondary/decoded').iterdir()).unlink()
                history.write_text(json.dumps(rows))
                digest = self.rehash(receipt, manifest)
                with self.assertRaises(ValueError):
                    adopter.verify_receipt(root, digest)

    def test_tampered_bytes_cannot_be_accepted_with_an_old_manifest(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            receipt, manifest = self.build(root)
            digest = self.rehash(receipt, manifest)
            next((receipt/'primary/decoded').iterdir()).write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                adopter.verify_receipt(root, digest)


if __name__ == '__main__':
    unittest.main()
