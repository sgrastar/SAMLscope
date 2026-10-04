"""Host-only contract tests. These values do not calibrate the SAML case or authorize adoption."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from slo_soap_adoption_proof import (
    CASE, VARIANT, MUTANT, PRODUCTION_CLASSES, FullCaseAdoptionProof, class_bindings, digest,
)


class ProofContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='soap-proof-contract-')
        self.root = Path(self.temp.name).resolve()
        self.archive = self.root / 'archive'
        self.archive.mkdir()
        self.pins = {}
        for jar in set(PRODUCTION_CLASSES.values()):
            file = self.archive / (jar + '.jar')
            with zipfile.ZipFile(file, 'w') as out:
                for name, owner in PRODUCTION_CLASSES.items():
                    if owner == jar:
                        out.writestr(name.replace('.', '/') + '.class', ('contract-test-only:' + name).encode())
            self.pins[jar] = digest(file.read_bytes())
        self.run = 'run_0123456789ABCDEFGHJKMNPQRS'
        self.positive = self.root / 'positive'
        self.positive.mkdir()
        (self.positive / 'target-metadata.xml').write_bytes(b'host-contract-only-target')
        self.target = digest((self.positive / 'target-metadata.xml').read_bytes())
        self.manifest = {'schema': 'samlscope-shibboleth-native-soap-continuation-v1',
                         'runId': self.run, 'targetMetadataSha256': self.target,
                         'files': {'target-metadata.xml': self.target},
                         'trials': [{'trial': t, 'beforeFile': t + '-before.json', 'afterFile': t + '-after.json'}
                                    for t in ('failure', 'all-success')]}
        (self.positive / 'manifest.json').write_text(json.dumps(self.manifest))
        self.calibration = self.root / 'control'
        self.calibration.mkdir()
        self.control_run = 'run_' + '0' * 26
        bindings = class_bindings(self.archive, self.pins)
        def outcome(value):
            return {'outcome': value, 'reasonCode': 'contract-only',
                    'evidence': [{'kind': 'artifact', 'reference': 'contract-only-original'}]}
        classes = {'public-contract.class': 'a' * 64}
        source = b'host-contract-only-source'
        target = b'host-contract-only-actor-target'
        manifests = {}
        reports = {}
        output_inventory = {}
        for mode, actor in [('baseline', 'ContinuingActor'), ('mutant', 'StopAfterErrorActor')]:
            folder = self.calibration / mode
            receipt = folder / 'receipt'
            receipt.mkdir(parents=True)
            (folder / 'target-metadata.xml').write_bytes(target)
            entries = [{'timestamp': 1791073818.400}]
            (folder / 'transcript.json').write_text(json.dumps(entries))
            files = {}
            def write(name, raw):
                file = receipt / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(raw)
                files[name] = digest(raw)
            write('actor/source.java', source)
            write('actor/classes.json', json.dumps(classes).encode())
            trials = []
            for trial in ('failure', 'all-success'):
                write(trial + '-input.json', ('host-contract-only-input-' + trial).encode())
                write(trial + '-output.json', ('host-contract-only-output-' + mode + trial).encode())
                write(trial + '-trace.xml', ('host-contract-only-trace-' + mode + trial).encode())
                trials.append({'trial': trial, 'operationInputFile': trial + '-input.json',
                               'operationOutputFile': trial + '-output.json', 'operationTraceFile': trial + '-trace.xml'})
            manifest = {'schema': 'samlscope-suite-actor-soap-continuation-v1', 'runId': self.control_run,
                        'targetMetadataSha256': digest(target), 'producerSourceSha256': digest(source),
                        'producerClassesFile': 'actor/classes.json', 'producerSourceFile': 'actor/source.java',
                        'actorClass': 'com.samlscope.runner.cases.SoapContinuationActor$' + actor,
                        'files': files, 'trials': trials}
            (receipt / 'manifest.json').write_text(json.dumps(manifest))
            manifests[mode] = manifest
            output_inventory[mode] = {p.relative_to(folder).as_posix(): digest(p.read_bytes())
                                      for p in folder.rglob('*') if p.is_file()}
            from slo_soap_adoption_proof import ACTOR_MUTATIONS
            reports[mode] = {'schema': 'samlscope-soap-controlled-replay-v1', 'runId': self.control_run,
                   'caseId': CASE, 'targetMetadataSha256': digest(target),
                   'fullWrapperLifecycleChecked': True, 'sameProductionPredicate': True,
                   'classBindings': copy.deepcopy(bindings), 'outcome': outcome('SATISFIED' if mode == 'baseline' else 'VIOLATED'),
                   'manifestOriginal': {'file': mode + '/receipt/manifest.json', 'sha256': digest((receipt / 'manifest.json').read_bytes())},
                   'readOnly': True, 'outboundActions': 0, 'ephemeralFactoryKeyPersisted': False,
                   'stockPlacementPermitted': False,
                   'negativeControls': {name: {'outcome': 'NOT_VERIFIED'} for name in ACTOR_MUTATIONS}}
        invocation = {'schema': 'samlscope-soap-continuation-actor-invocation-v1',
                      'argv': ['java', '-cp', 'host-contract-only', 'com.samlscope.runner.cases.SoapContinuationActor',
                               'host-contract-only-output', 'paired', 'host-contract-only-source.java'],
                      'sourceOriginal': 'host-contract-only-source.java', 'sourceSha256': digest(source),
                      'classes': classes, 'startedAt': '2026-10-04T00:30:18.100Z',
                      'finishedAt': '2026-10-04T00:30:18.900Z', 'exitCode': 0, 'outputs': output_inventory}
        for channel in ('stdout', 'stderr'):
            (self.calibration / (channel + '.txt')).write_bytes(b'')
            invocation[channel + 'File'] = channel + '.txt'
            invocation[channel + 'Sha256'] = digest(b'')
        (self.calibration / 'invocation.json').write_text(json.dumps(invocation))
        control = reports['mutant']
        control.update({'schema': 'samlscope-soap-continuation-approved-control-v1',
                   'approvedVariantId': VARIANT, 'mutantId': MUTANT,
                   'nativeAssociation': {'runId': self.run, 'targetMetadataSha256': self.target,
                       'manifestSha256': digest((self.positive / 'manifest.json').read_bytes())},
                   'counterfactualCalibrationOnly': True, 'controlsAdopted': False,
                   'normalControl': reports['baseline'],
                   'invocationOriginal': {'file': 'invocation.json', 'sha256': digest((self.calibration / 'invocation.json').read_bytes())}})
        for key, name in [('sourceOriginal', 'actor/source.java'), ('classesOriginal', 'actor/classes.json'),
                          ('inputOriginal', 'failure-input.json'), ('outputOriginal', 'failure-output.json'),
                          ('operationOriginal', 'failure-trace.xml')]:
            control[key] = {'file': name, 'sha256': manifests['mutant']['files'][name]}
        self.report = {'schema': 'samlscope-soap-continuation-replay-v2', 'runId': self.run,
                       'caseId': CASE, 'targetMetadataSha256': self.target, 'readOnly': True,
                       'outboundActions': 0, 'privateKeyExported': False, 'fullWrapperLifecycleChecked': True,
                       'positiveManifestOriginal': {'file': 'manifest.json',
                           'sha256': digest((self.positive / 'manifest.json').read_bytes())},
                       'classBindings': bindings, 'outcome': outcome('SATISFIED'), 'approvedNegativeControl': control}
        self.saved = copy.deepcopy(self.report)

    def tearDown(self):
        self.temp.cleanup()

    def validate(self):
        return FullCaseAdoptionProof.validate(fresh_report=self.report, saved_report=self.saved,
                archive=self.archive, pins=self.pins, positive_manifest=self.manifest,
                positive_root=self.positive, calibration_root=self.calibration)

    def test_valid_contract_is_typed_without_issuing_an_adoption_or_verdict(self):
        proof = self.validate()
        self.assertEqual(proof.run_id, self.run)
        self.assertEqual(proof.positive.outcome, 'SATISFIED')
        self.assertEqual(proof.negative.outcome, 'VIOLATED')
        self.assertFalse(hasattr(proof, 'verdict'))

    def test_partial_positive_and_missing_approved_control_fail_closed(self):
        baseline = copy.deepcopy(self.saved)
        for change in ('positive', 'negative'):
            with self.subTest(change=change):
                report = copy.deepcopy(baseline)
                if change == 'positive':
                    report['outcome']['outcome'] = 'NOT_VERIFIED'
                else:
                    del report['approvedNegativeControl']
                self.report = report
                self.saved = copy.deepcopy(report)
                with self.assertRaises(ValueError):
                    self.validate()
        # The test never runs a target or pretends that these dicts are native calibration.

    def test_claimed_violated_labels_without_actor_originals_are_blocked(self):
        del self.report['approvedNegativeControl']['invocationOriginal']
        self.saved = copy.deepcopy(self.report)
        with self.assertRaisesRegex(ValueError, 'original descriptor'):
            self.validate()

    def test_control_must_use_same_whole_case_classes_and_code_sources(self):
        self.report['approvedNegativeControl']['classBindings'][next(iter(PRODUCTION_CLASSES))]['jarSha256'] = '0' * 64
        self.saved = copy.deepcopy(self.report)
        with self.assertRaises(ValueError):
            self.validate()

    def test_native_invocation_or_input_byte_change_cannot_pass_hash_binding(self):
        (self.calibration / 'mutant/receipt/failure-input.json').write_bytes(b'changed host contract original')
        with self.assertRaisesRegex(ValueError, 'original changed'):
            self.validate()

    def test_control_for_foreign_run_or_variant_is_blocked(self):
        baseline = copy.deepcopy(self.saved)
        for key, value in [('runId', 'run_' + '1' * 26), ('approvedVariantId', 'unapproved')]:
            with self.subTest(key=key):
                report = copy.deepcopy(baseline)
                report['approvedNegativeControl'][key] = value
                self.report = report
                self.saved = copy.deepcopy(report)
                with self.assertRaises(ValueError):
                    self.validate()

    def test_fresh_full_case_output_and_evidence_must_equal_archived_report(self):
        self.report['outcome']['evidence'].append({'kind': 'artifact', 'reference': 'foreign'})
        with self.assertRaisesRegex(ValueError, 'Fresh full archived replay differs'):
            self.validate()
        self.report = copy.deepcopy(self.saved)
        self.report['outcome']['evidence'][0]['type'] = self.report['outcome']['evidence'][0].pop('kind')
        self.saved = copy.deepcopy(self.report)
        with self.assertRaisesRegex(ValueError, 'Malformed case evidence reference'):
            self.validate()

    def test_counterfactual_positive_and_symlink_input_are_blocked(self):
        self.manifest['counterfactualCalibrationOnly'] = True
        (self.positive / 'manifest.json').write_text(json.dumps(self.manifest))
        self.report['positiveManifestOriginal']['sha256'] = digest((self.positive / 'manifest.json').read_bytes())
        self.report['approvedNegativeControl']['nativeAssociation']['manifestSha256'] = self.report['positiveManifestOriginal']['sha256']
        self.saved = copy.deepcopy(self.report)
        with self.assertRaisesRegex(ValueError, 'cannot be adopted'):
            self.validate()
        del self.manifest['counterfactualCalibrationOnly']
        (self.positive / 'manifest.json').write_text(json.dumps(self.manifest))
        self.report['positiveManifestOriginal']['sha256'] = digest((self.positive / 'manifest.json').read_bytes())
        self.report['approvedNegativeControl']['nativeAssociation']['manifestSha256'] = self.report['positiveManifestOriginal']['sha256']
        self.saved = copy.deepcopy(self.report)
        (self.calibration / 'mutant/receipt/failure-input.json').unlink()
        (self.calibration / 'mutant/receipt/failure-input.json').symlink_to(self.calibration / 'mutant/receipt/failure-output.json')
        with self.assertRaisesRegex(ValueError, 'Symbolic proof original'):
            self.validate()

    def test_calibration_keeps_its_own_run_and_never_borrows_product_references(self):
        proof = self.validate()
        self.assertNotEqual(self.run, self.control_run)
        self.assertEqual(proof.run_id, self.run)
        self.report['approvedNegativeControl']['nativeAssociation']['runId'] = self.control_run
        self.saved = copy.deepcopy(self.report)
        with self.assertRaisesRegex(ValueError, 'association'):
            self.validate()

    def test_actor_source_cannot_be_rebranded_as_stock_by_false_counterflag(self):
        self.manifest['counterfactualCalibrationOnly'] = False
        self.manifest['actorClass'] = 'diagnostic-source'
        (self.positive / 'manifest.json').write_text(json.dumps(self.manifest))
        self.report['positiveManifestOriginal']['sha256'] = digest((self.positive / 'manifest.json').read_bytes())
        self.saved = copy.deepcopy(self.report)
        with self.assertRaisesRegex(ValueError, 'rebranded'):
            self.validate()

    def test_missing_complete_trace_control_and_failed_invocation_are_blocked(self):
        baseline = copy.deepcopy(self.report)
        del self.report['approvedNegativeControl']['negativeControls']['tampered-signed-complete-operation']
        self.saved = copy.deepcopy(self.report)
        with self.assertRaisesRegex(ValueError, 'trace mutation controls'):
            self.validate()
        self.report = baseline
        invocation = self.calibration / 'invocation.json'
        model = json.loads(invocation.read_bytes())
        model['exitCode'] = 1
        invocation.write_text(json.dumps(model))
        self.report['approvedNegativeControl']['invocationOriginal']['sha256'] = digest(invocation.read_bytes())
        self.saved = copy.deepcopy(self.report)
        with self.assertRaisesRegex(ValueError, 'invocation failed'):
            self.validate()


if __name__ == '__main__':
    unittest.main()
