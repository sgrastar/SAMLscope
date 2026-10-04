"""Host-only adoption boundaries; neither originals nor target state are changed."""
import importlib.util, json, pathlib, tempfile, unittest
from copy import deepcopy
from unittest.mock import patch

SOURCE = pathlib.Path(__file__).with_name('verify_shibboleth_metadata_application_acceptance.py')
spec = importlib.util.spec_from_file_location('_metadata_application_adopter_test', SOURCE)
adopter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adopter)
FOLDER = SOURCE.parents[2] / 'build/acceptance/reference-20261003/shibboleth-metadata-application-qualified-r1'

class MetadataApplicationAdoptionTest(unittest.TestCase):
    def setUp(self):
        self.entries = adopter.READ(FOLDER / 'transcript.json')
        self.report = adopter.READ(FOLDER / 'candidate-reader-replay-r19.json')
        self.run = adopter.READ(FOLDER / 'created.json')['run']['id']

    def test_whole_original_report_and_both_approved_triggers(self):
        adopter.check_report(self.report, self.run, self.entries)

    def test_unknown_transcript_reference_cannot_be_adopted(self):
        self.report['outcomes'][adopter.CASES[0]]['evidence'][0]['reference'] = 'tx_foreign'
        with self.assertRaisesRegex(ValueError, 'Unresolvable transcript'):
            adopter.check_report(self.report, self.run, self.entries)

    def test_calibration_product_outcome_cannot_be_adopted(self):
        control = next(iter(self.report['controls']['approvedTriggerCalibrations'].values()))
        control['publicOutcome']['outcome'] = 'VIOLATED'
        with self.assertRaisesRegex(ValueError, 'Public/calibration'):
            adopter.check_report(self.report, self.run, self.entries)

    def test_missing_or_ineffective_original_control_cannot_be_adopted(self):
        self.report['controls']['negativeControls']['wrong-target']['outcome'] = 'SATISFIED'
        with self.assertRaisesRegex(ValueError, 'Detection controls'):
            adopter.check_report(self.report, self.run, self.entries)

    def test_failed_attempts_remain_in_cumulative_costs(self):
        counts = adopter.cumulative_counts(FOLDER)
        self.assertEqual(counts['totals'], dict(samlSubmissions=24, credentialPosts=3,
            productConfigurationWrites=19, restorationWrites=9, productRestarts=6,
            nativeProviderReloads=1, personOperations=0))
        self.assertEqual([r['newlySubmittedSaml'] for r in counts['attempts']], [1, 5, 18])
        self.assertEqual(counts['attempts'][2]['reusedHistoricalSaml'], 3)

    def test_both_stored_before_snapshots_precede_first_result_get(self):
        events = []
        class Readback:
            def capture(self, folder, runtime, name, run, case):
                events.append(('capture', case))
        def read(path):
            events.append(('api', path))
            return [] if path.endswith('/transcript') else {}
        with tempfile.TemporaryDirectory() as name, patch.object(adopter, 'stored_helpers', return_value=Readback()), patch.object(adopter, 'api', side_effect=read):
            adopter.capture_before(pathlib.Path(name), self.run, [])
        self.assertEqual(events[:2], [('capture', c) for c in adopter.CASES])
        self.assertTrue(events[2][1].endswith('/result.json'))

    def natural_transition(self, edit=None):
        module = adopter.stored_helpers()
        case = adopter.CASES[1]
        before = adopter.READ(FOLDER / adopter.EVALUATION / ('stored-before-' + case + '.json'))['cases'][case]
        after = adopter.READ(FOLDER / adopter.EVALUATION / ('stored-after-' + case + '.json'))['cases'][case]
        if edit:
            edit(after)
        module.verify = lambda folder, runtime, name, run, selected: deepcopy(before if 'stored-before-' in name else after)
        with patch.object(adopter, 'stored_helpers', return_value=module):
            return adopter.compare_application_stored(FOLDER, case, self.report['outcomes'][case])

    def test_actual_two_step_pending_history_is_fully_bound(self):
        self.assertEqual(self.natural_transition()['revision'], 3)

    def test_unrelated_intermediate_reason_cannot_replace_native_pending(self):
        def change(after):
            after['outcome']['details']['previous_recorded_evidence_result']['reason_code'] = 'foreign.reason'
        with self.assertRaisesRegex(ValueError, 'Unexpected intermediate'):
            self.natural_transition(change)

    def test_missing_intermediate_envelope_cannot_skip_a_revision(self):
        with self.assertRaisesRegex(ValueError, 'Native pending envelope missing'):
            self.natural_transition(lambda after: after['outcome']['details'].pop('previous_recorded_evidence_result'))

    def test_out_of_order_native_history_is_rejected(self):
        def change(after):
            after['outcome']['details']['previous_recorded_evidence_result']['updated_at'] = '2000-01-01T00:00:00Z'
        with self.assertRaisesRegex(ValueError, 'Native causal history'):
            self.natural_transition(change)

if __name__ == '__main__':
    unittest.main()
