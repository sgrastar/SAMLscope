import copy
import json
from pathlib import Path
import tempfile
import unittest
from generate_comparison import withdrawn_source_case
from audit_async_feedback_failure_evidence import withdrawals, REPO

class ComparisonWithdrawalSourceTest(unittest.TestCase):
    def setUp(self):
        self.row = withdrawals(REPO / 'build/acceptance/reference-20260914')[0]

    def test_pinned_legacy_case_supplies_audited_state_independently_of_baseline(self):
        case = withdrawn_source_case(self.row)
        self.assertEqual(case['verdict'], 'PASS')
        self.assertEqual(case['id'], self.row['case'])
        self.assertEqual(case['reason_code'], self.row['audit_withdrawal']['original_reason'])

    def test_same_bytes_cannot_be_relabelled_as_another_run_or_reason(self):
        for field, value in [('run', 'run_00000000000000000000000000'), ('reason', 'unrelated')]:
            row = copy.deepcopy(self.row)
            if field == 'run': row['run'] = value
            else: row['audit_withdrawal']['original_reason'] = value
            with self.assertRaisesRegex(ValueError, 'Run or original conclusion'):
                withdrawn_source_case(row)

    def test_changed_original_is_rejected_before_rendering(self):
        with tempfile.TemporaryDirectory() as directory:
            row = copy.deepcopy(self.row)
            row['evidence_folder'] = directory
            source = Path(self.row['evidence_folder']) / 'result.json'
            changed = json.loads(source.read_bytes())
            changed['run']['id'] = 'run_00000000000000000000000000'
            (Path(directory) / 'result.json').write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'digest differs'):
                withdrawn_source_case(row)

if __name__ == '__main__': unittest.main()
