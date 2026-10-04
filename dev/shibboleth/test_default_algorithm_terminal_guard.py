import copy
import unittest

from default_algorithm_terminal_guard import OUTCOMES, require_unfinished

RUN = 'run_1VRHYBEMWK9XX9N0XY49PDJVZQ'
CASE = 'IIP-ALG08-c-idp-01'


class TerminalGuardTest(unittest.TestCase):
    def report(self, outcome=None):
        return {'runId': RUN, 'classifications': [
            {'caseId': 'unrelated-case', 'outcome': 'NOT_VERIFIED'},
            {'caseId': CASE, 'outcome': outcome},
        ]}

    def test_unfinished_selected_case_allows_next_selected_or_suite_only_action(self):
        require_unfinished(self.report(), RUN, CASE)

    def test_all_terminal_outcomes_stop_before_any_action_callback(self):
        calls = []
        for outcome in OUTCOMES:
            with self.subTest(outcome=outcome):
                with self.assertRaisesRegex(ValueError, 'already finished'):
                    require_unfinished(self.report(outcome), RUN, CASE)
                    calls.append('prepare')
        self.assertEqual([], calls)

    def test_not_verified_stays_unresolved_but_is_terminal(self):
        report = self.report('NOT_VERIFIED')
        report['classifications'][1]['resolved'] = False
        with self.assertRaisesRegex(ValueError, 'NOT_VERIFIED'):
            require_unfinished(report, RUN, CASE)
        self.assertFalse(report['classifications'][1]['resolved'])

    def test_missing_or_duplicate_selected_case_fails_closed(self):
        report = self.report()
        report['classifications'] = report['classifications'][:1]
        with self.assertRaises(ValueError):
            require_unfinished(report, RUN, CASE)
        report = self.report()
        report['classifications'].append(copy.deepcopy(report['classifications'][1]))
        with self.assertRaises(ValueError):
            require_unfinished(report, RUN, CASE)

    def test_foreign_run_and_missing_outcome_are_not_permission_to_skip(self):
        report = self.report()
        report['runId'] = 'another-run'
        with self.assertRaises(ValueError):
            require_unfinished(report, RUN, CASE)
        report = self.report()
        del report['classifications'][1]['outcome']
        with self.assertRaises(ValueError):
            require_unfinished(report, RUN, CASE)

    def test_unknown_or_non_string_outcomes_fail_closed(self):
        for outcome in ['FAILED', False, 0, {}, []]:
            with self.subTest(outcome=outcome):
                with self.assertRaises((ValueError, TypeError)):
                    require_unfinished(self.report(outcome), RUN, CASE)


if __name__ == '__main__':
    unittest.main()
