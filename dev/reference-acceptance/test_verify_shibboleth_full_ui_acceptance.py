import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('full_ui_adopter_test', Path(__file__).with_name('verify_shibboleth_full_ui_acceptance.py'))
adopter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adopter)


class FullUiAdoptionPreflightTest(unittest.TestCase):
    def test_not_ready_never_posts_evaluation(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / adopter.EVALUATION).mkdir()
            calls = []

            def api(path, body=None):
                calls.append((path, body))
                return {'cases': [{'caseId': adopter.CASE, 'ready': False}]}

            with patch.object(adopter, 'api', api), self.assertRaisesRegex(ValueError, 'POST skipped'):
                adopter.formal_preflight(folder, 'run_TEST')
            self.assertEqual(len(calls), 1)
            self.assertIsNone(calls[0][1])
            self.assertTrue((folder / adopter.EVALUATION / 'readiness.json').is_file())

    def test_missing_slot_with_unverified_result_never_posts(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / adopter.EVALUATION).mkdir()
            calls = []

            def api(path, body=None):
                calls.append((path, body))
                if path.endswith('/protocol-evidence'):
                    return {'cases': []}
                return {'run': {'id': 'run_TEST'}, 'requirements': [{'cases': [
                    {'id': adopter.CASE, 'outcome': 'NOT_VERIFIED'}]}]}

            with patch.object(adopter, 'api', api), self.assertRaisesRegex(ValueError, 'POST skipped'):
                adopter.formal_preflight(folder, 'run_TEST')
            self.assertTrue(all(body is None for _, body in calls))

    def test_private_stored_helper_does_not_mutate_shared_module(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent))
        import keycloak_registered_signer_stored_outcome as shared
        original = shared.HELPER
        isolated = adopter.stored_helpers()
        self.assertIsNot(isolated, shared)
        self.assertEqual(isolated.HELPER, 'ReadMetadataFullUiStoredConclusions')
        self.assertEqual(shared.HELPER, original)


if __name__ == '__main__':
    unittest.main()
