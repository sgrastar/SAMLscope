"""The real formal workflow must stop before POST when its live API proof is incomplete."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
import verify_ssp_certificate_runtime_acceptance as adoption

class FormalPreflightTest(unittest.TestCase):
    def folder(self,root):
        folder=Path(root);(folder/'receipt').mkdir();(folder/'receipt/manifest.json').write_text(json.dumps({'runId':'run_00000000000000000000000000'}))
        (folder/adoption.EVALUATION).mkdir();(folder/adoption.EVALUATION/'stored-before.json').write_text('{}')
        return folder

    def test_stored_helper_selection_leaves_other_product_module_unchanged(self):
        import keycloak_registered_signer_stored_outcome as shared
        original=shared.HELPER
        first=adoption.stored_helpers();second=adoption.stored_helpers()
        self.assertIsNot(first,shared);self.assertIsNot(second,shared)
        self.assertEqual(shared.HELPER,original)
        self.assertEqual(first.HELPER,'ReadSimpleSamlPhpCertificateStoredConclusions')
        self.assertIs(first.capture.__globals__,first.__dict__)
        self.assertIs(first.verify.__globals__,first.__dict__)
        self.assertIs(first.compare_stored.__globals__,first.__dict__)
        first.HELPER='local-test-only-selection'
        self.assertEqual(second.HELPER,'ReadSimpleSamlPhpCertificateStoredConclusions')
        self.assertEqual(shared.HELPER,original)

    def test_not_ready_never_posts_even_if_saved_offline_proof_could_pass(self):
        with TemporaryDirectory() as root:
            folder=self.folder(root);calls=[]
            def api(path,body=None):
                calls.append((path,body));return {'cases':[{'caseId':adoption.CASE,'ready':False}]}
            helper=Mock()
            with patch.object(adoption,'api',api),patch.object(adoption,'stored_helpers',return_value=helper):
                with self.assertRaisesRegex(ValueError,'not ready.*POST skipped'):adoption.formal(folder)
            self.assertEqual(len(calls),1);self.assertIsNone(calls[0][1]);helper.capture.assert_not_called()
            self.assertFalse((folder/adoption.EVALUATION/'evaluate.json').exists())
            self.assertFalse(json.loads((folder/adoption.EVALUATION/'protocol-evidence-preflight.json').read_text())['cases'][0]['ready'])

    def test_missing_case_with_not_verified_result_never_posts(self):
        with TemporaryDirectory() as root:
            folder=self.folder(root);calls=[]
            def api(path,body=None):
                calls.append((path,body))
                if path.endswith('/protocol-evidence'):return {'cases':[]}
                return {'run':{'id':'run_00000000000000000000000000'},'requirements':[{'cases':[{'id':adoption.CASE,'outcome':'NOT_VERIFIED'}]}]}
            helper=Mock()
            with patch.object(adoption,'api',api),patch.object(adoption,'stored_helpers',return_value=helper):
                with self.assertRaisesRegex(ValueError,'missing without.*POST skipped'):adoption.formal(folder)
            self.assertEqual(len(calls),2);self.assertTrue(all(body is None for _,body in calls));helper.capture.assert_not_called()
            self.assertTrue((folder/adoption.EVALUATION/'protocol-evidence-preflight-existing-result.json').is_file())

    def test_completed_formal_originals_are_not_replayed_or_given_retroactive_preflight(self):
        with TemporaryDirectory() as root:
            folder=self.folder(root);(folder/adoption.EVALUATION/'stored-after.json').write_text('immutable')
            with patch.object(adoption,'api') as api,patch.object(adoption,'stored_helpers'):
                with self.assertRaisesRegex(ValueError,'completed history'):adoption.formal(folder)
                api.assert_not_called()
            self.assertFalse((folder/adoption.EVALUATION/'protocol-evidence-preflight.json').exists())
            self.assertEqual((folder/adoption.EVALUATION/'stored-after.json').read_text(),'immutable')

if __name__=='__main__':unittest.main()
