import importlib.util,json,pathlib,tempfile,unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('ui_safety_adoption_under_test',pathlib.Path(__file__).with_name('verify_keycloak_ui_safety_acceptance.py'));subject=importlib.util.module_from_spec(spec);spec.loader.exec_module(subject)
class PreflightTest(unittest.TestCase):
 def exercise(self,status,result=None):
  with tempfile.TemporaryDirectory() as name:
   folder=pathlib.Path(name);ev=folder/subject.EVALUATION;ev.mkdir();(ev/'stored-before.json').write_text('{}');(folder/'created.json').write_text(json.dumps({'run':{'id':'run_00000000000000000000000000'}}));calls=[]
   def api(path,body=None):
    calls.append((path,body))
    if path.endswith('/protocol-evidence'):return status
    if path.endswith('/result.json'):return result
    raise AssertionError('No evaluation POST permitted')
   with patch.object(subject,'api',api):
    with self.assertRaisesRegex(ValueError,'POST skipped'):subject.formal(folder)
   self.assertTrue((ev/'protocol-evidence-preflight.json').is_file());self.assertFalse(any(body is not None for _,body in calls));self.assertFalse((ev/'evaluate.json').exists())
 def test_not_ready_prevents_evaluation_post(self):self.exercise({'cases':[{'caseId':subject.CASE,'ready':False}]})
 def test_missing_slot_with_not_verified_result_prevents_post(self):self.exercise({'cases':[]},{'run':{'id':'run_00000000000000000000000000'},'requirements':[{'cases':[{'id':subject.CASE,'outcome':'NOT_VERIFIED'}]}]})
 def test_isolated_stored_helper_does_not_modify_shared_global(self):
  import sys
  sys.path.insert(0,str(pathlib.Path(__file__).parent));import keycloak_registered_signer_stored_outcome as shared
  before=shared.HELPER;isolated=subject.stored_helpers();self.assertEqual(isolated.HELPER,'ReadKeycloakUiSafetyStoredConclusions');self.assertEqual(shared.HELPER,before)
if __name__=='__main__':unittest.main()
