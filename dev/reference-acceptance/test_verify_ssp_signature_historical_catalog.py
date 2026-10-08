import copy,importlib.util,json,pathlib,subprocess,unittest,yaml
from unittest.mock import patch
P=pathlib.Path(__file__).with_name('verify_ssp_metadata_signature_consumer_acceptance.py');S=importlib.util.spec_from_file_location('signature_history',P);M=importlib.util.module_from_spec(S);S.loader.exec_module(M)
R=P.resolve().parents[2]
class Historical(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.old={n:subprocess.run(['git','show',M.HISTORICAL_CATALOG_COMMIT+':tests/'+n+'.yaml'],cwd=R,capture_output=True,check=True).stdout for n in ['cases','coverage','specs','predicates']}
  cls.current={n:(R/'tests'/ (n+'.yaml')).read_bytes() for n in cls.old}
 def test_actual_four_cases_keep_owning_semantics(self):M.unchanged_signature_case_semantics(self.old,self.current)
 def test_actual_signed_bytes_are_used_without_digest_rewrite(self):
  f=R/'build/acceptance/reference-20260930'/M.FOLDER
  if not f.is_dir():self.skipTest('Public captured campaign absent')
  self.assertEqual(M.owning_signature_catalog(f,R),self.old['cases'])
 def test_unsigned_historical_commit_denied(self):
  f=R/'build/acceptance/reference-20260930'/M.FOLDER
  if not f.is_dir():self.skipTest('Public captured campaign absent')
  with patch.object(M.subprocess,'run',return_value=type('Failure',(),{'returncode':1})()):
   with self.assertRaises(AssertionError):M.owning_signature_catalog(f,R)
 def test_changed_case_coverage_or_predicate_denied(self):
  cases=yaml.safe_load(self.current['cases']);row=next(r for r in cases['cases'] if r['id']=='IIP-MD05-an-idp-01');row['controls']=[];changed={**self.current,'cases':yaml.safe_dump(cases).encode()}
  with self.assertRaises(AssertionError):M.unchanged_signature_case_semantics(self.old,changed)
  changed={**self.current,'predicates':self.current['predicates']+b'\n'}
  with self.assertRaises(AssertionError):M.unchanged_signature_case_semantics(self.old,changed)
if __name__=='__main__':unittest.main()
