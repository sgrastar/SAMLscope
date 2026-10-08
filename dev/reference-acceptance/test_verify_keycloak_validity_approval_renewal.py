"""Exact authority renewal only; does not change any native validity proof or case."""
import copy,importlib.util,pathlib,unittest
from unittest.mock import patch
P=pathlib.Path(__file__).with_name('verify_keycloak_validity_capability_absence.py');S=importlib.util.spec_from_file_location('kc_validity',P);M=importlib.util.module_from_spec(S);S.loader.exec_module(M)
class Renewal(unittest.TestCase):
 def row(self):return {'case':M.CASES[0],'case_digest':M.CASE_DIGESTS[M.CASES[0]],'reviewer':'hoshina@gmail.com','approved_at':'2026-10-08T05:24:49Z'}
 def test_original_timestamp_remains_accepted(self):
  r=self.row();r['approved_at']='2026-09-22T05:58:38+09:00';self.assertTrue(M.matching_approval_record(r,M.CASES[0],r['case_digest'],{}))
 def test_exact_signed_renewed_row_accepted(self):
  r=self.row();self.assertTrue(M.matching_approval_record(r,M.CASES[0],r['case_digest'],{r['case']:r}))
 def test_changed_date_signer_digest_case_or_extra_fields_rejected(self):
  original=self.row()
  for field,value in [('approved_at','future'),('reviewer','foreign'),('case_digest','sha256:'+'a'*64),('case','foreign'),('unverifiedClaim',True)]:
   r=copy.deepcopy(original);r[field]=value
   with self.subTest(field=field):self.assertFalse(M.matching_approval_record(r,M.CASES[0],original['case_digest'],{original['case']:original}))
 def test_role_mode_variant_or_control_change_cannot_keep_selfdeclared_digest(self):
  rows={row['id']:row for row in M.yaml.safe_load((M.REPO/'tests/cases.yaml').read_text())['cases']}
  base=rows[M.CASES[0]];digest=M.CASE_DIGESTS[M.CASES[0]];self.assertTrue(M.same_case_definition(base,digest))
  for field,value in [('role','sp'),('mode','BROWSER'),('variant_plan',[]),('controls',[])]:
   changed=copy.deepcopy(base);changed[field]=value
   with self.subTest(field=field):self.assertFalse(M.same_case_definition(changed,digest))
 def test_unverified_signature_rejected_before_source_load(self):
  with patch.object(M.subprocess,'run',return_value=type('Failure',(),{'returncode':1})()):
   with self.assertRaises(AssertionError):M.signed_renewed_approvals()
 def test_exact_current_signed_renewal_only_changes_timestamp_in_c_a_interval(self):
  from datetime import datetime,timezone
  anchor=M.signed_renewed_approvals();rows=[{**anchor[c],'approved_at':'2026-10-08T08:00:05Z'} for c in M.CASE_DIGESTS]
  low=datetime(2026,10,8,8,0,tzinfo=timezone.utc);high=datetime(2026,10,8,8,1,tzinfo=timezone.utc)
  current=M.current_renewal_rows({'approvals':rows},anchor,low,high)
  for row in rows:self.assertTrue(M.matching_approval_record(row,row['case'],row['case_digest'],anchor,current))
  for field,value in [('reviewer','foreign'),('case_digest','sha256:'+'a'*64),('approved_at','2026-10-08T07:00:00Z'),('approved_at','2026-10-08T08:02:00Z'),('approved_at','2026-10-08T08:00:05')]:
   bad=copy.deepcopy(rows);bad[0][field]=value
   with self.subTest(field=field,value=value),self.assertRaises(AssertionError):M.current_renewal_rows({'approvals':bad},anchor,low,high)
 def test_foreign_signed_principal_or_reviewer_set_is_denied(self):
  M.require_renewal_principal('hoshina@gmail.com',{'evidence':{'reviewers':['hoshina@gmail.com']}})
  for principal,reviewers in [('foreign@example.test',['hoshina@gmail.com']),('hoshina@gmail.com',['foreign@example.test']),('hoshina@gmail.com',['hoshina@gmail.com','foreign@example.test'])]:
   with self.subTest(principal=principal),self.assertRaises(AssertionError):M.require_renewal_principal(principal,{'evidence':{'reviewers':reviewers}})
 def test_current_unsigned_record_is_denied(self):
  with patch.object(M.subprocess,'run',return_value=type('Failure',(),{'returncode':1})()):
   with self.assertRaises(AssertionError):M.signed_current_renewal({})
 def test_actual_signed_renewal_preserves_all_four_case_contracts(self):M.verify_approved_definitions()
if __name__=='__main__':unittest.main()
