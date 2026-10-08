"""Finite adoption contract controls on public captured artifacts; no product operation."""
import copy,importlib.util,json,pathlib,unittest
from unittest.mock import patch
P=pathlib.Path(__file__).with_name('verify_owned_keycloak_nameid_acceptance.py')
SPEC=importlib.util.spec_from_file_location('owned_nameid_acceptance',P);M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)
BASE=M.REPO/'build/acceptance/reference-20261008'
class Contract(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if not (BASE/'owned-keycloak-nameid-native-r1/runtime.json').is_file():raise unittest.SkipTest('Captured public acceptance generation is not present')
  cls.docs=M.read_pins(BASE)
 def test_actual_native_central_case_unchanged(self):
  native,result,case=M.campaign_documents(BASE,self.docs);self.assertEqual(case['outcome'],'SATISFIED');self.assertEqual(case['verdict'],'PASS')
  actual=[c for r in result['requirements'] for c in r['cases'] if c['id']==M.CASE];self.assertEqual(actual,[case]);self.assertFalse(native['canonicalAdoption'])
 def test_actual_native13_mutations_replayed_without_new_protocol(self):self.assertEqual(M.actual_native_tamper_controls(BASE,self.docs),13)
 def test_unrestored_or_changed_client_is_not_adoptable(self):
  mutations=[('owned-keycloak-public-ci-setup-r4/setup.json',lambda d:d.update(clientDbId='foreign')),
   ('owned-keycloak-public-ci-setup-r4/setup.json',lambda d:d['nativeClientReadback']['attributes'].update({'saml_force_name_id_format':'true'})),
   ('owned-keycloak-public-ci-setup-r4/setup.json',lambda d:d.update(definitionIdentity={**M.IDENTITY,'version':'functional-case-v1'})),
   ('owned-keycloak-public-ci-restoration-r1/restoration.json',lambda d:d.update(restored=False)),
   ('owned-keycloak-public-ci-restoration-r1/restoration.json',lambda d:d.update(readbackStatus=200)),
   ('owned-keycloak-public-ci-restoration-r1/restoration.json',lambda d:d.update(originalClientStateSha256='a'*64)),
   ('owned-keycloak-public-ci-cleanup-r1/cleanup.json',lambda d:d.update(ownedContainerRemoved=False)),
   ('owned-keycloak-public-ci-cleanup-r1/cleanup.json',lambda d:d.update(ownedContainerId='a'*64)),
   ('owned-keycloak-nameid-native-r1/session-reuse-proof.json',lambda d:d.update(allSignedNativeSessionIndexesSameAndPresent=False)),
   ('owned-keycloak-nameid-browser-r2/result.json',lambda d:d['suite'].update(image_digest='sha256:'+'a'*64))]
  for key,mutate in mutations:
   docs=copy.deepcopy(self.docs);mutate(docs[key])
   with self.subTest(key=key),self.assertRaises(ValueError):M.campaign_documents(BASE,docs)
 def test_new_provenance_never_reinterprets_legacy_case(self):
  p=M.source_provenance(BASE);self.assertEqual(p['adoptedDefinitionIdentity'],M.IDENTITY);self.assertEqual(p['adoptedCaseDigest'],M.CASE_DIGEST)
  self.assertEqual(p['legacyLiteralEqualityCaseDigest'],M.LEGACY_CASE_DIGEST);self.assertFalse(p['legacyRunReinterpreted'])
  self.assertEqual(p['newLoginOperationsForAdoption'],0);self.assertEqual(p['newProtocolOperationsForAdoption'],0)
 def test_result_path_preserves_caller_lexical_style_and_generator_normalization(self):
  relative=pathlib.Path('build/acceptance/reference-20261008');absolute=M.REPO/relative
  self.assertFalse(M.source_result_path(relative).is_absolute());self.assertTrue(M.source_result_path(absolute).is_absolute())
  evidence=pathlib.Path('build/acceptance/reference-20260914/remaining-audit')
  for root in [relative,absolute]:
   path=M.source_result_path(root)
   if path.is_absolute():path=path.relative_to(M.REPO)
   self.assertEqual(path.parent.relative_to(evidence.parents[3]),relative/'owned-keycloak-nameid-browser-r2')
 def test_live_mode_rejected_before_any_io(self):
  with patch.object(M,'read_pins',side_effect=AssertionError('no read')):
   with self.assertRaises(ValueError):M.verify_adoption(BASE,live=True)
 def test_wrong_generation_rejected_before_original_read(self):
  with patch.object(M,'read_pins',side_effect=AssertionError('no read')):
   with self.assertRaises(ValueError):M.verify_adoption(BASE.parent/'reference-other')
if __name__=='__main__':unittest.main()
