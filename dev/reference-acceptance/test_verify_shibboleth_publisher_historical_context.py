import copy,importlib.util,pathlib,subprocess,unittest,yaml
from unittest.mock import patch
P=pathlib.Path(__file__).with_name('verify_shibboleth_publisher_endpoint_acceptance.py');S=importlib.util.spec_from_file_location('publisher',P);M=importlib.util.module_from_spec(S);S.loader.exec_module(M)
class HistoricalContext(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.raw={n:subprocess.run(['git','show',M.HISTORICAL_CATALOG_COMMIT+':tests/'+n+'.yaml'],cwd=M.REPO,capture_output=True,check=True).stdout for n in ['cases','coverage']}
 def test_actual_signed_historical_scope_and_unchanged_semantics(self):
  c,p=M.approved_publisher_source_context({'catalogDigests':dict(M.HISTORICAL_CATALOG_PINS)});self.assertEqual(p,M.HISTORICAL_CATALOG_PINS);self.assertEqual(c['id'],M.C1)
 def test_original_preflight_is_recomputed_from_exact_owning_bytes(self):
  folder=M.REPO/'build/acceptance/reference-20261004'/M.FOLDER
  if not folder.is_dir():self.skipTest('Captured public campaign unavailable')
  planned=M.load(folder/'planned-scope.json');self.assertEqual(M.publisher_scope_preflight(planned,folder/'result-before.json'),M.load(folder/'formal-slot-preflight.json'))
 def test_foreign_whole_catalog_digest_rejected(self):
  p=dict(M.HISTORICAL_CATALOG_PINS);p['cases_sha256']='a'*64
  with self.assertRaises(ValueError):M.approved_publisher_source_context({'catalogDigests':p})
 def test_unverified_historical_signature_denied(self):
  with patch.object(M.subprocess,'run',return_value=type('Failure',(),{'returncode':1})()):
   with self.assertRaises(ValueError):M.approved_publisher_source_context({'catalogDigests':M.HISTORICAL_CATALOG_PINS})
 def test_changed_selected_case_and_owner_level_condition_or_variants_denied(self):
  current={n:(M.REPO/'tests'/ (n+'.yaml')).read_bytes() for n in self.raw}
  for field,value in [('role','sp'),('mode','BROWSER'),('controls',[]),('variant_scopes',{})]:
   d=yaml.safe_load(current['cases']);r=next(r for r in d['cases'] if r['id']==M.C1);r[field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):M.same_publisher_case_semantics(self.raw['cases'],yaml.safe_dump(d).encode(),self.raw['coverage'],current['coverage'])
  for field,value in [('level','MAY'),('condition',{'foreign':True}),('required_variants',[])]:
   d=yaml.safe_load(current['coverage']);r=next(o for req in d['requirements'] for o in req['obligations'] if o['key']=='IIP-MD05.c1');r[field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):M.same_publisher_case_semantics(self.raw['cases'],current['cases'],self.raw['coverage'],yaml.safe_dump(d).encode())
class TransitiveContext(unittest.TestCase):
 def test_actual_link_schema_and_linked_condition_are_preserved_transitively(self):
  import json
  rows=[]
  for case in [M.C1,M.C3]:
   row={'id':case,'obligation':'owner','role':'idp','mode':'CONFIG','controls':['control']}
   row['case_digest']='sha256:'+M.sha(json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode());rows.append(row)
  cases=yaml.safe_dump({'cases':rows}).encode()
  doc={'requirements':[{'id':'root','source_section_digest':'source','obligations':[{'key':'owner','level':'MUST','linked_obligations':[{'obligation':'linked','kind':'inherit_variants','variant_applicability':'linked_condition'}]},{'key':'linked','condition':{'present':True},'level':'SHOULD','required_variants':['one']}]}]}
  raw=yaml.safe_dump(doc).encode();M.same_publisher_case_semantics(cases,cases,raw,raw)
  altered=copy.deepcopy(doc);altered['requirements'][0]['obligations'][1]['condition']={'present':False}
  with self.assertRaises(ValueError):M.same_publisher_case_semantics(cases,cases,raw,yaml.safe_dump(altered).encode())
if __name__=='__main__':unittest.main()
