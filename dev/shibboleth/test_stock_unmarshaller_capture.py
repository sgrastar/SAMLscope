import copy,hashlib,json,pathlib,tempfile,unittest
from capture_stock_unmarshaller import actual_inputs

class StockUnmarshallerInputTest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.parent=pathlib.Path(self.temp.name);self.run='run_KEQD39X2JY336WS5DV520WF09E';self.rows=[];self.decoded=[];self.http=[];self.obs=[]
  for i,fixture in enumerate(['sha256-control','rsa-md5']):
   reference='tx_'+['DV3B32FRZPVMFMB803RSWBH9MP','4BEXMWY92P5X88DNCC5TSHQBXW'][i];request='_action_'+str(i);raw=('<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="'+request+'" Destination="http://localhost:18280/idp/profile/SAML2/POST/SSO"/>').encode();digest=hashlib.sha256(raw).hexdigest();name=reference+'.xml';(self.parent/name).write_bytes(raw)
   self.rows.append(dict(id=reference,runId=self.run,direction='OUTBOUND',decodedSamlRef='transcripts/'+self.run+'/'+reference+'.saml.xml',decodedSamlBytes=len(raw),samlSummary=dict(fixture_id=fixture,scenario_case_id='IIP-ALG08-c-idp-01',active_probe=True,type='AuthnRequest')))
   self.decoded.append(dict(id=reference,file=name,sha256=digest));self.http.append(dict(requestId=request,requestSha256=digest,requestMethod='POST',requestUrl='http://localhost:18280/idp/profile/SAML2/POST/SSO'))
   self.obs.append(dict(fixtureId=fixture,requestReference=reference,requestSha256=digest))
 def tearDown(self):self.temp.cleanup()
 def call(self):
  for name,value in [('transcript.json',self.rows),('decoded-manifest.json',self.decoded),('native-http.json',self.http)]: (self.parent/name).write_text(json.dumps(value))
  return actual_inputs(self.parent,self.run,self.obs)
 def test_exact_actual_recorder_and_native_http_shape_is_bound(self):
  self.assertEqual([x[0] for x in self.call()],['sha256-control','rsa-md5'])
 def test_foreign_run_or_original_path_cannot_be_relabelled(self):
  for field,value in [('runId','run_266C8HC5SD2A4ZCBC4ZSNSSWHB'),('decodedSamlRef','transcripts/foreign/entry.saml.xml')]:
   old=self.rows[1][field];self.rows[1][field]=value
   with self.assertRaises(ValueError):self.call()
   self.rows[1][field]=old
 def test_duplicate_missing_or_another_case_is_not_a_decoder_control(self):
  self.rows.append(copy.deepcopy(self.rows[1]))
  with self.assertRaises(ValueError):self.call()
  self.rows.pop();self.rows[1]['samlSummary']['scenario_case_id']='IIP-OTHER'
  with self.assertRaises(ValueError):self.call()
 def test_modified_raw_hash_or_byte_count_is_not_trusted(self):
  self.decoded[1]['sha256']='a'*64
  with self.assertRaises(ValueError):self.call()
  self.decoded[1]['sha256']=self.obs[1]['requestSha256'];self.rows[1]['decodedSamlBytes']+=1
  with self.assertRaises(ValueError):self.call()
 def test_http_request_hash_method_url_and_uniqueness_are_required(self):
  for field,value in [('requestSha256','a'*64),('requestMethod','GET'),('requestUrl','https://foreign.example/sso')]:
   old=self.http[1][field];self.http[1][field]=value
   with self.assertRaises(ValueError):self.call()
   self.http[1][field]=old
  self.http.append(copy.deepcopy(self.http[1]))
  with self.assertRaises(ValueError):self.call()

if __name__=='__main__':unittest.main()
