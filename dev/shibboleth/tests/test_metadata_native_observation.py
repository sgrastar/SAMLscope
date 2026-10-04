import base64,pathlib,sys,tempfile,unittest
from unittest.mock import patch
REPO=pathlib.Path(__file__).resolve().parents[3]
sys.path[:0]=[str(REPO/'dev/shibboleth'),str(REPO/'dev/keycloak')]
from metadata_native_observation import MetadataNativeClient
from reference_flow import Client

class NativeMetadataErrorPrivacy(unittest.TestCase):
 def test_native_error_export_rejects_input_elements_in_all_valid_spellings(self):
  request=base64.b64encode(b'<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_privacy_control"/>').decode();url='http://localhost:18280/idp/profile/SAML2/POST/SSO'
  for input_tag in ["<input name='csrf' value='synthetic-secret'/>","<INPUT TYPE='hidden' value='synthetic-secret'>","<input\nname='csrf' value='synthetic-secret'>","<input>","<input/>"]:
   with self.subTest(input_tag=input_tag),tempfile.TemporaryDirectory() as folder:
    records=[];client=MetadataNativeClient(records,folder)
    with patch.object(Client,'request',return_value=(url,'Message Security Error '+input_tag,400)):client.request(url,{'SAMLRequest':request})
    self.assertEqual(list(pathlib.Path(folder).iterdir()),[]);self.assertNotIn('responseBodyFile',records[0]);self.assertEqual(records[0]['requestMethod'],'POST')
 def test_public_assertion_free_error_can_be_preserved(self):
  request=base64.b64encode(b'<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_privacy_control"/>').decode();url='http://localhost:18280/idp/profile/SAML2/POST/SSO'
  with tempfile.TemporaryDirectory() as folder:
   records=[];client=MetadataNativeClient(records,folder)
   with patch.object(Client,'request',return_value=(url,'<h1>Message Security Error</h1>',400)):client.request(url,{'SAMLRequest':request})
   self.assertEqual((pathlib.Path(folder)/records[0]['responseBodyFile']).read_text(),'<h1>Message Security Error</h1>')
if __name__=='__main__':unittest.main()
