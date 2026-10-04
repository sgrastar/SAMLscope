#!/usr/bin/env python3
"""Collector transport guards only; does not provide product evidence."""
import base64,json,unittest,urllib.parse,urllib.request,zlib
from unittest.mock import patch
import encrypted_logout_native_campaign as c
XML=b'<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_native-test" />'
def url(xml=XML):
 compressed=zlib.compress(xml)[2:-4]
 return 'http://localhost:18380/simplesaml/module.php/saml/idp/SingleLogoutService.php?'+urllib.parse.urlencode(dict(SAMLRequest=base64.b64encode(compressed).decode(),RelayState='public-test',SigAlg='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',Signature='AA=='))
class Guards(unittest.TestCase):
 def client(self):return c.LogoutClient([],{}, {},[],[],'http://localhost:18080/p/plan_test')
 def test_redirect_originals_and_immediate_location(self):
  client=self.client();target=url()
  with patch.object(c.subprocess,'check_output',return_value=b'{"valid":true}'),patch.object(c,'public_session',return_value={'authenticated':True}):
   client.before_native_redirect(target)
   returned='http://localhost:18080/p/plan_test/sp/slo?SAMLResponse=public-test'
   result=client.redirects.redirect_request(urllib.request.Request(target),None,302,'Found',{},returned)
  self.assertEqual(XML,client.request_originals['_native-test'][0]);self.assertEqual(urllib.parse.urlsplit(target).query.encode(),client.request_originals['_native-test'][1]);self.assertEqual(1,len(client.records));self.assertEqual(302,client.records[0]['response_status']);self.assertEqual(returned,client.records[0]['native_redirect_response_url']);self.assertEqual(returned,result.full_url);self.assertEqual(2,len(client.sessions));self.assertFalse(client.records[0]['nativeDirectResponseBody'])
 def test_native_intermediate_state_removed_final_signed_location_exact(self):
  client=self.client();target=url();intermediate='http://localhost:18380/simplesaml/module.php/core/logout-resume?id=must-not-persist'
  with patch.object(c.subprocess,'check_output',return_value=b'{"valid":true}'),patch.object(c,'public_session',return_value={'authenticated':False}):
   client.before_native_redirect(target)
   client.redirects.redirect_request(urllib.request.Request(target),None,303,'See Other',{},intermediate)
   self.assertEqual(1,len(client.sessions));self.assertNotIn('must-not-persist',json.dumps(client.records))
   final='http://localhost:18080/p/plan_test/sp/slo?SAMLResponse=public-test&Signature=public-signature'
   client.redirects.redirect_request(urllib.request.Request(intermediate),None,303,'See Other',{},final)
  self.assertEqual(final,client.records[0]['native_signed_response_url']);self.assertEqual('http://localhost:18380/simplesaml/module.php/core/logout-resume',client.records[0]['native_signed_response_source_url']);self.assertNotIn('must-not-persist',json.dumps(client.records));self.assertEqual(2,len(client.sessions));self.assertIsNone(client.pendingLogoutRecord)
 def test_non_native_response_cannot_consume_pending_logout(self):
  client=self.client()
  with patch.object(c.subprocess,'check_output',return_value=b'{"valid":true}'),patch.object(c,'public_session',return_value={}):
   client.before_native_redirect(url());client.redirects.redirect_request(urllib.request.Request('http://localhost:18080/unrelated'),None,302,'Found',{},'http://localhost:18080/sp/slo?SAMLResponse=public-test')
  self.assertIsNotNone(client.pendingLogoutRecord);self.assertNotIn('native_signed_response_url',client.records[0])
 def test_invalid_signature_prevents_record_and_dispatch(self):
  client=self.client()
  with patch.object(c.subprocess,'check_output',return_value=b'{"valid":false}'):
   with self.assertRaisesRegex(ValueError,'signature'):client.before_native_redirect(url())
  self.assertEqual([],client.records);self.assertEqual({},client.request_originals)
 def test_duplicate_dispatch_rejected(self):
  client=self.client()
  with patch.object(c.subprocess,'check_output',return_value=b'{"valid":true}'),patch.object(c,'public_session',return_value={}):
   client.before_native_redirect(url())
   with self.assertRaisesRegex(ValueError,'Duplicate'):client.before_native_redirect(url())
  self.assertEqual(1,len(client.records))
 def test_non_logout_redirect_rejected(self):
  with self.assertRaisesRegex(ValueError,'type'):self.client().before_native_redirect(url(XML.replace(b'LogoutRequest',b'AuthnRequest')))
if __name__=='__main__':unittest.main()
