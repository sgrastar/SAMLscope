import unittest,xml.etree.ElementTree as ET,base64
import export_owned_keycloak_nameid_originals as M
class Guards(unittest.TestCase):
 def test_public_seed_identity_is_only_typed_assertion_text(self):
  raw=('<p:Response xmlns:p="'+M.P+'" xmlns:a="'+M.A+'"><a:NameID>public-owned-user</a:NameID></p:Response>').encode()
  self.assertEqual(M.checked_xml(raw,'public-owned-user','pure-password'),raw)
  for raw in [raw.replace(b'a:NameID',b'p:StatusMessage'),raw.replace(b'public-owned-user',b'pure-password'),raw.replace(b'public-owned-user',b'prefix-public-owned-user'),b'<html>public-owned-user</html>',b'<!DOCTYPE Response>'+raw]:
   with self.assertRaises((ValueError,ET.ParseError)):M.checked_xml(raw,'public-owned-user','pure-password')
 def test_physical_declaration_hash_size_and_base64_cannot_be_selfasserted(self):
  raw=b'<public/>';self.assertEqual(M.decoded(base64.b64encode(raw).decode(),len(raw),M.sha(raw)),raw)
  for value,size,digest in [(base64.b64encode(raw).decode(),len(raw)+1,M.sha(raw)),(base64.b64encode(raw).decode(),len(raw),'a'*64),('invalid',7,'a'*64)]:
   with self.assertRaises(ValueError):M.decoded(value,size,digest)
 def test_wire_fields_cannot_hide_raw_login_auth_or_foreign_decoded_bytes(self):
  from urllib.parse import urlencode
  xml=b'<public/>';form=urlencode({'SAMLResponse':base64.b64encode(xml).decode(),'RelayState':'public'}).encode()
  o={'method':'POST','direction':'INBOUND','rawQuery':None,'contentType':'application/x-www-form-urlencoded'}
  M.checked_wire(o,form,xml)
  for body in [form+b'&password=private',form+b'&SAMLResponse=duplicate',urlencode({'SAMLResponse':base64.b64encode(b'<different/>').decode(),'RelayState':'public'}).encode()]:
   with self.assertRaises(ValueError):M.checked_wire(o,body,xml)
 def test_duplicate_or_private_json_is_rejected_before_original_retention(self):
  for raw in [b'{"runId":"one","runId":"two"}',b'{"token":"private"}',b'{"headers":{"Cookie":["raw"]}}',b'\xff']:
   with self.assertRaises((ValueError,UnicodeDecodeError)):M.strict_json(raw)
if __name__=='__main__':unittest.main()
