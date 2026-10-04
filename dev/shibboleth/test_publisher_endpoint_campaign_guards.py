import importlib.util,pathlib,unittest
SOURCE=pathlib.Path(__file__).with_name('publisher_endpoint_inventory_campaign.py')
spec=importlib.util.spec_from_file_location('publisher_guard_subject',SOURCE);subject=importlib.util.module_from_spec(spec);spec.loader.exec_module(subject)
class PublisherCampaignGuardTest(unittest.TestCase):
 def test_only_typed_suite_ids_reach_native_paths(self):
  for kind in ['run','plan']:
   valid=kind+'_0123456789ABCDEFGHJKMNPQRS';self.assertEqual(subject.identifier(valid,kind),valid)
   for value in ['../../etc','run_x/../../etc','$(command)','x;command',kind+'_short',None,12]:
    with self.assertRaises(ValueError):subject.identifier(value,kind)
 def test_public_servlet_cookie_policy_is_preserved(self):
  raw=b'<web-app><session-config><cookie-config><http-only>true</http-only><secure>false</secure></cookie-config></session-config></web-app>';self.assertEqual(subject.public_xml(raw),raw)
 def test_nested_or_attribute_private_fields_are_refused(self):
  for raw in [b'<beans clientSecret="value"/>',b'<beans passwordRef="value"/>',b'<beans><credentialValue/></beans>',b'<beans CookieValue="value"/>',b'<beans private-key="value"/>',b'<cookie-config token="value"/>']:
   with self.assertRaises(ValueError):subject.public_xml(raw)
 def test_public_configuration_references_are_not_private_material(self):
  raw=b'<bean id="publicCredentialResolver" parent="publicPasswordFlow"/>';self.assertEqual(subject.public_xml(raw),raw)
 def test_named_bean_secret_property_is_refused(self):
  with self.assertRaises(ValueError):subject.public_xml(b'<property name="clientSecret" value="hidden"/>')
if __name__=='__main__':unittest.main()
