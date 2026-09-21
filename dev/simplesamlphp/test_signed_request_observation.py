import json
import unittest
from signed_request_observation import signature_rejection


class NativeErrorClassificationTest(unittest.TestCase):
    def test_generic_http_or_other_native_error_is_not_signature_rejection(self):
        for page in ['Internal Server Error','SimpleSAML\\Error\\Error: UNHANDLEDEXCEPTION',
                     'Signature failed','<p>Unknown user</p>',
                     'SimpleSAML\\Error\\Error: {"errorCode":"NOTVALIDCERTSIGNATURE","%ELEMENT%":"SAML2\\\\LogoutRequest"}']:
            self.assertIsNone(signature_rejection(page,500))

    def test_explicit_signature_verification_errors_are_distinct(self):
        missing='<pre>Caused by: SimpleSAML\\Error\\Exception: Validation of received messages enabled, but no signature found on message.</pre>'
        invalid='<pre>SimpleSAML\\Error\\Error: '+json.dumps({'errorCode':'NOTVALIDCERTSIGNATURE','%ELEMENT%':'SAML2\\AuthnRequest'})+'</pre>'
        self.assertEqual('signature-not-established',signature_rejection(missing,500))
        self.assertEqual('signature-value-invalid',signature_rejection(invalid,500))
        for page in [missing,invalid]:
            self.assertIsNone(signature_rejection(page,200))
            self.assertIsNone(signature_rejection('<script>'+page+'</script>',500))
            self.assertIsNone(signature_rejection('<style>'+page+'</style>',500))


if __name__=='__main__':unittest.main()
