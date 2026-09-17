"""Offline controls for the reference driver's signature-only mutations."""
import base64
import unittest
from urllib.parse import quote

from reference_flow import SignatureMutation


class SignatureMutationTest(unittest.TestCase):
    def test_post_preserves_every_byte_outside_signature_text(self):
        prefix = b'<s:AuthnRequest ID="request"><ds:Signature><ds:SignedInfo> untouched </ds:SignedInfo><ds:SignatureValue>'
        suffix = b'</ds:SignatureValue></ds:Signature></s:AuthnRequest>'
        source = prefix + b'AQID&#13;\nBA==' + suffix
        mutation = SignatureMutation()
        result = mutation.post({'SAMLRequest': base64.b64encode(source).decode(), 'RelayState': 'state'})
        changed = base64.b64decode(result['SAMLRequest'])
        self.assertEqual(prefix + b'AAIDBA==' + suffix, changed)
        self.assertEqual('state', result['RelayState'])
        self.assertEqual(1, len(mutation.records))

    def test_redirect_preserves_raw_signed_query_encoding_and_order(self):
        prefix = 'http://localhost:18180/saml?RelayState=a%20b&SAMLRequest=x%2by%2F&SigAlg=urn%3Atest&Signature='
        url = prefix + quote('AQIDBA==', safe='') + '&extra=%2f'
        changed = SignatureMutation().redirect(url)
        self.assertEqual(prefix + quote('AAIDBA==', safe='') + '&extra=%2f', changed)

    def test_missing_or_multiple_signatures_fail_closed(self):
        for raw in [b'<AuthnRequest/>', b'<SignatureValue>AQ==</SignatureValue>' * 2]:
            with self.assertRaises(ValueError):
                SignatureMutation().post({'SAMLRequest': base64.b64encode(raw).decode()})
        with self.assertRaises(ValueError):
            SignatureMutation().redirect('http://localhost/saml?SAMLRequest=x')

    def test_response_is_never_mutated(self):
        response = {'SAMLResponse': 'unchanged', 'RelayState': 'state'}
        self.assertEqual(response, SignatureMutation().post(response))


if __name__ == '__main__':
    unittest.main()
