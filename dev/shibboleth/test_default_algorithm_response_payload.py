"""Host-only byte locator controls; no product or network operations."""
import base64
import hashlib
import unittest
import urllib.parse
import zlib

from default_algorithm_response_payload import P, redirect_response


class RedirectResponseTests(unittest.TestCase):
    def url(self, raw=None):
        if raw is None:
            raw = f'<p:LogoutResponse xmlns:p="{P}" ID="_reply"/>'.encode()
        compressor = zlib.compressobj(wbits=-15)
        payload = base64.b64encode(compressor.compress(raw) + compressor.flush()).decode()
        return "http://suite.example/slo?run=run_one&SAMLResponse=" + urllib.parse.quote(payload, safe="") + "&RelayState=a%2fb&SigAlg=opaque&Signature=opaque", raw

    def test_actual_deflated_bytes_and_untouched_query_hash(self):
        url, raw = self.url()
        result = redirect_response(url)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result["responseSamlSha256"])
        self.assertEqual(hashlib.sha256(urllib.parse.urlsplit(url).query.encode()).hexdigest(),
                         result["responseRawQuerySha256"])
        changed = url.replace("a%2fb", "a%2Fb")
        self.assertEqual(result["responseSamlSha256"], redirect_response(changed)["responseSamlSha256"])
        self.assertNotEqual(result["responseRawQuerySha256"], redirect_response(changed)["responseRawQuerySha256"])

    def test_url_without_actual_saml_response_is_not_evidence(self):
        self.assertIsNone(redirect_response("http://native.example/logout?execution=e1s1"))

    def test_duplicate_or_request_payload_is_ambiguous(self):
        url, _ = self.url()
        for suffix in ["&SAMLResponse=duplicate", "&SAMLRequest=request"]:
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                redirect_response(url + suffix)

    def test_incomplete_deflate_or_wrong_root_cannot_supply_response(self):
        url, _ = self.url()
        compressed = zlib.compress(b"xml")[:-1]
        invalid = "http://suite.example/slo?SAMLResponse=" + urllib.parse.quote(base64.b64encode(compressed).decode(), safe="")
        with self.assertRaises((ValueError, zlib.error)):
            redirect_response(invalid)
        wrong, _ = self.url(b"<other/>")
        with self.assertRaisesRegex(ValueError, "Unexpected response"):
            redirect_response(wrong)

    def test_entities_credentials_and_fragment_are_rejected(self):
        bad, _ = self.url(f'<!DOCTYPE p:LogoutResponse [<!ENTITY x "x">]><p:LogoutResponse xmlns:p="{P}"/>'.encode())
        with self.assertRaisesRegex(ValueError, "Unsafe Redirect XML"):
            redirect_response(bad)
        url, _ = self.url()
        for altered in [url.replace("http://", "http://user:password@"), url + "#fragment"]:
            with self.subTest(altered=altered), self.assertRaisesRegex(ValueError, "Unsafe response URL"):
                redirect_response(altered)


if __name__ == "__main__":
    unittest.main()
