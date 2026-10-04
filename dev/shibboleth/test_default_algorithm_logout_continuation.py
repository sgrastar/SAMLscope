import unittest
import base64
import hashlib
import tempfile
from pathlib import Path
from unittest.mock import patch
from default_algorithm_logout_continuation import continuation, public_response_identity, SLO_PATH

URL = 'http://localhost:18280' + SLO_PATH


class LogoutContinuationTest(unittest.TestCase):
    def test_actual_native_hidden_iframe_is_followed_without_saml_or_credentials(self):
        html = '<iframe style="display:none" src="' + SLO_PATH + '?execution=e7s1&amp;_eventId=proceed"></iframe>'
        target = continuation(URL, html, 200)
        self.assertEqual(URL + '?execution=e7s1&_eventId=proceed', target)
        self.assertNotIn('SAMLRequest', target)

    def test_same_flow_only_when_response_url_has_execution(self):
        page = '<iframe src="?execution=e7s1&amp;_eventId=proceed"></iframe>'
        self.assertEqual(URL + '?execution=e7s1&_eventId=proceed', continuation(URL + '?execution=e7s1', page, 200))
        with self.assertRaises(ValueError):
            continuation(URL + '?execution=e8s1', page, 200)

    def test_other_endpoint_failure_and_response_form_do_not_navigation(self):
        self.assertIsNone(continuation(URL.replace('/SLO', '/SSO'), '<iframe src="?execution=e7s1&_eventId=proceed">', 200))
        self.assertIsNone(continuation(URL, '<iframe src="?execution=e7s1&_eventId=proceed">', 400))
        self.assertIsNone(continuation(URL, '<form action="/acs"><input name="SAMLResponse"></form>', 200))

    def test_foreign_host_endpoint_and_saml_fields_fail_closed(self):
        for source in ['http://elsewhere.invalid' + SLO_PATH + '?execution=e7s1&_eventId=proceed',
                       '/idp/profile/SAML2/POST/SSO?execution=e7s1&_eventId=proceed',
                       '?execution=e7s1&_eventId=proceed&SAMLRequest=wrong',
                       '?execution=e7s1&_eventId=local', '?execution=&_eventId=proceed']:
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    continuation(URL, '<iframe src="' + source + '"></iframe>', 200)

    def test_duplicate_iframe_or_fields_are_not_one_operation(self):
        for page in ['<iframe src="?execution=e7s1&_eventId=proceed"></iframe>' * 2,
                     '<iframe src="?execution=e7s1&execution=e8s1&_eventId=proceed"></iframe>']:
            with self.assertRaises(ValueError):
                continuation(URL, page, 200)

    def test_webflow_execution_is_hashed_and_omitted_from_transport_original(self):
        original = URL + '?execution=e7s1&_eventId=proceed'
        value = public_response_identity(original)
        self.assertEqual(URL, value['responseUrl'])
        self.assertTrue(value['responseUrlQueryRedacted'])
        self.assertEqual(64, len(value['responseUrlSha256']))
        self.assertNotIn('e7s1', str(value))

    def test_normal_public_endpoint_identity_is_unchanged(self):
        self.assertEqual({'responseUrl': URL, 'responseUrlQueryRedacted': False}, public_response_identity(URL))

    def test_collector_one_saml_post_then_actual_iframe_get_keeps_token_in_memory(self):
        from default_algorithm_campaign import SharedClient
        from reference_flow import Client
        raw = b'<p:LogoutRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_one"/>'
        reply = b'<p:LogoutResponse xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_reply" InResponseTo="_one"/>'
        iframe = '<iframe style="display:none" src="?execution=e7s1&amp;_eventId=proceed"></iframe>'
        form = '<form action="http://localhost:18080/slo"><input name="SAMLResponse" value="' + base64.b64encode(reply).decode() + '"></form>'
        calls = []

        def transport(client, url, fields=None):
            calls.append((url, fields))
            return (url, iframe if len(calls) == 1 else form, 200)

        with tempfile.TemporaryDirectory() as folder, patch.object(Client, 'request', transport):
            client = SharedClient(Path(folder))
            client.request(URL, {'SAMLRequest': base64.b64encode(raw).decode()})
        self.assertEqual(2, len(calls))
        self.assertIn('SAMLRequest', calls[0][1])
        self.assertIsNone(calls[1][1])
        self.assertEqual(1, len(client.http))
        self.assertEqual(hashlib.sha256(reply).hexdigest(), client.http[0]['responseSamlSha256'])
        self.assertEqual(1, len(client.logout_continuations))
        self.assertEqual(0, client.credential_posts)
        self.assertNotIn('e7s1', str(client.http) + str(client.logout_continuations))


if __name__ == '__main__':
    unittest.main()
