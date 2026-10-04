import base64
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

path = Path(__file__).with_name('registered_signer_campaign.py')
spec = importlib.util.spec_from_file_location('ssp_registered_signer', path)
collector = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = collector
spec.loader.exec_module(collector)


class SignerCollectorTests(unittest.TestCase):
    def test_insufficient_capacity_aborts_before_product_or_login_work(self):
        with patch.object(sys, 'argv', ['campaign', '--output', '/private/tmp/no-signer-output']), \
             patch.object(collector.os, 'statvfs', return_value=SimpleNamespace(f_bavail=0, f_frsize=4096)), \
             patch.object(collector, 'api') as api, \
             patch.object(collector, 'SharedClient') as client, \
             patch.object(collector.Path, 'mkdir') as mkdir:
            with self.assertRaises(SystemExit) as result:
                collector.main()
        self.assertEqual(result.exception.code, 2)
        api.assert_not_called()
        client.assert_not_called()
        mkdir.assert_not_called()

    def test_second_login_is_blocked_before_transport(self):
        client = collector.SharedClient()
        with patch.object(collector.Client, 'request', return_value=('http://localhost:18380/login', '', 200)) as transport:
            client.request('http://localhost:18380/login', {'password': 'memory-only'})
            with self.assertRaises(ValueError):
                client.request('http://localhost:18380/login', {'password': 'memory-only'})
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(client.credential_posts, 1)
        self.assertEqual(client.credential_attempts, 2)
        self.assertNotIn('memory-only', repr(client.__dict__))

    def test_fresh_session_confirmation_never_uses_the_shared_jar(self):
        client = collector.SharedClient()
        with patch.object(collector.Client, 'request') as transport:
            with self.assertRaises(ValueError):
                client.request('http://localhost:18080/probe', {'freshSessionConfirmed': 'true'})
        transport.assert_not_called()

    def test_special_requests_are_blocked_before_transport(self):
        for attribute in ('ForceAuthn', 'IsPassive'):
            for value in ('true', '1', 'TRUE', ''):
                request = '<AuthnRequest ID="request" ' + attribute + '="' + value + '"/>'
                fields = dict(SAMLRequest=base64.b64encode(request.encode()).decode())
                with patch.object(collector.Client, 'request') as transport:
                    with self.assertRaises(ValueError):
                        collector.SharedClient().request('http://localhost:18380/sso', fields)
                    transport.assert_not_called()

    def test_terminal_forms_and_headers_are_not_persistable(self):
        self.assertTrue(collector.public_terminal('<h1>Public error</h1>'))
        for text in ('<INPUT name="password">', '< input value="hidden">', 'SAMLRequest',
                     'SAMLResponse', 'Cookie: secret', 'Authorization: secret', 'x' * 262145):
            self.assertFalse(collector.public_terminal(text))

    def test_native_json_credentials_are_blocked_recursively(self):
        collector.reject_sensitive({'keys': [{'X509Certificate': 'public'}]})
        for key in ('password', 'set-cookie', 'private_key', 'Authorization'):
            with self.assertRaises(ValueError):
                collector.reject_sensitive({'nested': [{key: 'never-save'}]})

    def test_actual_redirect_attempts_are_counted_without_query_persistence(self):
        client = collector.SharedClient()
        handlers = [h for h in client.op.handlers if isinstance(h, collector.urllib.request.HTTPRedirectHandler)]
        self.assertEqual(len(handlers), 1)
        req = collector.urllib.request.Request('http://localhost:18080/start')
        handlers[0].redirect_request(req, None, 302, '', {}, 'http://localhost:18380/sso?SAMLRequest=public')
        self.assertEqual(client.native_redirect_attempts, 1)
        self.assertNotIn('SAMLRequest=public', repr(client.__dict__))


if __name__ == '__main__':
    unittest.main()
