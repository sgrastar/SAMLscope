"""Protect session isolation and public-only native evidence in the reference driver."""
import unittest

from browser_chain_campaign import SessionDriver, public_client_readback


class FakeClient:
    def __init__(self):
        self.calls = []

    def request(self, url, fields=None):
        self.calls.append((url, fields))
        return 'response'


class BrowserChainTest(unittest.TestCase):
    def test_opt_in_reuses_only_explicit_false(self):
        driver = SessionDriver(True, FakeClient)
        client, reused = driver.probe_client({'requiresFreshSession': False})
        self.assertIs(driver.initial_client, client)
        self.assertTrue(reused)
        self.assertEqual(1, driver.reused_submissions)
        for status in [{}, {'requiresFreshSession': True}, {'requiresFreshSession': None},
                       {'requiresFreshSession': 0}, {'requiresFreshSession': 'false'}]:
            with self.subTest(status=status):
                client, reused = driver.probe_client(status)
                self.assertIsNot(driver.initial_client, client)
                self.assertFalse(reused)
        self.assertEqual(5, driver.fresh_session_boundaries)
        self.assertEqual(1, driver.fresh_session_requirements)

    def test_default_always_preserves_fresh_client_behavior(self):
        driver = SessionDriver(False, FakeClient)
        first, reused = driver.probe_client({'requiresFreshSession': False})
        second, _ = driver.probe_client({'requiresFreshSession': False})
        self.assertIsNot(first, second)
        self.assertIsNot(first, driver.initial_client)
        self.assertFalse(reused)
        self.assertEqual(0, driver.reused_submissions)
        self.assertEqual(2, driver.fresh_session_boundaries)

    def test_counts_real_credential_calls_across_shared_and_fresh_clients(self):
        driver = SessionDriver(True, FakeClient)
        driver.initial_client.request('http://localhost/login', {'password': 'memory-only'})
        reused, _ = driver.probe_client({'requiresFreshSession': False})
        reused.request('http://localhost/saml', {'SAMLRequest': 'fixture'})
        fresh, _ = driver.probe_client({'requiresFreshSession': True})
        fresh.request('http://localhost/login', {'j_password': 'memory-only'})
        fresh.request('http://localhost/normal')
        self.assertEqual(2, driver.login_submissions)
        self.assertEqual({'reuse_session', 'factory', 'login_submissions', 'fresh_session_boundaries', 'fresh_session_requirements',
                          'reused_submissions', 'initial_client'}, set(vars(driver)))

    def test_public_readback_removes_only_two_native_top_level_fields(self):
        original = {'id': 'native-id', 'secret': 'never-write', 'registrationAccessToken': 'never-write',
                    'attributes': {'saml.client.signature': 'true', 'client.secret.creation.time': '123'}}
        public, annotation = public_client_readback(original)
        self.assertEqual({'id': 'native-id', 'attributes': original['attributes']}, public)
        self.assertEqual(['$.secret', '$.registrationAccessToken'], annotation['redactions'])
        self.assertEqual('never-write', original['secret'])
        self.assertEqual(64, len(annotation['response_sha256']))

    def test_unknown_sensitive_fields_never_get_persisted(self):
        for original in [{'attributes': {'saml.private.key': 'never-write'}},
                         {'attributes': {'nested': {'password': 'never-write'}}},
                         {'credentials': []}, {'otherToken': 'never-write'}]:
            with self.subTest(original=original), self.assertRaises(ValueError):
                public_client_readback(original)

    def test_native_cookie_and_authorization_headers_are_rejected_recursively(self):
        for name in ['Cookie', 'Authorization', 'Set-Cookie', 'Proxy-Authorization']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                public_client_readback({'attributes': {'nested': {name: 'never-write'}}})


if __name__ == '__main__':
    unittest.main()
