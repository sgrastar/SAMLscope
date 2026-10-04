import base64
import unittest

from browser_chain_campaign import SessionDriver
from metadata_revocation_campaign import NativeMatrixClient, TARGET


class Client:
    def __init__(self): self.calls = []
    def request(self, url, fields=None):
        self.calls.append((url, fields))
        return url, 'Invalid requester', 400


def request(attributes=''):
    raw = ('<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_fixture" '
           + attributes + '/>').encode()
    return {'SAMLRequest': base64.b64encode(raw).decode()}


class NativeMatrixSessionTest(unittest.TestCase):
    def test_plain_normal_requests_share_cookie_jar_without_persisting_state(self):
        sessions = SessionDriver(True, Client)
        observations = []
        matrix = NativeMatrixClient(sessions, observations)
        self.assertIs(matrix.factory(), matrix.factory())
        matrix.factory().request(TARGET + '/protocol/saml', request())
        matrix.factory().request(TARGET + '/protocol/saml', request('ForceAuthn="false" IsPassive="0"'))
        self.assertEqual(len(observations), 2)
        self.assertEqual(sessions.login_submissions, 0)
        self.assertTrue(all(row['sameInMemoryClient'] for row in observations))
        self.assertTrue(all(not row['responseStateValuesPersisted'] for row in observations))
        self.assertTrue(all('SAMLRequest' not in row and 'responseBody' not in row for row in observations))

    def test_fresh_and_passive_boundaries_are_rejected_before_any_native_send(self):
        for attributes in ['ForceAuthn="true"', 'IsPassive="true"', 'ForceAuthn="1"', 'IsPassive="bad"']:
            sessions = SessionDriver(True, Client)
            observations = []
            matrix = NativeMatrixClient(sessions, observations)
            with self.assertRaises(ValueError):
                matrix.factory().request(TARGET + '/protocol/saml', request(attributes))
            self.assertEqual(sessions.initial_client.calls, [])
            self.assertEqual(observations, [])

    def test_credentials_counted_but_never_recorded_as_protocol_observations(self):
        sessions = SessionDriver(True, Client)
        observations = []
        matrix = NativeMatrixClient(sessions, observations)
        matrix.factory().request(TARGET + '/login-actions/authenticate', {'password': 'in-memory'})
        self.assertEqual(sessions.login_submissions, 1)
        self.assertEqual(observations, [])


if __name__ == '__main__': unittest.main()
