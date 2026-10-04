"""Host-only tests of Recorder raw-original correlation; no product operations."""
import copy
import hashlib
import unittest
import xml.etree.ElementTree as ET
from default_algorithm_transcript import CASE, P, correlate_exchange

RUN = 'run_00000000000000000000000000'
ACTION = 'action_1234567890abcdef1234567890abcdef'


class TranscriptCorrelationTest(unittest.TestCase):
    def sample(self, fixture='sha256-control', success=True):
        logout = fixture in {'rsa15-encrypted-id', 'oaep-encrypted-id-control'}
        request_kind = 'LogoutRequest' if logout else 'AuthnRequest'
        root = ET.Element(f'{{{P}}}{request_kind}', ID='_' + ACTION,
                          Destination='http://native.example/POST?one=1&two=2')
        request_bytes = ET.tostring(root)
        req = dict(id='tx_00000000000000000000000001', runId=RUN, direction='OUTBOUND',
                   correlationId=ACTION, method='POST', url=root.get('Destination'),
                   decodedSamlRef=f'transcripts/{RUN}/tx_00000000000000000000000001.saml.xml',
                   decodedSamlBytes=len(request_bytes), samlSummary=dict(
                       fixture_id=fixture, active_probe=True, action_id=ACTION,
                       type=request_kind, scenario_case_id=CASE))
        # Actual OUTBOUND summary intentionally has no SAML ID.
        bodies = {req['id']: request_bytes}
        http = dict(requestId=root.get('ID'), requestSha256=hashlib.sha256(request_bytes).hexdigest(),
                    requestUrl=root.get('Destination'), requestMethod='POST')
        rows = [req]
        if success:
            reply_kind = 'LogoutResponse' if logout else 'Response'
            reply = ET.Element(f'{{{P}}}{reply_kind}', ID='_reply', InResponseTo=root.get('ID'))
            raw = ET.tostring(reply)
            response = dict(id='tx_00000000000000000000000002', runId=RUN, direction='INBOUND',
                            decodedSamlRef=f'transcripts/{RUN}/tx_00000000000000000000000002.saml.xml',
                            decodedSamlBytes=len(raw), samlSummary=dict(type=reply_kind,
                                                                      inResponseTo=root.get('ID')))
            rows.append(response); bodies[response['id']] = raw
            http['responseSamlSha256'] = hashlib.sha256(raw).hexdigest()
        return rows, bodies, http

    def call(self, rows, bodies, http, fixture='sha256-control'):
        return correlate_exchange(rows, set(), RUN, fixture, ACTION, http, lambda e: bodies[e['id']])

    def test_all_six_outbox_shapes_use_raw_id_not_missing_summary_id(self):
        for fixture in ['sha256-control', 'invalid-sha256-signature', 'md5-digest', 'rsa-md5',
                        'rsa15-encrypted-id', 'oaep-encrypted-id-control']:
            with self.subTest(fixture=fixture):
                rows, bodies, http = self.sample(fixture)
                request, response = self.call(rows, bodies, http, fixture)
                self.assertEqual(rows[0], request); self.assertEqual(rows[1], response)

    def test_native_http_rejection_has_no_saml_reply(self):
        rows, bodies, http = self.sample('md5-digest', success=False)
        self.assertIsNone(self.call(rows, bodies, http, 'md5-digest')[1])

    def test_cross_run_or_original_path_cannot_supply_request(self):
        for field, value in [('runId', 'run_00000000000000000000000003'),
                             ('decodedSamlRef', 'transcripts/other/entry.saml.xml')]:
            rows, bodies, http = self.sample(); rows[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.call(rows, bodies, http)

    def test_actual_transport_hash_and_original_length_are_required(self):
        for mutation in ['hash', 'length']:
            rows, bodies, http = self.sample()
            if mutation == 'hash': http['requestSha256'] = '0' * 64
            else: rows[0]['decodedSamlBytes'] += 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.call(rows, bodies, http)

    def test_action_fixture_and_raw_request_identity_must_agree(self):
        for mutation in ['action', 'fixture', 'id']:
            rows, bodies, http = self.sample()
            if mutation == 'action': rows[0]['correlationId'] = 'action_other'
            elif mutation == 'fixture': rows[0]['samlSummary']['fixture_id'] = 'rsa-md5'
            else: http['requestId'] = '_foreign'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.call(rows, bodies, http)

    def test_summary_cannot_replace_raw_response_correlation(self):
        rows, bodies, http = self.sample()
        changed = ET.fromstring(bodies[rows[1]['id']]); changed.set('InResponseTo', '_foreign')
        raw = ET.tostring(changed); bodies[rows[1]['id']] = raw
        rows[1]['decodedSamlBytes'] = len(raw); http['responseSamlSha256'] = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(ValueError): self.call(rows, bodies, http)

    def test_duplicate_reply_or_missing_recording_is_not_complete(self):
        rows, bodies, http = self.sample(); rows.append(copy.deepcopy(rows[1]))
        with self.assertRaises(ValueError): self.call(rows, bodies, http)
        rows, bodies, http = self.sample(); rows.pop()
        with self.assertRaises(ValueError): self.call(rows, bodies, http)


if __name__ == '__main__': unittest.main()
