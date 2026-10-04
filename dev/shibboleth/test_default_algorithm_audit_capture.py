import hashlib,unittest
from default_algorithm_audit_capture import capture

class AuditCaptureTest(unittest.TestCase):
    def setUp(self):
        self.run='run_KEQD39X2JY336WS5DV520WF09E';self.request='_action_sample';self.sha='a'*64
        self.before=dict(inode=7,size=100,capturedAt='2026-10-03T15:51:11Z')
    def call(self,fixture,delta,before=None,after=None):
        return capture(self.run,self.request,self.sha,fixture,before or self.before,
            after or dict(inode=7,size=100+len(delta),capturedAt='2026-10-03T15:51:12Z'),delta)
    def test_real_empty_rsa_md5_capture_does_not_claim_a_decision(self):
        data,line=self.call('rsa-md5',b'');self.assertIsNone(line)
        self.assertFalse(data['decisionEvidence']);self.assertEqual(data['deltaSha256'],hashlib.sha256(b'').hexdigest())
        self.assertEqual(data['beforeOffset'],data['afterOffset'])
    def test_other_fixtures_still_require_exact_request_audit(self):
        for fixture in ['sha256-control','invalid-sha256-signature','md5-digest','rsa15-encrypted-id','oaep-encrypted-id-control']:
            with self.subTest(fixture=fixture),self.assertRaises(ValueError):self.call(fixture,b'')
        delta=b'SAMLscope-default-algorithm-v1|_action_sample|peer|event\n'
        data,line=self.call('md5-digest',delta);self.assertEqual(line,delta);self.assertEqual(data['matchingAuditCount'],1)
    def test_rotation_incomplete_range_duplicate_or_foreign_request_fails_closed(self):
        delta=b'SAMLscope-default-algorithm-v1|_action_sample|peer|event\n'
        for original in [delta+delta,delta.replace(b'_action_sample',b'_another'),b'Other-format|_action_sample\n']:
            with self.assertRaises(ValueError):self.call('rsa-md5',original)
        for after in [dict(inode=8,size=100,capturedAt='x'),dict(inode=7,size=101,capturedAt='x')]:
            with self.assertRaises(ValueError):self.call('rsa-md5',b'',after=after)
    def test_private_content_and_unsafe_identity_are_never_exported(self):
        with self.assertRaises(ValueError):self.call('rsa-md5',b'Cookie: private\n')
        with self.assertRaises(ValueError):capture('../run',self.request,self.sha,'rsa-md5',self.before,self.before,b'')

if __name__=='__main__':unittest.main()
