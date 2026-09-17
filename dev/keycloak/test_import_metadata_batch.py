import unittest
from unittest.mock import patch
from import_metadata_batch import recorded_exchange


class RecordedExchangeTest(unittest.TestCase):
    def exchange(self, responses):
        entries=[dict(id='issued',direction='OUTBOUND',samlSummary=dict(type='AuthnRequest',variant='control',id='request'))]
        entries += [dict(id='response-'+str(i),direction='INBOUND',samlSummary=dict(
            metadataProbeAccepted=True,inResponseTo=request,statusCode=status)) for i,(request,status) in enumerate(responses)]
        with patch('import_metadata_batch.api',return_value=entries):
            return recorded_exchange('run','control',set())

    def test_correlated_error_is_not_success(self):
        self.assertFalse(self.exchange([('request','urn:oasis:names:tc:SAML:2.0:status:Requester')])['success'])

    def test_wrong_request_and_conflicting_responses_are_not_success(self):
        success='urn:oasis:names:tc:SAML:2.0:status:Success'
        self.assertFalse(self.exchange([('other',success)])['success'])
        self.assertFalse(self.exchange([('request',success),('request','unknown')])['success'])

    def test_success_requires_issued_request_and_matching_response(self):
        result=self.exchange([('request','urn:oasis:names:tc:SAML:2.0:status:Success')])
        self.assertTrue(result['success'])
        self.assertEqual(['issued','response-0'],result['transcript_ids'])


if __name__=='__main__':unittest.main()
