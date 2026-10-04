"""No-network accounting controls; issued Suite pages are not native submissions."""
import copy
import unittest
from verify_version_mismatch_acceptance import account_native_requests,SHA


class VersionAccountingTests(unittest.TestCase):
    def setUp(self):
        self.run='run_0123456789ABCDEFGHJKMNPQRS';self.entries=[];self.raw={};self.native=[]
        for index,(method,case) in enumerate((('GET','M0'),('POST','IIP-SSO01-ep-idp-01'),('POST','IIP-unselected-a-idp-01'))):
            action='action_'+str(index);identity='_request_'+str(index);ref='tx_'+str(index)
            self.raw[ref]=('<AuthnRequest ID="'+identity+'"/>').encode()
            url='http://localhost:18380/sso'+('?SAMLRequest=exact%2Bbytes&Signature=untouched%2Bsignature' if method=='GET' else '')
            self.entries.append(dict(id=ref,runId=self.run,direction='OUTBOUND',method=method,url=url,correlationId=action,
                samlSummary=dict(type='AuthnRequest',action_id=action,scenario_case_id=case)))
            if index<2:
                row=dict(method=method,requestId=identity,requestUrl='http://localhost:18380/sso',requestSha256=SHA(self.raw[ref]))
                if method=='GET':row['rawQuerySha256']=SHA(url.split('?',1)[1].encode())
                self.native.append(row)
        self.skips=[dict(actionId='action_2',caseId='IIP-unselected-a-idp-01',prepared=True,sentToTarget=False,action='prepared-and-skipped-before-target-submission')]

    def test_all_issued_originals_partition_without_counting_unsubmitted_suite_page(self):
        self.assertEqual(dict(nativeProtocolSubmissions=2,suiteOnlyPreparedAndAborted=1,allIssuedRequestOriginals=3),account_native_requests(self.entries,self.raw,self.native,self.skips))

    def test_duplicate_native_or_skip_cannot_hide_repeated_actions(self):
        for native,skips in ((self.native+self.native[:1],self.skips),(self.native,self.skips*2)):
            with self.assertRaises(ValueError):account_native_requests(self.entries,self.raw,native,skips)

    def test_missing_or_unknown_submission_is_not_assumed_unsent(self):
        for native,skips in ((self.native[:-1],self.skips),(self.native,[])):
            with self.assertRaises(ValueError):account_native_requests(self.entries,self.raw,native,skips)

    def test_foreign_run_request_and_skip_case_do_not_bind(self):
        entries=copy.deepcopy(self.entries);entries[0]['runId']='run_11111111111111111111111111'
        with self.assertRaises(ValueError):account_native_requests(entries,self.raw,self.native,self.skips)
        native=copy.deepcopy(self.native);native[1]['requestId']='_foreign'
        with self.assertRaises(ValueError):account_native_requests(self.entries,self.raw,native,self.skips)
        skips=copy.deepcopy(self.skips);skips[0]['caseId']='IIP-foreign-a-idp-01'
        with self.assertRaises(ValueError):account_native_requests(self.entries,self.raw,self.native,skips)

    def test_skipped_but_actually_sent_is_rejected(self):
        native=self.native+[dict(method='POST',requestId='_request_2',requestUrl='http://localhost:18380/sso',requestSha256=SHA(self.raw['tx_2']))]
        with self.assertRaises(ValueError):account_native_requests(self.entries,self.raw,native,self.skips)

    def test_redirect_raw_query_and_actual_post_endpoint_remain_bound(self):
        for index,key,value in ((0,'rawQuerySha256',SHA(b'SAMLRequest=decoded-and-reserialized')),(1,'requestUrl','http://localhost:18380/other')):
            native=copy.deepcopy(self.native);native[index][key]=value
            with self.assertRaises(ValueError):account_native_requests(self.entries,self.raw,native,self.skips)


if __name__=='__main__':unittest.main()
