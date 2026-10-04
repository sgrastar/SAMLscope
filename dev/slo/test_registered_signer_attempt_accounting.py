import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'reference-acceptance'))
import slo_registered_signer_attempt_accounting as accounting


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve()
        for number in (1,2,3,4,5,6):
            p=self.root/('simplesamlphp-slo-registered-signer-r'+str(number));p.mkdir()
            values=dict(protocolSubmissions=(0,1,2,4,4,4)[number-1],outboxProtocolSubmissions=3 if number>=4 else 0,
                        credentialPosts=0 if number==1 else 1,credentialPostAttempts=0 if number==1 else 1,
                        nativeConfigurationWrites=4 if number>=3 else 2,restorationWrites=2 if number>=3 else 1,restored=True)
            (p/'operation-counts.json').write_text(json.dumps(values))
            (p/'native-restoration.json').write_text(json.dumps(dict(restored=True,original_sha256='a'*64,final_sha256='a'*64)))
            (p/'created.json').write_text(json.dumps(dict(run=dict(id='run_'+str(number)*26))))
            if number<6:(p/'failure.json').write_text(json.dumps(dict(productVerdictAdopted=False,reason='ValueError: Authentication/confirmation form refused before public recording' if number==3 else 'preparation-unproven')))
            else:(p/'receipt').mkdir();(p/'receipt/operation-counts.json').write_text(json.dumps(values))
            if number>=2:(p/'baseline.json').write_text(json.dumps(dict(requestReference='tx_'+'1'*26,responseReference='tx_'+'2'*26)))
            if number==3:(p/'common-collector-source.py').write_text('outboxProtocolSubmissions=sum(1 for r in client.records)\nsafe_body(body)\n')
        self.folder=self.root/'simplesamlphp-slo-registered-signer-r6'
    def tearDown(self):self.tmp.cleanup()

    def test_failed_writes_are_included_and_original_hash_changes_are_detected(self):
        accounting.record(self.folder,'simplesamlphp');row=accounting.verify(self.folder,'simplesamlphp')
        self.assertEqual(row['cumulative']['nativeConfigurationWrites'],20)
        self.assertEqual(row['derivedNativeSloAttempts'],10);self.assertEqual(row['attempts'][2]['historicalCompletedHttpRecords'],0)
        self.assertEqual(row['failed']['credentialPosts'],4);self.assertEqual(row['qualified']['protocolSubmissions'],4)
        path=self.root/'simplesamlphp-slo-registered-signer-r1/failure.json'
        path.write_text(json.dumps(dict(productVerdictAdopted=False,extra='changed original')))
        with self.assertRaisesRegex(ValueError,'original hashes changed'):accounting.verify(self.folder,'simplesamlphp')

    def test_operated_failed_attempt_without_restore_or_negative_cost_is_refused(self):
        p=self.root/'simplesamlphp-slo-registered-signer-r1/native-restoration.json';p.unlink()
        with self.assertRaisesRegex(ValueError,'absent accounting original'):accounting.summary(self.folder,'simplesamlphp')
        with self.assertRaisesRegex(ValueError,'Invalid actual operation count'):accounting.costs(dict(protocolSubmissions=-1))
        with self.assertRaisesRegex(ValueError,'Invalid actual operation count'):accounting.costs(dict(protocolSubmissions=True))

    def test_shibboleth_failed_batch_and_independent_restoration_reads_remain_separate(self):
        original={'/opt/reference-idp/conf/audit.xml':'a'*64,'/opt/reference-idp/conf/metadata-providers.xml':'b'*64}
        for number in (1,2):
            p=self.root/('shibboleth-slo-registered-signer-r'+str(number));p.mkdir()
            counts=dict(protocolSubmissions=4,outboxProtocolSubmissions=3,credentialPosts=1,credentialPostAttempts=1,
                        nativeConfigurationWrites=6,restorationWrites=2,metadataReloads=0,nativeLogoutCompletionGets=number-1,restored=True)
            (p/'operation-counts.json').write_text(json.dumps(counts));(p/'created.json').write_text(json.dumps(dict(run=dict(id='run_'+str(number)*26))))
            (p/'native-restoration.json').write_text(json.dumps(dict(restored=True,original=original,final=original,temporarySourcesAbsent=True)))
            if number==1:
                (p/'failure.json').write_text(json.dumps(dict(productVerdictAdopted=False)))
                check=dict(exactRestored=True,nativeReadbacks=2,checks=[dict(path=path,expectedSha256=digest,nativeSha256=digest) for path,digest in original.items()],settingWrites=0,samlSubmissions=0,credentialPosts=0,personOperations=0)
                (p/'root-restoration-check.json').write_text(json.dumps(check))
            else:
                (p/'receipt').mkdir();(p/'receipt/operation-counts.json').write_text(json.dumps(counts))
                (p/'native-logout-completion-attempts.json').write_text(json.dumps([dict(method='GET',executionValueExported=False)]))
        folder=self.root/'shibboleth-slo-registered-signer-r2';accounting.record(folder,'shibboleth');row=accounting.verify(folder,'shibboleth')
        self.assertEqual(row['cumulative']['protocolSubmissions'],8);self.assertEqual(row['cumulative']['credentialPosts'],2)
        self.assertEqual(row['cumulative']['nativeConfigurationWrites'],12);self.assertEqual(row['independentRestorationReadbacks'],2)
        self.assertEqual(row['nativeLogoutCompletionGets'],1)
        changed=self.root/'shibboleth-slo-registered-signer-r1/root-restoration-check.json';check=json.loads(changed.read_bytes());check['checks'][0]['nativeSha256']='c'*64;changed.write_text(json.dumps(check))
        with self.assertRaisesRegex(ValueError,'Independent Shibboleth restoration'):accounting.verify(folder,'shibboleth')


if __name__=='__main__':unittest.main()
