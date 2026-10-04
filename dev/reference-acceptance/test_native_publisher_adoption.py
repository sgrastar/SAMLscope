"""Host-only regressions for strict history and portable publisher adoption."""
import copy, importlib.util, json, pathlib, tempfile, unittest
from unittest.mock import patch

BASE=pathlib.Path(__file__).resolve().parent
def module(name):
    spec=importlib.util.spec_from_file_location(name,BASE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
stored=module('native_publisher_stored_outcome')
adopter=module('verify_native_publisher_key_inventory_acceptance')

class StoredHistoryTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.folder=pathlib.Path(self.temp.name)
        (self.folder/'created.json').write_text(json.dumps({'run':{'id':'run_test'}}))
        old=dict(outcome='NOT_VERIFIED',notVerifiedReason='missing',reasonCode='case.pending-interaction',reasonMessageKey=None,evidence=[],details={})
        self.before=dict(status='FINISHED',outboxCount=0,revision=3,updatedAt=1790000000.1234567,updatedAtIso='2026-09-21T14:13:20.123456789Z',outcome=old)
        # Use one exact ISO/numeric projection rather than a tolerance window.
        self.before['updatedAt']=float(stored._instant_seconds(self.before['updatedAtIso']))
        self.proof=dict(outcome='SATISFIED',notVerifiedReason=None,reasonCode='metadata.publisher.role-description-complete',reasonMessageKey=None,evidence=[dict(kind='transcript',reference='tx_new')],details={'case_id':adopter.C1})
        previous=dict(revision=3,updated_at=self.before['updatedAtIso'],outcome=old['outcome'],not_verified_reason=old['notVerifiedReason'],reason_code=old['reasonCode'],reason_message_key=old['reasonMessageKey'],evidence=old['evidence'],details=old['details'])
        outcome=copy.deepcopy(self.proof);outcome['details']['previous_recorded_evidence_result']=previous
        self.after=dict(status='FINISHED',outboxCount=0,revision=4,updatedAt=1790000001,updatedAtIso='2026-09-21T14:13:21Z',outcome=outcome)
    def tearDown(self):self.temp.cleanup()
    def compare(self):
        with patch.object(stored,'verify',side_effect=[self.before,self.after]):return stored.compare_stored(self.folder,'runtime',adopter.C1,self.proof)
    def test_exact_old_nv_envelope_is_preserved(self):self.assertEqual(self.compare(),self.after)
    def test_missing_previous_envelope_is_rejected(self):
        del self.after['outcome']['details']['previous_recorded_evidence_result']
        with self.assertRaises(ValueError):self.compare()
    def test_revision_and_outbox_may_not_be_invented(self):
        self.after['revision']=5
        with self.assertRaises(ValueError):self.compare()
        self.after['revision']=4;self.after['outboxCount']=1
        with self.assertRaises(ValueError):self.compare()
    def test_one_nanosecond_difference_and_old_details_change_rejected(self):
        p=self.after['outcome']['details']['previous_recorded_evidence_result'];p['updated_at']='2026-09-21T14:13:20.123456788Z'
        with self.assertRaises(ValueError):self.compare()
        p['updated_at']=self.before['updatedAtIso'];p['details']={'invented':True}
        with self.assertRaises(ValueError):self.compare()
    def test_conclusive_results_remain_byte_equivalent(self):
        self.before['outcome']=copy.deepcopy(self.proof);self.after=copy.deepcopy(self.before)
        self.assertEqual(self.compare(),self.after)
        self.after['revision']+=1
        with self.assertRaises(ValueError):self.compare()

class PortableArchiveTest(unittest.TestCase):
    def test_saved_dependency_order_and_hash_are_authoritative(self):
        with tempfile.TemporaryDirectory() as name:
            runtime=pathlib.Path(name);dep=runtime/'dependencies';dep.mkdir();a=dep/'a.jar';b=dep/'b.jar';a.write_bytes(b'a');b.write_bytes(b'b')
            inventory=dict(mutableProjectEntriesExcluded=True,entries=[dict(file='dependencies/b.jar',sha256=adopter.sha(b'b')),dict(file='dependencies/a.jar',sha256=adopter.sha(b'a'))])
            (runtime/'dependency-priority.json').write_text(json.dumps(inventory))
            cp=adopter.archived_classpath(runtime)
            self.assertTrue(cp.endswith(str(b.resolve())+':'+str(a.resolve())))
            b.write_bytes(b'changed')
            with self.assertRaises(ValueError):adopter.archived_classpath(runtime)
    def test_external_mutable_dependency_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            runtime=pathlib.Path(name);p=runtime/'external.jar';p.write_bytes(b'public')
            (runtime/'dependency-priority.json').write_text(json.dumps(dict(mutableProjectEntriesExcluded=True,entries=[dict(file='external.jar',sha256=adopter.sha(b'public'))])))
            with self.assertRaises(ValueError):adopter.archived_classpath(runtime)

if __name__=='__main__':unittest.main()
