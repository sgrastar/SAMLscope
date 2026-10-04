"""Public audit-envelope time serialization controls; no product or Docker operations."""
import copy,importlib.util,json,pathlib,tempfile,unittest
from unittest.mock import patch
SOURCE=pathlib.Path(__file__).with_name('keycloak_registered_signer_stored_outcome.py')
spec=importlib.util.spec_from_file_location('signer_stored_outcome',SOURCE)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
ISO='2026-10-02T08:32:00.393457416Z';NUMBER=1.7909299203934574E9

class TimestampSerializationTest(unittest.TestCase):
    def test_original_double_projection_is_exact_without_rewriting_original(self):
        original={'updatedAt':NUMBER};snapshot=copy.deepcopy(original)
        self.assertTrue(module._same_stored_update_timestamp(original,ISO))
        self.assertEqual(original,snapshot)
    def test_different_instant_and_wrong_numeric_precision_fail(self):
        self.assertFalse(module._same_stored_update_timestamp({'updatedAt':NUMBER},'2026-10-02T08:32:00.393458416Z'))
        self.assertFalse(module._same_stored_update_timestamp({'updatedAt':round(NUMBER,3)},ISO))
        self.assertFalse(module._same_stored_update_timestamp({'updatedAt':1790929920393},ISO))
    def test_new_iso_capture_preserves_even_a_one_nanosecond_difference(self):
        row={'updatedAt':NUMBER,'updatedAtIso':ISO}
        self.assertTrue(module._same_stored_update_timestamp(row,ISO))
        self.assertFalse(module._same_stored_update_timestamp(row,'2026-10-02T08:32:00.393457417Z'))
    def test_integer_timestamp_is_not_allowed_to_drop_fractional_seconds(self):
        self.assertTrue(module._same_stored_update_timestamp({'updatedAt':1790929920},'2026-10-02T08:32:00Z'))
        self.assertFalse(module._same_stored_update_timestamp({'updatedAt':1790929920},'2026-10-02T08:32:00.000000001Z'))
    def test_iso_and_invalid_types_are_distinct(self):
        self.assertTrue(module._same_stored_update_timestamp({'updatedAt':ISO},ISO))
        for value in [True,None,float('nan'),float('inf'),{'epoch':NUMBER}]:
            self.assertFalse(module._same_stored_update_timestamp({'updatedAt':value},ISO))
        for instant in [None,'2026-10-02','2026-10-02T08:32:00.3934574160Z','2026-10-02T99:32:00Z']:
            self.assertFalse(module._same_stored_update_timestamp({'updatedAt':NUMBER},instant))

class AuditEnvelopeTest(unittest.TestCase):
    def setUp(self):
        self.old={'outcome':'NOT_VERIFIED','notVerifiedReason':'native-proof-pending','reasonCode':'case.pending-interaction','reasonMessageKey':'case.pending-interaction','evidence':[],'details':{'scope':'original'}}
        self.proof={'outcome':'SATISFIED','notVerifiedReason':None,'reasonCode':'signature.signer.issuer-key-restriction-observed','reasonMessageKey':'signature.signer.issuer-key-restriction-observed','evidence':[{'kind':'transcript','reference':'tx_original'}],'details':{'native_originals_verified':True}}
        previous={'revision':4,'updated_at':ISO,'outcome':self.old['outcome'],'not_verified_reason':self.old['notVerifiedReason'],'reason_code':self.old['reasonCode'],'reason_message_key':self.old['reasonMessageKey'],'evidence':self.old['evidence'],'details':self.old['details']}
        self.before={'status':'FINISHED','revision':4,'updatedAt':NUMBER,'outboxCount':3,'outcome':copy.deepcopy(self.old)}
        self.after={'status':'FINISHED','revision':5,'updatedAt':NUMBER+1,'outboxCount':3,'outcome':copy.deepcopy(self.proof)}
        self.after['outcome']['details']['previous_recorded_evidence_result']=previous
    def compare(self):
        with tempfile.TemporaryDirectory() as name:
            folder=pathlib.Path(name);(folder/'created.json').write_text(json.dumps({'run':{'id':'run_00000000000000000000000000'}}))
            with patch.object(module,'verify',side_effect=[self.before,self.after]):
                return module.compare_stored(folder,'runtime','IIP-SSO01-al-idp-01',self.proof)
    def test_exact_whole_previous_outcome_is_still_required(self):
        self.assertEqual(self.compare(),self.after)
        self.after['outcome']['details']['previous_recorded_evidence_result']['details']={'scope':'different'}
        with self.assertRaisesRegex(ValueError,'Prior outcome audit envelope changed'):self.compare()
    def test_revision_and_instant_mismatch_are_rejected(self):
        previous=self.after['outcome']['details']['previous_recorded_evidence_result'];previous['revision']=3
        with self.assertRaisesRegex(ValueError,'Invalid previous-result audit envelope'):self.compare()
        previous['revision']=4;previous['updated_at']='2026-10-02T08:32:00.394457416Z'
        with self.assertRaisesRegex(ValueError,'Invalid previous-result audit envelope'):self.compare()
    def test_missing_envelope_field_or_manufactured_action_is_rejected(self):
        self.after['outcome']['details']['previous_recorded_evidence_result'].pop('evidence')
        with self.assertRaisesRegex(ValueError,'Invalid previous-result audit envelope'):self.compare()
        self.after['outboxCount']=4
        with self.assertRaisesRegex(ValueError,'manufactured a browser action'):self.compare()
    def test_native_replacement_cannot_drop_history_or_skip_revisions(self):
        self.after['outcome']['details'].pop('previous_recorded_evidence_result')
        with self.assertRaisesRegex(ValueError,'Missing prior-result audit'):self.compare()
        self.setUp();self.after['revision']=6
        with self.assertRaisesRegex(ValueError,'Missing prior-result audit'):self.compare()
    def test_first_conclusion_has_one_revision_and_no_fictional_previous_outcome(self):
        self.before['outcome']=None;self.after['outcome']['details'].pop('previous_recorded_evidence_result')
        self.assertEqual(self.compare(),self.after)
        self.after['outcome']['details']['previous_recorded_evidence_result']=None
        with self.assertRaisesRegex(ValueError,'Unexpected audit history'):self.compare()
    def test_preexisting_conclusive_result_is_unchanged(self):
        self.before=copy.deepcopy(self.after)
        self.assertEqual(self.compare(),self.after)
        self.after['revision']+=1
        with self.assertRaisesRegex(ValueError,'Existing conclusive result changed'):self.compare()

if __name__=='__main__':unittest.main()
