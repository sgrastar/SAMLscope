"""Operation journal regressions; no network, target state, or credentials."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

PATH = Path(__file__).with_name('verify_simplesamlphp_multiple_decryption_keys_source_run_acceptance.py')
SPEC = importlib.util.spec_from_file_location('native_source_adoption_test', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Response:
    status = 200
    def __init__(self, raw=b'{"ok":true}'):
        self.raw = raw
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self):
        return self.raw


class NativeSourceJournalTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        MODULE._OPERATION_DIRECTORY = Path(self.temporary.name)
        MODULE._OPERATIONS = []
    def tearDown(self):
        MODULE._OPERATION_DIRECTORY = None
        MODULE._OPERATIONS = []
        self.temporary.cleanup()
    def row(self):
        rows = json.loads((Path(self.temporary.name) / 'operations.json').read_bytes())
        self.assertEqual(len(rows), 1)
        return rows[0]
    def test_get_records_actual_get_status_and_response_without_request_body(self):
        with patch.object(MODULE.urllib.request, 'urlopen', return_value=Response()):
            self.assertEqual(MODULE.api('/read'), {'ok': True})
        row = self.row()
        self.assertEqual(row['command'][0], 'GET')
        self.assertEqual(row['httpStatus'], 200)
        self.assertEqual(row['requestBytes'], 0)
        self.assertEqual(row['stdoutSha256'], hashlib.sha256(b'{"ok":true}').hexdigest())
    def test_post_records_exact_body_and_post(self):
        with patch.object(MODULE.urllib.request, 'urlopen', return_value=Response()) as opened:
            MODULE.api('/evaluate', {})
        self.assertEqual(opened.call_args.args[0].data, b'{}')
        row = self.row()
        self.assertEqual(row['command'][0], 'POST')
        self.assertEqual(row['requestSha256'], hashlib.sha256(b'{}').hexdigest())
        self.assertEqual(row['requestBytes'], 2)
    def test_http_failure_is_one_actual_get_attempt_with_status_and_body(self):
        error = urllib.error.HTTPError('http://localhost:18080/read', 503, 'unavailable', {}, io.BytesIO(b'failure'))
        with patch.object(MODULE.urllib.request, 'urlopen', side_effect=error):
            with self.assertRaises(urllib.error.HTTPError):
                MODULE.api('/read')
        row = self.row()
        self.assertEqual(row['command'][0], 'GET')
        self.assertEqual(row['httpStatus'], 503)
        self.assertEqual(row['stdoutSha256'], hashlib.sha256(b'failure').hexdigest())
    def test_unknown_delivery_is_not_success_or_a_second_http_attempt(self):
        with patch.object(MODULE.urllib.request, 'urlopen', side_effect=urllib.error.URLError('timeout')):
            with self.assertRaises(urllib.error.URLError):
                MODULE.api('/evaluate', {})
        row = self.row()
        self.assertEqual(row['command'][0], 'POST')
        self.assertIsNone(row['httpStatus'])
        self.assertIsNone(row['exitCode'])
    def test_invalid_json_does_not_count_another_network_attempt(self):
        with patch.object(MODULE.urllib.request, 'urlopen', return_value=Response(b'invalid-json')):
            with self.assertRaises(json.JSONDecodeError):
                MODULE.api('/read')
        self.assertEqual(self.row()['httpStatus'], 200)


class FirstOutcomeTransitionContractTest(unittest.TestCase):
    def fixture(self):
        case=MODULE.CASE
        outcome={'outcome':'SATISFIED','reasonCode':'configuration.multiple-decryption-keys.source-run-native-proven','details':{},'evidence':[]}
        report={'fullProductionReaderPositive':outcome,'productionWrapperVerified':True,'allControlsRejected':True,
                'controls':{str(i):'NOT_VERIFIED' for i in range(48)},'sourceContextTranscriptComplete':False,
                'sourceCaseExecutionCreated':False,'targetOperations':0}
        old={'caseId':case,'runId':'recipient','status':'WAITING_CONFIG','revision':0,'state':{'phase':'await-configuration','data':{'instruction_key':'approved'}},'waitCondition':{'kind':'CONFIG'},'outcome':None}
        before={'fence':{'source':'unchanged'},'sourceExecutions':{},'executions':{case:'old','a':'unchanged','c':'original-failure'},
                'caseExecution':old,'caseStateSha256':'state-hash','caseWaitSha256':'config-wait','caseDocumentSha256':'old','recipientRunId':'recipient','verdict':None}
        after=json.loads(json.dumps(before))
        after['caseExecution'].update(status='FINISHED',revision=1,waitCondition=None,outcome=outcome)
        after.update(verdict='PASS',caseWaitSha256='no-wait',caseDocumentSha256='new')
        after['executions'][case]='new'
        transition=dict(after,stateAuditEqualsOutcomeAudit=False,stateWithoutPriorAuditSha256='state-hash',priorResultAudit=None,transitionKind='configuration-first-outcome')
        return report,before,after,transition
    def invoke(self,report,before,after,transition):
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary)
            for name,value in [('state-before.json',before),('state-final.json',after),('state-transition.json',transition)]:
                (folder/name).write_text(json.dumps(value))
            return MODULE.transition_ok(folder,report)
    def test_first_native_outcome_keeps_real_state_clears_wait_and_does_not_invent_prior_audit(self):
        report,before,after,transition=self.fixture()
        self.assertEqual(self.invoke(report,before,after,transition),after)
    def test_first_outcome_rejects_state_wait_revision_audit_source_and_other_case_changes(self):
        mutations={
            'state':lambda a:a['caseExecution']['state'].update(phase='invented-finish'),
            'wait':lambda a:a['caseExecution'].update(waitCondition={'kind':'CONFIG'}),
            'revision':lambda a:a['caseExecution'].update(revision=2),
            'prior-audit':lambda a:a['caseExecution']['outcome']['details'].update(previous_recorded_evidence_result={}),
            'source-execution':lambda a:a['sourceExecutions'].update(fake='inserted'),
            'other-c':lambda a:a['executions'].update(c='suppressed-failure'),
            'source-fence':lambda a:a['fence'].update(source='changed'),
        }
        for name,mutate in mutations.items():
            with self.subTest(name=name):
                report,before,after,transition=self.fixture()
                mutate(after)
                transition={**after,'stateAuditEqualsOutcomeAudit':False,'stateWithoutPriorAuditSha256':'state-hash','priorResultAudit':None,'transitionKind':'configuration-first-outcome'}
                with self.assertRaises(ValueError):self.invoke(report,before,after,transition)
    def test_first_outcome_rejects_foreign_transition_snapshot_and_wrong_original_wait(self):
        report,before,after,transition=self.fixture();transition['recipientRunId']='foreign'
        with self.assertRaises(ValueError):self.invoke(report,before,after,transition)
        report,before,after,transition=self.fixture();before['caseExecution']['waitCondition']['kind']='ATTESTATION'
        with self.assertRaises(ValueError):self.invoke(report,before,after,transition)


if __name__ == '__main__':
    unittest.main()
