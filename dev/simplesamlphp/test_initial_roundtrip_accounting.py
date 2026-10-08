import copy
import unittest
from initial_roundtrip_accounting import difference


def snapshot():
    return {'schema': 'samlscope-run-protocol-operations-v1',
            'runId': 'run_' + '0'*26, 'planId': 'plan_' + '1'*26,
            'runStatus': 'RUNNING', 'transcriptEntries': [], 'outboxActions': [], 'caseExecutions': []}

def entry(identifier, direction, kind):
    return {'id': identifier, 'entrySha256': 'a'*64, 'direction': direction, 'type': kind}

def action(status='PENDING'):
    return {'actionId': 'act-example', 'actionSha256': 'b'*64, 'status': status}


class AccountingTest(unittest.TestCase):
    def test_actual_profile_start_work_is_counted(self):
        before = snapshot(); after = copy.deepcopy(before)
        after['transcriptEntries'] = [entry('tx-normal', 'OUTBOUND', 'AuthnRequest'),
                                      entry('tx-response', 'INBOUND', 'Response')]
        after['outboxActions'] = [action('SENT')]
        after['caseExecutions'] = [{'caseId': 'case-example', 'documentSha256': 'c'*64}]
        result = difference(before, after)
        self.assertEqual(result['outboundProtocolMessagesRecorded'], 1)
        self.assertEqual(result['outboxActionsCreated'], 1)
        self.assertEqual(result['caseExecutionsCreated'], 1)
        self.assertIsNone(result['networkAttemptCount'])

    def test_metadata_is_not_reported_as_saml_protocol(self):
        before = snapshot(); after = copy.deepcopy(before)
        after['transcriptEntries'] = [entry('tx-metadata', 'OUTBOUND', 'MetadataPrepared')]
        self.assertEqual(difference(before, after)['outboundProtocolMessagesRecorded'], 0)

    def test_unknown_delivery_cannot_be_claimed_zero_attempts(self):
        before = snapshot(); before['outboxActions'] = [action('PENDING')]
        after = copy.deepcopy(before); after['outboxActions'][0]['status'] = 'UNKNOWN_DELIVERY'
        result = difference(before, after)
        self.assertEqual(result['outboxActionsCreated'], 0)
        self.assertEqual(result['outboxDeliveryStatesAfter']['UNKNOWN_DELIVERY'], 1)
        self.assertIsNone(result['networkAttemptCount'])

    def test_response_issued_by_suite_is_also_a_message(self):
        before = snapshot(); after = copy.deepcopy(before)
        after['transcriptEntries'] = [entry('tx-logout', 'OUTBOUND', 'LogoutResponse')]
        self.assertEqual(difference(before, after)['outboundProtocolMessagesRecorded'], 1)

    def test_foreign_run_or_plan_is_rejected(self):
        for key in ['runId', 'planId']:
            before = snapshot(); after = copy.deepcopy(before)
            after[key] = after[key].replace('0' if key == 'runId' else '1', '2')
            with self.assertRaises(ValueError): difference(before, after)

    def test_removed_or_modified_original_is_rejected(self):
        before = snapshot(); before['transcriptEntries'] = [entry('tx-one', 'OUTBOUND', 'AuthnRequest')]
        for replacement in [[], [dict(before['transcriptEntries'][0], entrySha256='d'*64)]]:
            after = copy.deepcopy(before); after['transcriptEntries'] = replacement
            with self.assertRaises(ValueError): difference(before, after)

    def test_changed_existing_action_is_rejected(self):
        before = snapshot(); before['outboxActions'] = [action()]
        after = copy.deepcopy(before); after['outboxActions'][0]['actionSha256'] = 'd'*64
        with self.assertRaises(ValueError): difference(before, after)

    def test_unknown_status_and_duplicate_entries_are_rejected(self):
        before = snapshot()
        for changes in [{'outboxActions': [action('UNRECOGNIZED')]},
                        {'transcriptEntries': [entry('tx-one', 'OUTBOUND', 'AuthnRequest')]*2}]:
            after = dict(snapshot(), **changes)
            with self.assertRaises(ValueError): difference(before, after)


if __name__ == '__main__': unittest.main()
