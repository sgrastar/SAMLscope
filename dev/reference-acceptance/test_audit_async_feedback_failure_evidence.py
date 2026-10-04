"""Focused qualification controls; never modify the immutable acceptance originals."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import audit_async_feedback_failure_evidence as audit
import audit_unresolved_contracts


class AsyncFeedbackWithdrawalTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='async-feedback-audit-')
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name).resolve()
        self.root = self.parent / 'reference-20260914'
        self.root.mkdir()
        originals = audit.REPO / 'build/acceptance'
        self.audit_folder = self.parent / audit.AUDIT
        self.audit_folder.mkdir(parents=True)
        for name in ['review.json', 'request-bound-facts.json',
                     'keycloak-transcript.json', 'shibboleth-transcript.json',
                     *[x + '.xml' for pin in audit.PINS.values() for x in pin['requests']]]:
            (self.audit_folder / name).write_bytes((originals / audit.AUDIT / name).read_bytes())
        for product in audit.PINS:
            relative = Path('reference-20260915/slo-oracle') / product / 'slo_probe_browser'
            folder = self.parent / relative
            folder.mkdir(parents=True)
            for name in ['result.json', 'exchange-log.json']:
                (folder / name).write_bytes((originals / relative / name).read_bytes())

    def replace_json(self, path, modify):
        value = json.loads(path.read_bytes())
        modify(value)
        path.write_text(json.dumps(value))
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_pinned_native_audit_withdraws_only_exact_two_legacy_passes(self):
        rows = audit.withdrawals(self.root)
        self.assertEqual([(r['product'], r['profile'], r['case'], r['verdict']) for r in rows],
            [(p, 'single_logout_idp', audit.CASE, 'NOT_VERIFIED') for p in audit.PINS])
        self.assertTrue(all(r['reason_code'] == audit.REASON and
            r['audit_withdrawal']['original_verdict'] == 'PASS' for r in rows))

    def test_even_repinned_result_must_be_the_qualified_pass(self):
        path = self.parent / 'reference-20260915/slo-oracle/keycloak/slo_probe_browser/result.json'
        def mutate(value):
            case = next(c for req in value['requirements'] for c in req['cases'] if c['id'] == audit.CASE)
            case['verdict'] = 'FAIL'
        pins = copy.deepcopy(audit.PINS)
        pins['keycloak']['result'] = self.replace_json(path, mutate)
        with patch.object(audit, 'PINS', pins), self.assertRaisesRegex(ValueError, 'audited feedback PASS'):
            audit.withdrawals(self.root)

    def test_actual_own_session_failure_trace_cannot_be_withdrawn_as_surrogate(self):
        path = self.audit_folder / 'keycloak-transcript.json'
        def mutate(value):
            row = next(e for e in value if e.get('samlSummary', {}).get('fixture_id') == 'slo-async-destination-mismatch'
                       and e['samlSummary'].get('scenario_case_id') == audit.CASE)
            row['samlSummary']['fixture_id'] = 'native-own-session-termination-failure'
        pins = copy.deepcopy(audit.PINS)
        pins['keycloak']['transcript'] = self.replace_json(path, mutate)
        with patch.object(audit, 'PINS', pins), self.assertRaisesRegex(ValueError, 'malformed-Destination surrogate'):
            audit.withdrawals(self.root)

    def test_modified_or_unbound_independent_audit_is_rejected(self):
        path = self.audit_folder / 'request-bound-facts.json'
        self.replace_json(path, lambda facts: facts[0].update(action='foreign-action'))
        with self.assertRaisesRegex(ValueError, 'SHA-256 differs'):
            audit.withdrawals(self.root)

    def inventory(self):
        definition, _ = audit.approved()
        rows = audit.withdrawals(self.root)
        for row in rows:
            row['category'] = 'browser'
            row['variant_references'] = [v['reference'] for v in definition['variant_plan']]
            row['variant_instructions'] = [v['instruction_en'] for v in definition['variant_plan']]
            row['controls'] = [{k: c[k] for k in ('id', 'kind', 'fixture')}
                               for c in definition['controls']]
        folder = self.root / 'remaining-audit'
        folder.mkdir(exist_ok=True)
        return folder / 'inventory.json', rows

    def test_contract_audit_accepts_pinned_withdrawal_without_rewriting_original_pass(self):
        path, rows = self.inventory()
        path.write_text(json.dumps(rows))
        checked = audit_unresolved_contracts.audit(self.root, audit.REPO / 'tests/cases.yaml')
        self.assertEqual(checked['errors'], [])
        self.assertEqual(checked['observation_count'], 2)

    def test_contract_audit_rejects_forged_withdrawal_even_with_valid_result_hash(self):
        path, rows = self.inventory()
        rows[0]['audit_withdrawal']['native_audit_sha256'] = '0' * 64
        path.write_text(json.dumps(rows))
        checked = audit_unresolved_contracts.audit(self.root, audit.REPO / 'tests/cases.yaml')
        self.assertEqual(len(checked['errors']), 1)
        self.assertIn('qualification differs', checked['errors'][0]['error'])


if __name__ == '__main__':
    unittest.main()
