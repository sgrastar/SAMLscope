"""Regression boundaries for the two qualified historical MD05.f withdrawals."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import audit_metadata_full_ui_evidence as audit


class FullUiWithdrawalTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.parent = Path(self.temporary.name).resolve()
        self.root = self.parent / 'reference-20260914'
        self.root.mkdir()
        self.audit_path = self.parent / audit.AUDIT
        self.audit_path.parent.mkdir(parents=True)
        original = audit.REPO / 'build/acceptance' / audit.AUDIT
        shutil.copyfile(original, self.audit_path)
        self.report = json.loads(self.audit_path.read_bytes())
        for row in self.report['rows']:
            target = self.parent / 'reference-20260918' / (row['product'] + '-md05f-v107')
            source = audit.REPO / 'build/acceptance/reference-20260918' / target.name
            for name in row['originalPins']:
                (target / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / name, target / name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_only_exact_two_full_ui_records_are_withdrawn_and_originals_unchanged(self):
        before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in self.parent.rglob('*') if p.is_file()}
        rows = audit.withdrawals(self.root)
        self.assertEqual({('shibboleth', audit.CASE), ('simplesamlphp', audit.CASE)},
                         {(r['product'], r['case']) for r in rows})
        self.assertTrue(all(r['verdict'] == 'NOT_VERIFIED' and r['reason_code'] == audit.REASON
                            and r['audit_withdrawal']['original_verdict'] == 'PASS' for r in rows))
        self.assertEqual(before, {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in self.parent.rglob('*') if p.is_file()})

    def test_correctly_scoped_fixture_is_not_withdrawn_even_if_audit_label_is_retained(self):
        row = self.report['rows'][0]
        target = self.parent / 'reference-20260918' / (row['product'] + '-md05f-v107') / 'full-ui-info/fixture.xml'
        root = ET.fromstring(target.read_bytes())
        info = root.find('.//' + audit.UI + 'UIInfo')
        hints = info.find(audit.UI + 'DiscoHints')
        parents = {c: p for p in root.iter() for c in p}
        info.remove(hints)
        parents[info].append(hints)
        raw = ET.tostring(root)
        target.write_bytes(raw)
        row['originalPins']['full-ui-info/fixture.xml'] = audit.sha(raw)
        self.audit_path.write_text(json.dumps(self.report))
        with patch.object(audit, 'AUDIT_SHA', audit.sha(self.audit_path.read_bytes())):
            with self.assertRaisesRegex(ValueError, 'mis-scoped full DiscoHints'):
                audit.withdrawals(self.root)

    def test_foreign_run_cannot_be_withdrawn_by_repinning_an_audit(self):
        row = self.report['rows'][0]
        result_path = self.parent / 'reference-20260918' / (row['product'] + '-md05f-v107') / 'result.json'
        result = json.loads(result_path.read_bytes())
        result['run']['id'] = 'run_FOREIGN'
        raw = json.dumps(result).encode()
        result_path.write_bytes(raw)
        row['originalPins']['result.json'] = audit.sha(raw)
        row['run'] = 'run_FOREIGN'
        self.audit_path.write_text(json.dumps(self.report))
        with patch.object(audit, 'AUDIT_SHA', audit.sha(self.audit_path.read_bytes())):
            with self.assertRaisesRegex(ValueError, 'Foreign legacy Run'):
                audit.withdrawals(self.root)


if __name__ == '__main__':
    unittest.main()
