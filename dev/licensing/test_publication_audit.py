import unittest
from publication_audit import source_row

class PublicationAuditTest(unittest.TestCase):
    def test_red_quotation_stays_a_quotation_and_preserves_inquiry(self):
        row = source_row({'id': 'source', 'material_allocation_status': 'QUOTATION_OR_IMPLEMENTATION_COMMENTARY',
            'publication_status': 'RED', 'source_url': 'https://example.test/spec', 'usage_review': 'A translated passage',
            'requires_inquiry': True, 'requires_legal_review': True})
        self.assertEqual('C', row['use'])
        self.assertTrue(row['requires_inquiry'])
        self.assertTrue(row['requires_legal_review'])
        self.assertIn('permission text', row['conditions'])

    def test_unknown_use_is_not_silently_reported_as_original(self):
        with self.assertRaisesRegex(ValueError, 'Unclassified source use'):
            source_row({'id': 'source', 'material_allocation_status': 'NOT_REVIEWED'})
