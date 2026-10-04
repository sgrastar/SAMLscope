import unittest
import xml.etree.ElementTree as ET
from relying_party_attribute_preparation import prepare, verify_readback, NAMESPACES


class RelyingPartyPreparationTest(unittest.TestCase):
    def setUp(self):
        self.run = 'run_C97YCPR7F5KNWRMCMHWNPQ11N9'
        self.entities = {'first': 'https://suite.test/first', 'second': 'https://suite.test/second'}
        self.files = {side: '/opt/reference-idp/metadata/' + side + '.xml' for side in self.entities}
        tags = {'metadata-providers': 'MetadataProvider', 'attribute-resolver': 'AttributeResolver',
                'attribute-filter': 'AttributeFilterPolicyGroup'}
        self.originals = {name: ('<' + tags[name] + ' xmlns="' + ns + '"/>').encode()
                          for name, ns in NAMESPACES.items()}

    def test_exact_native_recipe_and_preserved_requester_scope(self):
        configured = prepare(self.originals, self.run, self.entities, self.files)
        receipt = verify_readback(configured, configured, self.run, self.entities, self.files)
        self.assertFalse(receipt['verdict_adopted'])
        self.assertEqual(receipt['entity_ids'], self.entities)
        for name, raw in configured.items():
            self.assertIn(('xmlns="' + NAMESPACES[name] + '"').encode(), raw)
        with self.assertRaises(ValueError):
            prepare(configured, self.run, self.entities, self.files)
        wrong = dict(configured)
        root = ET.fromstring(wrong['attribute-filter'])
        root[0][0].set('value', self.entities['second'])
        wrong['attribute-filter'] = ET.tostring(root)
        # Even self-consistent read-back hashes cannot bless the wrong requester rule.
        with self.assertRaises(ValueError):
            verify_readback(wrong, wrong, self.run, self.entities, self.files)
        with self.assertRaises(ValueError):
            verify_readback(configured, wrong, self.run, self.entities, self.files)

    def test_distinct_entities_are_mandatory(self):
        with self.assertRaises(ValueError):
            prepare(self.originals, self.run, {'first': 'same', 'second': 'same'}, self.files)
