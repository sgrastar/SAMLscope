import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from attribute_policy_campaign import policies
from attribute_policy_preparation import snapshot, verify_readback, verify_policy_semantics


class PreparationReadbackTest(unittest.TestCase):
    def configured(self, run='run_test'):
        originals = {
            'metadata-providers': b'<MetadataProvider xmlns="urn:mace:shibboleth:2.0:metadata"/>',
            'attribute-resolver': b'<AttributeResolver xmlns="urn:mace:shibboleth:2.0:resolver"/>',
            'attribute-filter': b'<AttributeFilterPolicyGroup xmlns="urn:mace:shibboleth:2.0:afp"/>',
        }
        return policies(originals, 'https://suite.example/p/plan_test', run, '/tmp/fixture.xml')

    def test_policy_meaning_is_checked_even_when_changed_content_has_a_matching_hash(self):
        run = 'run_' + '0' * 26
        policy = snapshot(self.configured(run), run)
        entity, path = 'https://suite.example/p/plan_test', '/tmp/fixture.xml'
        self.assertEqual(policy['policy_sha256'], verify_policy_semantics(policy, run, entity, path))
        for mutation in ['requester', 'input', 'name', 'required', 'silent', 'entity-value', 'provider', 'extra-rule']:
            changed = copy.deepcopy(policy)
            nodes = changed['nodes']
            rules = nodes['attribute-filter'][0]['children']
            if mutation == 'requester':
                rules[0]['attributes']['value'] = 'https://different.example'
            elif mutation == 'input':
                nodes['attribute-resolver'][0]['children'][0]['attributes']['ref'] = 'other-input'
            elif mutation == 'name':
                nodes['attribute-resolver'][0]['children'][1]['attributes']['name'] = 'urn:other'
            elif mutation == 'required':
                rules[3]['children'][0]['attributes']['onlyIfRequired'] = 'false'
            elif mutation == 'silent':
                rules[3]['children'][0]['attributes']['matchIfMetadataSilent'] = 'true'
            elif mutation == 'entity-value':
                rules[2]['children'][0]['attributes']['attributeValue'] = 'other-value'
            elif mutation == 'provider':
                nodes['metadata-providers'][0]['attributes']['metadataFile'] = '/tmp/other.xml'
            else:
                rules.append(copy.deepcopy(rules[-1]))
            encoded = json.dumps(nodes, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
            changed['policy_sha256'] = hashlib.sha256(encoded).hexdigest()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                verify_policy_semantics(changed, run, entity, path)

    def test_snapshot_contains_only_suite_nodes_and_matches_readback(self):
        configured = self.configured()
        result = verify_readback(configured, configured, 'run_test')
        self.assertEqual(snapshot(configured, 'run_test'), result['policy'])
        self.assertEqual(5, len(result['policy']['nodes']['attribute-resolver']))
        self.assertEqual(3, len(result['configuration_sha256']))

    def test_changed_configuration_and_wrong_run_are_rejected(self):
        configured = self.configured()
        changed = copy.copy(configured)
        changed['attribute-filter'] = changed['attribute-filter'].replace(b'onlyIfRequired="true"', b'onlyIfRequired="false"', 1)
        with self.assertRaises(ValueError):
            verify_readback(configured, changed, 'run_test')
        with self.assertRaises(ValueError):
            snapshot(configured, 'another_run')

    def test_missing_or_duplicate_owned_definition_is_ambiguous(self):
        import xml.etree.ElementTree as ET
        for duplicate in [False, True]:
            configured = self.configured()
            root = ET.fromstring(configured['attribute-resolver'])
            node = list(root)[0]
            if duplicate:
                root.append(copy.deepcopy(node))
            else:
                root.remove(node)
            configured['attribute-resolver'] = ET.tostring(root)
            with self.assertRaises(ValueError):
                snapshot(configured, 'run_test')


if __name__ == '__main__':
    unittest.main()
