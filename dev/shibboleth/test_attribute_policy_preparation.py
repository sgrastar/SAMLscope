import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from attribute_policy_campaign import policies
from attribute_policy_preparation import snapshot, verify_readback


class PreparationReadbackTest(unittest.TestCase):
    def configured(self):
        originals = {
            'metadata-providers': b'<MetadataProvider xmlns="urn:mace:shibboleth:2.0:metadata"/>',
            'attribute-resolver': b'<AttributeResolver xmlns="urn:mace:shibboleth:2.0:resolver"/>',
            'attribute-filter': b'<AttributeFilterPolicyGroup xmlns="urn:mace:shibboleth:2.0:afp"/>',
        }
        return policies(originals, 'https://suite.example/p/plan_test', 'run_test', '/tmp/fixture.xml')

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
