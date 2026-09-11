import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

import yaml

SPEC = importlib.util.spec_from_file_location('export_material', Path(__file__).with_name('export_material.py'))
export = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(export)


class ExportTest(unittest.TestCase):
    def test_yaml_roundtrip_preserves_payload_and_hash(self):
        source = b'%YAML 1.2\n---\nkey: IIP-G01.a\ntext: "quoted: value"\n'
        output = export.render('tests/example.yaml', source)
        self.assertEqual(yaml.safe_load(source), yaml.safe_load(output))
        self.assertTrue(output.endswith(source))
        self.assertIn(hashlib.sha256(source).hexdigest().encode(), output)
        self.assertIn(b'Internet2', output)
        self.assertNotIn(b'RFC7457', output)

    def test_json_has_explicit_envelope_and_exact_original(self):
        source = b'{ "key": "IIP-G01.a", "result": false }\n'
        output = json.loads(export.render('profiles/example.json', source))
        self.assertEqual(source, output['original_utf8'].encode())
        self.assertEqual(json.loads(source), output['content'])
        self.assertEqual(['kantara-fedinterop-impl'], [s['id'] for s in output['attribution']['sources']])

    def test_real_profile_selects_its_cases_without_expanding_unrelated_siblings(self):
        index = json.loads((export.ROOT / 'LICENSES/material-index.json').read_text())
        for path in (export.ROOT / 'profiles').glob('*.json'):
            with self.subTest(profile=path.stem):
                meta = export.attribution(str(path.relative_to(export.ROOT)), path.read_bytes())
                selected = {s['id'] for s in meta['sources'] + meta['unresolved_sources']}
                self.assertEqual(set(index['profile_sources'][path.stem]), selected)

    def test_numbered_obligation_and_case_preserve_owner_sources(self):
        index = json.loads((export.ROOT / 'LICENSES/material-index.json').read_text())
        owner = set(index['obligation_sources']['IIP-MD05.a1'])
        self.assertTrue(owner)
        self.assertTrue(owner.issubset(index['case_sources']['IIP-MD05-a1-idp-01']))
        for text in ['IIP-MD05.a1', 'IIP-MD05-a1-idp-01']:
            meta = export.attribution('docs/example.md', text.encode())
            selected = {s['id'] for s in meta['sources'] + meta['unresolved_sources']}
            self.assertTrue(owner.issubset(selected))

    def test_markdown_notices_do_not_execute_markup(self):
        source = b'# Example\nIIP-G01.a\n'
        output = export.render('docs/example.md', source)
        self.assertTrue(output.startswith(source))
        self.assertIn(b'    "sources"', output)


if __name__ == '__main__':
    unittest.main()
