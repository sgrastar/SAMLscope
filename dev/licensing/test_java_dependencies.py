import io
import json
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from pathlib import Path

from java_dependencies import inventory


class DependencyInventoryTest(unittest.TestCase):
    def test_changed_dependency_cannot_reuse_permission_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'LICENSES').mkdir()
            (root / 'LICENSES/java-permissions.json').write_text(json.dumps({
                'packages': {'example-1.jar': {'jar_sha256': 'old-reviewed-digest'}}}))
            jar = root / 'example-1.jar'
            with zipfile.ZipFile(jar, 'w') as archive:
                archive.writestr('schema/example.xsd', '<schema/>')
            with patch('java_dependencies.ROOT', root):
                with self.assertRaisesRegex(ValueError, 'Stale reviewed permission evidence'):
                    inventory(jar_paths=[jar])

    def test_actual_notice_declarations_and_schema_are_kept_separate(self):
        jar_bytes = io.BytesIO()
        with zipfile.ZipFile(jar_bytes, 'w') as jar:
            jar.writestr('META-INF/MANIFEST.MF', 'Bundle-License: https://example.test/first,\r\n https://example.test/second\r\n')
            jar.writestr('META-INF/maven/example/lib/pom.xml', '<project xmlns="http://maven.apache.org/POM/4.0.0"><licenses><license><name>Custom terms</name><url>https://example.test/terms</url></license></licenses></project>')
            jar.writestr('META-INF/NOTICE', 'Copyright upstream\nDo not remove.\n')
            jar.writestr('schema/example.xsd', '<schema/>')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'dist.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('app/lib/example-1.jar', jar_bytes.getvalue())
                archive.writestr('app/lib/core-1.jar', b'first party skipped')
            packages = inventory(path)['packages']
            standalone = Path(directory) / 'example-1.jar'
            standalone.write_bytes(jar_bytes.getvalue())
            self.assertEqual(packages, inventory(jar_paths=[str(standalone)])['packages'])
        self.assertEqual(1, len(packages))
        package = packages[0]
        self.assertEqual('Copyright upstream\nDo not remove.\n', package['notices'][0]['text'])
        self.assertEqual('https://example.test/first,https://example.test/second', package['declarations'][0]['fields']['Bundle-License'])
        self.assertEqual('Custom terms', package['declarations'][1]['licenses'][0]['name'])
        self.assertEqual('RESOURCE_PERMISSION_REVIEW_PENDING', package['embedded_schemas'][0]['review_status'])


if __name__ == '__main__':
    unittest.main()
