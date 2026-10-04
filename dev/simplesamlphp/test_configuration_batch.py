import tempfile
import unittest
from unittest.mock import patch
import subprocess
from pathlib import Path
from configuration_batch import ConfigurationBatch


class ConfigurationBatchTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / 'metadata.php'
        self.original = b'<?php\n$metadata = [];\n'
        self.path.write_bytes(self.original)

    def test_replaces_overlay_without_accumulation_and_restores_once(self):
        batch = ConfigurationBatch(self.path)
        inode = self.path.stat().st_ino
        for i in range(13):
            overlay = ('$metadata["unique-client"] = '+str(i)+';').encode()
            batch.apply(overlay)
            self.assertEqual(self.original+b'\n'+overlay+b'\n', self.path.read_bytes())
        result = batch.restore()
        self.assertTrue(result['restored'])
        self.assertEqual(14, result['configuration_write_attempts'])
        self.assertEqual(1, result['restoration_write_attempts'])
        self.assertEqual(inode, self.path.stat().st_ino)
        self.assertEqual(self.original, self.path.read_bytes())
        self.assertEqual(14, batch.restore()['configuration_write_attempts'])

    def test_failed_flow_can_restore_without_intermediate_writes(self):
        batch = ConfigurationBatch(self.path)
        try:
            batch.apply(b'first')
            raise ValueError('protocol flow failed')
        except ValueError:
            pass
        finally:
            result = batch.restore()
        self.assertTrue(result['restored'])
        self.assertEqual(2, result['configuration_write_attempts'])

    def test_external_edit_is_not_overwritten_by_apply_or_restore(self):
        batch = ConfigurationBatch(self.path)
        batch.apply(b'first')
        self.path.write_bytes(b'operator edit')
        with self.assertRaises(RuntimeError):
            batch.apply(b'next')
        with self.assertRaises(RuntimeError):
            batch.restore()
        self.assertEqual(b'operator edit', self.path.read_bytes())
        self.assertEqual(1, batch.write_count)

    def test_empty_batch_does_not_write(self):
        self.assertEqual(0, ConfigurationBatch(self.path).restore()['configuration_write_attempts'])

    def test_failed_container_push_restores_known_host_write(self):
        batch = ConfigurationBatch(self.path)
        batch.container = 'reference-product'
        batch.container_path = '/public/metadata.php'
        with patch('subprocess.run', side_effect=[subprocess.CalledProcessError(1, 'docker'), None]):
            with self.assertRaises(subprocess.CalledProcessError):
                batch.apply(b'next')
            result = batch.restore()
        self.assertTrue(result['restored'])
        self.assertEqual(self.original, self.path.read_bytes())
        self.assertEqual(2, batch.write_count)
        self.assertEqual(0, batch.applied_count)
        self.assertEqual(1, batch.restoration_writes)

    def test_external_edit_after_failed_push_is_preserved(self):
        batch = ConfigurationBatch(self.path)
        batch.container = 'reference-product'
        batch.container_path = '/public/metadata.php'
        with patch('subprocess.run', side_effect=subprocess.CalledProcessError(1, 'docker')):
            with self.assertRaises(subprocess.CalledProcessError):
                batch.apply(b'next')
        self.path.write_bytes(b'operator edit')
        with self.assertRaises(RuntimeError):
            batch.restore()
        self.assertEqual(b'operator edit', self.path.read_bytes())


if __name__ == '__main__':
    unittest.main()
