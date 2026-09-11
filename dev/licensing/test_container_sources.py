import hashlib
import io
import unittest
from unittest.mock import patch

import container_sources


class ContainerSourceGateTest(unittest.TestCase):
    def test_changed_download_is_rejected(self):
        asset = {'url': 'https://example.invalid/source', 'size': 8,
                 'sha256': hashlib.sha256(b'original').hexdigest()}
        with patch('urllib.request.urlopen', return_value=io.BytesIO(b'modified')):
            with self.assertRaisesRegex(ValueError, 'asset changed'):
                container_sources.check_download(asset)

    def test_inventory_change_blocks_same_base_image(self):
        manifest = {'runtime_file_sha256': {'/var/lib/dpkg/status': 'reviewed'}}
        with patch('subprocess.check_output', side_effect=['amd64', 'changed  /var/lib/dpkg/status\n']):
            with self.assertRaisesRegex(ValueError, 'inventory'):
                container_sources.check_runtime(manifest, 'test-image')

    def test_other_architecture_cannot_reuse_approval(self):
        with patch('subprocess.check_output', return_value='arm64'):
            with self.assertRaisesRegex(ValueError, 'amd64'):
                container_sources.check_runtime({}, 'test-image')


if __name__ == '__main__':
    unittest.main()
