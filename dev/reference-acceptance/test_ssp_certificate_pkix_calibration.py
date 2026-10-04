"""Ensure malformed original input cannot reach the native diagnostic operation."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from ssp_certificate_pkix_calibration import locate


class PublicCalibrationOriginalsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.receipt = self.folder / 'receipt'
        self.receipt.mkdir()
        (self.receipt / 'decoded').mkdir()
        self.request = b'<AuthnRequest ID="_original"/>'
        self.fixture = b'<EntityDescriptor entityID="public-only"/>'
        self.sha = lambda raw: hashlib.sha256(raw).hexdigest()
        self.manifest = dict(runId='run_original', targetMetadataSha256='public-target',
                             epochs=[dict(variant='certificate-revoked', probes=[dict(requestReference='tx_original')])],
                             files={'certificate-revoked-fixture.xml': self.sha(self.fixture)})
        self.history = [dict(id='tx_original', runId='run_original', direction='OUTBOUND')]
        self.decoded = [dict(id='tx_original', file='decoded/tx_original.xml', sha256=self.sha(self.request))]
        (self.receipt / 'decoded/tx_original.xml').write_bytes(self.request)
        (self.receipt / 'certificate-revoked-fixture.xml').write_bytes(self.fixture)
        self.save()

    def tearDown(self):
        self.temp.cleanup()

    def save(self):
        for name, value in [('manifest.json', self.manifest), ('transcript.json', self.history),
                            ('decoded-manifest.json', self.decoded)]:
            (self.receipt / name).write_text(json.dumps(value))

    def test_one_same_run_byte_bound_request_is_selected(self):
        _, manifest, ref, request_id, request, fixture = locate(self.folder)
        self.assertEqual(('run_original', 'tx_original', '_original', self.request, self.fixture),
                         (manifest['runId'], ref, request_id, request, fixture))

    def test_foreign_run_and_duplicate_request_originals_are_rejected(self):
        self.history[0]['runId'] = 'run_foreign'
        self.save()
        with self.assertRaises(ValueError):
            locate(self.folder)
        self.history[0]['runId'] = 'run_original'
        self.history.append(dict(self.history[0]))
        self.save()
        with self.assertRaises(ValueError):
            locate(self.folder)

    def test_request_or_fixture_byte_change_is_rejected(self):
        (self.receipt / 'decoded/tx_original.xml').write_bytes(b'<AuthnRequest ID="_foreign"/>')
        with self.assertRaises(ValueError):
            locate(self.folder)
        (self.receipt / 'decoded/tx_original.xml').write_bytes(self.request)
        (self.receipt / 'certificate-revoked-fixture.xml').write_bytes(b'<different/>')
        with self.assertRaises(ValueError):
            locate(self.folder)


if __name__ == '__main__':
    unittest.main()
