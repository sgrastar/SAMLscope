#!/usr/bin/env python3
"""SimpleSAMLphp offline plan and isolated public overlay batch; no Docker push.

The archived native selector lacks inexact/DeclRef support. No PHP comparison or
response-rewriting implementation is fabricated. See PLAN.md before any live work.
"""
from campaign import cli, module_at

ConfigurationBatch = module_at('sso01g_configuration_batch',
    'dev/simplesamlphp/configuration_batch.py').ConfigurationBatch


class PublicOverlayBatch(ConfigurationBatch):
    """Only for a separately provisioned, credential-free public config fragment.

    ConfigurationBatch preserves the inode and rejects unexpected external edits.
    Product-runtime PHP read-back must be supplied separately by a reviewed driver;
    write_count/applied_count here NEVER imply effective native application.
    """
    def __init__(self, path, counters):
        if path.is_symlink() or not path.is_file():
            raise ValueError('Expected an isolated ordinary public configuration fragment')
        self.counters = counters
        self.restoring = False
        super().__init__(path)

    def _write(self, payload):
        # No container/container_path is configured; prohibit accidental Docker fallback.
        if getattr(self, 'container', None) or getattr(self, 'container_path', None):
            raise ValueError('Docker backend is not part of offline preparation')
        return self.counters.write(lambda: super(PublicOverlayBatch, self)._write(payload),
                                   location='host', restoring=self.restoring)

    def restore(self):
        self.restoring = True
        try:
            return super().restore()
        finally:
            self.restoring = False


if __name__ == '__main__':
    cli('simplesamlphp')
