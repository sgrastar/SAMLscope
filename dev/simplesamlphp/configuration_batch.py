"""Keep one isolated metadata overlay active through a batch and restore the original bytes."""
import hashlib


class ConfigurationBatch:
    def __init__(self, path):
        self.path = path
        self.original = path.read_bytes()
        self.expected = self.original
        self.write_count = 0
        self.applied_count = 0
        self.restoration_writes = 0

    def _write(self, payload):
        # Replace the file contents in place. A plain write_bytes() swaps the inode, and a Docker
        # Desktop bind mount then keeps serving the old inode, so the reference container never
        # sees the new metadata (the file looks correct on the host but the product cannot resolve
        # the entity). Truncating and rewriting preserves the shared inode.
        with open(self.path, 'r+b') as handle:
            handle.seek(0)
            handle.write(payload)
            handle.truncate()

    def apply(self, overlay):
        if self.path.read_bytes() != self.expected:
            raise RuntimeError('Configuration changed outside this batch; refusing to overwrite it')
        configured = self.original + b'\n' + overlay + b'\n'
        self.write_count += 1
        self._write(configured)
        self.expected = configured
        if self.path.read_bytes() != configured:
            raise RuntimeError('Configuration read-back failed')
        self.applied_count += 1
        return hashlib.sha256(configured).hexdigest()

    def restore(self):
        current = self.path.read_bytes()
        if current != self.expected:
            # Preserve unexpected operator changes instead of blindly restoring a snapshot.
            raise RuntimeError('Configuration changed outside this batch; restoration requires review')
        if current != self.original:
            self.write_count += 1
            self.restoration_writes += 1
            self._write(self.original)
            self.expected = self.original
        final = self.path.read_bytes()
        return dict(restored=final == self.original,
                    original_sha256=hashlib.sha256(self.original).hexdigest(),
                    final_sha256=hashlib.sha256(final).hexdigest(),
                    configuration_write_attempts=self.write_count,
                    applied_conditions=self.applied_count,
                    restoration_write_attempts=self.restoration_writes)
