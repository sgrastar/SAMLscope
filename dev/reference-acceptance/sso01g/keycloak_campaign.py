#!/usr/bin/env python3
"""Keycloak plan, native setting batch and explicit management-only live CLI.

The live investigation never invokes the unqualified SAML campaign lifecycle.
"""
import copy
from campaign import cli, digest


class NativeSettingBatch:
    """Reuse Keycloak campaigns' native GET/compare/PUT/GET restoration pattern.

    Each instance owns one public-only setting resource. The future driver owns
    dependencies and restores them in reverse order. Never pass realm exports,
    credentials, tokens, or full private client representations to this class.
    """
    def __init__(self, read, write, counters):
        self.read, self.write, self.counters = read, write, counters
        self.original = copy.deepcopy(read())
        self.expected = copy.deepcopy(self.original)
        self.pending = None

    def _current(self):
        current = self.read()
        # A failed PUT may already have applied. Do not retry it blindly.
        if current != self.expected and (self.pending is None or current != self.pending):
            raise RuntimeError('Concurrent native setting edit; recovery requires review')
        return current

    def apply(self, configured):
        self._current()
        self.pending = copy.deepcopy(configured)
        self.counters.write(lambda: self.write(copy.deepcopy(configured)), location='native')
        if self.read() != configured:
            raise RuntimeError('Product management read-back mismatch')
        self.expected = copy.deepcopy(configured)
        self.pending = None
        # This digest is NOT a running-flow read-back or a proof of LoA behavior.
        return digest(configured)

    def restore(self):
        if self._current() != self.original:
            self.pending = copy.deepcopy(self.original)
            self.counters.write(lambda: self.write(copy.deepcopy(self.original)),
                                location='native', restoring=True)
        if self.read() != self.original:
            raise RuntimeError('Native restoration read-back mismatch')
        self.expected = copy.deepcopy(self.original)
        self.pending = None


if __name__ == '__main__':
    from keycloak_live import main
    raise SystemExit(main())
