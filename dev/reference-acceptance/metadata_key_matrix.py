"""Shared native metadata key conditions; the baseline control precedes evaluative inputs."""
KEY_CONDITIONS = ('entity-root', 'keyvalue-only', 'certificate-runtime-same-key', 'certificate-runtime-other-key', 'multiple-signing-keys-first', 'multiple-signing-keys', 'multiple-signing-keys-unadvertised', 'multiple-omitted-keys-first', 'multiple-omitted-keys-second', 'three-signing-keys-first', 'three-signing-keys-second', 'three-signing-keys')
KEY_CAMPAIGN = ("control", *KEY_CONDITIONS)
