package com.samlscope.runner.cases;

import java.security.PrivateKey;
import java.util.Optional;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.function.BiConsumer;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/** Shared secrets are visible only to synchronous evaluation on the current thread and Run. */
public final class ScopedSharedDecryptionKeys implements SamlDecryptionKeyProvider {
    private record Input(String runId, SecretKey key) {}
    private final ThreadLocal<Input> current = new ThreadLocal<>();
    private final SamlDecryptionKeyProvider privateKeys;
    private final BiConsumer<String, String> bindDigest;
    public ScopedSharedDecryptionKeys(SamlDecryptionKeyProvider privateKeys, BiConsumer<String, String> bindDigest) {
        this.privateKeys = Objects.requireNonNull(privateKeys);
        this.bindDigest = Objects.requireNonNull(bindDigest);
    }
    @Override public Optional<PrivateKey> keyFor(String runId) { return privateKeys.keyFor(runId); }
    @Override public Optional<SecretKey> sharedKeyFor(String runId) {
        var input = current.get();
        return input != null && input.runId().equals(runId) ? Optional.of(input.key()) : Optional.empty();
    }
    /** Consumes and clears the caller's key buffer, including on failure. */
    public <T> T evaluate(String runId, byte[] key, Supplier<T> operation) {
        if (key == null) return operation.get();
        try {
            if (key.length != 16 && key.length != 24 && key.length != 32)
                throw new IllegalArgumentException("An AES key must contain 16, 24 or 32 bytes");
            if (current.get() != null) throw new IllegalStateException("Nested shared-key evaluation is not allowed");
            String digest;
            try { digest = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(key)); }
            catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
            bindDigest.accept(runId, digest);
            current.set(new Input(runId, new SecretKeySpec(key, "AES")));
            try { return operation.get(); }
            finally { current.remove(); }
        } finally { java.util.Arrays.fill(key, (byte) 0); }
    }
}
