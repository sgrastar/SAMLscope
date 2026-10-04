package com.samlscope.saml.metadata;

import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.function.Supplier;

/** Instance-local fixture bytes, bounded by both entry count and retained payload size. */
final class BoundedMetadataFixtureCache<K> {
    private final int maximumEntries;
    private final long maximumBytes;
    private final LinkedHashMap<K, byte[]> values = new LinkedHashMap<>(16, 0.75f, true);
    private long retainedBytes;

    BoundedMetadataFixtureCache(int maximumEntries, long maximumBytes) {
        if (maximumEntries < 1 || maximumBytes < 1) {
            throw new IllegalArgumentException("Fixture cache limits must be positive");
        }
        this.maximumEntries = maximumEntries;
        this.maximumBytes = maximumBytes;
    }

    synchronized byte[] getOrCompute(K key, Supplier<byte[]> supplier) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(supplier, "supplier");
        var cached = values.get(key);
        if (cached != null) return cached.clone();
        var generated = Objects.requireNonNull(supplier.get(), "fixture payload").clone();
        if (generated.length <= maximumBytes) {
            values.put(key, generated);
            retainedBytes += generated.length;
            while (values.size() > maximumEntries || retainedBytes > maximumBytes) {
                retainedBytes -= values.remove(values.keySet().iterator().next()).length;
            }
        }
        return generated.clone();
    }
}
