package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class BoundedMetadataFixtureCacheTest {
    @Test
    void entryAndByteLimitsEvictTheLeastRecentlyUsedPayload() {
        var byCount = new BoundedMetadataFixtureCache<String>(2, 100);
        assertEvictsOldest(byCount);
        var byBytes = new BoundedMetadataFixtureCache<String>(10, 4);
        assertEvictsOldest(byBytes);
    }

    private void assertEvictsOldest(BoundedMetadataFixtureCache<String> cache) {
        cache.getOrCompute("one", () -> new byte[] {1, 1});
        cache.getOrCompute("two", () -> new byte[] {2, 2});
        assertArrayEquals(new byte[] {1, 1}, cache.getOrCompute("one", () -> new byte[] {9}));
        cache.getOrCompute("three", () -> new byte[] {3, 3});
        assertArrayEquals(new byte[] {4}, cache.getOrCompute("two", () -> new byte[] {4}));
    }

    @Test
    void oversizedPayloadIsReturnedWithoutRetainingItOrEvictingOtherFixtures() {
        var cache = new BoundedMetadataFixtureCache<String>(2, 2);
        cache.getOrCompute("small", () -> new byte[] {1});
        var generated = new AtomicInteger();
        for (int attempt = 0; attempt < 2; attempt++) {
            assertArrayEquals(new byte[] {2, 3, 4}, cache.getOrCompute("large", () -> {
                generated.incrementAndGet();
                return new byte[] {2, 3, 4};
            }));
        }
        assertEquals(2, generated.get());
        assertArrayEquals(new byte[] {1}, cache.getOrCompute("small", () -> new byte[] {9}));
    }
}
