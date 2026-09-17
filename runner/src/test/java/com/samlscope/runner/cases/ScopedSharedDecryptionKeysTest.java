package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;

class ScopedSharedDecryptionKeysTest {
    @Test void keyIsRunScopedThreadScopedClearedAfterFailureAndDigestBound() throws Exception {
        var bindings = new HashMap<String,String>();
        var keys = new ScopedSharedDecryptionKeys(run -> Optional.empty(), (run, digest) -> {
            var previous = bindings.putIfAbsent(run, digest);
            if (previous != null && !previous.equals(digest)) throw new IllegalArgumentException("Fixed input");
        });
        var key = new byte[16]; Arrays.fill(key, (byte) 7);
        assertThrows(IllegalStateException.class, () -> keys.evaluate("run", key, () -> {
            assertTrue(keys.sharedKeyFor("run").isPresent());
            assertTrue(keys.sharedKeyFor("other").isEmpty());
            assertTrue(java.util.concurrent.CompletableFuture.supplyAsync(() -> keys.sharedKeyFor("run").isEmpty()).join());
            throw new IllegalStateException("Evaluation failed");
        }));
        assertArrayEquals(new byte[16], key);
        assertTrue(keys.sharedKeyFor("run").isEmpty());
        var same = new byte[16]; Arrays.fill(same, (byte) 7);
        assertEquals("ok", keys.evaluate("run", same, () -> "ok"));
        var different = new byte[16]; Arrays.fill(different, (byte) 9);
        assertThrows(IllegalArgumentException.class, () -> keys.evaluate("run", different, () -> fail("Rebinding allowed")));
        assertArrayEquals(new byte[16], different);
        assertTrue(keys.sharedKeyFor("run").isEmpty());
        var invalid = new byte[15]; Arrays.fill(invalid, (byte) 9);
        assertThrows(IllegalArgumentException.class, () -> keys.evaluate("run", invalid, () -> fail("Invalid key allowed")));
        assertArrayEquals(new byte[15], invalid);
    }
}
