package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class ProtocolEvidenceSharedKeyInputTest {
    @Test void acceptsOnlyExplicitAesInputWithoutEchoingInvalidSecrets() {
        assertNull(ProtocolEvidenceRoutes.sharedKey("{}"));
        assertNull(ProtocolEvidenceRoutes.sharedKey(""));
        for (int size : new int[]{16,24,32}) {
            var encoded = java.util.Base64.getEncoder().encodeToString(new byte[size]);
            assertEquals(size, ProtocolEvidenceRoutes.sharedKey("{\"sharedKeyBase64\":\""+encoded+"\"}").length);
        }
        for (String body : new String[]{"[]", "null", "{\"key\":\"secret\"}", "{\"sharedKeyBase64\":\"secret\"}", "{bad-secret"}) {
            var failure = assertThrows(IllegalArgumentException.class, () -> ProtocolEvidenceRoutes.sharedKey(body));
            assertFalse(failure.getMessage().contains("secret"));
            assertNull(failure.getCause());
        }
    }
}
