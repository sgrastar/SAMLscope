package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.saml.metadata.MetadataService.Variant;
import org.junit.jupiter.api.Test;

class AttributePolicyRequestOptionsTest {
    @Test void restrictsSelectionToAdvertisedFixtureInputs() {
        assertNull(AttributePolicyRequestOptions.parse(Variant.BASELINE, null));
        assertNull(AttributePolicyRequestOptions.parse(Variant.ATTRIBUTE_POLICY_INDEXED, null));
        assertEquals(0, AttributePolicyRequestOptions.parse(Variant.ATTRIBUTE_POLICY_INDEXED, "0"));
        assertEquals(1, AttributePolicyRequestOptions.parse(Variant.ATTRIBUTE_POLICY_INDEXED, "1"));
        for (String invalid : new String[]{"", "-1", "2", "65536", "00", " 1", "1.0"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> AttributePolicyRequestOptions.parse(Variant.ATTRIBUTE_POLICY_INDEXED, invalid));
        }
        assertThrows(IllegalArgumentException.class,
                () -> AttributePolicyRequestOptions.parse(Variant.ATTRIBUTE_POLICY_REQUESTED_REQUIRED, "1"));
    }
}
