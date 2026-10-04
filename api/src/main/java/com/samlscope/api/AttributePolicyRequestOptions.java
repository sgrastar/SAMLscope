package com.samlscope.api;

import com.samlscope.saml.metadata.MetadataService;

/** Explicit selector for the indexed attribute-policy fixture only. */
final class AttributePolicyRequestOptions {
    private AttributePolicyRequestOptions() {}

    static Integer parse(MetadataService.Variant variant, String value) {
        if (value == null) return null;
        if (variant != MetadataService.Variant.ATTRIBUTE_POLICY_INDEXED) {
            throw new IllegalArgumentException("Attribute service selection requires the indexed attribute-policy fixture");
        }
        return switch (value) {
            case "0" -> 0;
            case "1" -> 1;
            default -> throw new IllegalArgumentException("The indexed attribute-policy fixture advertises selectors 0 and 1");
        };
    }
}
