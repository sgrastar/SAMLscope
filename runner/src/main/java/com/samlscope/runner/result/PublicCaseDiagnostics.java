package com.samlscope.runner.result;

import java.util.*;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.SamlErrorProbeRequestFactory;

/** Only Suite-defined condition identifiers can leave private CaseOutcome details. */
final class PublicCaseDiagnostics {
    private static final Set<String> KEYS = Set.of("confirmed_character_fixtures", "confirmed_type_conditions", "responded_extension_string_fixtures", "remaining_conditions", "missing_inputs",
            "remaining_protocol_elements", "fixtures", "fetched_variants", "used_variants", "missing_fetches",
            "missing_acceptance", "unresolved_rejection", "wrong_endpoint_variants", "successful_variants",
            "error_variants", "violating_fixtures", "unverifiable_fixtures", "evidence_issues", "decryption_key_source",
            "encryption_algorithm", "key_transport_algorithm", "digest_algorithm", "mgf_algorithm");
    private static final Set<String> TOKENS = tokens();
    private PublicCaseDiagnostics() {}
    static Map<String,List<String>> from(CaseOutcome outcome) {
        if (outcome == null) return Map.of();
        var result = new LinkedHashMap<String,List<String>>();
        copy(outcome.details(), "", result);
        if (outcome.details().get("metadata_attribute_observations") instanceof Map<?,?> nested)
            copy(nested, "metadata_attribute_", result);
        return Collections.unmodifiableMap(result);
    }
    private static void copy(Map<?,?> source,String prefix,Map<String,List<String>> result) {
        for (var key : KEYS.stream().sorted().toList()) {
            if (!(source.get(key) instanceof List<?> values)) continue;
            var safe = values.stream().filter(String.class::isInstance).map(String.class::cast)
                    .filter(TOKENS::contains).distinct().sorted().toList();
            if (!safe.isEmpty()) result.put(prefix + key, safe);
        }
    }
    private static Set<String> tokens() {
        var tokens = new HashSet<>(List.of("control", "target-encryption-key", "persistent-nameid", "transient-nameid",
                "user-defined-advice-string", "user-defined-attribute-value-string",
                "user-defined-extension-string-attribute", "literal-tab-and-lf-on-wire",
                "SubjectConfirmationData", "Attribute", "published-metadata", "supplemental-input",
                "history_unavailable", "history_incomplete", "run_mismatch",
                "ambiguous_entry_id", "decoded_content_missing", "decoded_content_size_mismatch",
                "logout_message_scope_unresolved", "logout_type_mismatch", "decoded_content_unreadable", "redirect_message_mismatch", "response_type_mismatch", "decoded_content_invalid_xml",
                "http://www.w3.org/2009/xmlenc11#aes128-gcm", "http://www.w3.org/2009/xmlenc11#aes256-gcm",
                "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", "http://www.w3.org/2009/xmlenc11#rsa-oaep",
                "http://www.w3.org/2000/09/xmldsig#sha1", "http://www.w3.org/2001/04/xmlenc#sha256",
                "http://www.w3.org/2009/xmlenc11#mgf1sha1", "http://www.w3.org/2009/xmlenc11#mgf1sha256"));
        Arrays.stream(MetadataService.Variant.values()).map(MetadataService.Variant::id).forEach(tokens::add);
        Arrays.stream(SamlErrorProbeRequestFactory.Probe.values())
                .map(value -> value.name().toLowerCase(Locale.ROOT).replace('_','-')).forEach(tokens::add);
        com.samlscope.saml.crypto.SamlEncryptionFixtureFactory.matrix().stream()
                .map(value -> "enc-subject-" + value.id()).forEach(tokens::add);
        com.samlscope.saml.normal.SamlTypedStringFixtures.matrix().stream()
                .map(value -> value.id().replace(':', '-')).forEach(tokens::add);
        return Set.copyOf(tokens);
    }
}
