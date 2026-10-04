package com.samlscope.runner.result;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.*;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.SamlErrorProbeRequestFactory;

class PublicCaseDiagnosticsTest {
    @Test void exportsEvidenceFailureCategoriesWithoutExceptionTextOrFilePaths() {
        for (var token : List.of("history_unavailable", "history_incomplete", "run_mismatch", "ambiguous_entry_id",
                "decoded_content_missing", "decoded_content_size_mismatch", "logout_message_scope_unresolved",
                "logout_type_mismatch", "decoded_content_unreadable")) {
            var outcome = new CaseOutcome(Outcome.NOT_VERIFIED,"incomplete","incomplete","incomplete",List.of(),Map.of(
                    "evidence_issues", List.of(token,"/private/secret.xml","Authorization: Bearer secret","user@example.test")));
            assertEquals(Map.of("evidence_issues",List.of(token)),PublicCaseDiagnostics.from(outcome));
        }
    }
    @Test void exportsEveryDefinedFixtureButNeverArbitraryDetailsOrValues() {
        var candidates = new ArrayList<String>();
        Arrays.stream(MetadataService.Variant.values()).map(MetadataService.Variant::id).forEach(candidates::add);
        Arrays.stream(SamlErrorProbeRequestFactory.Probe.values())
                .map(v -> v.name().toLowerCase(Locale.ROOT).replace('_','-')).forEach(candidates::add);
        com.samlscope.saml.normal.SamlTypedStringFixtures.matrix().stream()
                .map(v -> v.id().replace(':', '-')).forEach(candidates::add);
        for (var candidate : candidates) {
            var details = Map.<String,Object>of("fixtures", List.of(candidate, "private-user@example.test", "</script>", candidate),
                    "authorization", "Bearer confidential", "configuration_note", "private note",
                    "metadata_attribute_observations", Map.of("used_variants", List.of(candidate, "session-secret"),
                            "NameID", "private-user@example.test"));
            var result = PublicCaseDiagnostics.from(new CaseOutcome(Outcome.NOT_VERIFIED, "partial", "partial", "partial", List.of(), details));
            assertEquals(Map.of("fixtures",List.of(candidate),"metadata_attribute_used_variants",List.of(candidate)),result);
            assertThrows(UnsupportedOperationException.class, () -> result.put("secret", List.of("x")));
        }
    }
    @Test void exposesExtensionExchangeIdentifiersWithoutExposingTheirPayloads() {
        for (var f : com.samlscope.saml.normal.SamlTypedStringFixtures.matrix()) {
            var id = f.id().replace(':', '-');
            var outcome = new CaseOutcome(Outcome.NOT_VERIFIED,"partial","partial","partial",List.of(),
                    Map.of("responded_extension_string_fixtures",List.of(id,f.value(),"user@example.test")));
            assertEquals(Map.of("responded_extension_string_fixtures",List.of(id)),PublicCaseDiagnostics.from(outcome));
        }
    }
    @Test void exportsConfirmedTypeConditionsWithoutArbitraryTypeNamesOrValues() {
        var outcome = new CaseOutcome(Outcome.NOT_VERIFIED,"partial","partial","partial",List.of(),Map.of(
                "confirmed_type_conditions",List.of("user-defined-extension-string-attribute","private-user@example.test","unknown-type")));
        assertEquals(Map.of("confirmed_type_conditions",List.of("user-defined-extension-string-attribute")),
                PublicCaseDiagnostics.from(outcome));
    }
    @Test void retainsOnlyExplicitRemainingConditionNamesAndDoesNotRecurseIntoHistoricalResults() {
        var outcome = new CaseOutcome(Outcome.NOT_VERIFIED,"partial","partial","partial",List.of(),Map.of(
                "remaining_conditions",List.of("persistent-nameid","unknown-user-condition"),
                "remaining_protocol_elements",List.of("Attribute","SubjectConfirmationData"),
                "previous_recorded_evidence_result",Map.of("fixtures",List.of("control"),"note","private"),
                "confirmed_character_fixtures", "not a list"));
        assertEquals(Map.of("remaining_conditions",List.of("persistent-nameid"),
                "remaining_protocol_elements",List.of("Attribute","SubjectConfirmationData")),PublicCaseDiagnostics.from(outcome));
        assertEquals(Map.of(),PublicCaseDiagnostics.from(null));
    }
}
