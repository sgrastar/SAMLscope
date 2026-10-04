package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Set;

/** Public native inventories are separate from the metadata being compared.
 * An adapter must derive applicability and completeness from native originals,
 * rather than accepting a collector's complete/unused/current booleans. */
public interface NativeMetadataPublisherInventoryAdapter {
    record RoleKey(String spkiSha256, String purpose, String origin) {
        public RoleKey {
            if (spkiSha256 == null || !spkiSha256.matches("[a-f0-9]{64}") ||
                    !Set.of("signing", "encryption", "transport-authentication").contains(purpose)
                    || origin == null || origin.isBlank()) throw new IllegalArgumentException("Invalid public role key");
        }
    }
    record Endpoint(String kind, String binding, String location, String responseLocation) {}
    record Inventory(List<RoleKey> keys, List<Endpoint> endpoints, Set<String> protocols,
                     Boolean wantAuthnRequestsSigned, List<String> unresolvedScope) {
        public Inventory {
            keys = List.copyOf(keys); endpoints = List.copyOf(endpoints);
            protocols = Set.copyOf(protocols); unresolvedScope = List.copyOf(unresolvedScope);
        }
    }
    String id();
    Inventory validate(MetadataPublisherKeyInventoryEvidence.Frame frame, JsonNode epoch) throws Exception;
    void validateTransition(MetadataPublisherKeyInventoryEvidence.Frame frame, JsonNode epoch, byte[] target) throws Exception;
    List<String> validateControls(MetadataPublisherKeyInventoryEvidence.Frame frame, String caseId) throws Exception;
    void validateRestoration(MetadataPublisherKeyInventoryEvidence.Frame frame) throws Exception;
}
