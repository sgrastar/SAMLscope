package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.core.casedef.CaseDefinitionCatalogMapper;
import com.samlscope.core.evaluation.CoverageCatalogMapper;
import com.samlscope.core.profile.FunctionalCaseDefinitionLoader;
import com.samlscope.core.profile.FunctionalProfile;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class FunctionalProfileDocumentsTest {
    @Test
    void everyReleasedProfileIsInstalledUnderItsExactArtifactPin() throws Exception {
        var bundle = FunctionalProfileDocuments.load();
        var expected = Set.of(FunctionalProfile.values());
        assertEquals(expected, bundle.artifacts().keySet());
        assertEquals(expected, bundle.digests().keySet());
        for (var profile : expected) {
            var actual = "sha256:" + HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(bundle.artifacts().get(profile)));
            assertEquals(actual, bundle.digests().get(profile));
        }
    }

    @Test
    void everyReleasedFunctionalProfileIsAValidSetOfApprovedCases() throws Exception {
        var catalogs = CatalogDocuments.load();
        for (var profile : FunctionalProfile.values()) {
            byte[] bytes;
            try (var stream = getClass().getResourceAsStream("/profiles/" + profile.id() + ".json")) {
                bytes = stream.readAllBytes();
            }
            var document = new ObjectMapper().readValue(bytes, new TypeReference<Map<String,Object>>() {});
            var definition = FunctionalCaseDefinitionLoader.load(
                    document,
                    Map.of(
                            "tests/coverage.yaml", catalogs.bytes("tests/coverage.yaml"),
                            "tests/cases.yaml", catalogs.bytes("tests/cases.yaml"),
                            "tests/predicates.yaml", catalogs.bytes("tests/predicates.yaml")),
                    CaseDefinitionCatalogMapper.fromDocument(catalogs.parsed("tests/cases.yaml")),
                    CoverageCatalogMapper.fromDocument(catalogs.parsed("tests/coverage.yaml")));

            assertEquals(profile, definition.profile());
            assertTrue(!definition.cases().isEmpty());
            assertTrue(definition.cases().stream().allMatch(caseDefinition ->
                    caseDefinition.role() == profile.role()));
        }
    }
}
