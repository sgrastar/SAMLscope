package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.evaluation.Rfc2119Level;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.profile.FunctionalDefinitionIdentity;
import com.samlscope.core.profile.FunctionalProfile;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PinnedFunctionalCaseDefinitionResolverTest {
    private static final String CASE_DIGEST = "sha256:" + "1".repeat(64);

    @Test
    void resolvesOnlyThePinnedCaseSet() throws Exception {
        var sources = Map.of(
                "tests/coverage.yaml", new byte[] {1},
                "tests/cases.yaml", new byte[] {2});
        var artifact = new ObjectMapper().writeValueAsBytes(Map.of(
                "schema_version", 1,
                "version", "metadata-idp-v1",
                "profile", "metadata_idp",
                "source_digests", Map.of(
                        "tests/coverage.yaml", digest(sources.get("tests/coverage.yaml")),
                        "tests/cases.yaml", digest(sources.get("tests/cases.yaml"))),
                "cases", List.of(Map.of("id", "case-a", "digest", CASE_DIGEST)),
                "non_executable_obligations", List.of()));
        var resolver = new PinnedFunctionalCaseDefinitionResolver(
                Map.of(FunctionalProfile.METADATA_IDP, artifact),
                Map.of(FunctionalProfile.METADATA_IDP, digest(artifact)),
                sources, cases(), coverage());

        var identity = resolver.identity(FunctionalProfile.METADATA_IDP);
        assertEquals(java.util.Set.of("case-a"), resolver.resolve(identity).caseIds());
        assertThrows(IllegalArgumentException.class, () -> resolver.resolve(
                new FunctionalDefinitionIdentity(identity.profile(), identity.version(),
                        "sha256:" + "f".repeat(64))));
        assertThrows(IllegalArgumentException.class,
                () -> resolver.identity(FunctionalProfile.METADATA_SP));
    }

    private static CaseDefinitionCatalog cases() {
        return new CaseDefinitionCatalog(List.of(new CaseDefinitionCatalog.CaseDefinition(
                "case-a", "owner-a", TargetRole.IDP,
                CaseDefinitionCatalog.ExecutionMode.AUTOMATED,
                CaseDefinitionCatalog.Milestone.M1,
                List.of(), Map.of(), List.of(), List.of(),
                List.of(new CaseDefinitionCatalog.Control(
                        "positive", CaseDefinitionCatalog.ControlKind.POSITIVE,
                        "fixture", "control", "control_failed")),
                "counterexample", List.of(),
                new CaseDefinitionCatalog.Requirements(List.of(), "none"), false, null,
                CASE_DIGEST)));
    }

    private static CoverageCatalog coverage() {
        return new CoverageCatalog(List.of(new CoverageCatalog.Obligation(
                "owner-a", "requirement-a", Rfc2119Level.MUST,
                List.of(TargetRole.IDP), null, CoverageCatalog.Testability.AUTOMATED,
                CoverageCatalog.ProfileScope.CORE)));
    }

    private static String digest(byte[] bytes) {
        try {
            return "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (Exception impossible) {
            throw new AssertionError(impossible);
        }
    }
}
