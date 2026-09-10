package com.samlscope.core.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.casedef.CaseDefinitionCatalog.CaseDefinition;
import com.samlscope.core.casedef.CaseDefinitionCatalog.Control;
import com.samlscope.core.casedef.CaseDefinitionCatalog.ExecutionMode;
import com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone;
import com.samlscope.core.casedef.CaseDefinitionCatalog.Requirements;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.evaluation.Rfc2119Level;
import com.samlscope.core.plan.TargetRole;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class FunctionalCaseDefinitionLoaderTest {
    private static final String CASE_DIGEST = "sha256:" + "1".repeat(64);
    private static final byte[] COVERAGE = "coverage".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CASES = "cases".getBytes(StandardCharsets.UTF_8);

    @Test
    void loadsApprovedCasesAsTheOnlyExecutionUnits() throws Exception {
        var definition = FunctionalCaseDefinitionLoader.load(document(), sources(), cases(), coverage());

        assertEquals(FunctionalProfile.METADATA_IDP, definition.profile());
        assertEquals(java.util.Set.of("case-a"), definition.caseIds());
        assertEquals(java.util.Set.of("not-observable"), definition.nonExecutableObligations());
        assertEquals(java.util.Set.of("owner-a", "not-observable"),
                definition.selectedCoverage(coverage()).byKey().keySet());
    }

    @Test
    void rejectsChangedCasesRolesAndExecutableCaseBypass() {
        var changed = document();
        ((Map<String,Object>) ((List<?>) changed.get("cases")).getFirst()).put("digest", "sha256:" + "2".repeat(64));
        assertThrows(IllegalArgumentException.class,
                () -> FunctionalCaseDefinitionLoader.load(changed, sources(), cases(), coverage()));

        var wrongProfile = document();
        wrongProfile.put("profile", "metadata_sp");
        assertThrows(IllegalArgumentException.class,
                () -> FunctionalCaseDefinitionLoader.load(wrongProfile, sources(), cases(), coverage()));

        var bypass = document();
        bypass.put("non_executable_obligations", List.of("owner-a"));
        assertThrows(IllegalArgumentException.class,
                () -> FunctionalCaseDefinitionLoader.load(bypass, sources(), cases(), coverage()));
    }

    @Test
    void rejectsReviewOnlyOrIncompleteShapes() {
        var pending = document();
        pending.put("status", "PENDING");
        assertThrows(IllegalArgumentException.class,
                () -> FunctionalCaseDefinitionLoader.load(pending, sources(), cases(), coverage()));

        var missing = document();
        missing.put("cases", List.of());
        assertThrows(IllegalArgumentException.class,
                () -> FunctionalCaseDefinitionLoader.load(missing, sources(), cases(), coverage()));
    }

    private static Map<String,Object> document() {
        var result = new LinkedHashMap<String,Object>();
        result.put("schema_version", 1);
        result.put("version", "metadata-idp-v1");
        result.put("profile", "metadata_idp");
        result.put("source_digests", Map.of(
                "tests/coverage.yaml", digest(COVERAGE), "tests/cases.yaml", digest(CASES)));
        result.put("cases", List.of(new LinkedHashMap<>(Map.of("id", "case-a", "digest", CASE_DIGEST))));
        result.put("non_executable_obligations", List.of("not-observable"));
        return result;
    }

    private static Map<String,byte[]> sources() {
        return Map.of("tests/coverage.yaml", COVERAGE, "tests/cases.yaml", CASES);
    }

    private static CaseDefinitionCatalog cases() {
        return new CaseDefinitionCatalog(List.of(new CaseDefinition(
                "case-a", "owner-a", TargetRole.IDP, ExecutionMode.AUTOMATED, Milestone.M1,
                List.of(), Map.of(), List.of(), List.of(),
                List.of(new Control("control", CaseDefinitionCatalog.ControlKind.POSITIVE,
                        "fixture", "control", "control_failed")),
                "counterexample", List.of(), new Requirements(List.of(), "none"), false, null,
                CASE_DIGEST)));
    }

    private static CoverageCatalog coverage() {
        return new CoverageCatalog(List.of(
                new CoverageCatalog.Obligation("owner-a", "requirement-a", Rfc2119Level.MUST,
                        List.of(TargetRole.IDP), null, CoverageCatalog.Testability.AUTOMATED,
                        CoverageCatalog.ProfileScope.CORE),
                new CoverageCatalog.Obligation("not-observable", "requirement-b", Rfc2119Level.MUST,
                        List.of(TargetRole.IDP), null, CoverageCatalog.Testability.NOT_OBSERVABLE,
                        CoverageCatalog.ProfileScope.FULL)));
    }

    private static String digest(byte[] bytes) {
        try {
            return "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (Exception impossible) {
            throw new AssertionError(impossible);
        }
    }
}
