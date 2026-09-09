package com.samlscope.runner;

import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.profile.FunctionalCaseDefinition;
import com.samlscope.core.profile.FunctionalProfile;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Small case-set definitions for runner unit tests. Production definitions remain digest pinned. */
public final class FunctionalCaseFixtures {
    private static final String DIGEST = "sha256:" + "a".repeat(64);

    private FunctionalCaseFixtures() {}

    public static FunctionalCaseDefinition definition(
            FunctionalProfile profile,
            CaseDefinitionCatalog definitions,
            CoverageCatalog coverage,
            String... caseIds) {
        var references = Arrays.stream(caseIds)
                .map(id -> new FunctionalCaseDefinition.CaseReference(
                        id, definitions.require(id).caseDigest()))
                .toList();
        return new FunctionalCaseDefinition(
                "test-v1", profile, Map.of("test", DIGEST), references, Set.of(),
                definitions, coverage);
    }

    public static FunctionalCaseDefinition automated(FunctionalProfile profile, String... caseIds) {
        var cases = new java.util.ArrayList<CaseDefinitionCatalog.CaseDefinition>();
        var obligations = new java.util.ArrayList<CoverageCatalog.Obligation>();
        for (var index = 0; index < caseIds.length; index++) {
            var obligation = "TEST." + index;
            cases.add(new CaseDefinitionCatalog.CaseDefinition(
                    caseIds[index], obligation, profile.role(),
                    CaseDefinitionCatalog.ExecutionMode.AUTOMATED,
                    CaseDefinitionCatalog.Milestone.M1,
                    List.of(), Map.of(), List.of(), List.of(), List.of(),
                    "Test fixture counterexample.", List.of(),
                    new CaseDefinitionCatalog.Requirements(List.of(), "none"),
                    false, null, DIGEST));
            obligations.add(new CoverageCatalog.Obligation(
                    obligation, "TEST", com.samlscope.core.evaluation.Rfc2119Level.MUST,
                    List.of(profile.role()), null, CoverageCatalog.Testability.AUTOMATED,
                    CoverageCatalog.ProfileScope.CORE));
        }
        var definitions = new CaseDefinitionCatalog(cases);
        return definition(profile, definitions, new CoverageCatalog(obligations), caseIds);
    }

    public static FunctionalCaseDefinition forObligations(
            FunctionalProfile profile, CoverageCatalog coverage, String... obligationKeys) {
        var mapping = new java.util.LinkedHashMap<String,String>();
        for (var index = 0; index < obligationKeys.length; index++) {
            mapping.put("fixture-" + index, obligationKeys[index]);
        }
        return forCases(profile, coverage, mapping);
    }

    public static FunctionalCaseDefinition forCases(
            FunctionalProfile profile, CoverageCatalog coverage, Map<String,String> caseOwners) {
        return forCases(profile, coverage, caseOwners, Set.of());
    }

    public static FunctionalCaseDefinition forCases(
            FunctionalProfile profile, CoverageCatalog coverage, Map<String,String> caseOwners,
            Set<String> nonExecutableObligations) {
        var cases = new java.util.ArrayList<CaseDefinitionCatalog.CaseDefinition>();
        var ids = new java.util.ArrayList<String>();
        for (var entry : caseOwners.entrySet()) {
            var id = entry.getKey();
            ids.add(id);
            cases.add(new CaseDefinitionCatalog.CaseDefinition(
                    id, entry.getValue(), profile.role(),
                    CaseDefinitionCatalog.ExecutionMode.AUTOMATED,
                    CaseDefinitionCatalog.Milestone.M1,
                    List.of(), Map.of(), List.of(), List.of(), List.of(),
                    "Test fixture counterexample.", List.of(),
                    new CaseDefinitionCatalog.Requirements(List.of(), "none"),
                    false, null, DIGEST));
        }
        var definitions = new CaseDefinitionCatalog(cases);
        var references = ids.stream().map(id ->
                new FunctionalCaseDefinition.CaseReference(id, definitions.require(id).caseDigest())).toList();
        return new FunctionalCaseDefinition(
                "test-v1", profile, Map.of("test", DIGEST), references,
                nonExecutableObligations, definitions, coverage);
    }
}
