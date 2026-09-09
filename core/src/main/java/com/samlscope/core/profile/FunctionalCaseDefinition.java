package com.samlscope.core.profile;

import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.plan.TargetRole;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Immutable functional profile definition whose execution units are approved G2 cases. */
public final class FunctionalCaseDefinition {
    private final String version;
    private final FunctionalProfile profile;
    private final Map<String, String> sourceDigests;
    private final List<CaseDefinitionCatalog.CaseDefinition> cases;
    private final Set<String> nonExecutableObligations;

    public FunctionalCaseDefinition(
            String version,
            FunctionalProfile profile,
            Map<String, String> sourceDigests,
            List<CaseReference> caseReferences,
            Set<String> nonExecutableObligations,
            CaseDefinitionCatalog approvedCases,
            CoverageCatalog coverage) {
        this.version = text(version, "definition version");
        this.profile = Objects.requireNonNull(profile, "profile");
        this.sourceDigests = Map.copyOf(Objects.requireNonNull(sourceDigests, "sourceDigests"));
        if (this.sourceDigests.isEmpty()) throw new IllegalArgumentException("Source digests are required");
        this.sourceDigests.forEach((path, digest) -> {
            text(path, "source path");
            if (digest == null || !digest.matches("sha256:[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Invalid source digest: " + path);
            }
        });

        var selected = new ArrayList<CaseDefinitionCatalog.CaseDefinition>();
        var ids = new LinkedHashSet<String>();
        for (var reference : List.copyOf(caseReferences == null ? List.of() : caseReferences)) {
            Objects.requireNonNull(reference, "case reference");
            if (!ids.add(reference.id())) throw new IllegalArgumentException("Duplicate case: " + reference.id());
            var approved = approvedCases.require(reference.id());
            if (!approved.caseDigest().equals(reference.digest())) {
                throw new IllegalArgumentException("Approved case digest changed: " + reference.id());
            }
            if (approved.role() != profile.role()) {
                throw new IllegalArgumentException("Case role differs from profile: " + reference.id());
            }
            selected.add(approved);
        }
        if (selected.isEmpty()) throw new IllegalArgumentException("Functional profile must contain cases");
        this.cases = List.copyOf(selected);

        var obligations = coverage.byKey();
        var noCases = new LinkedHashSet<String>();
        for (var key : Set.copyOf(nonExecutableObligations == null ? Set.of() : nonExecutableObligations)) {
            var obligation = obligations.get(key);
            if (obligation == null) throw new IllegalArgumentException("Unknown non-executable obligation: " + key);
            if (obligation.testability() != CoverageCatalog.Testability.NOT_OBSERVABLE) {
                throw new IllegalArgumentException("Executable obligation cannot bypass a case: " + key);
            }
            if (!obligation.roles().contains(profile.role())) {
                throw new IllegalArgumentException("Non-executable obligation role differs from profile: " + key);
            }
            noCases.add(key);
        }
        this.nonExecutableObligations = Set.copyOf(noCases);
    }

    public String version() { return version; }
    public FunctionalProfile profile() { return profile; }
    public Map<String, String> sourceDigests() { return sourceDigests; }
    public List<CaseDefinitionCatalog.CaseDefinition> cases() { return cases; }
    public Set<String> caseIds() {
        return cases.stream().map(CaseDefinitionCatalog.CaseDefinition::id)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }
    public Set<String> nonExecutableObligations() { return nonExecutableObligations; }

    /** Selects owner arithmetic without using the obsolete Core/Full catalog tag. */
    public CoverageCatalog selectedCoverage(CoverageCatalog coverage) {
        var keys = new LinkedHashSet<String>(nonExecutableObligations);
        cases.forEach(definition -> keys.add(definition.obligation()));
        var selected = coverage.obligations().stream().filter(value -> keys.contains(value.key())).toList();
        if (selected.size() != keys.size()) throw new IllegalArgumentException("Profile has unknown obligation owners");
        return new CoverageCatalog(selected);
    }

    public record CaseReference(String id, String digest) {
        public CaseReference {
            id = text(id, "case ID");
            if (digest == null || !digest.matches("sha256:[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Invalid case digest");
            }
        }
    }

    private static String text(String value, String label) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(label + " must not be blank");
        return value;
    }
}
