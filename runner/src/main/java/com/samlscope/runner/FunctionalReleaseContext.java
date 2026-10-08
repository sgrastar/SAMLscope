package com.samlscope.runner;

import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.profile.*;
import com.samlscope.runner.result.EvaluationArtifactDigests;
import com.samlscope.runner.result.ResultDocumentContext;
import java.util.*;

/** One exact installed release and its own catalogs; a profile name never selects a replacement. */
public final class FunctionalReleaseContext {
    public enum Kind { CURRENT, HISTORICAL }
    public static final Set<String> SOURCE_PATHS = Set.of("tests/coverage.yaml", "tests/cases.yaml",
            "tests/predicates.yaml", "tests/specs.yaml", "tests/feasibility.yaml",
            "tests/mutants/baselines.yaml", "tests/mutants/catalog.yaml", "tests/mutants/control-mutants.yaml");
    private final FunctionalDefinitionIdentity identity;
    private final FunctionalCaseDefinition definition;
    private final CaseDefinitionCatalog cases;
    private final CoverageCatalog coverage;
    private final PredicateCatalog predicates;
    private final SourceInventory sourceInventory;
    private final Kind kind;
    private final String sourceCommit;
    private final ResultDocumentContext.EvaluationComponents components;

    public FunctionalReleaseContext(FunctionalDefinitionIdentity identity, FunctionalCaseDefinition definition,
            CaseDefinitionCatalog cases, CoverageCatalog coverage, PredicateCatalog predicates,
            Map<String,byte[]> sourceBytes, Kind kind, String sourceCommit) {
        this(identity, definition, cases, coverage, predicates, new SourceInventory(sourceBytes), kind, sourceCommit);
    }

    public FunctionalReleaseContext(FunctionalDefinitionIdentity identity, FunctionalCaseDefinition definition,
            CaseDefinitionCatalog cases, CoverageCatalog coverage, PredicateCatalog predicates,
            SourceInventory sourceInventory, Kind kind, String sourceCommit) {
        this.identity = Objects.requireNonNull(identity);
        this.definition = Objects.requireNonNull(definition);
        this.cases = Objects.requireNonNull(cases);
        this.coverage = Objects.requireNonNull(coverage);
        this.predicates = Objects.requireNonNull(predicates);
        this.kind = Objects.requireNonNull(kind);
        if (identity.profile() != definition.profile() || !identity.version().equals(definition.version()))
            throw new IllegalArgumentException("Definition identity differs from release");
        if (sourceCommit != null && !sourceCommit.matches("[0-9a-f]{40}"))
            throw new IllegalArgumentException("Invalid release source revision");
        if (kind == Kind.HISTORICAL && sourceCommit == null)
            throw new IllegalArgumentException("Historical release requires its verified source revision");
        this.sourceCommit = sourceCommit;
        this.sourceInventory = Objects.requireNonNull(sourceInventory, "sourceInventory");
        definition.sourceDigests().forEach((path,digest) -> {
            if (!digest.equals(sourceInventory.digests().get(path)))
                throw new IllegalArgumentException("Release source digest differs: " + path);
        });
        for (var selected : definition.cases()) {
            if (!selected.caseDigest().equals(cases.require(selected.id()).caseDigest()))
                throw new IllegalArgumentException("Release case digest differs");
        }
        definition.selectedCoverage(coverage);
        for (var obligation : coverage.obligations()) {
            if (obligation.condition() != null && !predicates.byKey().containsKey(obligation.condition()))
                throw new IllegalArgumentException("Release predicate is unavailable");
        }
        components = sourceInventory.components();
    }

    public FunctionalDefinitionIdentity identity() { return identity; }
    public FunctionalCaseDefinition definition() { return definition; }
    public CaseDefinitionCatalog cases() { return cases; }
    public CoverageCatalog coverage() { return coverage; }
    public PredicateCatalog predicates() { return predicates; }
    public Kind kind() { return kind; }
    public Optional<String> sourceCommit() { return Optional.ofNullable(sourceCommit); }
    public ResultDocumentContext.EvaluationComponents components() { return components; }
    public SourceInventory sourceInventory() { return sourceInventory; }
    public byte[] sourceBytes(String path) { return sourceInventory.bytes(path); }
    public Map<String,String> sourceDigests() { return sourceInventory.digests(); }

    /** One owning release inventory; callers can neither mutate its ingress nor its reads. */
    public static final class SourceInventory {
        private final Map<String,byte[]> bytes;
        private final Map<String,String> digests;
        private final ResultDocumentContext.EvaluationComponents components;
        public SourceInventory(Map<String,byte[]> sourceBytes) {
            if (!SOURCE_PATHS.equals(Objects.requireNonNull(sourceBytes).keySet()))
                throw new IllegalArgumentException("Release source inventory differs");
            var originals = new LinkedHashMap<String,byte[]>();
            var hashes = new LinkedHashMap<String,String>();
            sourceBytes.forEach((path,value) -> {
                if (value == null || value.length == 0) throw new IllegalArgumentException("Missing release source bytes");
                byte[] owned = value.clone(); originals.put(path,owned);
                hashes.put(path,EvaluationArtifactDigests.digestBytes(owned));
            });
            bytes = Collections.unmodifiableMap(originals); digests = Map.copyOf(hashes);
            var definitions = new LinkedHashMap<String,byte[]>();
            for (var path : SOURCE_PATHS) if (!Set.of("tests/coverage.yaml","tests/predicates.yaml","tests/specs.yaml").contains(path))
                definitions.put(path,originals.get(path));
            components = EvaluationArtifactDigests.fromDocuments(originals.get("tests/coverage.yaml"),definitions,originals.get("tests/specs.yaml"));
        }
        public byte[] bytes(String path) {
            var value = bytes.get(path);
            if (value == null) throw new IllegalArgumentException("Unknown release source path");
            return value.clone();
        }
        public Map<String,String> digests() { return digests; }
        public ResultDocumentContext.EvaluationComponents components() { return components; }
        public boolean matches(Map<String,byte[]> other) {
            return other != null && SOURCE_PATHS.equals(other.keySet())
                    && bytes.entrySet().stream().allMatch(e -> Arrays.equals(e.getValue(),other.get(e.getKey())));
        }
    }
    public Evaluator.FunctionalEvaluation evaluate(List<ApplicabilityEvaluation> applicability,
            List<CaseRun> completed, List<SuiteIncident> incidents) {
        return Evaluator.evaluateFunctionalCaseSnapshot(definition,coverage,applicability,completed,incidents);
    }
}
