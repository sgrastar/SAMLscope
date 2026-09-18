package com.samlscope.runner.cases;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.casedef.CaseDefinitionCatalog.CaseDefinition;
import com.samlscope.core.casedef.CaseDefinitionCatalog.ExecutionMode;
import com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.CaseImplementationAudit;
import com.samlscope.runner.TestCaseRegistry;
import com.samlscope.core.transcript.TranscriptContentReader;

/** Builds the M1 CONFIG slice as a configuration gate followed by explicit evidence review. */
public final class ApprovedConfigCaseRegistry {
    private static final Duration CONFIG_TTL = Duration.ofDays(7);
    private static final Duration EVIDENCE_TTL = Duration.ofDays(7);

    private ApprovedConfigCaseRegistry() {}

    public static TestCaseRegistry withMultipleDecryptionKeys(TestCaseRegistry registry,
            Function<String,com.samlscope.runner.SupplementalDecryptionKeyService.KeySet> keys,
            java.util.function.BiFunction<String,String,java.util.Optional<com.samlscope.core.caseexec.CaseExecution>> executions) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                MultipleDecryptionKeysConfigurationTestCase.ID.equals(testCase.id())
                        ? (TestCase)new MultipleDecryptionKeysConfigurationTestCase(testCase,keys,executions) : testCase).toList());
    }

    public static TestCaseRegistry create(CaseDefinitionCatalog definitions) {
        return create(definitions, Milestone.M1);
    }

    public static TestCaseRegistry create(CaseDefinitionCatalog definitions, Milestone milestone) {
        return create(definitions, milestone, null, null, null);
    }

    public static TestCaseRegistry create(
            CaseDefinitionCatalog definitions, Milestone milestone, Function<String, byte[]> targetMetadata) {
        return create(definitions, milestone, targetMetadata, null, null);
    }

    public static TestCaseRegistry create(
            CaseDefinitionCatalog definitions,
            Milestone milestone,
            Function<String, byte[]> targetMetadata,
            TranscriptContentReader transcriptContent,
            SamlDecryptionKeyProvider decryptionKeys) {
        return create(definitions,milestone,targetMetadata,transcriptContent,decryptionKeys,(run,variant)->java.util.Optional.empty());
    }

    public static TestCaseRegistry create(CaseDefinitionCatalog definitions, Milestone milestone,
            Function<String, byte[]> targetMetadata, TranscriptContentReader transcriptContent,
            SamlDecryptionKeyProvider decryptionKeys,
            java.util.function.BiFunction<String,String,java.util.Optional<com.samlscope.saml.crypto.PlanCredentials>> metadataKeys) {
        Objects.requireNonNull(definitions, "definitions");
        Objects.requireNonNull(milestone, "milestone");
        var cases = new ArrayList<TestCase>();
        definitions.cases().stream()
                .filter(value -> value.milestone() == milestone)
                .filter(value -> value.mode() == ExecutionMode.CONFIG)
                .map(value -> createCase(value, targetMetadata, transcriptContent, decryptionKeys, metadataKeys))
                .forEach(cases::add);
        var registry = new TestCaseRegistry(cases);
        CaseImplementationAudit.requireExact(definitions, registry, milestone, ExecutionMode.CONFIG);
        return registry;
    }

    private static TestCase createCase(
            CaseDefinition definition,
            Function<String, byte[]> targetMetadata,
            TranscriptContentReader transcriptContent,
            SamlDecryptionKeyProvider decryptionKeys,
            java.util.function.BiFunction<String,String,java.util.Optional<com.samlscope.saml.crypto.PlanCredentials>> metadataKeys) {
        if (List.of(
                "IIP-MD03-e-idp-01", "IIP-MD05-at-idp-01", "IIP-MD05-au-idp-01",
                "IIP-MD05-c4-idp-01", "IIP-MD06-a4-idp-01", "IIP-MD06-aa-idp-01")
                .contains(definition.id())) {
            return new InformationalChoiceTestCase(definition.id(), definition.role());
        }
        var metadata = MetadataConfigCaseFactory.create(definition);
        if (metadata.isPresent()) return metadata.orElseThrow();
        var evidence = new AttestedOutcomeTestCase(
                definition.id(), definition.role(), "case." + definition.id() + ".evidence",
                evidencePrompt(definition), EVIDENCE_TTL,
                List.of(
                        AttestationOption.of(
                                "evidence_satisfies", Outcome.SATISFIED, "configuration.evidence-satisfies"),
                        AttestationOption.of(
                                "evidence_violates", Outcome.VIOLATED, "configuration.evidence-violates"),
                        AttestationOption.notVerified(
                                "unable_to_verify", "configuration.evidence-unavailable",
                                "configuration_evidence_unavailable")));
        var fallback = new ConfigurationGateTestCase(
                evidence,
                "case." + definition.id() + ".configuration",
                configurationPrompt(definition),
                CONFIG_TTL,
                definition.configurationFailureSemantics());
        if (targetMetadata != null && transcriptContent != null && decryptionKeys != null && AttributeNameConfigurationTestCase.ID.equals(definition.id())) {
            return new AttributeNameConfigurationTestCase(fallback,transcriptContent,targetMetadata,decryptionKeys);
        }
        if (targetMetadata != null && transcriptContent != null && MetadataAlgorithmConfigurationTestCase.supports(definition.id())) {
            return new MetadataAlgorithmConfigurationTestCase(fallback, transcriptContent, targetMetadata, metadataKeys);
        }
        if (targetMetadata != null && TargetMetadataObservation.supports(definition.id())) {
            return new AutoConfigurationEvidenceTestCase(fallback, targetMetadata);
        }
        if (transcriptContent != null && decryptionKeys != null
                && TranscriptConfigurationObservation.supports(definition.id())) {
            return new AutoConfigurationTranscriptEvidenceTestCase(
                    fallback, transcriptContent, decryptionKeys);
        }
        return fallback;
    }

    private static String configurationPrompt(CaseDefinition definition) {
        return "Prepare the target configuration required by the approved case " + definition.id()
                + ". Confirm only after the configuration is active. If the capability is absent, unavailable, or "
                + "undetermined, choose the matching answer so the common configuration semantics can be applied.";
    }

    private static String evidencePrompt(CaseDefinition definition) {
        var value = new StringBuilder()
                .append("Execute the approved CONFIG evidence plan for ")
                .append(definition.obligation())
                .append(" after the target configuration has been confirmed. Select a conclusive result only when ")
                .append("the observed evidence supports it; otherwise select unable_to_verify.\n\nEvidence instructions:\n");
        definition.variantPlan().forEach(item -> value.append("- ").append(item.instructionEn()).append('\n'));
        value.append("\nRequired controls:\n");
        definition.controls().forEach(item -> value.append("- ").append(item.descriptionEn()).append('\n'));
        if (!definition.interpretationConstraints().isEmpty()) {
            value.append("\nInterpretation constraints:\n");
            definition.interpretationConstraints().forEach(item -> value.append("- ").append(item).append('\n'));
        }
        value.append("\nCounterexample to avoid:\n").append(definition.counterexampleEn());
        return value.toString();
    }
}
