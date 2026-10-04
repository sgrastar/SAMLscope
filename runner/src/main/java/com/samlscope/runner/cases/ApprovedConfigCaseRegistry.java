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

    public static TestCaseRegistry withMetadataKeySelection(TestCaseRegistry registry,
            TranscriptContentReader content, Function<String, byte[]> metadata, java.nio.file.Path directory) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                MetadataKeySelectionConfigurationTestCase.supports(testCase.id())
                        ? (TestCase)new MetadataKeySelectionConfigurationTestCase(testCase, content, metadata, directory)
                        : testCase).toList());
    }

    public static TestCaseRegistry withMetadataRejection(TestCaseRegistry registry,
            TranscriptContentReader content, Function<String, byte[]> metadata, java.nio.file.Path directory) {
        return new TestCaseRegistry(registry.all().stream().map(testCase -> {
            if (MetadataPublisherKeyInventoryConfigurationTestCase.supports(testCase.id())
                    && testCase.role() == com.samlscope.core.plan.TargetRole.IDP
                    && testCase instanceof ConfigurationPrompt && testCase instanceof AttestationPrompt
                    && !(testCase instanceof MetadataPublisherKeyInventoryConfigurationTestCase)) {
                return (TestCase) new MetadataPublisherKeyInventoryConfigurationTestCase(testCase, content, metadata,
                        directory.toAbsolutePath().normalize().getParent().resolve("metadata-publisher-key-evidence"));
            }
            if (MetadataFullUiConfigurationTestCase.CASE.equals(testCase.id())) {
                return withNativeFullUi(testCase, directory.toAbsolutePath().normalize().getParent(), content, metadata);
            }
            if (MetadataSchemaAdmissionConfigurationTestCase.ID.equals(testCase.id())
                    && !(testCase instanceof MetadataSchemaAdmissionConfigurationTestCase)) {
                return (TestCase) new MetadataSchemaAdmissionConfigurationTestCase(testCase, content, metadata, directory);
            }
            if (KeycloakMdiopRepresentationEvidenceFile.ID.equals(testCase.id())
                    && testCase instanceof MetadataFixtureObservationTestCase) {
                return (TestCase) new KeycloakMdiopRepresentationConfigurationTestCase(
                        testCase, content, metadata, directory);
            }
            if (MetadataRefreshConfigurationTestCase.ID.equals(testCase.id())) {
                return (TestCase) new MetadataRefreshConfigurationTestCase(testCase, content, directory);
            }
            if (MdqAcquisitionConfigurationTestCase.ID.equals(testCase.id())) {
                return (TestCase) new MdqAcquisitionConfigurationTestCase(testCase, content, directory);
            }
            if (PublisherRootSignatureConfigurationTestCase.ID.equals(testCase.id())) {
                return (TestCase) new PublisherRootSignatureConfigurationTestCase(testCase, metadata, directory);
            }
            if (MetadataRejectionConfigurationTestCase.supports(testCase.id())
                    && testCase instanceof MetadataFixtureObservationTestCase) {
                return (TestCase) new MetadataRejectionConfigurationTestCase(testCase, content, metadata, directory);
            }
            // Acceptance of a metadata document only decides MD03.b/c once the Run proves the target
            // verifies the document signature with an out-of-band anchor. The same Run-scoped evidence
            // directory carries that product-independent proof.
            if (MetadataSignatureVerificationConfigurationTestCase.supports(testCase.id())
                    && testCase instanceof MetadataFixtureObservationTestCase) {
                return (TestCase) new MetadataSignatureVerificationConfigurationTestCase(
                        testCase, content, metadata, directory);
            }
            return testCase;
        }).toList());
    }

    public static TestCaseRegistry withNativeCertificates(TestCaseRegistry registry,
            TranscriptContentReader content, Function<String, byte[]> metadata, java.nio.file.Path directory) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                NativeCertificateConfigurationTestCase.supports(testCase.id())
                        ? (TestCase)new NativeCertificateConfigurationTestCase(testCase, content, metadata, directory)
                        : testCase).toList());
    }

    public static TestCaseRegistry withAttributePolicyPreparation(TestCaseRegistry registry,
            TranscriptContentReader content, Function<String, byte[]> metadata,
            java.util.function.BiFunction<String,String,java.util.Optional<com.samlscope.saml.crypto.PlanCredentials>> keys,
            java.nio.file.Path directory) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                testCase instanceof SubjectConfirmationConfigurationTestCase subjectConfirmation
                        ? (TestCase)subjectConfirmation.withMetadataKeys(keys)
                        : AttributePolicyConfigurationTestCase.supports(testCase.id())
                        ? (TestCase)new AttributePolicyConfigurationTestCase(testCase, content, metadata, keys, directory)
                        : testCase).toList());
    }

    public static TestCaseRegistry withAuthnContextPreparation(TestCaseRegistry registry,
            TranscriptContentReader content, Function<String, byte[]> metadata,
            java.util.function.BiFunction<String,String,java.util.Optional<com.samlscope.saml.crypto.PlanCredentials>> keys,
            java.nio.file.Path directory) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                AuthnContextConfigurationTestCase.supports(testCase.id())
                        ? (TestCase)new AuthnContextConfigurationTestCase(testCase, content, metadata, keys, directory)
                        : testCase).toList());
    }

    public static TestCaseRegistry withNameIdOmissionPreparation(TestCaseRegistry registry,
            TranscriptContentReader content, Function<String, byte[]> metadata,
            java.util.function.BiFunction<String,String,java.util.Optional<com.samlscope.saml.crypto.PlanCredentials>> keys,
            java.nio.file.Path directory) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                NameIdOmissionConfigurationTestCase.supports(testCase.id())
                        ? (TestCase)new NameIdOmissionConfigurationTestCase(testCase, content, metadata, keys, directory)
                        : testCase).toList());
    }

    public static TestCaseRegistry withRelyingPartyAttributePreparation(TestCaseRegistry registry,
            TranscriptContentReader content, Function<String, byte[]> metadata,
            java.util.function.BiFunction<String,String,java.util.Optional<com.samlscope.saml.crypto.PlanCredentials>> keys,
            java.nio.file.Path directory) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                RelyingPartyAttributeConfigurationTestCase.supports(testCase.id())
                        ? (TestCase)new RelyingPartyAttributeConfigurationTestCase(testCase, content, metadata, keys, directory)
                        : testCase).toList());
    }

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
        if (metadata.isPresent()) {
            var candidate = metadata.orElseThrow();
            TestCase prepared = candidate;
            if (MetadataFullUiConfigurationTestCase.CASE.equals(definition.id())) {
                return withNativeFullUi(prepared, SuiteRunProfileLookup.configuredDataDirectory(),
                        transcriptContent, targetMetadata);
            }
            if (targetMetadata != null && transcriptContent != null && decryptionKeys != null
                    && ShibbolethEntityIdUniquenessEvidence.CASE.equals(definition.id())
                    && candidate instanceof MetadataFixtureObservationTestCase fixture) {
                prepared = new EntityIdUniquenessConfigurationTestCase(fixture, transcriptContent, targetMetadata,
                        decryptionKeys, SuiteRunProfileLookup.configuredDataDirectory().resolve("entityid-uniqueness-evidence"));
            }
            if (targetMetadata != null && transcriptContent != null && decryptionKeys != null
                    && MetadataEntityIdentityConfigurationTestCase.IDS.contains(definition.id())) {
                return new MetadataEntityIdentityConfigurationTestCase(prepared,
                        SuiteRunProfileLookup.configuredDataDirectory().resolve("keycloak-metadata-entity-identity-evidence"),
                        transcriptContent, targetMetadata, decryptionKeys);
            }
            return prepared;
        }
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
        if (targetMetadata != null && transcriptContent != null && metadataKeys != null
                && MetadataValidityConfigurationTestCase.ID.equals(definition.id())) {
            return new MetadataValidityConfigurationTestCase(fallback,
                    SuiteRunProfileLookup.configuredDataDirectory().resolve("metadata-validity-evidence"),
                    transcriptContent, targetMetadata, metadataKeys);
        }
        if (targetMetadata != null && transcriptContent != null && metadataKeys != null
                && MetadataRoleKeyProbeTestCase.CASE.equals(definition.id())) {
            return new MetadataRoleKeyProbeTestCase(fallback, targetMetadata, transcriptContent, metadataKeys,
                    SuiteRunProfileLookup.configuredDataDirectory().resolve("metadata-role-key-evidence"),
                    new SimpleSamlPhpMetadataRoleKeyNativeAdapter(transcriptContent),
                    new KeycloakMetadataRoleKeyNativeAdapter(transcriptContent));
        }
        if (targetMetadata != null && transcriptContent != null && metadataKeys != null
                && MetadataCertificateRuntimeProbeTestCase.CASE.equals(definition.id())) {
            return new MetadataCertificateRuntimeProbeTestCase(fallback, targetMetadata, transcriptContent,
                    metadataKeys, SuiteRunProfileLookup.configuredDataDirectory()
                            .resolve("metadata-certificate-runtime-evidence"),
                    SuiteRunProfileLookup.configuredDataDirectory()
                            .resolve("metadata-certificate-runtime-evidence-simplesamlphp"));
        }
        if (targetMetadata != null && transcriptContent != null
                && SubjectConfirmationConfigurationTestCase.supports(definition.id())) {
            var data = SuiteRunProfileLookup.configuredDataDirectory();
            var profiles = new SuiteRunProfileLookup(data);
            return new SubjectConfirmationConfigurationTestCase(fallback, transcriptContent, targetMetadata,
                    data.resolve("subject-confirmation-evidence"), profiles::profile, metadataKeys);
        }
        if (targetMetadata != null && transcriptContent != null && decryptionKeys != null
                && AuthenticationIdentityConfigurationTestCase.ID.equals(definition.id())) {
            return new AuthenticationIdentityConfigurationTestCase(fallback, transcriptContent, targetMetadata,
                    decryptionKeys, SuiteRunProfileLookup.configuredDataDirectory().resolve("authentication-identity-evidence"));
        }
        if (targetMetadata != null && transcriptContent != null
                && MetadataSupersessionProbeTestCase.supports(definition.id())) {
            return new MetadataSupersessionProbeTestCase(fallback, targetMetadata, transcriptContent,
                    metadataKeys, SuiteRunProfileLookup.configuredDataDirectory().resolve("metadata-rejection-evidence"),
                    decryptionKeys);
        }
        if (targetMetadata != null && transcriptContent != null && decryptionKeys != null
                && AlgorithmPreventionConfigurationTestCase.supports(definition.id())) {
            var data = SuiteRunProfileLookup.configuredDataDirectory();
            var profiles = new SuiteRunProfileLookup(data);
            return new AlgorithmPreventionConfigurationTestCase(
                    fallback, transcriptContent, targetMetadata, decryptionKeys, profiles::profile,
                    data.resolve("algorithm-prevention-evidence"));
        }
        if (targetMetadata != null && transcriptContent != null && decryptionKeys != null && AttributeNameConfigurationTestCase.ID.equals(definition.id())) {
            return new AttributeNameConfigurationTestCase(fallback,transcriptContent,targetMetadata,decryptionKeys);
        }
        if (targetMetadata != null && transcriptContent != null && MetadataAlgorithmConfigurationTestCase.supports(definition.id())) {
            var algorithm = new MetadataAlgorithmConfigurationTestCase(fallback, transcriptContent, targetMetadata, metadataKeys);
            if (KeycloakAlgorithmPreferenceEvidenceFile.CASES.contains(definition.id())) {
                return new KeycloakAlgorithmPreferenceConfigurationTestCase(algorithm, transcriptContent, targetMetadata,
                        SuiteRunProfileLookup.configuredDataDirectory().resolve("metadata-rejection-evidence"));
            }
            return algorithm;
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

    static TestCase withNativeFullUi(TestCase fallback, java.nio.file.Path data,
            TranscriptContentReader transcriptContent, Function<String, byte[]> targetMetadata) {
        if (fallback instanceof MetadataFullUiConfigurationTestCase) return fallback;
        var bridge = new KeycloakNativeRunEvidenceBridge(data);
        var content = transcriptContent == null
                ? (TranscriptContentReader) bridge::content : transcriptContent;
        return new MetadataFullUiConfigurationTestCase(fallback,
                new ShibbolethMetadataFullUiEvidence(data.resolve("metadata-full-ui-evidence"), content),
                targetMetadata == null ? bridge::targetMetadata : targetMetadata);
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
