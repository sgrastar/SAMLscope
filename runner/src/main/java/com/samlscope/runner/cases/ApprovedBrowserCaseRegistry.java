package com.samlscope.runner.cases;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.security.cert.X509Certificate;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.casedef.CaseDefinitionCatalog.CaseDefinition;
import com.samlscope.core.casedef.CaseDefinitionCatalog.ExecutionMode;
import com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.CaseImplementationAudit;
import com.samlscope.runner.TestCaseRegistry;

/** Builds the complete manual-user-agent M1 BROWSER slice from the signed G2 instructions. */
public final class ApprovedBrowserCaseRegistry {
    private static final Duration BROWSER_TTL = Duration.ofDays(7);
    private static final Duration EVIDENCE_TTL = Duration.ofDays(7);

    private ApprovedBrowserCaseRegistry() {}

    public static TestCaseRegistry withBasicLogout(TestCaseRegistry registry,
            java.util.function.Function<String, IdpBasicLogoutScenarioTestCase.Configuration> configurations) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                IdpBasicLogoutScenarioTestCase.ID.equals(testCase.id())
                        ? (com.samlscope.core.caseexec.TestCase)new IdpBasicLogoutScenarioTestCase(configurations)
                        : testCase).toList());
    }

    public static TestCaseRegistry withLogoutScenarios(TestCaseRegistry registry,
            java.util.function.BiFunction<String, String, IdpBasicLogoutScenarioTestCase.Configuration> configurations) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                java.util.Set.of(IdpBasicLogoutScenarioTestCase.ID, IdpBasicLogoutScenarioTestCase.REDIRECT_ID, IdpBasicLogoutScenarioTestCase.ENCRYPTED_ID, IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID).contains(testCase.id())
                        ? (com.samlscope.core.caseexec.TestCase)new IdpBasicLogoutScenarioTestCase(testCase.id(),
                                runId -> configurations.apply(testCase.id(), runId))
                        : testCase).toList());
    }

    public static TestCaseRegistry withPublishedMetadata(TestCaseRegistry registry,
            java.util.function.Function<String, byte[]> metadata,
            java.util.function.Function<String, java.util.Optional<String>> entityIds) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                PublishedUiUrlTestCase.ID.equals(testCase.id())
                        ? (com.samlscope.core.caseexec.TestCase) new PublishedUiUrlTestCase(metadata, entityIds)
                        : testCase).toList());
    }

    public static TestCaseRegistry create(CaseDefinitionCatalog definitions, URI publicBase) {
        return create(definitions, publicBase, Milestone.M1, null);
    }

    public static TestCaseRegistry create(
            CaseDefinitionCatalog definitions, URI publicBase, TranscriptContentReader transcriptContent) {
        return create(
                definitions, publicBase, Milestone.M1, transcriptContent,
                ignored -> java.util.Optional.empty(), ignored -> java.util.Optional.empty(),
                ignored -> List.of(), null, ignored -> java.util.Optional.empty());
    }

    public static TestCaseRegistry create(
            CaseDefinitionCatalog definitions,
            URI publicBase,
            TranscriptContentReader transcriptContent,
            SamlDecryptionKeyProvider decryptionKeys) {
        return create(
                definitions, publicBase, Milestone.M1, transcriptContent, decryptionKeys,
                ignored -> java.util.Optional.empty(), ignored -> List.of(), null,
                ignored -> java.util.Optional.empty());
    }

    public static TestCaseRegistry create(
            CaseDefinitionCatalog definitions,
            URI publicBase,
            TranscriptContentReader transcriptContent,
            SamlDecryptionKeyProvider decryptionKeys,
            java.util.function.Function<String, java.util.Optional<String>> targetEntityIds) {
        return create(
                definitions, publicBase, Milestone.M1, transcriptContent,
                decryptionKeys, targetEntityIds, ignored -> List.of(), null,
                ignored -> java.util.Optional.empty());
    }

    public static TestCaseRegistry create(
            CaseDefinitionCatalog definitions,
            URI publicBase,
            TranscriptContentReader transcriptContent,
            SamlDecryptionKeyProvider decryptionKeys,
            java.util.function.Function<String, java.util.Optional<String>> targetEntityIds,
            java.util.function.Function<String, IdpErrorProbeConfiguration> idpScenarioConfigurations) {
        return create(definitions, publicBase, transcriptContent, decryptionKeys, targetEntityIds,
                ignored -> List.of(), idpScenarioConfigurations);
    }

    public static TestCaseRegistry create(
            CaseDefinitionCatalog definitions,
            URI publicBase,
            TranscriptContentReader transcriptContent,
            SamlDecryptionKeyProvider decryptionKeys,
            java.util.function.Function<String, java.util.Optional<String>> targetEntityIds,
            java.util.function.Function<String, List<X509Certificate>> targetSigningCertificates,
            java.util.function.Function<String, IdpErrorProbeConfiguration> idpScenarioConfigurations) {
        return create(definitions, publicBase, transcriptContent, decryptionKeys, targetEntityIds,
                targetSigningCertificates, idpScenarioConfigurations,
                ignored -> java.util.Optional.empty());
    }

    public static TestCaseRegistry create(
            CaseDefinitionCatalog definitions,
            URI publicBase,
            TranscriptContentReader transcriptContent,
            SamlDecryptionKeyProvider decryptionKeys,
            java.util.function.Function<String, java.util.Optional<String>> targetEntityIds,
            java.util.function.Function<String, List<X509Certificate>> targetSigningCertificates,
            java.util.function.Function<String, IdpErrorProbeConfiguration> idpScenarioConfigurations,
            SamlPlanCredentialsProvider suiteCredentials) {
        return create(
                definitions, publicBase, Milestone.M1, transcriptContent,
                decryptionKeys, targetEntityIds, targetSigningCertificates,
                idpScenarioConfigurations, suiteCredentials);
    }

    public static TestCaseRegistry create(
            CaseDefinitionCatalog definitions, URI publicBase, Milestone milestone) {
        return create(definitions, publicBase, milestone, null);
    }

    public static TestCaseRegistry create(
            CaseDefinitionCatalog definitions,
            URI publicBase,
            Milestone milestone,
            TranscriptContentReader transcriptContent,
            SamlDecryptionKeyProvider decryptionKeys,
            java.util.function.Function<String, java.util.Optional<String>> targetEntityIds,
            java.util.function.Function<String, List<X509Certificate>> targetSigningCertificates) {
        return create(
                definitions, publicBase, milestone, transcriptContent, decryptionKeys,
                targetEntityIds, targetSigningCertificates, null, ignored -> java.util.Optional.empty());
    }

    public static TestCaseRegistry create(
            CaseDefinitionCatalog definitions,
            URI publicBase,
            Milestone milestone,
            TranscriptContentReader transcriptContent) {
        return create(
                definitions, publicBase, milestone, transcriptContent,
                ignored -> java.util.Optional.empty(), ignored -> java.util.Optional.empty(),
                ignored -> List.of(), null, ignored -> java.util.Optional.empty());
    }

    public static TestCaseRegistry create(
            CaseDefinitionCatalog definitions,
            URI publicBase,
            Milestone milestone,
            TranscriptContentReader transcriptContent,
            SamlDecryptionKeyProvider decryptionKeys,
            java.util.function.Function<String, java.util.Optional<String>> targetEntityIds,
            java.util.function.Function<String, List<X509Certificate>> targetSigningCertificates,
            java.util.function.Function<String, IdpErrorProbeConfiguration> idpScenarioConfigurations,
            SamlPlanCredentialsProvider suiteCredentials) {
        Objects.requireNonNull(definitions, "definitions");
        Objects.requireNonNull(publicBase, "publicBase");
        Objects.requireNonNull(milestone, "milestone");
        Objects.requireNonNull(decryptionKeys, "decryptionKeys");
        var cases = new ArrayList<com.samlscope.core.caseexec.TestCase>();
        definitions.cases().stream()
                .filter(value -> value.milestone() == milestone)
                .filter(value -> value.mode() == ExecutionMode.BROWSER)
                .map(value -> createCase(
                        value, publicBase, transcriptContent, decryptionKeys, targetEntityIds,
                        targetSigningCertificates, idpScenarioConfigurations, suiteCredentials))
                .forEach(cases::add);
        var registry = new TestCaseRegistry(cases);
        CaseImplementationAudit.requireExact(definitions, registry, milestone, ExecutionMode.BROWSER);
        return registry;
    }

    private static com.samlscope.core.caseexec.TestCase createCase(
            CaseDefinition definition,
            URI publicBase,
            TranscriptContentReader transcriptContent,
            SamlDecryptionKeyProvider decryptionKeys,
            java.util.function.Function<String, java.util.Optional<String>> targetEntityIds,
            java.util.function.Function<String, List<X509Certificate>> targetSigningCertificates,
            java.util.function.Function<String, IdpErrorProbeConfiguration> idpScenarioConfigurations,
            SamlPlanCredentialsProvider suiteCredentials) {
        if (EcSignatureSupportTestCase.ID.equals(definition.id())) return new EcSignatureSupportTestCase();
        if ("IIP-IDP12-c-idp-01".equals(definition.id())) {
            return new MetadataFixtureObservationTestCase(definition.id(), definition.role(), List.of(
                    new MetadataFixtureObservationTestCase.Fixture("default-acs-first",
                            MetadataFixtureObservationTestCase.Behavior.ACCEPT, "select the first explicit default", 0),
                    new MetadataFixtureObservationTestCase.Fixture("default-acs-second",
                            MetadataFixtureObservationTestCase.Behavior.ACCEPT, "follow the changed explicit default", 1),
                    new MetadataFixtureObservationTestCase.Fixture("default-acs-implicit",
                            MetadataFixtureObservationTestCase.Behavior.ACCEPT, "select the first endpoint when defaults are omitted", 0)),
                    com.samlscope.core.caseexec.ConfigurationFailureSemantics.TEST_PRECONDITION);
        }
        if (List.of(
                "IIP-SSO01-bk-idp-01", "IIP-EXT01-b1-idp-01",
                "IIP-EXT01-c1-idp-01", "IIP-ALG05-a-idp-01").contains(definition.id())) {
            return new InformationalChoiceTestCase(definition.id(), definition.role());
        }
        if (idpScenarioConfigurations != null && List.of(
                IdpNameIdPolicyScenarioTestCase.PROCESSING_CASE,
                IdpNameIdPolicyScenarioTestCase.REJECTION_CASE,
                IdpNameIdPolicyScenarioTestCase.CONFORMANCE_CASE).contains(definition.id())) {
            return new IdpNameIdPolicyScenarioTestCase(
                    definition.id(), idpScenarioConfigurations, decryptionKeys);
        }
        if (idpScenarioConfigurations != null && List.of(
                IdpErrorAssertionScenarioTestCase.SUBJECT_ERROR_CASE,
                IdpErrorAssertionScenarioTestCase.ERROR_ASSERTION_CASE).contains(definition.id())) {
            return new IdpErrorAssertionScenarioTestCase(
                    definition.id(), idpScenarioConfigurations);
        }
        if (idpScenarioConfigurations != null
                && IdpUnknownExtensionScenarioTestCase.CASE_ID.equals(definition.id())) {
            return new IdpUnknownExtensionScenarioTestCase(idpScenarioConfigurations);
        }
        if (idpScenarioConfigurations != null
                && IdpExecutableBrowserFixtureScenarioTestCase.CASE_IDS.contains(definition.id())) {
            return new IdpExecutableBrowserFixtureScenarioTestCase(
                    definition.id(), idpScenarioConfigurations, decryptionKeys);
        }
        if (idpScenarioConfigurations != null
                && IdpVersionScenarioTestCase.CASE_ID.equals(definition.id())) {
            return new IdpVersionScenarioTestCase(idpScenarioConfigurations);
        }
        if (idpScenarioConfigurations != null
                && IdpAuthnContextScenarioTestCase.CASE_ID.equals(definition.id())) {
            return new IdpAuthnContextScenarioTestCase(idpScenarioConfigurations);
        }
        if (idpScenarioConfigurations != null
                && IdpDestinationScenarioTestCase.CASE_ID.equals(definition.id())) {
            return new IdpDestinationScenarioTestCase(idpScenarioConfigurations);
        }
        if (idpScenarioConfigurations != null
                && IdpForceAuthnScenarioTestCase.CASE_ID.equals(definition.id())) {
            return new IdpForceAuthnScenarioTestCase(idpScenarioConfigurations);
        }
        if (idpScenarioConfigurations != null && suiteCredentials != null && List.of(
                IdpSignedRequestScenarioTestCase.VERIFY_CASE,
                IdpSignedRequestScenarioTestCase.RELIANCE_CASE,
                IdpSignedRequestScenarioTestCase.ERROR_CASE,
                IdpSignedRequestScenarioTestCase.EXCLUDED_CONTENT_CASE,
                IdpSignedRequestScenarioTestCase.SIGNED_OBJECT_CASE,
                IdpSignedRequestScenarioTestCase.SHA256_DIGEST_CASE,
                IdpSignedRequestScenarioTestCase.RSA_SHA256_CASE).contains(definition.id())) {
            return new IdpSignedRequestScenarioTestCase(
                    definition.id(), idpScenarioConfigurations, suiteCredentials);
        }
        if (idpScenarioConfigurations != null && List.of(
                IdpInvalidRequestScenarioTestCase.STATUS_CASE,
                IdpInvalidRequestScenarioTestCase.CORRELATION_CASE).contains(definition.id())) {
            return new IdpInvalidRequestScenarioTestCase(
                    definition.id(), idpScenarioConfigurations);
        }
        if (idpScenarioConfigurations != null && List.of(
                IdpPassiveScenarioTestCase.PASSIVE_CASE,
                IdpPassiveScenarioTestCase.FORCE_PASSIVE_CASE).contains(definition.id())) {
            return new IdpPassiveScenarioTestCase(definition.id(), idpScenarioConfigurations);
        }
        if (idpScenarioConfigurations != null && List.of(
                IdpAcsSelectionScenarioTestCase.INDEX_CASE,
                IdpAcsSelectionScenarioTestCase.URL_CASE,
                IdpAcsSelectionScenarioTestCase.BINDING_CASE,
                IdpAcsSelectionScenarioTestCase.UNREGISTERED_URL_CASE,
                IdpAcsSelectionScenarioTestCase.UNKNOWN_INDEX_CASE).contains(definition.id())) {
            return new IdpAcsSelectionScenarioTestCase(
                    definition.id(), idpScenarioConfigurations);
        }
        var transcriptDriven = transcriptContent != null && NormalFlowBrowserObservation.supports(definition.id());
        var evidence = new AttestedOutcomeTestCase(
                definition.id(), definition.role(), "case." + definition.id() + ".browser-evidence",
                evidencePrompt(definition), EVIDENCE_TTL,
                List.of(
                        AttestationOption.of(
                                "evidence_satisfies", Outcome.SATISFIED, "browser.evidence-satisfies"),
                        AttestationOption.of(
                                "evidence_violates", Outcome.VIOLATED, "browser.evidence-violates"),
                        AttestationOption.notVerified(
                                "unable_to_verify", "browser.evidence-unavailable",
                                "browser_evidence_unavailable")));
        var fallback = new BrowserEvidenceTestCase(
                evidence, publicBase, browserPrompt(definition, transcriptDriven), BROWSER_TTL);
        if (transcriptContent != null && LogoutBrowserEvidenceTestCase.supports(definition.id())) {
            return new LogoutBrowserEvidenceTestCase(
                    fallback, transcriptContent, targetEntityIds, targetSigningCertificates);
        }
        if (transcriptDriven) {
            return new AutoBrowserEvidenceTestCase(
                    fallback, transcriptContent, decryptionKeys, targetEntityIds, targetSigningCertificates);
        }
        return new UnavailableBrowserOracleTestCase(definition.id(), definition.role());
    }

    private static String browserPrompt(CaseDefinition definition, boolean transcriptDriven) {
        var value = new StringBuilder()
                .append("Use a real browser as the SAML user agent for approved case ")
                .append(definition.id())
                .append(transcriptDriven
                        ? ". Complete every applicable target instruction. SAMLscope completes this case when the "
                                + "correlated Transcript becomes conclusive; do not submit a completion answer."
                        : ". Complete every applicable target instruction before marking the browser step complete.")
                .append("\n\nInstructions:\n");
        definition.variantPlan().forEach(item -> value.append("- ").append(item.instructionEn()).append('\n'));
        // G2 controls prove the Suite's oracle against baseline and mutant fixtures. They are not
        // additional actions to perform against the real target represented by this Run.
        return value.toString();
    }

    private static String evidencePrompt(CaseDefinition definition) {
        var value = new StringBuilder()
                .append("Review the evidence produced by the completed browser steps for ")
                .append(definition.obligation())
                .append(". Select a conclusive result only when the observed browser and Transcript evidence supports it; ")
                .append("otherwise select unable_to_verify.");
        if (!definition.interpretationConstraints().isEmpty()) {
            value.append("\n\nInterpretation constraints:\n");
            definition.interpretationConstraints().forEach(item -> value.append("- ").append(item).append('\n'));
        }
        value.append("\nCounterexample to avoid:\n").append(definition.counterexampleEn());
        return value.toString();
    }
}
