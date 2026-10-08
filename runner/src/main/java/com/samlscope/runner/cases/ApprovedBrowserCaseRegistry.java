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

    public static TestCaseRegistry withNativeEcSignature(TestCaseRegistry registry, TranscriptContentReader content,
            java.util.function.Function<String, byte[]> metadata, java.nio.file.Path directory) {
        var nativeEvidence=new NativeEcSignatureEvidence(directory,content,metadata);
        var cases = new ArrayList<com.samlscope.core.caseexec.TestCase>(registry.all().stream().map(testCase ->
                EcSignatureSupportTestCase.ID.equals(testCase.id())
                        ? (com.samlscope.core.caseexec.TestCase)new EcSignatureSupportTestCase(nativeEvidence)
                        : testCase instanceof IdpVersionMismatchScenarioTestCase versionMismatch
                        ? versionMismatch.withNativeEvidence(directory.getParent().resolve("version-mismatch-evidence"),
                                content, metadata)
                        : testCase instanceof IdpAcsSelectionScenarioTestCase acs
                            && IdpAcsSelectionScenarioTestCase.BINDING_CASE.equals(testCase.id())
                        ? acs.withArtifactInput(content, metadata)
                        : testCase instanceof IdpExecutableBrowserFixtureScenarioTestCase scenario
                            && IdpExecutableBrowserFixtureScenarioTestCase.G03_CASE.equals(testCase.id())
                        ? scenario.withNativeDtdEvidence(directory.getParent().resolve("dtd-rejection-evidence"),
                                content, metadata)
                        : testCase instanceof IdpExecutableBrowserFixtureScenarioTestCase scenario
                            && PersistentPairwiseNameIdEvidence.CASE.equals(testCase.id())
                        ? new PersistentPairwiseQueuedTestCase(scenario.withPersistentPairwiseEvidence(
                                directory.getParent().resolve("persistent-nameid-evidence"), content, metadata))
                        : testCase instanceof IdpExecutableBrowserFixtureScenarioTestCase scenario
                            && RequestedSubjectMatchTestCase.CASE.equals(testCase.id())
                        ? scenario.withRequestedSubjectMatchEvidence(directory.getParent().resolve("subject-match-evidence"),
                                content, metadata)
                        : testCase instanceof TransientAllowCreateScenarioTestCase scenario
                        ? scenario.withNativeEvidence(directory.getParent().resolve("transient-allow-create-evidence"),
                                content, metadata)
                        : testCase instanceof SamlSubjectPrincipalTranscriptTestCase
                            && SamlSubjectPrincipalTranscriptTestCase.CASE_ID.equals(testCase.id())
                        ? new NativeSubjectPrincipalTestCase(testCase,
                                directory.getParent().resolve("subject-principal-evidence"), content, metadata)
                        : testCase).toList());
        // M1 passive cases are created by QuickCheckService, outside this runtime registry.
        // Register the original-backed observer here so an existing FINISHED, unresolved
        // principal case can be re-evaluated through the same auditable evidence service.
        // Starting is idempotent for that existing execution and emits no outbox action.
        if (cases.stream().noneMatch(testCase -> SamlSubjectPrincipalTranscriptTestCase.CASE_ID.equals(testCase.id()))) {
            var fallback = new SamlSubjectPrincipalTranscriptTestCase(content,
                    (run, identifier) -> PrincipalIdentityResolver.Resolution.unknown());
            cases.add(new NativeSubjectPrincipalTestCase(fallback,
                    directory.getParent().resolve("subject-principal-evidence"), content, metadata));
        }
        return new TestCaseRegistry(cases);
    }

    public static TestCaseRegistry withNativeSignedRequests(TestCaseRegistry registry,TranscriptContentReader content,
            java.util.function.Function<String,byte[]> metadata,java.nio.file.Path directory) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
            testCase instanceof IdpSignedRequestScenarioTestCase scenario && NativeSignedRequestEvidence.supports(testCase.id())
                ? (com.samlscope.core.caseexec.TestCase)scenario.withNativeEvidence(directory,content,metadata) : testCase).toList());
    }

    public static TestCaseRegistry withNativeUiLogo(TestCaseRegistry registry, TranscriptContentReader content,
            java.util.function.Function<String, byte[]> metadata, java.nio.file.Path directory) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                UiLogoComparison.CASE_ID.equals(testCase.id())
                        ? (com.samlscope.core.caseexec.TestCase)new UiLogoBrowserEvidenceTestCase(content, metadata, directory)
                        : testCase).toList());
    }

    public static TestCaseRegistry withSignatureModes(TestCaseRegistry registry, TranscriptContentReader content,
            java.util.function.Function<String,byte[]> metadata, SamlDecryptionKeyProvider keys) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                SignatureModesObservation.ID.equals(testCase.id())
                        ? (com.samlscope.core.caseexec.TestCase)new SignatureModesBrowserTestCase(testCase, content, metadata, keys)
                        : testCase).toList());
    }

    public static TestCaseRegistry withNativeUiDisplay(TestCaseRegistry registry, TranscriptContentReader content,
            java.util.function.Function<String, byte[]> metadata, java.nio.file.Path directory) {
        var nativeAbsence = new NativeUiFeatureAbsenceEvidence(
                directory.getParent().resolve("ui-native-feature-absence"), content);
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                UiDisplayComparison.CASE_ID.equals(testCase.id())
                        ? (com.samlscope.core.caseexec.TestCase)new NativeUiFeatureAbsenceTestCase(
                                new UiDisplayBrowserEvidenceTestCase(content, metadata, directory),
                                metadata, nativeAbsence)
                        : testCase).toList());
    }

    public static TestCaseRegistry withNativeUiUrls(TestCaseRegistry registry, TranscriptContentReader content,
            java.util.function.Function<String, byte[]> metadata, java.nio.file.Path directory) {
        var nativeAbsence = new NativeUiFeatureAbsenceEvidence(
                directory.getParent().resolve("ui-native-feature-absence"), content);
        var nativeShibboleth = new ShibbolethUiConsumerEvidence(directory, content);
        var nativeSimpleSamlPhp = new SimpleSamlPhpConsentSafetyEvidence(
                directory.resolveSibling("ui-safety-evidence"), content);
        var nativeSimpleSamlPhpUri = new SimpleSamlPhpConsentUriEvidence(
                directory.resolveSibling("ui-consent-uri-evidence"), content);
        var nativeKeycloakSafety = new KeycloakUiSafetyEvidence(
                directory.getParent().resolve("ui-native-feature-absence"), content);
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                UiUrlComparison.CASE_ID.equals(testCase.id())
                        ? (com.samlscope.core.caseexec.TestCase)new UiUrlBrowserEvidenceTestCase(content, metadata, directory)
                        : NativeUiFeatureAbsenceEvidence.DISCOVERY.equals(testCase.id())
                        ? (com.samlscope.core.caseexec.TestCase)new NativeUiFeatureAbsenceTestCase(
                                testCase, metadata, nativeAbsence, nativeShibboleth, nativeSimpleSamlPhpUri)
                        : NativeUiSafetyTestCase.CASE.equals(testCase.id())
                            && testCase instanceof IdpExecutableBrowserFixtureScenarioTestCase scenario
                        ? new NativeUiSafetyTestCase(scenario, nativeShibboleth, nativeSimpleSamlPhp,
                                nativeKeycloakSafety, metadata)
                        : testCase).toList());
    }

    public static TestCaseRegistry withMetadataEncryption(TestCaseRegistry registry,TranscriptContentReader content,
            java.util.function.Function<String,byte[]> metadata,
            java.util.function.BiFunction<String,String,java.util.Optional<com.samlscope.saml.crypto.PlanCredentials>> keys) {
        var evidence=new MetadataEncryptionAlgorithmEvidence(content,metadata,keys);
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                testCase instanceof EncryptionAlgorithmBrowserEvidenceTestCase algorithm
                        ? (com.samlscope.core.caseexec.TestCase)algorithm.withMetadataEvidence(evidence) : testCase).toList());
    }

    public static TestCaseRegistry withBasicLogout(TestCaseRegistry registry,
            java.util.function.Function<String, IdpBasicLogoutScenarioTestCase.Configuration> configurations) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                IdpBasicLogoutScenarioTestCase.ID.equals(testCase.id())
                        ? (com.samlscope.core.caseexec.TestCase)new IdpBasicLogoutScenarioTestCase(configurations)
                        : testCase).toList());
    }

    public static TestCaseRegistry withLogoutScenarios(TestCaseRegistry registry,
            java.util.function.BiFunction<String, String, IdpBasicLogoutScenarioTestCase.Configuration> configurations,
            TranscriptContentReader transcriptContent) {
        return withLogoutScenarios(registry, configurations, transcriptContent,
                SuiteRunProfileLookup.configuredDataDirectory());
    }

    static TestCaseRegistry withLogoutScenarios(TestCaseRegistry registry,
            java.util.function.BiFunction<String, String, IdpBasicLogoutScenarioTestCase.Configuration> configurations,
            TranscriptContentReader transcriptContent, java.nio.file.Path dataDirectory) {
        var data = dataDirectory.toAbsolutePath().normalize();
        return new TestCaseRegistry(registry.all().stream().map(testCase -> {
            // This seam is applied to the real M3 registry; the M1 EC seam never sees IDP17.s.
            if (testCase instanceof LogoutBrowserEvidenceTestCase logout
                    && ShibbolethNativeSloPropagationEvidence.CASE.equals(testCase.id())) {
                return (com.samlscope.core.caseexec.TestCase) logout.withNativePropagation(
                        data.resolve("slo-propagation-evidence"), run -> recordedTargetMetadata(data, run));
            }
            if (testCase instanceof LogoutBrowserEvidenceTestCase logout
                    && ShibbolethNativeSloContinuationEvidence.CASE.equals(testCase.id())) {
                var observed = logout.withNativePropagation(data.resolve("slo-soap-continuation-evidence"),
                        run -> recordedTargetMetadata(data, run));
                return (com.samlscope.core.caseexec.TestCase) new SoapSloPropagationTestCase(observed,
                        run -> configurations.apply(testCase.id(), run), transcriptContent)
                        .withTargetMetadata(run -> recordedTargetMetadata(data, run));
            }
            if (LogoutRejectionScenarioTestCase.CASE_IDS.contains(testCase.id())) {
                return (com.samlscope.core.caseexec.TestCase) new LogoutRejectionScenarioTestCase(
                        testCase.id(), runId -> configurations.apply(testCase.id(), runId), transcriptContent);
            }
            if (LogoutAsyncScenarioTestCase.CASE_IDS.contains(testCase.id())) {
                return (com.samlscope.core.caseexec.TestCase) new LogoutAsyncScenarioTestCase(
                        testCase.id(), runId -> configurations.apply(testCase.id(), runId), transcriptContent);
            }
            if (java.util.Set.of(IdpBasicLogoutScenarioTestCase.ID, IdpBasicLogoutScenarioTestCase.REDIRECT_ID,
                    IdpBasicLogoutScenarioTestCase.REDIRECT_RESPONSE_ID,
                    IdpBasicLogoutScenarioTestCase.ENCRYPTED_ID, IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID)
                    .contains(testCase.id())) {
                java.util.function.Function<String,IdpBasicLogoutScenarioTestCase.Configuration> configured =
                        runId -> configurations.apply(testCase.id(), runId);
                var scenario = new IdpBasicLogoutScenarioTestCase(testCase.id(),configured);
                return IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID.equals(testCase.id())
                        ? (com.samlscope.core.caseexec.TestCase)new EncryptedLogoutNativeTestCase(scenario,
                                new SimpleSamlPhpEncryptedLogoutEvidence(data.resolve("encrypted-logout-evidence"),
                                        transcriptContent,run -> recordedTargetMetadata(data,run),configured))
                        : scenario;
            }
            return testCase;
        }).toList());
    }

    private static byte[] recordedTargetMetadata(java.nio.file.Path data, String run) {
        if (run == null || !run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"))
            throw new IllegalArgumentException("Invalid native target Run");
        var file = data.resolve("target-metadata").resolve(run + ".xml");
        try {
            for (var path = file; path != null; path = path.getParent())
                if (java.nio.file.Files.isSymbolicLink(path)) throw new IllegalArgumentException("Symbolic target metadata");
            if (!java.nio.file.Files.isRegularFile(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    || java.nio.file.Files.size(file) > 10_485_760)
                throw new IllegalArgumentException("Recorded target metadata unavailable");
            return java.nio.file.Files.readAllBytes(file);
        } catch (java.io.IOException unavailable) {
            throw new IllegalArgumentException("Recorded target metadata unavailable", unavailable);
        }
    }

    public static TestCaseRegistry withPublishedMetadata(TestCaseRegistry registry,
            java.util.function.Function<String, byte[]> metadata,
            java.util.function.Function<String, java.util.Optional<String>> entityIds) {
        return new TestCaseRegistry(registry.all().stream().map(testCase ->
                PublishedUiUrlTestCase.ID.equals(testCase.id())
                        ? (com.samlscope.core.caseexec.TestCase) new PublishedUiUrlTestCase(metadata, entityIds)
                        : java.util.Set.of("IIP-MD05-f7-idp-01", "IIP-MD05-f8-idp-01", "IIP-MD05-fa-idp-01").contains(testCase.id())
                                ? new AutoBrowserMetadataEvidenceTestCase(testCase, metadata, entityIds)
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
                            MetadataFixtureObservationTestCase.Behavior.ACCEPT, "select the first endpoint when defaults are omitted", 0),
                    new MetadataFixtureObservationTestCase.Fixture("default-acs-first-omitted",
                            MetadataFixtureObservationTestCase.Behavior.ACCEPT, "skip explicit false and select the first omitted default", 1),
                    new MetadataFixtureObservationTestCase.Fixture("default-acs-all-false",
                            MetadataFixtureObservationTestCase.Behavior.ACCEPT, "select the first endpoint when all defaults are false", 0),
                    new MetadataFixtureObservationTestCase.Fixture("default-acs-multiple-true",
                            MetadataFixtureObservationTestCase.Behavior.ACCEPT, "select the first of multiple explicit defaults", 0)),
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
        if (idpScenarioConfigurations != null && TransientAllowCreateScenarioTestCase.CASE.equals(definition.id())) {
            return new TransientAllowCreateScenarioTestCase(idpScenarioConfigurations, decryptionKeys);
        }
        if (idpScenarioConfigurations != null && List.of(
                IdpErrorAssertionScenarioTestCase.SUBJECT_ERROR_CASE,
                IdpErrorAssertionScenarioTestCase.ERROR_ASSERTION_CASE).contains(definition.id())) {
            var scenario = new IdpErrorAssertionScenarioTestCase(
                    definition.id(), idpScenarioConfigurations);
            if (IdpErrorAssertionScenarioTestCase.ERROR_ASSERTION_CASE.equals(definition.id())
                    && transcriptContent != null && suiteCredentials != null) {
                return new IdpErrorAssertionRecordedEvidenceTestCase(scenario,
                        idpScenarioConfigurations, transcriptContent, suiteCredentials,
                        targetEntityIds, targetSigningCertificates);
            }
            return scenario;
        }
        if (idpScenarioConfigurations != null
                && IdpUnknownExtensionScenarioTestCase.CASE_ID.equals(definition.id())) {
            return new IdpUnknownExtensionScenarioTestCase(idpScenarioConfigurations);
        }
        if (idpScenarioConfigurations != null
                && IdpExecutableBrowserFixtureScenarioTestCase.CASE_IDS.contains(definition.id())) {
            var fallback = new IdpExecutableBrowserFixtureScenarioTestCase(
                    definition.id(), idpScenarioConfigurations, decryptionKeys);
            if ("IIP-EXT01-c-idp-01".equals(definition.id())) {
                var data = SuiteRunProfileLookup.configuredDataDirectory();
                var bridge = new KeycloakNativeRunEvidenceBridge(data);
                return ExtensionAttributeParserTestCase.wrap(fallback,
                        transcriptContent == null ? bridge::content : transcriptContent,
                        bridge::targetMetadata, data.resolve("extension-attribute-parser-evidence"));
            }
            return fallback;
        }
        if (idpScenarioConfigurations != null
                && IdpVersionScenarioTestCase.CASE_ID.equals(definition.id())) {
            return new IdpVersionScenarioTestCase(idpScenarioConfigurations);
        }
        if (idpScenarioConfigurations != null && suiteCredentials != null && transcriptContent != null
                && definition.role() == com.samlscope.core.plan.TargetRole.IDP
                && IdpVersionMismatchScenarioTestCase.CASE_ID.equals(definition.id())) {
            return new IdpVersionMismatchScenarioTestCase(
                    idpScenarioConfigurations, suiteCredentials, transcriptContent, decryptionKeys);
        }
        if (idpScenarioConfigurations != null
                && IdpAuthnContextScenarioTestCase.CASE_ID.equals(definition.id())) {
            return new IdpAuthnContextScenarioTestCase(idpScenarioConfigurations, decryptionKeys);
        }
        if (idpScenarioConfigurations != null
                && IdpDestinationScenarioTestCase.CASE_ID.equals(definition.id())) {
            return new IdpDestinationScenarioTestCase(idpScenarioConfigurations);
        }
        if (idpScenarioConfigurations != null
                && IdpForceAuthnScenarioTestCase.CASE_ID.equals(definition.id())) {
            return new IdpForceAuthnScenarioTestCase(idpScenarioConfigurations, decryptionKeys);
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
            if (IdpAcsSelectionScenarioTestCase.BINDING_CASE.equals(definition.id())
                    && transcriptContent != null && suiteCredentials != null) {
                return new IdpAcsSelectionScenarioTestCase(
                        definition.id(), idpScenarioConfigurations, transcriptContent,
                        targetEntityIds, targetSigningCertificates, suiteCredentials);
            }
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
                    fallback, transcriptContent, targetEntityIds, targetSigningCertificates,
                    decryptionKeys == null ? ignored -> java.util.Optional.empty() : decryptionKeys);
        }
        if (transcriptContent != null && decryptionKeys != null
                && EncryptionAlgorithmObservation.supports(definition.id())) {
            return new EncryptionAlgorithmBrowserEvidenceTestCase(
                    fallback, transcriptContent, decryptionKeys);
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
