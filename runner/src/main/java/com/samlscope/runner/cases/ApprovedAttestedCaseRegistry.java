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
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.CaseImplementationAudit;
import com.samlscope.runner.TestCaseRegistry;

/** Builds the complete M1 ATTESTED registry directly from the signed G2 case designs. */
public final class ApprovedAttestedCaseRegistry {
    private static final Duration ATTESTATION_TTL = Duration.ofDays(7);

    private ApprovedAttestedCaseRegistry() {}

    public static TestCaseRegistry create(CaseDefinitionCatalog definitions) {
        return create(definitions, Milestone.M1);
    }

    public static TestCaseRegistry create(CaseDefinitionCatalog definitions, Milestone milestone) {
        return create(definitions, milestone, null, null, null, null, null);
    }

    public static TestCaseRegistry create(
            CaseDefinitionCatalog definitions,
            Milestone milestone,
            java.net.URI publicBase,
            Function<String, IdpErrorProbeConfiguration> idpScenarioConfigurations,
            com.samlscope.core.transcript.TranscriptContentReader transcriptContent,
            Function<String, java.util.Optional<String>> targetEntityIds,
            Function<String, List<java.security.cert.X509Certificate>> targetSigningCertificates) {
        return create(
                definitions, milestone, publicBase, idpScenarioConfigurations, transcriptContent,
                targetEntityIds, targetSigningCertificates, null);
    }

    public static TestCaseRegistry create(
            CaseDefinitionCatalog definitions,
            Milestone milestone,
            java.net.URI publicBase,
            Function<String, IdpErrorProbeConfiguration> idpScenarioConfigurations,
            com.samlscope.core.transcript.TranscriptContentReader transcriptContent,
            Function<String, java.util.Optional<String>> targetEntityIds,
            Function<String, List<java.security.cert.X509Certificate>> targetSigningCertificates,
            Function<String, byte[]> targetMetadata) {
        Objects.requireNonNull(definitions, "definitions");
        Objects.requireNonNull(milestone, "milestone");
        var cases = new ArrayList<com.samlscope.core.caseexec.TestCase>();
        definitions.cases().stream()
                .filter(value -> value.milestone() == milestone)
                .filter(value -> value.mode() == ExecutionMode.ATTESTED)
                .map(value -> createCase(
                        value, idpScenarioConfigurations, transcriptContent,
                        targetEntityIds, targetSigningCertificates, publicBase, targetMetadata))
                .forEach(cases::add);
        var registry = new TestCaseRegistry(cases);
        CaseImplementationAudit.requireExact(definitions, registry, milestone, ExecutionMode.ATTESTED);
        return registry;
    }

    private static com.samlscope.core.caseexec.TestCase createCase(
            CaseDefinition definition,
            Function<String, IdpErrorProbeConfiguration> idpScenarioConfigurations,
            com.samlscope.core.transcript.TranscriptContentReader transcriptContent,
            Function<String, java.util.Optional<String>> targetEntityIds,
            Function<String, List<java.security.cert.X509Certificate>> targetSigningCertificates,
            java.net.URI publicBase,
            Function<String, byte[]> targetMetadata) {
        if (List.of("IIP-IDP13-b-idp-01", "IIP-IDP14-b-idp-01").contains(definition.id())) {
            return new InformationalChoiceTestCase(definition.id(), definition.role());
        }
        if (idpScenarioConfigurations != null
                && IdpForceAuthnScenarioTestCase.MECHANISM_ACCESS_CASE.equals(definition.id())) {
            var bridge=new KeycloakNativeRunEvidenceBridge(SuiteRunProfileLookup.configuredDataDirectory());
            return new ForceAuthnMechanismEvidenceTestCase(
                    new IdpForceAuthnScenarioTestCase(definition.id(), idpScenarioConfigurations),
                    new ShibbolethForceAuthnMechanismEvidence(
                            SuiteRunProfileLookup.configuredDataDirectory().resolve("force-authn-mechanism-evidence"),
                            transcriptContent == null ? bridge::content : transcriptContent,
                            targetMetadata == null ? bridge::targetMetadata : targetMetadata,
                            bridge::primaryKey));
        }
        if (idpScenarioConfigurations != null
                && IdpTimePrecisionScenarioTestCase.CASE_ID.equals(definition.id())) {
            return new IdpTimePrecisionScenarioTestCase(idpScenarioConfigurations);
        }
        if (transcriptContent != null && publicBase != null
                && "IIP-IDP17-ak-idp-01".equals(definition.id())) {
            return new LogoutAttestedEvidenceTestCase(
                    definition.id(), definition.role(), publicBase, transcriptContent,
                    targetEntityIds == null ? ignored -> java.util.Optional.empty() : targetEntityIds,
                    targetSigningCertificates == null ? ignored -> List.of() : targetSigningCertificates,
                    LogoutTranscriptProfileCase.Rule.REQUEST_VERSION_2);
        }
        var fallback = new AttestedOutcomeTestCase(
                definition.id(),
                definition.role(),
                "case." + definition.id() + ".attestation",
                prompt(definition),
                ATTESTATION_TTL,
                List.of(
                        AttestationOption.of(
                                "satisfied", Outcome.SATISFIED, "attestation.satisfied"),
                        AttestationOption.of(
                                "violated", Outcome.VIOLATED, "attestation.violated"),
                        AttestationOption.notVerified(
                                "unable_to_verify", "attestation.unavailable", "attestation_unavailable")));
        if (DefaultAlgorithmPreventionProbeTestCase.CASE.equals(definition.id())) {
            return withNativeDefaultAlgorithms(fallback, SuiteRunProfileLookup.configuredDataDirectory(),
                    transcriptContent, targetMetadata);
        }
        if (SloRegisteredSignerEvidence.CASE.equals(definition.id())) {
            return withNativeSloRegisteredSigner(fallback,SuiteRunProfileLookup.configuredDataDirectory(),
                    transcriptContent,targetMetadata);
        }
        if (RegisteredSignerObservationTestCase.CASE.equals(definition.id())) {
            var data = SuiteRunProfileLookup.configuredDataDirectory();
            var bridge = new KeycloakNativeRunEvidenceBridge(data);
            return new RegisteredSignerObservationTestCase(fallback,
                    data.resolve("keycloak-registered-signer-evidence"),
                    transcriptContent == null ? bridge::content : transcriptContent,
                    targetMetadata == null ? bridge::targetMetadata : targetMetadata,
                    bridge::key,
                    new SimpleSamlPhpRegisteredSignerEvidence(
                            data.resolve("registered-signer-evidence-simplesamlphp"),
                            transcriptContent == null ? bridge::content : transcriptContent,
                            targetMetadata == null ? bridge::targetMetadata : targetMetadata,
                            bridge::key),
                    new ShibbolethRegisteredSignerEvidence(
                            data.resolve("registered-signer-evidence-shibboleth"),
                            transcriptContent == null ? bridge::content : transcriptContent,
                            targetMetadata == null ? bridge::targetMetadata : targetMetadata,
                            bridge::key));
        }
        if (targetMetadata != null && KeycloakSelfContainedTrustEvidenceFile.ID.equals(definition.id())) {
            var data = SuiteRunProfileLookup.configuredDataDirectory();
            return withNativeMetadataTrust(fallback, data, transcriptContent, targetMetadata);
        }
        if (targetMetadata != null && List.of("IIP-MD09-a-idp-01", "IIP-MD09-a-sp-01")
                .contains(definition.id())) {
            return new AutoAttestedMetadataEvidenceTestCase(fallback, targetMetadata);
        }
        return fallback;
    }

    static com.samlscope.core.caseexec.TestCase withNativeDefaultAlgorithms(
            com.samlscope.core.caseexec.TestCase fallback, java.nio.file.Path data,
            com.samlscope.core.transcript.TranscriptContentReader transcriptContent,
            Function<String, byte[]> targetMetadata) {
        var bridge = new KeycloakNativeRunEvidenceBridge(data);
        var content = transcriptContent == null
                ? (com.samlscope.core.transcript.TranscriptContentReader) bridge::content : transcriptContent;
        var profiles = new SuiteRunProfileLookup(data);
        // The original control metadata advertises the polling control key, not the Plan primary key.
        return new DefaultAlgorithmPreventionProbeTestCase(fallback, content,
                targetMetadata == null ? bridge::targetMetadata : targetMetadata,
                run -> bridge.key(run, "control"), profiles::profile,
                data.resolve("default-algorithm-evidence"),
                new ShibbolethDefaultAlgorithmNativeAdapter(content));
    }

    static com.samlscope.core.caseexec.TestCase withNativeSloRegisteredSigner(
            com.samlscope.core.caseexec.TestCase fallback, java.nio.file.Path data,
            com.samlscope.core.transcript.TranscriptContentReader transcriptContent,
            Function<String, byte[]> targetMetadata) {
        var bridge=new KeycloakNativeRunEvidenceBridge(data);
        return new SloRegisteredSignerObservationTestCase(fallback,data.resolve("slo-registered-signer-evidence"),
                transcriptContent==null?bridge::content:transcriptContent,
                targetMetadata==null?bridge::targetMetadata:targetMetadata,bridge::key);
    }

    static com.samlscope.core.caseexec.TestCase withNativeMetadataTrust(
            com.samlscope.core.caseexec.TestCase fallback, java.nio.file.Path data,
            com.samlscope.core.transcript.TranscriptContentReader transcriptContent,
            Function<String, byte[]> targetMetadata) {
        var bridge = new KeycloakNativeRunEvidenceBridge(data);
        var keycloak = new KeycloakSelfContainedTrustEvidenceFile(
                bridge.evidenceDirectory(), bridge::content, bridge::key);
        var nativeFallback = new KeycloakSelfContainedTrustAttestedTestCase(fallback, targetMetadata, keycloak);
        var content = transcriptContent == null
                ? (com.samlscope.core.transcript.TranscriptContentReader) bridge::content : transcriptContent;
        var simpleSamlPhp = new SimpleSamlPhpSelfContainedTrustEvidenceFile(
                data.resolve("metadata-trust-evidence"), data.resolve("metadata-role-key-evidence"),
                content, targetMetadata, bridge::metadataRoleKey);
        var shibboleth = new ShibbolethSelfContainedTrustEvidenceFile(
                data.resolve("metadata-trust-evidence"), data.resolve("metadata-role-key-evidence"),
                content, targetMetadata, bridge::metadataRoleKey);
        var simpleSamlPhpCase = new SelfContainedMetadataTrustEvidenceTestCase(nativeFallback,
                simpleSamlPhp::exists,
                context -> keycloak.exists(context.runId()) ? ambiguousNativeTrust() : simpleSamlPhp.evaluate(context),
                SimpleSamlPhpSelfContainedTrustEvidenceFile.ADAPTER,
                "native-self-contained-trust-evidence", ".simplesamlphp-trust.json");
        return new SelfContainedMetadataTrustEvidenceTestCase(simpleSamlPhpCase,
                shibboleth::exists,
                context -> simpleSamlPhp.exists(context.runId()) || keycloak.exists(context.runId())
                        ? ambiguousNativeTrust() : shibboleth.evaluate(context),
                ShibbolethSelfContainedTrustEvidenceFile.ADAPTER,
                ShibbolethSelfContainedTrustEvidenceFile.KIND, ".shibboleth-trust.json");
    }

    private static com.samlscope.core.evaluation.CaseOutcome ambiguousNativeTrust() {
        return com.samlscope.core.evaluation.CaseOutcome.notVerified(
                "native_metadata_trust_ambiguous", "metadata.trust.native-evidence-incomplete");
    }

    private static String prompt(CaseDefinition definition) {
        var value = new StringBuilder()
                .append("Review the approved evidence instructions for ")
                .append(definition.obligation())
                .append(". Select satisfied or violated only when the available evidence supports that result; ")
                .append("otherwise select unable_to_verify.\n\nEvidence instructions:\n");
        for (var variant : definition.variantPlan()) {
            value.append("- ").append(variant.instructionEn()).append('\n');
        }
        if (!definition.interpretationConstraints().isEmpty()) {
            value.append("\nInterpretation constraints:\n");
            definition.interpretationConstraints().forEach(item -> value.append("- ").append(item).append('\n'));
        }
        value.append("\nCounterexample to avoid:\n").append(definition.counterexampleEn());
        return value.toString();
    }
}
