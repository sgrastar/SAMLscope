package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;

import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.casedef.CaseDefinitionCatalog.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NativeCampaignRegistryTest {
    @TempDir Path directory;

    private CaseContext context() {
        return SelfContainedMetadataTrustEvidenceTestCaseTest.context(true);
    }

    private CaseContext attestationOnlyContext() {
        var c = context();
        return new DefaultCaseContext(c.runId(), c.targetRole(), c.clock(), c.parameters(),
                new com.samlscope.core.plan.TestPlan.Interaction(false, true), c.reachability(),
                c.transcript(), c.transcriptComplete());
    }

    private TestCase weakLegacyUiDelegate() {
        return new TestCase() {
            public String id() { return MetadataFullUiConfigurationTestCase.CASE; }
            public TargetRole role() { return TargetRole.IDP; }
            public CaseStep start(CaseContext context) { throw new AssertionError("Legacy import/SSO must not decide full UI"); }
            public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) { return start(context); }
        };
    }

    private AttestedOutcomeTestCase algorithmFallback() {
        return new AttestedOutcomeTestCase(DefaultAlgorithmPreventionProbeTestCase.CASE,
                TargetRole.IDP, "default-algorithm-attestation", "Approved default algorithm prompt",
                Duration.ofDays(7), List.of(AttestationOption.of("satisfied", Outcome.SATISFIED, "attestation.satisfied")));
    }

    @Test void fullUiAlwaysGatesLegacyAcceptanceWithoutAnotherLogin() {
        var test = ApprovedConfigCaseRegistry.withNativeFullUi(weakLegacyUiDelegate(), directory,
                entry -> { throw new AssertionError("No missing original may be read"); }, run -> new byte[0]);
        var wait = assertInstanceOf(CaseStep.AwaitConfig.class, test.start(context()));
        assertTrue(wait.actions().isEmpty());
        var confirmed = assertInstanceOf(CaseStep.Finish.class,
                test.resume(context(), wait.next(), new CaseEvent.ConfigConfirmed()));
        assertEquals(Outcome.NOT_VERIFIED, confirmed.outcome().outcome());
        assertFalse(test instanceof BrowserFrontChannelScenario);
        assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,
                assertInstanceOf(FallbackEvidenceCase.class, test).evidenceClass(null));
        assertTrue(assertInstanceOf(RecordedEvidenceReevaluation.class, test)
                .reevaluateRecordedEvidence(context(), CaseOutcome.notVerified("before", "before")).isEmpty());
        assertSame(test, ApprovedConfigCaseRegistry.withNativeFullUi(test, directory, null, null));
    }

    @Test void malformedNativeUiProofCannotBorrowTheLegacyOutcome() throws Exception {
        var proof = directory.resolve("metadata-full-ui-evidence").resolve(context().runId());
        Files.createDirectories(proof);
        Files.writeString(proof.resolve("manifest.json"), "{\"schema\":\"wrong\",\"success\":true}");
        var test = ApprovedConfigCaseRegistry.withNativeFullUi(weakLegacyUiDelegate(), directory,
                entry -> { throw new AssertionError("Malformed receipt must fail before reading"); }, run -> new byte[0]);
        var wait = assertInstanceOf(CaseStep.AwaitConfig.class, test.start(context()));
        assertEquals(Outcome.NOT_VERIFIED, assertInstanceOf(CaseStep.Finish.class,
                test.resume(context(), wait.next(), new CaseEvent.ConfigConfirmed())).outcome().outcome());
        assertFalse(assertInstanceOf(ProtocolEvidenceCase.class, test).evidenceStatus(context()).ready());
    }

    @Test void missingDefaultPolicyPreparationDoesNotOfferALoginOrSelfAttest() {
        var test = ApprovedAttestedCaseRegistry.withNativeDefaultAlgorithms(algorithmFallback(), directory,
                entry -> { throw new AssertionError("Absent native preparation has no originals"); }, run -> new byte[0]);
        var finished = assertInstanceOf(CaseStep.Finish.class, test.start(context()));
        assertEquals(Outcome.NOT_VERIFIED, finished.outcome().outcome());
        assertFalse(assertInstanceOf(ProtocolEvidenceCase.class, test).evidenceStatus(context()).ready());
        assertTrue(assertInstanceOf(RecordedEvidenceReevaluation.class, test)
                .reevaluateRecordedEvidence(context(), finished.outcome()).isEmpty());
        assertEquals(algorithmFallback().options(), assertInstanceOf(AttestationPrompt.class, test).options());
    }

    @Test void missingPersistentConstructionPreservesManualOptionsWithoutAnotherLogin() {
        String id = "IIP-SSO05-a1-idp-01";
        var fallback = new AttestedOutcomeTestCase(id, TargetRole.IDP, "persistent-attestation",
                "Approved persistent construction prompt", Duration.ofDays(7),
                List.of(AttestationOption.of("satisfied", Outcome.SATISFIED, "attestation.satisfied")));
        var test = ApprovedAttestedCaseRegistry.withNativePersistentIdentifiers(fallback, directory,
                entry -> { throw new AssertionError("Absent construction has no original to consume"); }, run -> new byte[0]);
        assertEquals(Outcome.NOT_VERIFIED,
                assertInstanceOf(CaseStep.Finish.class, test.start(context())).outcome().outcome());
        assertFalse(test instanceof BrowserFrontChannelScenario);
        assertEquals(fallback.options(), assertInstanceOf(AttestationPrompt.class, test).options());
        var manual = assertInstanceOf(CaseStep.AwaitAttestation.class, test.start(attestationOnlyContext()));
        assertTrue(manual.actions().isEmpty());
    }

    @Test void actualSevenArgumentRuntimeConstructionWiresBothPersistentCases() {
        var approved = KeycloakPersistentIdentifierEvidence.DIGESTS.entrySet().stream()
                .map(entry -> new CaseDefinition(entry.getKey(),
                        entry.getKey().contains("a1-") ? "IIP-SSO05.a1" : "IIP-SSO05.a8",
                        TargetRole.IDP, ExecutionMode.ATTESTED, Milestone.M1, List.of(), Map.of(),
                        List.of(), List.of(), List.of(), "Native controls remain required", List.of(),
                        new Requirements(List.of(), "none"), false, null, entry.getValue())).toList();
        var catalog = new CaseDefinitionCatalog(approved);
        var bare = ApprovedAttestedCaseRegistry.create(catalog, Milestone.M1);
        var actual = ApprovedAttestedCaseRegistry.create(catalog, Milestone.M1,
                java.net.URI.create("http://localhost:18080"), null,
                entry -> { throw new AssertionError("Registry construction must not read evidence"); },
                ignored -> Optional.empty(), ignored -> List.of());
        for (String id : KeycloakPersistentIdentifierEvidence.DIGESTS.keySet()) {
            assertInstanceOf(AttestedOutcomeTestCase.class, bare.require(id));
            assertInstanceOf(NativePersistentIdentifierEvidenceTestCase.class, actual.require(id));
            assertEquals(((AttestationPrompt) bare.require(id)).options(),
                    ((AttestationPrompt) actual.require(id)).options());
        }
    }

    @Test void ownedMalformedDefaultPolicyCannotBecomeAnAttestedSuccess() throws Exception {
        var proof = directory.resolve("default-algorithm-evidence").resolve(context().runId());
        Files.createDirectories(proof);
        Files.writeString(proof.resolve("manifest.json"), "{\"schema\":\"wrong\",\"success\":true}");
        var test = ApprovedAttestedCaseRegistry.withNativeDefaultAlgorithms(algorithmFallback(), directory,
                entry -> { throw new AssertionError("Malformed native proof has no original to consume"); }, run -> new byte[0]);
        assertEquals(Outcome.NOT_VERIFIED, assertInstanceOf(CaseStep.Finish.class,
                test.resume(context(), CaseState.initial(), new CaseEvent.Attested("satisfied", "")))
                .outcome().outcome());
    }

    @Test void explicitlyEnabledManualFallbackRemainsSelfAttestedWithoutALogin() {
        var test = ApprovedAttestedCaseRegistry.withNativeDefaultAlgorithms(algorithmFallback(), directory,
                entry -> { throw new AssertionError("Manual fallback does not consume native originals"); }, run -> new byte[0]);
        var c = attestationOnlyContext();
        var wait = assertInstanceOf(CaseStep.AwaitAttestation.class, test.start(c));
        assertTrue(wait.actions().isEmpty());
        var result = assertInstanceOf(CaseStep.Finish.class,
                test.resume(c, wait.next(), new CaseEvent.Attested("satisfied", "Operator evidence checked"))).outcome();
        assertEquals(Outcome.SATISFIED, result.outcome());
        assertEquals(true, result.details().get("attested"));
        assertEquals(List.of("attestation"), result.evidence().stream().map(EvidenceRef::kind).toList());
        var execution = new CaseExecution(c.runId(), test.id(), 1, CaseExecutionStatus.FINISHED,
                wait.next(), null, result, c.clock().instant());
        var source = assertInstanceOf(FallbackEvidenceCase.class, test);
        assertEquals(RunCampaignQuery.EvidenceClass.SELF_ATTESTED, source.evidenceClass(execution));
        assertFalse(source.resolvedFromExternalEvidence(execution));
    }

    @Test void ownedInvalidPreparationBlocksEvenAnExplicitlyEnabledManualFallback() throws Exception {
        var c = attestationOnlyContext();
        var path = directory.resolve("default-algorithm-evidence");
        Files.createDirectories(path);
        Files.writeString(path.resolve(c.runId() + ".preparation.json"), "{}");
        var test = ApprovedAttestedCaseRegistry.withNativeDefaultAlgorithms(algorithmFallback(), directory,
                entry -> { throw new AssertionError(); }, run -> new byte[0]);
        assertEquals(Outcome.NOT_VERIFIED, assertInstanceOf(CaseStep.Finish.class, test.start(c)).outcome().outcome());
        var staleManualState = assertInstanceOf(CaseStep.AwaitAttestation.class, algorithmFallback().start(c)).next();
        assertEquals(Outcome.NOT_VERIFIED, assertInstanceOf(CaseStep.Finish.class,
                test.resume(c, staleManualState, new CaseEvent.Attested("satisfied", ""))).outcome().outcome());
    }

    @Test void everyRegistryConstructionPathKeepsTheExactApprovedCaseIds() {
        var definitions = new CaseDefinitionCatalog(List.of(
                definition(DefaultAlgorithmPreventionProbeTestCase.CASE, "IIP-ALG08.c", ExecutionMode.ATTESTED, Milestone.M1),
                definition(MetadataFullUiConfigurationTestCase.CASE, "IIP-MD05.f", ExecutionMode.CONFIG, Milestone.M2)));
        var attested = ApprovedAttestedCaseRegistry.create(definitions, Milestone.M1);
        assertEquals(Set.of(DefaultAlgorithmPreventionProbeTestCase.CASE), attested.ids());
        assertInstanceOf(DefaultAlgorithmSourceRunTestCase.class,
                attested.require(DefaultAlgorithmPreventionProbeTestCase.CASE));
        var config = ApprovedConfigCaseRegistry.create(definitions, Milestone.M2);
        assertEquals(Set.of(MetadataFullUiConfigurationTestCase.CASE), config.ids());
        var original = config.require(MetadataFullUiConfigurationTestCase.CASE);
        assertInstanceOf(MetadataFullUiConfigurationTestCase.class, original);
        var decorated = ApprovedConfigCaseRegistry.withMetadataRejection(config,
                entry -> { throw new AssertionError(); }, run -> new byte[0], directory.resolve("metadata-rejection-evidence"));
        assertEquals(config.ids(), decorated.ids());
        assertSame(original, decorated.require(MetadataFullUiConfigurationTestCase.CASE));
    }

    @Test void actualMultipleKeyRuntimeDecorationKeepsTheApprovedConfigCaseAndManualOptions() {
        var definitions = new CaseDefinitionCatalog(List.of(
                definition(SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE, "IIP-IDP19.b",
                        ExecutionMode.CONFIG, Milestone.M3)));
        var bare = ApprovedConfigCaseRegistry.create(definitions, Milestone.M3);
        var fallback = bare.require(SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE);
        var actual = ApprovedConfigCaseRegistry.withMultipleDecryptionKeys(bare,
                ignored -> new SupplementalDecryptionKeyService.KeySet(List.of(), List.of()),
                (run, id) -> Optional.empty());
        var test = actual.require(SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE);
        assertInstanceOf(NativeConfigurationSourceRunTestCase.class, test);
        assertEquals(bare.ids(), actual.ids());
        assertEquals(((ConfigurationPrompt) fallback).instructionEn(),
                ((ConfigurationPrompt) test).instructionEn());
        assertEquals(((AttestationPrompt) fallback).options(), ((AttestationPrompt) test).options());
        var wait = assertInstanceOf(CaseStep.AwaitConfig.class, test.start(context()));
        assertTrue(wait.actions().isEmpty());
        assertFalse(test instanceof BrowserFrontChannelScenario);
        assertEquals(List.of(SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE),
                ((EvidenceCampaignCase) test).evidenceActionKeys());
        assertSame(test, ApprovedConfigCaseRegistry.withMultipleDecryptionKeys(actual,
                ignored -> { throw new AssertionError("Decoration must be idempotent"); },
                (run, id) -> Optional.empty()).require(test.id()));
    }

    private CaseDefinition definition(String id, String obligation, ExecutionMode mode, Milestone milestone) {
        return new CaseDefinition(id, obligation, TargetRole.IDP, mode, milestone, List.of(), Map.of(),
                List.of(), List.of(), List.of(), "Approved counterexample remains required", List.of(),
                new Requirements(List.of(), "none"), false,
                mode == ExecutionMode.CONFIG ? ConfigurationFailureSemantics.TEST_PRECONDITION : null,
                "sha256:" + "a".repeat(64));
    }
}
