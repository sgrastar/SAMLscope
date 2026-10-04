package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MetadataEntityIdentityConfigurationTestCaseTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String ADAPTER = "keycloak-native-simultaneous-entity-registration-v1";
    private static final String A1 = "IIP-MD05-a1-idp-01";
    @TempDir Path root;

    @Test void missingNativeProofKeepsTheApprovedExistingPath() {
        for (var id : MetadataEntityIdentityConfigurationTestCase.IDS) {
            var test = implementation(id);
            assertEquals(Outcome.SATISFIED, finish(test.start(context(true))).outcome());
            assertEquals(Outcome.SATISFIED, finish(test.resume(context(true), state(),
                    new CaseEvent.TranscriptReady())).outcome());
            assertEquals(List.of("control", "fixture"), test.evidenceActionKeys());
        }
    }

    @Test void ownedMalformedOriginalsCannotUseAnOlderSatisfiedFallback() throws Exception {
        malformed("keycloak-metadata-entity-identity-evidence");
        for (var id : MetadataEntityIdentityConfigurationTestCase.IDS) {
            var test = implementation(id);
            assertEquals(Outcome.NOT_VERIFIED, finish(test.start(context(true))).outcome());
            for (var event : List.<CaseEvent>of(new CaseEvent.ConfigConfirmed(), new CaseEvent.TranscriptReady(),
                    new CaseEvent.Attested("evidence_satisfies", "registered"))) {
                assertEquals(Outcome.NOT_VERIFIED, finish(test.resume(context(true), state(), event)).outcome());
            }
            assertFalse(test.evidenceStatus(context(true)).ready());
            assertTrue(test.reevaluateRecordedEvidence(context(true), pending()).isEmpty());
        }
    }

    @Test void conflictingOwnersAndIncompleteHistoryNeverAdoptAnOldConclusion() throws Exception {
        malformed("keycloak-metadata-entity-identity-evidence");
        malformed("entityid-uniqueness-evidence");
        var test = implementation(A1);
        assertEquals(Outcome.NOT_VERIFIED, finish(test.start(context(false))).outcome());
        assertEquals(Outcome.NOT_VERIFIED, finish(test.resume(context(true), state(),
                new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT, "unavailable"))).outcome());
        assertTrue(test.reevaluateRecordedEvidence(context(false), pending()).isEmpty());
        assertTrue(test.reevaluateRecordedEvidence(context(true), satisfied(List.of(), Map.of())).isEmpty());
    }

    @Test void configurationUnavailabilityRetainsItsPreconditionMeaning() throws Exception {
        malformed("keycloak-metadata-entity-identity-evidence");
        var test = implementation(A1);
        var outcome = finish(test.resume(context(true), state(),
                new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT, "unavailable")));
        assertEquals(Outcome.NOT_VERIFIED, outcome.outcome());
        assertEquals("configuration.evidence-unavailable", outcome.reasonCode());
    }

    @Test void laterFilesDoNotRelabelEarlierManualOrShibbolethEvidence() throws Exception {
        var test = implementation(A1);
        var manual = execution(A1, satisfied(List.of(new EvidenceRef("attestation", "attestation:run:" + A1)), Map.of()));
        var shib = execution(A1, satisfied(List.of(new EvidenceRef("shibboleth-proof", "earlier")), Map.of()));
        assertEquals(RunCampaignQuery.EvidenceClass.SELF_ATTESTED, test.evidenceClass(manual));
        assertEquals(RunCampaignQuery.EvidenceClass.PROTOCOL_OBSERVED, test.evidenceClass(shib));
        malformed("keycloak-metadata-entity-identity-evidence");
        assertEquals(RunCampaignQuery.EvidenceClass.SELF_ATTESTED, test.evidenceClass(manual));
        assertEquals(RunCampaignQuery.EvidenceClass.PROTOCOL_OBSERVED, test.evidenceClass(shib));
    }

    @Test void nativeEvidenceKeepsPreparationAndRunBoundProvenance() throws Exception {
        malformed("keycloak-metadata-entity-identity-evidence");
        var test = implementation(A1);
        var nativePending = execution(A1, finish(test.start(context(true))));
        assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED, test.evidenceClass(nativePending));
        assertFalse(test.resolvedFromExternalEvidence(nativePending));
        var details = Map.<String, Object>of("evidence_adapter", ADAPTER, "native_run_id", RUN, "case_id", A1);
        var proof = List.of(new EvidenceRef("transcript", "tx_original"),
                new EvidenceRef("native-metadata-entity-identity-evidence", RUN + "/manifest.json#" + "1".repeat(64)));
        var nativeResult = execution(A1, satisfied(proof, details));
        assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED, test.evidenceClass(nativeResult));
        assertTrue(test.resolvedFromExternalEvidence(nativeResult));
        var foreign = execution(A1, satisfied(proof,
                Map.of("evidence_adapter", ADAPTER, "native_run_id", "another-run", "case_id", A1)));
        assertEquals(RunCampaignQuery.EvidenceClass.SELF_ATTESTED, test.evidenceClass(foreign));
        assertFalse(test.resolvedFromExternalEvidence(foreign));
        assertEquals(RunCampaignQuery.EvidenceClass.SELF_ATTESTED,
                test.evidenceClass(execution(A1, satisfied(List.of(), details))));
    }

    private MetadataEntityIdentityConfigurationTestCase implementation(String id) {
        return new MetadataEntityIdentityConfigurationTestCase(new Legacy(id),
                root.resolve("keycloak-metadata-entity-identity-evidence"), e -> new byte[0],
                r -> new byte[0], r -> Optional.empty());
    }
    private void malformed(String adapter) throws Exception {
        var folder = Files.createDirectories(root.resolve(adapter).resolve(RUN));
        Files.writeString(folder.resolve("manifest.json"), "{}");
    }
    private static CaseState state() { return new CaseState("legacy", Map.of()); }
    private static CaseOutcome finish(CaseStep step) { return assertInstanceOf(CaseStep.Finish.class, step).outcome(); }
    private static CaseOutcome pending() { return CaseOutcome.notVerified("pending", "legacy.pending"); }
    private static CaseOutcome satisfied(List<EvidenceRef> proof, Map<String, Object> details) {
        return new CaseOutcome(Outcome.SATISFIED, null, "legacy.satisfied", "legacy.satisfied", proof, details);
    }
    private static CaseExecution execution(String id, CaseOutcome outcome) {
        return new CaseExecution(RUN, id, 1, CaseExecutionStatus.FINISHED, state(), null, outcome, Instant.EPOCH);
    }
    private static DefaultCaseContext context(boolean complete) {
        var recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String run) { return List.of(); }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String, Object> summary) {
                throw new UnsupportedOperationException();
            }
        };
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, complete);
    }
    private record Legacy(String id) implements TestCase, ConfigurationPrompt, ProtocolEvidenceCase,
            EvidenceCampaignCase, RecordedEvidenceReevaluation, FallbackEvidenceCase {
        public TargetRole role() { return TargetRole.IDP; }
        public String instructionEn() { return "Prepare the existing approved fixture"; }
        public String evidenceCampaignId() { return "metadata-fixture-refresh"; }
        public String evidenceCampaignTitle() { return "Existing metadata fixture"; }
        public RunCampaignQuery.ActionKind evidenceActionKind() { return RunCampaignQuery.ActionKind.METADATA_REFRESH; }
        public List<String> evidenceActionKeys() { return List.of("control", "fixture"); }
        public CaseStep start(CaseContext context) { return new CaseStep.Finish(satisfied(List.of(), Map.of())); }
        public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
            return new CaseStep.Finish(event instanceof CaseEvent.ConfigUnavailable
                    ? CaseOutcome.notVerified("unavailable", "configuration.evidence-unavailable")
                    : satisfied(List.of(), Map.of()));
        }
        public EvidenceStatus evidenceStatus(CaseContext context) {
            return new EvidenceStatus(false, List.of("fixture"), List.of(), Map.of());
        }
        public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
            return previous.outcome() == Outcome.NOT_VERIFIED;
        }
        public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
            return Optional.empty();
        }
        public boolean resolvedFromExternalEvidence(CaseExecution execution) {
            return execution.outcome().evidence().stream().anyMatch(ref -> "shibboleth-proof".equals(ref.kind()));
        }
    }
}
