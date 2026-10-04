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

class MetadataSchemaAdmissionConfigurationTestCaseTest {
    private static final String RUN = "run_00000000000000000000000000";
    @TempDir Path directory;
    private MetadataFixtureObservationTestCase fallback(String id) {
        return new MetadataFixtureObservationTestCase(id, TargetRole.IDP, List.of(
                new MetadataFixtureObservationTestCase.Fixture("schema-sso-endpoint-set",
                        MetadataFixtureObservationTestCase.Behavior.ACCEPT, "schema-valid endpoint content")),
                ConfigurationFailureSemantics.NORMATIVE_CAPABILITY);
    }
    private MetadataSchemaAdmissionConfigurationTestCase implementation() {
        return new MetadataSchemaAdmissionConfigurationTestCase(fallback(MetadataSchemaAdmissionConfigurationTestCase.ID),
                e -> { throw new AssertionError("No native original declared"); }, r -> new byte[0], directory);
    }
    private CaseContext context(boolean complete) {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, new TranscriptRecorder() {
                    public List<TranscriptEntry> list(String run) { return List.of(); }
                    public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("Read only"); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) {
                        throw new AssertionError("Read only");
                    }
                }, complete);
    }
    @Test void absentProofPreservesTheApprovedConfigurationAndFullFixturePresentation() {
        var test = implementation();
        assertInstanceOf(CaseStep.AwaitConfig.class, test.start(context(true)));
        assertEquals(fallback(test.id()).instructionEn(), test.instructionEn());
        assertEquals("metadata-native-schema-admission", test.evidenceCampaignId());
        assertEquals(List.of("control", "schema-sso-endpoint-set", "schema-sso-endpoint-without-foreign",
                "schema-invalid-endpoint-location"), test.evidenceActionKeys());
        assertFalse(test.evidenceStatus(context(true)).ready());
        assertEquals(Outcome.NOT_VERIFIED, test.queuedEvidenceOutcome(context(true)).outcome());
    }
    @Test void configurationFailureSemanticsRemainApprovedWithoutANativeReceipt() {
        var test = implementation(); var state = ((CaseStep.AwaitConfig)test.start(context(true))).next();
        var result = ((CaseStep.Finish)test.resume(context(true), state,
                new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT, "not supported"))).outcome();
        assertEquals(Outcome.VIOLATED, result.outcome()); assertEquals("capability_absent", result.reasonCode());
    }
    @Test void malformedOwnedReceiptNeverFallsThroughToTheLegacyFixtureGate() throws Exception {
        Files.writeString(directory.resolve(RUN + ".keycloak-schema-admission.json"), "{}");
        var test = implementation();
        for (boolean complete : List.of(true, false)) {
            assertUnproven(test.start(context(complete)));
            for (var event : List.<CaseEvent>of(new CaseEvent.ConfigConfirmed(), new CaseEvent.TranscriptReady(),
                    new CaseEvent.Aborted("cancel"), new CaseEvent.TimedOut(Duration.ofSeconds(1))))
                assertUnproven(test.resume(context(complete), null, event));
            assertFalse(test.evidenceStatus(context(complete)).ready());
            assertEquals(Outcome.NOT_VERIFIED, test.queuedEvidenceOutcome(context(complete)).outcome());
        }
        assertTrue(test.reevaluateRecordedEvidence(context(true), CaseOutcome.notVerified("pending", "case.pending-interaction")).isEmpty());
    }
    @Test void receiptDirectoriesAndSymlinksAlsoOwnTheNativeBranch() throws Exception {
        var path = directory.resolve(RUN + ".keycloak-schema-admission.json");
        Files.createDirectory(path); assertUnproven(implementation().start(context(true))); Files.delete(path);
        var other = directory.resolve("other.json"); Files.writeString(other, "{}");
        Files.createSymbolicLink(path, other); assertUnproven(implementation().start(context(true)));
    }
    @Test void queuedAndRecordedPathsCannotSubmitAnAttestationOrReplaceAConclusion() {
        var test = implementation();
        assertEquals(Outcome.NOT_VERIFIED, test.queuedEvidenceOutcome(context(true)).outcome());
        for (var outcome : List.of(Outcome.SATISFIED, Outcome.SATISFIED_WITH_NOTE, Outcome.VIOLATED)) {
            var previous = CaseOutcome.of(outcome, "prior", List.of());
            assertFalse(test.supportsRecordedEvidenceReevaluation(previous));
            assertTrue(test.reevaluateRecordedEvidence(context(true), previous).isEmpty());
        }
        assertTrue(test.reevaluateRecordedEvidence(context(false), CaseOutcome.notVerified("pending", "case.pending-interaction")).isEmpty());
    }
    @Test void registryComposesOnlyTheApprovedSchemaCase() {
        var approved = fallback(MetadataSchemaAdmissionConfigurationTestCase.ID); var other = fallback("IIP-MD05-a-idp-01");
        var registry = ApprovedConfigCaseRegistry.withMetadataRejection(new TestCaseRegistry(List.of(approved, other)),
                e -> new byte[0], r -> new byte[0], directory);
        assertInstanceOf(MetadataSchemaAdmissionConfigurationTestCase.class, registry.require(approved.id()));
        assertSame(other, registry.require(other.id()));
        assertThrows(IllegalArgumentException.class, () -> new MetadataSchemaAdmissionConfigurationTestCase(other,
                e -> new byte[0], r -> new byte[0], directory));
    }
    @Test void approvedFixtureAndNativeConclusionsRemainExternalWithoutAManualVerdictPath() {
        var test = implementation();
        assertInstanceOf(ExternallyObservedCase.class, test);
        assertFalse(((Object)test) instanceof AttestationPrompt);
        var legacy = new AttestedOutcomeTestCase(test.id(), TargetRole.IDP, "manual", Duration.ofDays(1),
                List.of(AttestationOption.of("yes", Outcome.SATISFIED, "manual")));
        assertThrows(IllegalArgumentException.class, () -> new MetadataSchemaAdmissionConfigurationTestCase(
                legacy, e -> new byte[0], r -> new byte[0], directory));
    }
    private static void assertUnproven(CaseStep step) {
        var result = assertInstanceOf(CaseStep.Finish.class, step).outcome();
        assertEquals(Outcome.NOT_VERIFIED, result.outcome()); assertEquals("metadata.schema.native-admission-incomplete", result.reasonCode());
    }
}
