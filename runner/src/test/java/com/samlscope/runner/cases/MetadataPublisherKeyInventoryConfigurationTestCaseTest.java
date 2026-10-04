package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.time.*;
import java.util.*;
import java.util.function.Function;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.casedef.CaseDefinitionCatalog.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.RunCampaignQuery;
import com.samlscope.runner.TestCaseRegistry;
import com.samlscope.runner.RunCampaignService;

class MetadataPublisherKeyInventoryConfigurationTestCaseTest {
    @TempDir Path directory;
    private static final String RUN = "run_00000000000000000000000001";
    private static final String CASE = "IIP-MD05-c1-idp-01";
    private static final String REASON = "metadata.publisher.role-description-complete";
    private static final CaseState STATE = new CaseState("publisher", Map.of());
    private static final EvidenceRef TX = new EvidenceRef("transcript", "tx_00000000000000000000000001");
    private static final EvidenceRef MANIFEST = new EvidenceRef("native-metadata-publisher-key-evidence",
            RUN + "/manifest.json#" + "a".repeat(64));
    private final CaseContext context = new CaseContext() {
        @Override public String runId() { return RUN; }
        @Override public TargetRole targetRole() { return TargetRole.IDP; }
        @Override public Clock clock() { return Clock.fixed(Instant.EPOCH, ZoneOffset.UTC); }
        @Override public TestPlan.Parameters parameters() { return null; }
        @Override public TestPlan.Interaction interaction() { return null; }
        @Override public Reachability reachability() { return Reachability.CONFIRMED; }
        @Override public TranscriptRecorder transcript() { return null; }
        @Override public boolean transcriptComplete() { return true; }
    };

    @Test void completeNativeProofFinishesWithoutAnOperatorConfirmation() {
        var fallback = new Fallback(CASE, TargetRole.IDP);
        var testCase = wrapper(fallback, c -> proof(Outcome.SATISFIED, REASON, List.of(TX, MANIFEST), Map.of()));
        var finished = assertInstanceOf(CaseStep.Finish.class, testCase.start(context));
        assertEquals(Outcome.SATISFIED, finished.outcome().outcome());
        assertEquals(0, fallback.calls);
        assertTrue(testCase.evidenceStatus(context).ready());
        assertEquals(Boolean.TRUE, finished.outcome().details().get("native_publisher_inventory_verified"));
    }

    @Test void MissingOrUnreadableEvidenceRetainsTheApprovedWait() {
        for (Function<CaseContext, CaseOutcome> observation : List.<Function<CaseContext, CaseOutcome>>of(
                c -> null, c -> CaseOutcome.notVerified("missing", "metadata.publisher.key-inventory-unproven"),
                c -> { throw new IllegalArgumentException("unreadable original"); })) {
            var testCase = wrapper(new Fallback(CASE, TargetRole.IDP), observation);
            assertInstanceOf(CaseStep.AwaitConfig.class, testCase.start(context));
            assertFalse(testCase.evidenceStatus(context).ready());
            assertTrue(testCase.reevaluateRecordedEvidence(context, pending(List.of())).isEmpty());
        }
    }

    @Test void LabelsWithoutBothOwnRunOriginalReferencesCannotConclude() {
        var foreign = new EvidenceRef(MANIFEST.kind(), "run_foreign/manifest.json#" + "a".repeat(64));
        var naked = new EvidenceRef(MANIFEST.kind(), RUN + "/manifest.json");
        for (var evidence : List.of(List.of(TX), List.of(MANIFEST), List.of(TX, foreign), List.of(TX, naked))) {
            var testCase = wrapper(new Fallback(CASE, TargetRole.IDP),
                    c -> proof(Outcome.SATISFIED, REASON, evidence, Map.of()));
            assertInstanceOf(CaseStep.AwaitConfig.class, testCase.start(context));
        }
    }

    @Test void AnotherCasesConclusionAndDiagnosticControlAreNotAdopted() {
        for (var result : List.of(
                proof(Outcome.SATISFIED, "metadata.publisher.current-key-inventory-complete", List.of(TX, MANIFEST), Map.of()),
                proof(Outcome.SATISFIED, REASON, List.of(TX, MANIFEST), Map.of("counterfactual_calibration_only", true)),
                proof(Outcome.INCONSISTENT, REASON, List.of(TX, MANIFEST), Map.of()))) {
            var testCase = wrapper(new Fallback(CASE, TargetRole.IDP), c -> result);
            assertFalse(testCase.evidenceStatus(context).ready());
            assertTrue(testCase.reevaluateRecordedEvidence(context, pending(List.of())).isEmpty());
        }
    }

    @Test void ConfigurationFailureSemanticsRemainWithTheApprovedFallback() {
        var fallback = new Fallback(CASE, TargetRole.IDP);
        var testCase = wrapper(fallback, c -> proof(Outcome.SATISFIED, REASON, List.of(TX, MANIFEST), Map.of()));
        var step = assertInstanceOf(CaseStep.Finish.class, testCase.resume(context, STATE,
                new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT, "stock capability")));
        assertEquals(Outcome.VIOLATED, step.outcome().outcome());
        assertEquals("configuration.capability-absent", step.outcome().reasonCode());
        assertEquals(1, fallback.calls);
    }

    @Test void ReassessmentRequiresNewTranscriptEvidenceAndPreservesConclusiveHistory() {
        var result = proof(Outcome.SATISFIED, REASON, List.of(TX, MANIFEST), Map.of());
        var testCase = wrapper(new Fallback(CASE, TargetRole.IDP), c -> result);
        assertTrue(testCase.reevaluateRecordedEvidence(context, pending(List.of())).isPresent());
        assertTrue(testCase.reevaluateRecordedEvidence(context, pending(List.of(TX))).isEmpty());
        assertTrue(testCase.reevaluateRecordedEvidence(context, result).isEmpty());
    }

    @Test void PublisherInventoryProvenanceRemainsOperatorAssistedAndRunBound() {
        var testCase = wrapper(new Fallback(CASE, TargetRole.IDP),
                c -> proof(Outcome.SATISFIED, REASON, List.of(TX, MANIFEST), Map.of()));
        var nativeOutcome = assertInstanceOf(CaseStep.Finish.class, testCase.start(context)).outcome();
        assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,
                testCase.evidenceClass(execution(RUN, CASE, nativeOutcome)));
        assertFalse(testCase.resolvedFromExternalEvidence(execution("run_foreign", CASE, nativeOutcome)));
        assertFalse(testCase.resolvedFromExternalEvidence(execution(RUN, "IIP-MD05-c3-idp-01", nativeOutcome)));
        assertFalse(testCase.resolvedFromExternalEvidence(execution(RUN, CASE,
                proof(Outcome.SATISFIED, REASON, List.of(TX, MANIFEST), Map.of()))));
    }

    @Test void UnrelatedCasesAndRolesCannotUseThePublisherProof() {
        assertThrows(IllegalArgumentException.class, () -> wrapper(new Fallback("other", TargetRole.IDP), c -> null));
        assertThrows(IllegalArgumentException.class, () -> wrapper(new Fallback(CASE, TargetRole.SP), c -> null));
    }

    @Test void normalMetadataRegistryConnectsBothApprovedCasesToOneCampaign() {
        var definitions = new CaseDefinitionCatalog(List.of(
                definition(CASE, "IIP-MD05.c1"),
                definition("IIP-MD05-c3-idp-01", "IIP-MD05.c3"),
                definition("IIP-MD05-c5-idp-01", "IIP-MD05.c5")));
        var original = ApprovedConfigCaseRegistry.create(definitions, Milestone.M2);
        var registered = decorate(original);
        assertEquals(original.ids(), registered.ids());
        for (String id : List.of(CASE, "IIP-MD05-c3-idp-01")) {
            var testCase = assertInstanceOf(MetadataPublisherKeyInventoryConfigurationTestCase.class,
                    registered.require(id));
            assertEquals("native-metadata-publisher-key-inventory", testCase.evidenceCampaignId());
            assertEquals(RunCampaignQuery.ActionKind.CONFIGURATION, testCase.evidenceActionKind());
            assertInstanceOf(CaseStep.AwaitConfig.class, testCase.start(context));
            assertFalse(testCase.evidenceStatus(context).ready());
        }
        assertSame(original.require("IIP-MD05-c5-idp-01"), registered.require("IIP-MD05-c5-idp-01"));
    }

    @Test void decoratingTheRegistryTwicePreservesTheSameNativeCaseInstance() {
        var first = decorate(new TestCaseRegistry(List.of(new Fallback(CASE, TargetRole.IDP))));
        var again = decorate(first);
        assertSame(first.require(CASE), again.require(CASE));
    }

    @Test void registryDecorationDoesNotReplaceAnotherRoleOrAnUnrelatedCase() {
        var wrongRole = new Fallback(CASE, TargetRole.SP);
        var unrelated = new Fallback("IIP-MD05-c5-idp-01", TargetRole.IDP);
        var registered = decorate(new TestCaseRegistry(List.of(wrongRole, unrelated)));
        assertSame(wrongRole, registered.require(CASE));
        assertSame(unrelated, registered.require(unrelated.id()));
    }

    @Test void pendingNativePreparationIsStandardButAnUnprovenAnswerRemainsSelfAttested() {
        var testCase = wrapper(new Fallback(CASE, TargetRole.IDP), c -> null);
        assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED, testCase.evidenceClass(null));
        var pendingExecution = execution(RUN, CASE, pending(List.of()));
        assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED, testCase.evidenceClass(pendingExecution));
        var declared = execution(RUN, CASE,
                proof(Outcome.SATISFIED, "configuration.evidence-satisfies", List.of(), Map.of("attested", true)));
        assertEquals(RunCampaignQuery.EvidenceClass.SELF_ATTESTED, testCase.evidenceClass(declared));
        assertFalse(testCase.resolvedFromExternalEvidence(declared));
    }

    @Test void bothPublisherCasesShareThePreparationBudgetWithoutAddingALogin() {
        var c3 = "IIP-MD05-c3-idp-01";
        var definitions = new CaseDefinitionCatalog(List.of(definition(CASE, "IIP-MD05.c1"),
                definition(c3, "IIP-MD05.c3")));
        var registry = new TestCaseRegistry(List.of(wrapper(new Fallback(CASE, TargetRole.IDP), c -> null),
                wrapper(new Fallback(c3, TargetRole.IDP), c -> null)));
        var executions = List.of(waiting(CASE), waiting(c3));
        var repository = (CaseExecutionRepository) java.lang.reflect.Proxy.newProxyInstance(
                CaseExecutionRepository.class.getClassLoader(), new Class<?>[]{CaseExecutionRepository.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "list" -> { assertEquals(RUN, arguments[0]); yield executions; }
                    case "find" -> executions.stream().filter(e -> e.runId().equals(arguments[0])
                            && e.caseId().equals(arguments[1])).findFirst();
                    default -> throw new AssertionError("Campaign report must not mutate an execution");
                });
        var report = new RunCampaignService(repository, definitions, registry, run -> context).report(RUN);
        assertEquals(2, report.cases());
        assertEquals(0, report.externallyVerifiedCases());
        assertEquals(1, report.campaigns().size());
        var campaign = report.campaigns().getFirst();
        assertEquals(Set.of(CASE, c3), Set.copyOf(campaign.caseIds()));
        assertEquals(3, campaign.deliberateUserActions());
        assertEquals(3, campaign.remainingUserActions());
        assertFalse(campaign.freshSessionRequired());
        assertEquals(RunCampaignQuery.Plan.STANDARD, campaign.plan());
        assertEquals(RunCampaignQuery.ActionKind.CONFIGURATION, campaign.actionKind());
        assertTrue(report.plans().stream().allMatch(plan -> plan.loginActions() == 0));
    }

    private TestCaseRegistry decorate(TestCaseRegistry registry) {
        return ApprovedConfigCaseRegistry.withMetadataRejection(registry,
                entry -> { throw new AssertionError("Absent native proof must not read an original"); },
                run -> new byte[0], directory.resolve("metadata-rejection-evidence"));
    }

    private static CaseDefinition definition(String id, String obligation) {
        return new CaseDefinition(id, obligation, TargetRole.IDP, ExecutionMode.CONFIG, Milestone.M2,
                List.of(), Map.of(), List.of(), List.of(), List.of(), "Approved publisher controls remain required",
                List.of(), new Requirements(List.of(), "none"), false,
                ConfigurationFailureSemantics.NORMATIVE_CAPABILITY, "sha256:" + "a".repeat(64));
    }

    private static MetadataPublisherKeyInventoryConfigurationTestCase wrapper(Fallback fallback,
            Function<CaseContext, CaseOutcome> observation) {
        return new MetadataPublisherKeyInventoryConfigurationTestCase(fallback, observation);
    }
    private static CaseOutcome proof(Outcome outcome, String reason, List<EvidenceRef> evidence, Map<String, Object> details) {
        return new CaseOutcome(outcome, null, reason, reason, evidence, details);
    }
    private static CaseOutcome pending(List<EvidenceRef> evidence) {
        return new CaseOutcome(Outcome.NOT_VERIFIED, "missing", "case.pending-interaction",
                "case.pending-interaction", evidence, Map.of());
    }
    private static CaseExecution execution(String run, String id, CaseOutcome result) {
        return new CaseExecution(run, id, 1, CaseExecutionStatus.FINISHED, STATE, null, result, Instant.EPOCH);
    }
    private static CaseExecution waiting(String id) {
        return new CaseExecution(RUN, id, 1, CaseExecutionStatus.WAITING_CONFIG,
                STATE, new WaitCondition(WaitCondition.Kind.CONFIG, "publisher.prepare", null, null,
                        Instant.EPOCH.plusSeconds(86400)), null, Instant.EPOCH);
    }
    private static final class Fallback implements TestCase, ConfigurationPrompt, AttestationPrompt {
        final String id; final TargetRole role; int calls;
        Fallback(String id, TargetRole role) { this.id = id; this.role = role; }
        @Override public String id() { return id; }
        @Override public TargetRole role() { return role; }
        @Override public String instructionEn() { return "Prepare native publication"; }
        @Override public String promptEn() { return "Review the recorded publisher evidence"; }
        @Override public List<AttestationOption> options() { return List.of(); }
        @Override public CaseStep start(CaseContext context) {
            calls++;
            return new CaseStep.AwaitConfig(STATE, List.of(), "publisher.prepare", Duration.ofDays(1));
        }
        @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
            calls++;
            if (event instanceof CaseEvent.ConfigUnavailable) return new CaseStep.Finish(
                    proof(Outcome.VIOLATED, "configuration.capability-absent", List.of(), Map.of()));
            return new CaseStep.AwaitConfig(STATE, List.of(), "publisher.prepare", Duration.ofDays(1));
        }
    }
}
