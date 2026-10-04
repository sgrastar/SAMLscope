package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboxEntry;
import com.samlscope.core.caseexec.OutboxStatus;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.caseexec.WaitCondition;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.InteractionQuery.Kind;
import com.samlscope.runner.cases.AttestationOption;
import com.samlscope.runner.cases.AttestedOutcomeTestCase;
import com.samlscope.runner.cases.ConfigurationGateTestCase;
import com.samlscope.runner.cases.BrowserEvidenceTestCase;
import com.samlscope.runner.cases.BrowserPrompt;
import com.samlscope.runner.cases.ConfigurationPrompt;
import com.samlscope.runner.cases.ProtocolEvidenceCase;
import com.samlscope.core.caseexec.ConfigurationFailureSemantics;

class PendingInteractionServiceTest {
    private static final Instant EXPIRES = Instant.parse("2026-08-29T04:00:00Z");

    @Test
    void exposesOnlySafePromptDataAndServerDefinedAnswerValues() {
        var browserEvidence = new AttestedOutcomeTestCase(
                "IIP-SSO01-a-sp-01", TargetRole.SP, "browser.evidence", Duration.ofMinutes(5),
                List.of(AttestationOption.of("satisfied", Outcome.SATISFIED, "satisfied")));
        var browser = new BrowserEvidenceTestCase(
                browserEvidence, URI.create("https://suite.example"), "Complete both browser controls.",
                Duration.ofMinutes(5));
        var config = new ConfigurationGateTestCase(
                passiveCase("IIP-MD01-a-sp-01", TargetRole.SP), "configuration.md01",
                "Refresh the target metadata.", Duration.ofMinutes(5),
                ConfigurationFailureSemantics.TEST_PRECONDITION);
        var attested = new AttestedOutcomeTestCase(
                "IIP-G02-c-sp-01", TargetRole.SP, "attestation.g02", "Review approved evidence.",
                Duration.ofMinutes(5),
                List.of(
                        AttestationOption.of("preserved", Outcome.SATISFIED, "preserved"),
                        AttestationOption.of("truncated", Outcome.VIOLATED, "truncated")));
        var service = new PendingInteractionService(
                repository(List.of(
                        execution(browser.id(), CaseExecutionStatus.WAITING_BROWSER,
                                new WaitCondition(
                                        WaitCondition.Kind.BROWSER, null, URI.create("https://suite.example/start"),
                                        null, EXPIRES)),
                        execution(config.id(), CaseExecutionStatus.WAITING_CONFIG,
                                new WaitCondition(WaitCondition.Kind.CONFIG, "configuration.md01", null, null, EXPIRES)),
                        execution(attested.id(), CaseExecutionStatus.WAITING_ATTESTATION,
                                new WaitCondition(WaitCondition.Kind.ATTESTATION, "attestation.g02", null, null, EXPIRES)),
                        execution("IIP-G03-a-sp-01", CaseExecutionStatus.FINISHED, null))),
                new TestCaseRegistry(List.of(browser, config, attested, passiveCase("IIP-G03-a-sp-01", TargetRole.SP))));

        var pending = service.pending("run");

        assertEquals(3, pending.size());
        assertEquals(Kind.BROWSER, pending.get(0).kind());
        assertEquals(URI.create("https://suite.example/start"), pending.get(0).startUrl());
        assertEquals("Complete both browser controls.", pending.get(0).promptEn());
        assertEquals(InteractionQuery.CompletionMode.OPERATOR, pending.get(0).completionMode());
        assertEquals(List.of(
                "confirmed", "capability_absent", "target_config_unavailable", "capability_undetermined"),
                pending.get(1).answerValues());
        assertEquals("Refresh the target metadata.", pending.get(1).promptEn());
        assertEquals(List.of("preserved", "truncated"), pending.get(2).answerValues());
        assertEquals("Review approved evidence.", pending.get(2).promptEn());
        assertEquals(EXPIRES, pending.get(2).expiresAt());
    }

    @Test
    void failsClosedForAnUnregisteredOrOpaqueAttestationCase() {
        var unknown = new PendingInteractionService(
                repository(List.of(execution(
                        "IIP-G02-c-sp-01", CaseExecutionStatus.WAITING_ATTESTATION,
                        new WaitCondition(WaitCondition.Kind.ATTESTATION, "question", null, null, EXPIRES)))),
                new TestCaseRegistry(List.of()));
        assertThrows(IllegalArgumentException.class, () -> unknown.pending("run"));

        var opaque = passiveCase("IIP-G02-c-sp-01", TargetRole.SP);
        var opaqueService = new PendingInteractionService(
                repository(List.of(execution(
                        opaque.id(), CaseExecutionStatus.WAITING_ATTESTATION,
                        new WaitCondition(WaitCondition.Kind.ATTESTATION, "question", null, null, EXPIRES)))),
                new TestCaseRegistry(List.of(opaque)));
        assertThrows(IllegalStateException.class, () -> opaqueService.pending("run"));
    }

    @Test
    void transcriptDrivenBrowserWaitDoesNotOfferAnOperatorCompletionAnswer() {
        var browser = new TranscriptBrowserCase();
        var service = new PendingInteractionService(
                repository(List.of(execution(
                        browser.id(), CaseExecutionStatus.WAITING_BROWSER,
                        new WaitCondition(
                                WaitCondition.Kind.BROWSER, null,
                                URI.create("https://suite.example/start"), null, EXPIRES)))),
                new TestCaseRegistry(List.of(browser)));

        var pending = service.pending("run").get(0);

        assertEquals(InteractionQuery.CompletionMode.TRANSCRIPT, pending.completionMode());
        assertEquals(List.of(), pending.answerValues());
    }

    @Test
    void transcriptDrivenConfigurationWaitKeepsOnlyTheUnavailabilityFallback() {
        var configuration = new TranscriptConfigurationCase();
        var service = new PendingInteractionService(
                repository(List.of(execution(
                        configuration.id(), CaseExecutionStatus.WAITING_CONFIG,
                        new WaitCondition(
                                WaitCondition.Kind.CONFIG, "metadata-fixture-probe",
                                null, null, EXPIRES)))),
                new TestCaseRegistry(List.of(configuration)));

        var pending = service.pending("run").get(0);

        assertEquals(InteractionQuery.CompletionMode.TRANSCRIPT_OR_OPERATOR, pending.completionMode());
        assertEquals(List.of(
                "capability_absent", "target_config_unavailable", "capability_undetermined"),
                pending.answerValues());
    }

    @Test
    void obsoleteInteractionFreeBrowserWaitIsNotProjectedAsAnotherUserAction() {
        var evidenceOnly = new InteractionFreeCase();
        var browser = new TranscriptBrowserCase();
        var oldWait = execution(evidenceOnly.id(), CaseExecutionStatus.WAITING_BROWSER,
                new WaitCondition(WaitCondition.Kind.BROWSER, null,
                        URI.create("https://suite.example/obsolete-start"), null, EXPIRES));
        var service = new PendingInteractionService(repository(List.of(oldWait,
                execution(browser.id(), CaseExecutionStatus.WAITING_BROWSER,
                        new WaitCondition(WaitCondition.Kind.BROWSER, null,
                                URI.create("https://suite.example/start"), null, EXPIRES)))),
                new TestCaseRegistry(List.of(evidenceOnly, browser)));

        var pending = service.pending("run");

        assertEquals(1, pending.size());
        assertEquals(browser.id(), pending.getFirst().caseId());
        assertEquals(URI.create("https://suite.example/start"), pending.getFirst().startUrl());
        assertEquals(InteractionQuery.CompletionMode.TRANSCRIPT, pending.getFirst().completionMode());
        assertEquals(CaseExecutionStatus.WAITING_BROWSER, oldWait.status());
        assertEquals(0, oldWait.revision());
        assertEquals(null, oldWait.outcome(), "GET projection must not migrate the persisted wait");
    }

    @Test
    void unregisteredAndOpaqueBrowserWaitsStillFailClosed() {
        var opaque = passiveCase("ordinary-browser", TargetRole.IDP);
        var oldWait = execution(opaque.id(), CaseExecutionStatus.WAITING_BROWSER,
                new WaitCondition(WaitCondition.Kind.BROWSER, null,
                        URI.create("https://suite.example/start"), null, EXPIRES));
        var unregistered = new PendingInteractionService(repository(List.of(oldWait)),
                new TestCaseRegistry(List.of()));
        assertThrows(IllegalArgumentException.class, () -> unregistered.pending("run"));

        var service = new PendingInteractionService(repository(List.of(oldWait)),
                new TestCaseRegistry(List.of(opaque)));
        assertThrows(IllegalStateException.class, () -> service.pending("run"));
    }

    private CaseExecution execution(String caseId, CaseExecutionStatus status, WaitCondition wait) {
        return new CaseExecution(
                "run", caseId, 0, status, new CaseState("test", Map.of("secret", "not exposed")), wait,
                status == CaseExecutionStatus.FINISHED
                        ? com.samlscope.core.evaluation.CaseOutcome.of(Outcome.SATISFIED, "done", List.of())
                        : null,
                EXPIRES.minusSeconds(60));
    }

    private TestCase passiveCase(String id, TargetRole role) {
        return new TestCase() {
            @Override public String id() { return id; }
            @Override public TargetRole role() { return role; }
            @Override public CaseStep start(CaseContext context) { throw new UnsupportedOperationException(); }
            @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
                throw new UnsupportedOperationException();
            }
        };
    }

    private static final class TranscriptBrowserCase
            implements TestCase, BrowserPrompt, ProtocolEvidenceCase {
        @Override public String id() { return "IIP-SSO03-a-idp-01"; }
        @Override public TargetRole role() { return TargetRole.IDP; }
        @Override public String browserInstructionsEn() { return "Run the correlated flow."; }
        @Override public CaseStep start(CaseContext context) { throw new UnsupportedOperationException(); }
        @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
            throw new UnsupportedOperationException();
        }
        @Override public EvidenceStatus evidenceStatus(CaseContext context) {
            return new EvidenceStatus(false, List.of("response"), List.of(), Map.of());
        }
    }

    private static final class InteractionFreeCase
            implements com.samlscope.runner.cases.InteractionFreeEvidenceCase {
        @Override public String id() { return "IIP-IDP06-b-idp-01"; }
        @Override public TargetRole role() { return TargetRole.IDP; }
        @Override public EvidenceStatus evidenceStatus(CaseContext context) {
            return new EvidenceStatus(false, List.of("native-mechanism-trace"), List.of(), Map.of());
        }
        @Override public com.samlscope.core.evaluation.CaseOutcome queuedEvidenceOutcome(CaseContext context) {
            return com.samlscope.core.evaluation.CaseOutcome.notVerified("native evidence unavailable",
                    "native-mechanism.unproven");
        }
    }

    private static final class TranscriptConfigurationCase
            implements TestCase, ConfigurationPrompt, ProtocolEvidenceCase {
        @Override public String id() { return "IIP-MD05-an-sp-01"; }
        @Override public TargetRole role() { return TargetRole.SP; }
        @Override public String instructionEn() { return "Use the stable Suite metadata URL."; }
        @Override public CaseStep start(CaseContext context) { throw new UnsupportedOperationException(); }
        @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
            throw new UnsupportedOperationException();
        }
        @Override public EvidenceStatus evidenceStatus(CaseContext context) {
            return new EvidenceStatus(false, List.of("metadata-fetch"), List.of(), Map.of());
        }
    }

    private CaseExecutionRepository repository(List<CaseExecution> values) {
        return new CaseExecutionRepository() {
            @Override public Optional<CaseExecution> find(String runId, String caseId) { return Optional.empty(); }
            @Override public List<CaseExecution> list(String runId) { return values; }
            @Override public boolean apply(long expectedRevision, CaseExecution execution, List<OutboundAction> actions) {
                throw new UnsupportedOperationException();
            }
            @Override public List<OutboxEntry> listOutbox(String runId) { return List.of(); }
            @Override public Optional<OutboxEntry> findOutbox(String actionId) { return Optional.empty(); }
            @Override public boolean transitionOutbox(
                    String actionId, OutboxStatus expected, OutboxStatus next, Map<String, Object> sendResult,
                    String transcriptEntryId, Instant updatedAt) {
                throw new UnsupportedOperationException();
            }
            @Override public int recoverSendingAsUnknownDelivery(Instant updatedAt) { return 0; }
        };
    }
}
