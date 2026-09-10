package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.OutboxStatus;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.runner.cases.IdpErrorProbeConfiguration;
import com.samlscope.runner.cases.IdpErrorResponseTestCase;
import com.samlscope.runner.cases.IdpForceAuthnScenarioTestCase;
import com.samlscope.runner.cases.IdpNameIdPolicyScenarioTestCase;
import com.samlscope.runner.outbox.OutboundDispatcher;
import com.samlscope.runner.outbox.OutboundSender;
import com.samlscope.store.FileTranscriptRecorder;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteCaseExecutionRepository;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

class ActiveProbeCoordinatorTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String PLAN = "plan_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @TempDir java.nio.file.Path directory;
    private SqliteCaseExecutionRepository executions;
    private SqliteRunRepository runs;
    private SqlitePlanRepository plans;
    private FileTranscriptRecorder transcript;
    private ActiveProbeCoordinator coordinator;
    private CaseContextProvider contexts;

    @BeforeEach
    void setUp() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        plans = new SqlitePlanRepository(database, json);
        var plan = new TestPlan(
                PLAN, "Active probe", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.HTTP_URL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
        plans.save(plan);
        runs = new SqliteRunRepository(database, json);
        runs.save(new TestRun(RUN, PLAN, RunStatus.COMPLETED, Reachability.CONFIRMED, Map.of(), NOW, NOW));
        executions = new SqliteCaseExecutionRepository(database, json);
        transcript = new FileTranscriptRecorder(database, json, directory);
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        contexts = ignored -> new DefaultCaseContext(
                RUN, plan.profile().role(), clock, plan.parameters(), plan.interaction(),
                Reachability.CONFIRMED, transcript, true);
        var configuration = configuration(true);
        new CaseExecutionService(executions).start(
                RUN, new IdpErrorResponseTestCase(configuration), contexts.contextFor(RUN));
        var dispatcher = new OutboundDispatcher(
                executions,
                (runId, action, credential) -> new OutboundSender.SendResult(false, Map.of(), "unused"),
                (runId, actionId) -> Optional.empty(),
                new OutboundPolicy(true), clock);
        coordinator = new ActiveProbeCoordinator(
                URI.create("https://suite.example"), plans, runs, executions, dispatcher,
                transcript, contexts, (ignored, runId) -> configuration, clock);
    }

    @Test
    void runsAllAbnormalRequestsSequentiallyAndCompletesFromCorrelatedResponses() {
        var passive = coordinator.status(RUN);
        assertEquals(ActiveProbeCoordinator.State.READY, passive.state());
        assertTrue(passive.requiresFreshSession());
        assertTrue(passive.startUrl().toString().contains(passive.actionId()));
        assertThrows(IllegalArgumentException.class,
                () -> coordinator.prepare(RUN, passive.actionId(), false));

        var first = coordinator.prepare(RUN, passive.actionId(), true);
        assertEquals(74, first.relayState().getBytes(StandardCharsets.UTF_8).length);
        assertTrue(new String(Base64s.decode(first.samlRequest()), StandardCharsets.UTF_8)
                .contains("IsPassive=\"true\""));
        assertEquals(OutboxStatus.UNKNOWN_DELIVERY,
                executions.findOutbox(passive.actionId()).orElseThrow().status());
        assertThrows(IllegalStateException.class,
                () -> coordinator.prepare(RUN, passive.actionId(), true));

        var baseline = coordinator.accept(
                RUN, passive.actionId(), response("Requester"), new EvidenceRef("transcript", "tx-passive"));
        assertEquals(ActiveProbeCoordinator.State.READY, baseline.state());
        assertFalse(baseline.requiresFreshSession());

        var second = coordinator.prepare(RUN, baseline.actionId(), false);
        var baselineXml = new String(Base64s.decode(second.samlRequest()), StandardCharsets.UTF_8);
        assertFalse(baselineXml.contains("NameIDPolicy"));
        assertFalse(baselineXml.contains("RequestedAuthnContext"));
        var unknown = coordinator.accept(
                RUN, baseline.actionId(), response("Success"), new EvidenceRef("transcript", "tx-baseline"));

        var third = coordinator.prepare(RUN, unknown.actionId(), false);
        assertTrue(new String(Base64s.decode(third.samlRequest()), StandardCharsets.UTF_8)
                .contains("NameIDPolicy"));
        var authnContext = coordinator.accept(
                RUN, unknown.actionId(), response("Responder"), new EvidenceRef("transcript", "tx-nameid"));
        assertEquals(ActiveProbeCoordinator.State.READY, authnContext.state());

        var fourth = coordinator.prepare(RUN, authnContext.actionId(), false);
        assertTrue(new String(Base64s.decode(fourth.samlRequest()), StandardCharsets.UTF_8)
                .contains("RequestedAuthnContext"));
        var finished = coordinator.accept(
                RUN, authnContext.actionId(), response("Responder"), new EvidenceRef("transcript", "tx-context"));

        assertEquals(ActiveProbeCoordinator.State.FINISHED, finished.state());
        assertEquals(Outcome.SATISFIED.name(), finished.outcome());
        assertEquals(4, transcript.list(RUN).size());
        assertEquals(CaseExecutionStatus.FINISHED,
                executions.find(RUN, IdpErrorResponseTestCase.CASE_ID).orElseThrow().status());
    }

    @Test
    void aResponseWithTheWrongInResponseToIsRoutedButRemainsInconclusive() {
        var current = coordinator.status(RUN);
        coordinator.prepare(RUN, current.actionId(), true);
        var response = """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="_wrong">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>
                </samlp:Response>
                """.getBytes(StandardCharsets.UTF_8);

        var next = coordinator.accept(
                RUN, current.actionId(), response, new EvidenceRef("transcript", "tx-wrong"));

        assertEquals(ActiveProbeCoordinator.State.READY, next.state());
    }

    @Test
    void correlationCannotBeReusedAcrossRuns() {
        var otherRun = "run_1123456789ABCDEFGHJKMNPQRS";
        runs.save(new TestRun(
                otherRun, PLAN, RunStatus.COMPLETED, Reachability.CONFIRMED, Map.of(), NOW, NOW));
        var current = coordinator.status(RUN);
        coordinator.prepare(RUN, current.actionId(), true);

        assertThrows(IllegalArgumentException.class, () -> coordinator.accept(
                otherRun, current.actionId(), response("Requester"),
                new EvidenceRef("transcript", "tx-cross-run")));
        assertEquals(OutboxStatus.UNKNOWN_DELIVERY,
                executions.findOutbox(current.actionId()).orElseThrow().status());
    }

    @Test
    void duplicateResponseForThePreviousFixtureIsIdempotent() {
        var first = coordinator.status(RUN);
        coordinator.prepare(RUN, first.actionId(), true);
        var requestId = String.valueOf(executions.find(RUN, IdpErrorResponseTestCase.CASE_ID)
                .orElseThrow().state().data().get("expected_response_correlation"));
        var response = responseFor(requestId, "Requester");

        var next = coordinator.accept(
                RUN, first.actionId(), response, new EvidenceRef("transcript", "tx-first"));
        var duplicate = coordinator.accept(
                RUN, first.actionId(), response, new EvidenceRef("transcript", "tx-duplicate"));

        assertEquals(ActiveProbeCoordinator.State.READY, duplicate.state());
        assertEquals(next.actionId(), duplicate.actionId());
    }

    @Test
    void expiresItsPlanSpecificWaitAsSuiteUncertainty() {
        var current = coordinator.status(RUN);
        coordinator.prepare(RUN, current.actionId(), true);
        var later = new ActiveProbeCoordinator(
                URI.create("https://suite.example"),
                new SqlitePlanRepository(new SqliteDatabase(directory), new JsonCodec()),
                runs, executions,
                new OutboundDispatcher(
                        executions,
                        (runId, action, credential) -> new OutboundSender.SendResult(false, Map.of(), "unused"),
                        (runId, actionId) -> Optional.empty(),
                        new OutboundPolicy(true), Clock.fixed(NOW.plus(Duration.ofMinutes(6)), ZoneOffset.UTC)),
                transcript, contexts, (ignored, runId) -> configuration(true),
                Clock.fixed(NOW.plus(Duration.ofMinutes(6)), ZoneOffset.UTC));

        var expired = later.expireReady(RUN);

        assertTrue(expired.isPresent());
        assertEquals(CaseExecutionStatus.FINISHED, expired.orElseThrow().status());
        assertEquals(Outcome.NOT_VERIFIED, expired.orElseThrow().outcome().outcome());
        assertEquals(ActiveProbeCoordinator.State.FINISHED, later.status(RUN).state());
        assertEquals(Outcome.NOT_VERIFIED.name(), later.status(RUN).outcome());
        assertTrue(later.expireReady(RUN).isEmpty());
    }

    @Test
    void lateResponseAfterTimeoutIsAcknowledgedWithoutChangingSuiteUncertainty() {
        var current = coordinator.status(RUN);
        coordinator.prepare(RUN, current.actionId(), true);
        var requestId = String.valueOf(executions.find(RUN, IdpErrorResponseTestCase.CASE_ID)
                .orElseThrow().state().data().get("expected_response_correlation"));
        var later = new ActiveProbeCoordinator(
                URI.create("https://suite.example"),
                new SqlitePlanRepository(new SqliteDatabase(directory), new JsonCodec()),
                runs, executions,
                new OutboundDispatcher(
                        executions,
                        (runId, action, credential) -> new OutboundSender.SendResult(false, Map.of(), "unused"),
                        (runId, actionId) -> Optional.empty(),
                        new OutboundPolicy(true), Clock.fixed(NOW.plus(Duration.ofMinutes(6)), ZoneOffset.UTC)),
                transcript, contexts, (ignored, runId) -> configuration(true),
                Clock.fixed(NOW.plus(Duration.ofMinutes(6)), ZoneOffset.UTC));
        assertTrue(later.expireReady(RUN).isPresent());

        var status = later.accept(
                RUN, current.actionId(), responseFor(requestId, "Requester"),
                new EvidenceRef("transcript", "tx-late"));

        assertEquals(ActiveProbeCoordinator.State.FINISHED, status.state());
        assertEquals(Outcome.NOT_VERIFIED.name(), status.outcome());
        assertEquals(OutboxStatus.SENT,
                executions.findOutbox(current.actionId()).orElseThrow().status());
    }

    @Test
    void missingBrowserResponseSkipsOnlyTheCurrentFixtureAndContinuesTheScenario() {
        var runId = "run_2123456789ABCDEFGHJKMNPQRS";
        runs.save(new TestRun(runId, PLAN, RunStatus.COMPLETED, Reachability.CONFIRMED, Map.of(), NOW, NOW));
        var configuration = configuration(true);
        var scenario = new IdpNameIdPolicyScenarioTestCase(
                IdpNameIdPolicyScenarioTestCase.PROCESSING_CASE, configuration);
        var runContexts = (CaseContextProvider) ignored -> new DefaultCaseContext(
                runId, com.samlscope.core.plan.TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(),
                Reachability.CONFIRMED, transcript, true);
        new CaseExecutionService(executions).start(runId, scenario, runContexts.contextFor(runId));
        var dispatcher = new OutboundDispatcher(
                executions,
                (candidateRun, action, credential) -> new OutboundSender.SendResult(false, Map.of(), "unused"),
                (candidateRun, actionId) -> Optional.empty(),
                new OutboundPolicy(true), Clock.fixed(NOW, ZoneOffset.UTC));
        var generic = new ActiveProbeCoordinator(
                URI.create("https://suite.example"), plans, runs, executions, dispatcher,
                transcript, runContexts, (ignored, candidateRun) -> configuration,
                new TestCaseRegistry(java.util.List.of(scenario)), Clock.fixed(NOW, ZoneOffset.UTC));

        var ready = generic.status(runId);
        assertEquals(ActiveProbeCoordinator.State.READY, ready.state());
        assertEquals(IdpNameIdPolicyScenarioTestCase.PROCESSING_CASE, ready.caseId());
        assertTrue(ready.instructionsEn().contains("browser session"));
        generic.prepare(runId, ready.actionId(), false);
        assertEquals(ActiveProbeCoordinator.State.AWAITING_RESPONSE, generic.status(runId).state());

        var next = generic.abort(runId);
        assertEquals(ActiveProbeCoordinator.State.READY, next.state());
        assertEquals(IdpNameIdPolicyScenarioTestCase.PROCESSING_CASE, next.caseId());
        var execution = executions.find(runId, scenario.id()).orElseThrow();
        assertEquals(CaseExecutionStatus.WAITING_INBOUND, execution.status());
        assertEquals(1, execution.state().data().get("fixture_index"));
        assertEquals(List.of("policy-omitted"), execution.state().data().get("unverifiable"));
    }

    @Test
    void reissuesAnUncertainOneTimeFixtureAsANewOutboxAction() {
        var original = coordinator.status(RUN);
        coordinator.prepare(RUN, original.actionId(), true);
        assertEquals(ActiveProbeCoordinator.State.AWAITING_RESPONSE, coordinator.status(RUN).state());

        var retried = coordinator.retry(RUN);

        assertEquals(ActiveProbeCoordinator.State.READY, retried.state());
        org.junit.jupiter.api.Assertions.assertNotEquals(original.actionId(), retried.actionId());
        assertEquals(OutboxStatus.UNKNOWN_DELIVERY,
                executions.findOutbox(original.actionId()).orElseThrow().status());
        assertEquals(OutboxStatus.PENDING,
                executions.findOutbox(retried.actionId()).orElseThrow().status());
        assertEquals(2, executions.listOutbox(RUN).size());
    }

    @Test
    void recordsStageBasedScenarioWithoutAnOptionalFixtureId() {
        var runId = "run_3123456789ABCDEFGHJKMNPQRS";
        runs.save(new TestRun(runId, PLAN, RunStatus.COMPLETED, Reachability.CONFIRMED, Map.of(), NOW, NOW));
        var configuration = configuration(true);
        var scenario = new IdpForceAuthnScenarioTestCase(ignored -> configuration);
        var runContexts = (CaseContextProvider) ignored -> new DefaultCaseContext(
                runId, com.samlscope.core.plan.TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(),
                Reachability.CONFIRMED, transcript, true);
        new CaseExecutionService(executions).start(runId, scenario, runContexts.contextFor(runId));
        var dispatcher = new OutboundDispatcher(
                executions,
                (candidateRun, action, credential) -> new OutboundSender.SendResult(false, Map.of(), "unused"),
                (candidateRun, actionId) -> Optional.empty(),
                new OutboundPolicy(true), Clock.fixed(NOW, ZoneOffset.UTC));
        var generic = new ActiveProbeCoordinator(
                URI.create("https://suite.example"), plans, runs, executions, dispatcher,
                transcript, runContexts, (ignored, candidateRun) -> configuration,
                new TestCaseRegistry(List.of(scenario)), Clock.fixed(NOW, ZoneOffset.UTC));

        var ready = generic.status(runId);
        generic.prepare(runId, ready.actionId(), true);

        var recorded = transcript.list(runId).getFirst();
        assertEquals(scenario.id(), recorded.samlSummary().get("scenario_case_id"));
        assertFalse(recorded.samlSummary().containsKey("fixture_id"));
        assertEquals(ActiveProbeCoordinator.State.AWAITING_RESPONSE, generic.status(runId).state());
    }

    private byte[] response(String status) {
        var requestId = executions.find(RUN, IdpErrorResponseTestCase.CASE_ID).orElseThrow()
                .state().data().get("expected_response_correlation");
        return responseFor(String.valueOf(requestId), status);
    }

    private byte[] responseFor(String requestId, String status) {
        var assertion = "Success".equals(status)
                ? "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>"
                : "";
        return """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="%s">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:%s"/></samlp:Status>%s
                </samlp:Response>
                """.formatted(requestId, status, assertion).getBytes(StandardCharsets.UTF_8);
    }

    private IdpErrorProbeConfiguration configuration(boolean freshGate) {
        return new IdpErrorProbeConfiguration(
                URI.create("https://idp.example/sso"), "https://suite.example/p/" + PLAN,
                URI.create("https://suite.example/p/" + PLAN + "/sp/acs/0"),
                Duration.ofMinutes(5), true, true, freshGate);
    }

    private static final class Base64s {
        static byte[] decode(String value) { return java.util.Base64.getDecoder().decode(value); }
    }
}
