package com.samlscope.runner.scenario;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboundKind;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.runner.CaseExecutionService;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.FileTranscriptRecorder;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteCaseExecutionRepository;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

class FixtureScenarioTestCaseTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String CASE = "scenario-case";
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @TempDir java.nio.file.Path directory;
    private SqliteCaseExecutionRepository repository;
    private CaseExecutionService executions;
    private DefaultCaseContext context;

    @BeforeEach
    void setUp() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plan = new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "Scenario", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.HTTP_URL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
        new SqlitePlanRepository(database, json).save(plan);
        new SqliteRunRepository(database, json).save(new TestRun(
                RUN, plan.id(), RunStatus.RUNNING, Reachability.CONFIRMED, Map.of(), NOW, NOW));
        repository = new SqliteCaseExecutionRepository(database, json);
        executions = new CaseExecutionService(repository);
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        context = new DefaultCaseContext(
                RUN, TargetRole.IDP, clock, plan.parameters(), plan.interaction(),
                Reachability.CONFIRMED, new FileTranscriptRecorder(database, json, directory), false);
    }

    @Test
    void persistsAndExecutesOnlyOneFixtureAtATimeAcrossEngineRecreation() {
        var scenario = scenario(List.of(
                fixture("first", FixtureObservation.SATISFIED),
                fixture("second", FixtureObservation.VIOLATED),
                fixture("third", FixtureObservation.NOT_VERIFIED)));

        var first = executions.start(RUN, scenario, context);
        assertEquals(CaseExecutionStatus.WAITING_INBOUND, first.status());
        assertEquals("first", first.state().data().get("fixture_id"));
        assertEquals(1, repository.listOutbox(RUN).size());

        var second = executions.resume(RUN, scenario, context, inbound("tx-first"));
        assertEquals("second", second.state().data().get("fixture_id"));
        assertEquals(2, repository.listOutbox(RUN).size());

        var recreated = scenario(List.of(
                fixture("first", FixtureObservation.SATISFIED),
                fixture("second", FixtureObservation.VIOLATED),
                fixture("third", FixtureObservation.NOT_VERIFIED)));
        var third = executions.resume(RUN, recreated, context, inbound("tx-second"));
        assertEquals("third", third.state().data().get("fixture_id"));
        assertEquals(3, repository.listOutbox(RUN).size());

        var finished = executions.resume(RUN, recreated, context, inbound("tx-third"));
        assertEquals(CaseExecutionStatus.FINISHED, finished.status());
        assertEquals(Outcome.VIOLATED, finished.outcome().outcome());
        assertEquals(List.of("second"), finished.outcome().details().get("violating_fixtures"));
        assertEquals(
                List.of(com.samlscope.core.caseexec.ActionIds.derive(
                        RUN, CASE, "await-fixture-second", 0)),
                finished.outcome().details().get("violating_action_ids"));
        assertEquals(List.of("third"), finished.outcome().details().get("unverifiable_fixtures"));
        assertEquals(3, finished.outcome().evidence().size());
    }

    @Test
    void controlFailureStopsTheSequenceAsSuiteUncertainty() {
        var scenario = scenario(List.of(
                fixture("control", FixtureObservation.CONTROL_FAILED),
                fixture("must-not-run", FixtureObservation.VIOLATED)));
        executions.start(RUN, scenario, context);

        var finished = executions.resume(RUN, scenario, context, inbound("tx-control"));

        assertEquals(CaseExecutionStatus.FINISHED, finished.status());
        assertEquals(Outcome.NOT_VERIFIED, finished.outcome().outcome());
        assertEquals("control_failed", finished.outcome().reasonCode());
        assertEquals(1, repository.listOutbox(RUN).size());
    }

    @Test
    void missingInboundMarksOnlyThatFixtureUnverifiableAndContinues() {
        var scenario = scenario(List.of(
                fixture("html-error", FixtureObservation.SATISFIED),
                fixture("observable", FixtureObservation.SATISFIED)));
        executions.start(RUN, scenario, context);

        var second = executions.resume(
                RUN, scenario, context, new CaseEvent.InboundUnavailable("no-saml-response"));

        assertEquals(CaseExecutionStatus.WAITING_INBOUND, second.status());
        assertEquals("observable", second.state().data().get("fixture_id"));
        assertEquals(List.of("html-error"), second.state().data().get("unverifiable"));
        assertEquals(2, repository.listOutbox(RUN).size());

        var finished = executions.resume(RUN, scenario, context, inbound("tx-observable"));
        assertEquals(CaseExecutionStatus.FINISHED, finished.status());
        assertEquals(Outcome.NOT_VERIFIED, finished.outcome().outcome());
        assertEquals(List.of("html-error"), finished.outcome().details().get("unverifiable_fixtures"));
        assertEquals(List.of(new EvidenceRef("transcript", "tx-observable")), finished.outcome().evidence());
    }

    @Test
    void retryCreatesANewActionForTheSameFixtureWithoutLosingPriorEvidence() {
        var scenario = scenario(List.of(
                fixture("first", FixtureObservation.SATISFIED),
                fixture("second", FixtureObservation.SATISFIED)));
        var first = executions.start(RUN, scenario, context);
        var originalAction = first.waitCondition().inboundMatcher().criteria().get("ScenarioActionId");

        var retried = executions.resume(RUN, scenario, context, new CaseEvent.RetryInbound());

        assertEquals(CaseExecutionStatus.WAITING_INBOUND, retried.status());
        assertEquals("first", retried.state().data().get("fixture_id"));
        assertEquals(1, retried.state().data().get("fixture_attempt"));
        var retryAction = retried.waitCondition().inboundMatcher().criteria().get("ScenarioActionId");
        org.junit.jupiter.api.Assertions.assertNotEquals(originalAction, retryAction);
        assertEquals(2, repository.listOutbox(RUN).size());

        var second = executions.resume(RUN, scenario, context, inbound("tx-retried"));
        assertEquals("second", second.state().data().get("fixture_id"));
        assertEquals(List.of("tx-retried"), second.state().data().get("evidence"));
    }

    @Test
    void retryLimitFailsClosedWithoutChangingTheTargetOutcome() {
        var scenario = scenario(List.of(fixture("only", FixtureObservation.SATISFIED)));
        executions.start(RUN, scenario, context);
        executions.resume(RUN, scenario, context, new CaseEvent.RetryInbound());
        executions.resume(RUN, scenario, context, new CaseEvent.RetryInbound());
        executions.resume(RUN, scenario, context, new CaseEvent.RetryInbound());

        assertThrows(IllegalStateException.class,
                () -> executions.resume(RUN, scenario, context, new CaseEvent.RetryInbound()));
        assertEquals(CaseExecutionStatus.WAITING_INBOUND,
                repository.find(RUN, CASE).orElseThrow().status());
    }

    @Test
    void expiredOneTimeFixtureCanBeReissuedInsteadOfBecomingATargetFailure() {
        var scenario = scenario(List.of(fixture("expired", FixtureObservation.SATISFIED)));
        var original = executions.start(RUN, scenario, context);
        var later = new DefaultCaseContext(
                RUN, TargetRole.IDP, Clock.fixed(NOW.plus(Duration.ofMinutes(2)), ZoneOffset.UTC),
                context.parameters(), context.interaction(), Reachability.CONFIRMED,
                context.transcript(), false);

        var retried = executions.resume(RUN, scenario, later, new CaseEvent.RetryInbound());

        assertEquals(CaseExecutionStatus.WAITING_INBOUND, retried.status());
        org.junit.jupiter.api.Assertions.assertNotEquals(
                original.waitCondition().inboundMatcher().criteria().get("ScenarioActionId"),
                retried.waitCondition().inboundMatcher().criteria().get("ScenarioActionId"));
        assertEquals(2, repository.listOutbox(RUN).size());
    }

    @Test
    void aNegativeFixtureCanTreatAnExplicitMissingCallbackAsSatisfied() {
        var discarded = new ScenarioFixture() {
            @Override public String id() { return "discarded-negative"; }
            @Override public Prepared prepare(
                    com.samlscope.core.caseexec.CaseContext ignored, String actionId) {
                return new Prepared(new OutboundAction(
                        actionId, OutboundKind.AUTHN_REQUEST, new byte[] {1},
                        URI.create("https://idp.example/sso"), false), "_" + actionId);
            }
            @Override public FixtureObservation observe(String expected, byte[] decoded) {
                return FixtureObservation.VIOLATED;
            }
            @Override public FixtureObservation observeUnavailable(String reason) {
                return "operator-reported-no-saml-response".equals(reason)
                        ? FixtureObservation.SATISFIED : FixtureObservation.NOT_VERIFIED;
            }
            @Override public String definitionKey() { return "discarded-negative|v1"; }
        };
        var scenario = scenario(List.of(discarded));
        executions.start(RUN, scenario, context);

        var finished = executions.resume(
                RUN, scenario, context,
                new CaseEvent.InboundUnavailable("operator-reported-no-saml-response"));

        assertEquals(CaseExecutionStatus.FINISHED, finished.status());
        assertEquals(Outcome.SATISFIED, finished.outcome().outcome());
    }

    @Test
    void changedFixtureSequenceCannotResumePersistedState() {
        var original = scenario(List.of(
                fixture("first", FixtureObservation.SATISFIED),
                fixture("second", FixtureObservation.SATISFIED)));
        executions.start(RUN, original, context);
        var changed = scenario(List.of(
                fixture("first", FixtureObservation.SATISFIED),
                fixture("replacement", FixtureObservation.SATISFIED)));

        var finished = executions.resume(RUN, changed, context, inbound("tx-first"));

        assertEquals(CaseExecutionStatus.FINISHED, finished.status());
        assertEquals(Outcome.NOT_VERIFIED, finished.outcome().outcome());
        assertEquals("scenario_definition_changed", finished.outcome().notVerifiedReason());
        assertEquals(1, repository.listOutbox(RUN).size());
    }

    @Test
    void changedFixtureSemanticsCannotHideBehindTheSameFixtureId() {
        var original = scenario(List.of(fixture("same-id", FixtureObservation.SATISFIED)));
        executions.start(RUN, original, context);
        var changed = scenario(List.of(fixture("same-id", FixtureObservation.VIOLATED)));

        var finished = executions.resume(RUN, changed, context, inbound("tx-same-id"));

        assertEquals(CaseExecutionStatus.FINISHED, finished.status());
        assertEquals(Outcome.NOT_VERIFIED, finished.outcome().outcome());
        assertEquals("scenario_definition_changed", finished.outcome().notVerifiedReason());
    }

    @Test
    void timeoutPreservesEvidenceFromCompletedFixtures() {
        var scenario = scenario(List.of(
                fixture("first", FixtureObservation.SATISFIED),
                fixture("second", FixtureObservation.SATISFIED)));
        executions.start(RUN, scenario, context);
        var waiting = executions.resume(RUN, scenario, context, inbound("tx-first"));

        var finished = executions.resume(
                RUN, scenario, context, new CaseEvent.TimedOut(Duration.ofMinutes(1)));

        assertEquals(CaseExecutionStatus.FINISHED, finished.status());
        assertEquals(Outcome.NOT_VERIFIED, finished.outcome().outcome());
        assertEquals("timeout", finished.outcome().notVerifiedReason());
        assertEquals(List.of(new EvidenceRef("transcript", "tx-first")), finished.outcome().evidence());
        assertEquals("second", finished.outcome().details().get("fixture_id"));
        assertEquals(1, finished.outcome().details().get("completed_fixtures"));
        assertEquals("second", waiting.state().data().get("fixture_id"));
    }

    @Test
    void rejectsDuplicateFixtureIdsAndNondeterministicActions() {
        assertThrows(IllegalArgumentException.class, () -> scenario(List.of(
                fixture("same", FixtureObservation.SATISFIED),
                fixture("same", FixtureObservation.SATISFIED))));
        var bad = new ScenarioFixture() {
            @Override public String id() { return "bad-action"; }
            @Override public Prepared prepare(com.samlscope.core.caseexec.CaseContext ignored, String actionId) {
                return new Prepared(new OutboundAction(
                        "action_wrong", OutboundKind.AUTHN_REQUEST, new byte[] {1},
                        URI.create("https://idp.example/sso"), false), "_wrong");
            }
            @Override public FixtureObservation observe(String expected, byte[] decoded) {
                return FixtureObservation.SATISFIED;
            }
            @Override public String definitionKey() { return "bad-action-v1"; }
        };
        assertThrows(IllegalArgumentException.class, () -> executions.start(
                RUN, scenario(List.of(bad)), context));
    }

    private FixtureScenarioTestCase scenario(List<ScenarioFixture> fixtures) {
        return new FixtureScenarioTestCase(
                CASE, TargetRole.IDP, fixtures, ignored -> true,
                new FixtureScenarioTestCase.Vocabulary(
                        "precondition", "scenario.precondition",
                        "timeout", "scenario.timeout",
                        "aborted", "scenario.aborted",
                        "scenario.control-failed",
                        "scenario.violated", "scenario.violated",
                        "scenario_inconclusive", "scenario.inconclusive", "scenario.inconclusive",
                        "scenario.satisfied", "scenario.satisfied"));
    }

    private ScenarioFixture fixture(String id, FixtureObservation observation) {
        return new ScenarioFixture() {
            @Override public String id() { return id; }
            @Override public Prepared prepare(com.samlscope.core.caseexec.CaseContext ignored, String actionId) {
                return new Prepared(new OutboundAction(
                        actionId, OutboundKind.AUTHN_REQUEST,
                        id.getBytes(StandardCharsets.UTF_8), URI.create("https://idp.example/sso"), false),
                        "_" + actionId);
            }
            @Override public FixtureObservation observe(String expected, byte[] decoded) { return observation; }
            @Override public Duration timeout() { return Duration.ofMinutes(1); }
            @Override public String definitionKey() { return id + "|" + observation.name() + "|v1"; }
        };
    }

    private CaseEvent.InboundMessage inbound(String evidence) {
        return new CaseEvent.InboundMessage(
                "<Response/>".getBytes(StandardCharsets.UTF_8),
                new EvidenceRef("transcript", evidence));
    }
}
