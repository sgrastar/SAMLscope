package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.ActionIds;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.ConfigurationFailureSemantics;
import com.samlscope.core.caseexec.InboundMatcher;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboundKind;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.plan.PlanProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.cases.ConfigurationGateTestCase;
import com.samlscope.store.FileTranscriptRecorder;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteCaseExecutionRepository;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

class CaseExecutionServiceTest {
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-29T00:00:00Z");

    @TempDir java.nio.file.Path directory;
    private SqliteCaseExecutionRepository repository;
    private CaseExecutionService service;
    private CaseContext context;

    @BeforeEach
    void setUp() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plan = plan();
        new SqlitePlanRepository(database, json).save(plan);
        new SqliteRunRepository(database, json).save(new TestRun(
                RUN_ID, plan.id(), RunStatus.RUNNING, Reachability.UNKNOWN, Map.of(), NOW, NOW));
        var transcript = new FileTranscriptRecorder(database, json, directory);
        repository = new SqliteCaseExecutionRepository(database, json);
        service = new CaseExecutionService(repository);
        context = context(plan.parameters(), transcript);
    }

    @Test
    void requiredModeWithoutAnInstalledSignerCannotPersistUnsignedRequests() {
        var requiredContext = context(new TestPlan.Parameters(180, 300, "", TestPlan.RequestSigningMode.REQUIRED),
                context.transcript());
        var result = service.start(RUN_ID, waitingCase("missing-signer", new AtomicInteger()), requiredContext);
        assertEquals(Outcome.NOT_VERIFIED, result.outcome().outcome());
        assertEquals("request_signing_unavailable", result.outcome().notVerifiedReason());
        assertEquals(0, repository.listOutbox(RUN_ID).size());
    }

    @Test
    void requiredModeAlsoFailsClosedWhenAResumedCaseFirstEmitsARequest() {
        var requiredContext = context(new TestPlan.Parameters(180, 300, "", TestPlan.RequestSigningMode.REQUIRED),
                context.transcript());
        var outboundCase = waitingCase("resumed-missing-signer", new AtomicInteger());
        TestCase delayed = new TestCase() {
            public String id() { return outboundCase.id(); }
            public TargetRole role() { return TargetRole.IDP; }
            public CaseStep start(CaseContext c) { return new CaseStep.Continue(CaseState.initial(), List.of()); }
            public CaseStep resume(CaseContext c, CaseState state, CaseEvent event) { return outboundCase.start(c); }
        };
        service.start(RUN_ID, delayed, requiredContext);
        var result = service.resume(RUN_ID, delayed, requiredContext, new CaseEvent.Custom("ready", Map.of()));
        assertEquals(Outcome.NOT_VERIFIED, result.outcome().outcome());
        assertEquals("request_signing_unavailable", result.outcome().notVerifiedReason());
        assertEquals(0, repository.listOutbox(RUN_ID).size());
    }

    @Test
    void signingFailureCannotBecomeTargetFailureOrAnUnsignedSend() {
        var signingService = new CaseExecutionService(repository, (runId, action) -> {
            throw new com.samlscope.saml.normal.SamlException("Unsupported malformed fixture");
        });
        var result = signingService.start(RUN_ID, waitingCase("signing-unavailable", new AtomicInteger()), context);
        assertEquals(CaseExecutionStatus.FINISHED, result.status());
        assertEquals(Outcome.NOT_VERIFIED, result.outcome().outcome());
        assertEquals("request_signing_unavailable", result.outcome().notVerifiedReason());
        assertEquals(0, repository.listOutbox(RUN_ID).size());
    }

    @Test
    void persistsWaitingStateAndOutboxBeforeReturning() {
        var starts = new AtomicInteger();
        var testCase = waitingCase("case-outbox", starts);

        var execution = service.start(RUN_ID, testCase, context);
        var repeated = service.start(RUN_ID, testCase, context);

        assertEquals(CaseExecutionStatus.WAITING_INBOUND, execution.status());
        assertEquals(NOW.plus(Duration.ofMinutes(5)), execution.waitCondition().expiresAt());
        assertEquals(execution, repeated);
        assertEquals(1, starts.get());
        assertEquals(1, repository.listOutbox(RUN_ID).size());
    }

    @Test
    void resumesToAnOutcomeWithoutAllowingCaseSideVerdicts() {
        var testCase = waitingCase("case-finish", new AtomicInteger());
        service.start(RUN_ID, testCase, context);

        var finished = service.resume(
                RUN_ID, testCase, context, new CaseEvent.InboundMessage(
                        "<Response/>".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        new EvidenceRef("transcript", "transcript:response")));

        assertEquals(CaseExecutionStatus.FINISHED, finished.status());
        assertEquals(Outcome.SATISFIED, finished.outcome().outcome());
        assertEquals(finished, service.resume(
                RUN_ID, testCase, context, new CaseEvent.InboundMessage(
                        "<Response/>".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        new EvidenceRef("transcript", "transcript:response"))));
    }

    @Test
    void rejectsNondeterministicActionIdsBeforeWritingAnything() {
        var testCase = new TestCase() {
            @Override public String id() { return "case-random-action"; }
            @Override public TargetRole role() { return TargetRole.IDP; }

            @Override
            public CaseStep start(CaseContext ignored) {
                return new CaseStep.Continue(
                        new CaseState("send", Map.of()),
                        List.of(new OutboundAction(
                                "random", OutboundKind.AUTHN_REQUEST, new byte[] {1},
                                URI.create("https://idp.example/sso"), false)));
            }

            @Override
            public CaseStep resume(CaseContext ignored, CaseState state, CaseEvent event) {
                throw new UnsupportedOperationException();
            }
        };

        assertThrows(IllegalArgumentException.class, () -> service.start(RUN_ID, testCase, context));
        assertEquals(List.of(), repository.listOutbox(RUN_ID));
    }

    @Test
    void rejectsAnEventThatDoesNotMatchThePersistedWaitState() {
        var testCase = waitingCase("case-event-type", new AtomicInteger());
        service.start(RUN_ID, testCase, context);

        assertThrows(IllegalArgumentException.class, () -> service.resume(
                RUN_ID, testCase, context, new CaseEvent.ConfigConfirmed()));
        assertEquals(CaseExecutionStatus.WAITING_INBOUND,
                repository.find(RUN_ID, testCase.id()).orElseThrow().status());
    }

    @Test
    void rejectsACaseDesignedForAnotherTargetRoleBeforeStartingIt() {
        var testCase = waitingCase("case-wrong-role", new AtomicInteger(), TargetRole.SP);

        assertThrows(IllegalArgumentException.class, () -> service.start(RUN_ID, testCase, context));
        assertEquals(List.of(), repository.listOutbox(RUN_ID));
    }

    @Test
    void appliesConfigurationFailureSemanticsCentrally() {
        var normative = new ConfigurationGateTestCase(
                immediateCase("case-config-normative"), "configure.feature", Duration.ofMinutes(5),
                ConfigurationFailureSemantics.NORMATIVE_CAPABILITY);
        service.start(RUN_ID, normative, context);
        var absent = service.resume(
                RUN_ID, normative, context,
                new CaseEvent.ConfigUnavailable(
                        CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT, "No setting exists"));
        assertEquals(Outcome.VIOLATED, absent.outcome().outcome());
        assertEquals("capability_absent", absent.outcome().reasonCode());

        var precondition = new ConfigurationGateTestCase(
                immediateCase("case-config-precondition"), "configure.fixture", Duration.ofMinutes(5),
                ConfigurationFailureSemantics.TEST_PRECONDITION);
        service.start(RUN_ID, precondition, context);
        var unmet = service.resume(
                RUN_ID, precondition, context,
                new CaseEvent.ConfigUnavailable(
                        CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT, "Fixture cannot be enabled"));
        assertEquals(Outcome.NOT_VERIFIED, unmet.outcome().outcome());
        assertEquals("test_precondition_unavailable", unmet.outcome().notVerifiedReason());

        var unavailable = new ConfigurationGateTestCase(
                immediateCase("case-config-permission"), "configure.feature", Duration.ofMinutes(5),
                ConfigurationFailureSemantics.NORMATIVE_CAPABILITY);
        service.start(RUN_ID, unavailable, context);
        var permission = service.resume(
                RUN_ID, unavailable, context,
                new CaseEvent.ConfigUnavailable(
                        CaseEvent.ConfigurationIssue.TARGET_CONFIG_UNAVAILABLE, "Insufficient permission"));
        assertEquals(Outcome.NOT_VERIFIED, permission.outcome().outcome());
        assertEquals("target_config_unavailable", permission.outcome().notVerifiedReason());

        var unknown = new ConfigurationGateTestCase(
                immediateCase("case-config-unknown"), "configure.feature", Duration.ofMinutes(5),
                ConfigurationFailureSemantics.NORMATIVE_CAPABILITY);
        service.start(RUN_ID, unknown, context);
        var undetermined = service.resume(
                RUN_ID, unknown, context,
                new CaseEvent.ConfigUnavailable(
                        CaseEvent.ConfigurationIssue.CAPABILITY_UNDETERMINED, "Administrator is unavailable"));
        assertEquals(Outcome.NOT_VERIFIED, undetermined.outcome().outcome());
        assertEquals("capability_undetermined", undetermined.outcome().notVerifiedReason());
    }

    @Test
    void confirmedConfigurationContinuesIntoTheConcreteCase() {
        var configured = new ConfigurationGateTestCase(
                immediateCase("case-config-confirmed"), "configure.feature", Duration.ofMinutes(5),
                ConfigurationFailureSemantics.NORMATIVE_CAPABILITY);

        var waiting = service.start(RUN_ID, configured, context);
        assertEquals(CaseExecutionStatus.WAITING_CONFIG, waiting.status());
        var finished = service.resume(RUN_ID, configured, context, new CaseEvent.ConfigConfirmed());

        assertEquals(CaseExecutionStatus.FINISHED, finished.status());
        assertEquals(Outcome.SATISFIED, finished.outcome().outcome());
    }

    @Test
    void configuredCaseCanSuspendAgainAndResumeAfterRestartSafePersistence() {
        var configured = new ConfigurationGateTestCase(
                waitingCase("case-config-then-inbound", new AtomicInteger()),
                "configure.feature", Duration.ofMinutes(5),
                ConfigurationFailureSemantics.TEST_PRECONDITION);
        service.start(RUN_ID, configured, context);

        var inboundWait = service.resume(RUN_ID, configured, context, new CaseEvent.ConfigConfirmed());
        assertEquals(CaseExecutionStatus.WAITING_INBOUND, inboundWait.status());
        assertEquals("await-response", inboundWait.state().phase());
        assertEquals(1, repository.listOutbox(RUN_ID).size());

        var finished = service.resume(
                RUN_ID, configured, context, new CaseEvent.InboundMessage(
                        "<Response/>".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        new EvidenceRef("transcript", "transcript:configured-response")));
        assertEquals(Outcome.SATISFIED, finished.outcome().outcome());
    }

    @Test
    void centrallyBlocksInteractiveWaitsAndTheirOutboundActionsWhenInteractionIsDisabled() {
        var disabled = context(
                plan().parameters(), context.transcript(), new TestPlan.Interaction(false, false));
        var browser = interactiveCase("case-browser-disabled", true);
        var attestation = interactiveCase("case-attestation-disabled", false);

        var browserResult = service.start(RUN_ID, browser, disabled);
        var attestationResult = service.start(RUN_ID, attestation, disabled);

        assertEquals(CaseExecutionStatus.FINISHED, browserResult.status());
        assertEquals("interaction_disallowed", browserResult.outcome().notVerifiedReason());
        assertEquals(CaseExecutionStatus.FINISHED, attestationResult.status());
        assertEquals("interaction_disallowed", attestationResult.outcome().notVerifiedReason());
        assertEquals(List.of(), repository.listOutbox(RUN_ID));
    }

    private TestCase interactiveCase(String caseId, boolean browser) {
        return new TestCase() {
            @Override public String id() { return caseId; }
            @Override public TargetRole role() { return TargetRole.IDP; }
            @Override public CaseStep start(CaseContext ignored) {
                var next = new CaseState("interactive-wait", Map.of());
                var action = new OutboundAction(
                        ActionIds.derive(RUN_ID, caseId, next.phase(), 0),
                        OutboundKind.AUTHN_REQUEST, new byte[] {1}, URI.create("https://idp.example/sso"), false);
                if (browser) {
                    return new CaseStep.AwaitBrowser(
                            next, List.of(action), URI.create("https://suite.example/start"), Duration.ofMinutes(5));
                }
                return new CaseStep.AwaitAttestation(
                        next, List.of(action), "attestation.question", Duration.ofMinutes(5));
            }
            @Override public CaseStep resume(CaseContext ignored, CaseState state, CaseEvent event) {
                throw new UnsupportedOperationException();
            }
        };
    }

    private TestCase immediateCase(String caseId) {
        return new TestCase() {
            @Override public String id() { return caseId; }
            @Override public TargetRole role() { return TargetRole.IDP; }
            @Override public CaseStep start(CaseContext ignored) {
                return new CaseStep.Finish(CaseOutcome.of(
                        Outcome.SATISFIED, "configured.observation-satisfied", List.of()));
            }
            @Override public CaseStep resume(CaseContext ignored, CaseState state, CaseEvent event) {
                throw new UnsupportedOperationException();
            }
        };
    }

    private TestCase waitingCase(String caseId, AtomicInteger starts) {
        return waitingCase(caseId, starts, TargetRole.IDP);
    }

    private TestCase waitingCase(String caseId, AtomicInteger starts, TargetRole role) {
        return new TestCase() {
            @Override public String id() { return caseId; }
            @Override public TargetRole role() { return role; }

            @Override
            public CaseStep start(CaseContext ignored) {
                starts.incrementAndGet();
                var next = new CaseState("await-response", Map.of("sequence", 0));
                var action = new OutboundAction(
                        ActionIds.derive(RUN_ID, caseId, next.phase(), 0),
                        OutboundKind.AUTHN_REQUEST,
                        "<AuthnRequest/>".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        URI.create("https://idp.example/sso"),
                        false);
                return new CaseStep.AwaitInbound(
                        next, List.of(action), new InboundMatcher("saml-response", Map.of()), Duration.ofMinutes(5));
            }

            @Override
            public CaseStep resume(CaseContext ignored, CaseState state, CaseEvent event) {
                return new CaseStep.Finish(CaseOutcome.of(Outcome.SATISFIED, "response.accepted", List.of()));
            }
        };
    }

    private CaseContext context(TestPlan.Parameters parameters, TranscriptRecorder transcript) {
        return context(parameters, transcript, TestPlan.Interaction.defaults());
    }

    private CaseContext context(
            TestPlan.Parameters parameters,
            TranscriptRecorder transcript,
            TestPlan.Interaction interaction) {
        return new CaseContext() {
            @Override public String runId() { return RUN_ID; }
            @Override public TargetRole targetRole() { return TargetRole.IDP; }
            @Override public Clock clock() { return Clock.fixed(NOW, ZoneOffset.UTC); }
            @Override public TestPlan.Parameters parameters() { return parameters; }
            @Override public TestPlan.Interaction interaction() { return interaction; }
            @Override public Reachability reachability() { return Reachability.UNKNOWN; }
            @Override public TranscriptRecorder transcript() { return transcript; }
            @Override public boolean transcriptComplete() { return false; }
        };
    }

    private TestPlan plan() {
        return new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS",
                "Case execution test",
                PlanProfile.IDP_CORE,
                new TestPlan.Target(
                        TargetKind.IDP,
                        "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL,
                Map.of(),
                TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),
                NOW,
                NOW);
    }
}
