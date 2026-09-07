package com.samlscope.runner;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.OutboxStatus;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.RunRepository;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.cases.IdpErrorProbeConfiguration;
import com.samlscope.runner.cases.IdpErrorResponseTestCase;
import com.samlscope.runner.outbox.OutboundDispatcher;

/** Bridges persisted active-probe cases to a real SAML browser front channel. */
public final class ActiveProbeCoordinator {
    private final URI publicBase;
    private final PlanRepository plans;
    private final RunRepository runs;
    private final CaseExecutionRepository repository;
    private final OutboundDispatcher dispatcher;
    private final TranscriptRecorder transcript;
    private final CaseContextProvider contexts;
    private final BiFunction<TestPlan, String, IdpErrorProbeConfiguration> configurations;
    private final TestCaseRegistry scenarioCases;
    private final Clock clock;
    private final CaseExecutionService executionService;

    public ActiveProbeCoordinator(
            URI publicBase,
            PlanRepository plans,
            RunRepository runs,
            CaseExecutionRepository repository,
            OutboundDispatcher dispatcher,
            TranscriptRecorder transcript,
            CaseContextProvider contexts,
            BiFunction<TestPlan, String, IdpErrorProbeConfiguration> configurations,
            Clock clock) {
        this(publicBase, plans, runs, repository, dispatcher, transcript, contexts,
                configurations, new TestCaseRegistry(List.of()), clock);
    }

    public ActiveProbeCoordinator(
            URI publicBase,
            PlanRepository plans,
            RunRepository runs,
            CaseExecutionRepository repository,
            OutboundDispatcher dispatcher,
            TranscriptRecorder transcript,
            CaseContextProvider contexts,
            BiFunction<TestPlan, String, IdpErrorProbeConfiguration> configurations,
            TestCaseRegistry scenarioCases,
            Clock clock) {
        this(publicBase, plans, runs, repository, dispatcher, transcript, contexts, configurations,
                scenarioCases, clock, new CaseExecutionService(repository));
    }

    public ActiveProbeCoordinator(
            URI publicBase, PlanRepository plans, RunRepository runs,
            CaseExecutionRepository repository, OutboundDispatcher dispatcher,
            TranscriptRecorder transcript, CaseContextProvider contexts,
            BiFunction<TestPlan, String, IdpErrorProbeConfiguration> configurations,
            TestCaseRegistry scenarioCases, Clock clock, CaseExecutionService executionService) {
        this.executionService = Objects.requireNonNull(executionService, "executionService");
        this.publicBase = Objects.requireNonNull(publicBase, "publicBase");
        this.plans = Objects.requireNonNull(plans, "plans");
        this.runs = Objects.requireNonNull(runs, "runs");
        this.repository = Objects.requireNonNull(repository, "repository");
        this.dispatcher = Objects.requireNonNull(dispatcher, "dispatcher");
        this.transcript = Objects.requireNonNull(transcript, "transcript");
        this.contexts = Objects.requireNonNull(contexts, "contexts");
        this.configurations = Objects.requireNonNull(configurations, "configurations");
        this.scenarioCases = Objects.requireNonNull(scenarioCases, "scenarioCases");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public Status status(String runId) {
        var run = requireRun(runId);
        var candidates = repository.list(runId).stream()
                .filter(value -> value.status() == CaseExecutionStatus.WAITING_INBOUND)
                .filter(value -> scenario(value.caseId(), run).isPresent())
                .sorted(java.util.Comparator.comparingInt((CaseExecution value) ->
                                IdpErrorResponseTestCase.CASE_ID.equals(value.caseId()) ? 0 : 1)
                        .thenComparing(CaseExecution::caseId))
                .toList();
        if (candidates.isEmpty()) {
            var executions = repository.list(runId).stream()
                    .filter(value -> scenario(value.caseId(), run).isPresent()).toList();
            if (executions.isEmpty()) {
                return new Status(run.planId(), State.NOT_STARTED, null, null, false, null, null, null);
            }
            var unfinished = executions.stream().anyMatch(value -> value.status() != CaseExecutionStatus.FINISHED);
            var lastOutcome = executions.stream()
                    .filter(value -> IdpErrorResponseTestCase.CASE_ID.equals(value.caseId()))
                    .map(CaseExecution::outcome).filter(Objects::nonNull)
                    .map(value -> value.outcome().name()).findFirst().orElse(null);
            return new Status(run.planId(), unfinished ? State.UNAVAILABLE : State.FINISHED,
                    null, null, false, lastOutcome, null, null);
        }
        var current = candidates.get(0);
        var testCase = scenario(current.caseId(), run).orElseThrow();
        var action = repository.listOutbox(runId).stream()
                .filter(value -> value.caseId().equals(current.caseId()))
                .filter(value -> value.action().actionId().equals(
                        current.waitCondition().inboundMatcher().criteria().get("ScenarioActionId")))
                .findFirst().orElseThrow(() -> new IllegalStateException("Active probe has no matching outbox action"));
        var state = action.status() == OutboxStatus.PENDING ? State.READY : State.AWAITING_RESPONSE;
        var startUrl = state == State.READY
                ? publicBase.resolve("/p/" + run.planId() + "/probe/" + action.action().actionId()
                        + "?run=" + url(runId))
                : null;
        var browserScenario = (BrowserFrontChannelScenario) testCase;
        return new Status(run.planId(), state, action.action().actionId(), startUrl,
                browserScenario.requiresFreshSession(current.state()), null,
                current.caseId(), browserScenario.instructionsEn(current.state()));
    }

    /** Expires this coordinator's Plan-specific case without exposing it to a static registry. */
    public Optional<CaseExecution> expireReady(String runId) {
        var run = requireRun(runId);
        var current = repository.find(runId, IdpErrorResponseTestCase.CASE_ID);
        if (current.isEmpty() || current.orElseThrow().status() == CaseExecutionStatus.FINISHED) {
            return Optional.empty();
        }
        var execution = current.orElseThrow();
        var wait = execution.waitCondition();
        var now = clock.instant();
        if (wait == null || now.isBefore(wait.expiresAt())) return Optional.empty();
        var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
        var waited = Duration.between(execution.updatedAt(), now);
        if (waited.isNegative()) waited = Duration.ZERO;
        return Optional.of(executionService.resume(
                runId, new IdpErrorResponseTestCase(configurations.apply(plan, runId)),
                contexts.contextFor(runId), new CaseEvent.TimedOut(waited)));
    }

    public PreparedProbe prepare(String runId, String actionId, boolean freshSessionConfirmed) {
        var status = status(runId);
        if (status.state() != State.READY || !Objects.equals(status.actionId(), actionId)) {
            throw new IllegalStateException("Active probe action is not ready");
        }
        if (status.requiresFreshSession() && !freshSessionConfirmed) {
            throw new IllegalArgumentException("The passive probe requires a browser context with no target session");
        }
        var relayState = ActiveProbeCorrelation.encode(runId, actionId);
        requireRun(runId);
        var current = repository.findOutbox(actionId).orElseThrow();
        var execution = repository.find(runId, current.caseId()).orElseThrow();
        var dispatch = dispatcher.dispatchFrontChannel(actionId, action -> {
            var encodedRequest = Base64.getEncoder().encodeToString(action.payload());
            var body = "SAMLRequest=" + url(encodedRequest) + "&RelayState=" + url(relayState);
            var summary = new java.util.LinkedHashMap<String, Object>();
            summary.put("type", "AuthnRequest");
            summary.put("active_probe", true);
            summary.put("action_id", action.actionId());
            summary.put("scenario_case_id", current.caseId());
            var fixtureId = execution.state().data().get("fixture_id");
            if (fixtureId != null) summary.put("fixture_id", fixtureId);
            return transcript.record(new TranscriptInput(
                    runId, Direction.OUTBOUND, clock.instant(), action.actionId(), "POST",
                    action.target().toString(), null,
                    Map.of("Content-Type", List.of("application/x-www-form-urlencoded")),
                    body.getBytes(StandardCharsets.UTF_8), "application/x-www-form-urlencoded",
                    null, action.payload(),
                    Map.copyOf(summary))).id();
        });
        return new PreparedProbe(
                dispatch.action().target(),
                Base64.getEncoder().encodeToString(dispatch.action().payload()),
                relayState,
                dispatch.transcriptEntryId());
    }

    public Status accept(
            String runId,
            String actionId,
            byte[] decodedSaml,
            EvidenceRef evidence) {
        requireRun(runId);
        var outbox = repository.findOutbox(actionId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown active-probe action"));
        var run = requireRun(runId);
        if (!outbox.runId().equals(runId) || scenario(outbox.caseId(), run).isEmpty()) {
            throw new IllegalArgumentException("Active-probe correlation belongs to another execution");
        }
        if (outbox.status() == OutboxStatus.UNKNOWN_DELIVERY) {
            dispatcher.confirmInboundDelivery(actionId, evidence.reference());
        } else if (outbox.status() != OutboxStatus.SENT) {
            throw new IllegalStateException("Inbound response arrived before front-channel dispatch");
        }
        var current = repository.find(runId, outbox.caseId())
                .orElseThrow(() -> new IllegalStateException("Active-probe execution is missing"));
        if (current.status() == CaseExecutionStatus.FINISHED) {
            // A response may cross the timeout boundary after the raw message has already been
            // durably recorded. Preserve the Suite-side NOT_VERIFIED result and acknowledge the
            // late delivery instead of turning the browser POST into an application error.
            return status(runId);
        }
        var waitingAction = current.waitCondition() == null
                ? null : current.waitCondition().inboundMatcher().criteria().get("ScenarioActionId");
        if (!actionId.equals(waitingAction)) {
            // Browser retries of an already-consumed POST must be idempotent. The prior fixture is
            // already represented by Transcript evidence and must not advance the next fixture.
            return status(runId);
        }
        var testCase = scenario(outbox.caseId(), run).orElseThrow();
        var router = new InboundCaseRouter(
                repository, new TestCaseRegistry(List.of(testCase)), executionService);
        router.route(
                runId, "saml-response", Map.of("ScenarioActionId", actionId), decodedSaml,
                evidence, contexts.contextFor(runId))
                .orElseThrow(() -> new IllegalStateException("Active-probe response did not match the waiting case"));
        return status(runId);
    }

    /** Marks only the current fixture unavailable and continues the remaining scenario controls. */
    public Status abort(String runId) {
        var currentStatus = status(runId);
        if (currentStatus.state() != State.AWAITING_RESPONSE || currentStatus.caseId() == null) {
            throw new IllegalStateException("No dispatched browser scenario is awaiting a response");
        }
        var run = requireRun(runId);
        var current = repository.find(runId, currentStatus.caseId())
                .orElseThrow(() -> new IllegalStateException("Browser scenario execution is missing"));
        var testCase = scenario(current.caseId(), run).orElseThrow();
        executionService.resume(
                runId, testCase, contexts.contextFor(runId),
                new CaseEvent.InboundUnavailable("operator-reported-no-saml-response"));
        return status(runId);
    }

    /** Reissues the current fixture as a new deterministic outbox action after an uncertain delivery. */
    public Status retry(String runId) {
        var currentStatus = status(runId);
        if (currentStatus.state() != State.AWAITING_RESPONSE || currentStatus.caseId() == null) {
            throw new IllegalStateException("No dispatched browser scenario is awaiting a response");
        }
        var run = requireRun(runId);
        var current = repository.find(runId, currentStatus.caseId())
                .orElseThrow(() -> new IllegalStateException("Browser scenario execution is missing"));
        var testCase = scenario(current.caseId(), run).orElseThrow();
        executionService.resume(
                runId, testCase, contexts.contextFor(runId), new CaseEvent.RetryInbound());
        return status(runId);
    }

    private com.samlscope.core.run.TestRun requireRun(String runId) {
        if (runId == null || runId.isBlank()) throw new IllegalArgumentException("runId must not be blank");
        return runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
    }

    private Optional<com.samlscope.core.caseexec.TestCase> scenario(
            String caseId, com.samlscope.core.run.TestRun run) {
        if (IdpErrorResponseTestCase.CASE_ID.equals(caseId)) {
            var plan = plans.find(run.planId())
                    .orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
            return Optional.of(new IdpErrorResponseTestCase(configurations.apply(plan, run.id())));
        }
        return scenarioCases.find(caseId)
                .filter(value -> value instanceof BrowserFrontChannelScenario);
    }

    private static String url(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    public record Status(
            String planId,
            State state,
            String actionId,
            URI startUrl,
            boolean requiresFreshSession,
            String outcome,
            String caseId,
            String instructionsEn) {
        public Status {
            if (planId == null || planId.isBlank()) throw new IllegalArgumentException("planId is required");
        }
    }

    public record PreparedProbe(
            URI destination,
            String samlRequest,
            String relayState,
            String transcriptEntryId) {
        public PreparedProbe {
            Objects.requireNonNull(destination, "destination");
            if (samlRequest == null || samlRequest.isBlank()) throw new IllegalArgumentException("samlRequest is required");
            if (relayState == null || relayState.isBlank()) throw new IllegalArgumentException("relayState is required");
            if (transcriptEntryId == null || transcriptEntryId.isBlank()) {
                throw new IllegalArgumentException("transcriptEntryId is required");
            }
        }
    }

    public enum State { NOT_STARTED, READY, AWAITING_RESPONSE, FINISHED, UNAVAILABLE }
}
