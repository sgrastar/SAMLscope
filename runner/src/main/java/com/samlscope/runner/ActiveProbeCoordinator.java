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
    private final java.util.function.Function<String, com.samlscope.saml.crypto.PlanCredentials> redirectCredentials;

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
        this(publicBase, plans, runs, repository, dispatcher, transcript, contexts, configurations,
                scenarioCases, clock, executionService, runId -> { throw new IllegalStateException("Redirect signing is not configured"); });
    }

    public ActiveProbeCoordinator(
            URI publicBase, PlanRepository plans, RunRepository runs,
            CaseExecutionRepository repository, OutboundDispatcher dispatcher,
            TranscriptRecorder transcript, CaseContextProvider contexts,
            BiFunction<TestPlan, String, IdpErrorProbeConfiguration> configurations,
            TestCaseRegistry scenarioCases, Clock clock, CaseExecutionService executionService,
            java.util.function.Function<String, com.samlscope.saml.crypto.PlanCredentials> redirectCredentials) {
        this.redirectCredentials = Objects.requireNonNull(redirectCredentials, "redirectCredentials");
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
        // Cases are reserved by the profile starter, but only the selected browser case
        // gets a request timestamp and timeout. Do not rewrite an existing outbox intent.
        while (true) {
        var candidates = repository.list(runId).stream()
                .filter(value -> value.status() == CaseExecutionStatus.WAITING_INBOUND
                        || CaseExecutionService.isQueuedFrontChannel(value))
                .filter(value -> scenario(value.caseId(), run).isPresent())
                .sorted(java.util.Comparator.comparingInt((CaseExecution value) ->
                                value.status() == CaseExecutionStatus.WAITING_INBOUND ? 0 : 1)
                        .thenComparingInt(value -> IdpErrorResponseTestCase.CASE_ID.equals(value.caseId()) ? 0 : 1)
                        .thenComparing(CaseExecution::caseId))
                .toList();
        if (candidates.isEmpty()) {
            var executions = repository.list(runId).stream()
                    .filter(value -> scenario(value.caseId(), run).isPresent()).toList();
            if (executions.isEmpty()) {
                return new Status(run.planId(), State.NOT_STARTED, null, null, false, null, null, null, false);
            }
            var unfinished = executions.stream().anyMatch(value -> value.status() != CaseExecutionStatus.FINISHED);
            var lastOutcome = executions.stream()
                    .filter(value -> IdpErrorResponseTestCase.CASE_ID.equals(value.caseId()))
                    .map(CaseExecution::outcome).filter(Objects::nonNull)
                    .map(value -> value.outcome().name()).findFirst().orElse(null);
            return new Status(run.planId(), unfinished ? State.UNAVAILABLE : State.FINISHED,
                    null, null, false, lastOutcome, null, null, false);
        }
        var current = candidates.get(0);
        var testCase = scenario(current.caseId(), run).orElseThrow();
        if (CaseExecutionService.isQueuedFrontChannel(current)) {
            executionService.activateFrontChannel(runId, testCase, contexts.contextFor(runId));
            continue; // Preconditions may have finished this case without creating an action.
        }
        var action = repository.listOutbox(runId).stream()
                .filter(value -> value.caseId().equals(current.caseId()))
                .filter(value -> value.action().actionId().equals(
                        current.waitCondition().inboundMatcher().criteria().get("ScenarioActionId")))
                .findFirst().orElseThrow(() -> new IllegalStateException("Active probe has no matching outbox action"));
        if (action.action().kind() == com.samlscope.core.caseexec.OutboundKind.LOGOUT_PROBE) {
            // Suite-side delivery: the response body is recorded as Transcript evidence and routed
            // back to the waiting case. Unknown delivery never becomes a target failure.
            var dispatched = dispatcher.dispatch(action.action().actionId());
            if (dispatched.state() == com.samlscope.runner.outbox.OutboundDispatcher.State.SENT) {
                var updated = repository.findOutbox(action.action().actionId()).orElseThrow();
                var entryId = updated.transcriptEntryId();
                if (entryId == null || entryId.isBlank()) {
                    throw new IllegalStateException("Direct probe delivery has no transcript entry");
                }
                var router = new InboundCaseRouter(repository, scenarioCases, executionService);
                router.route(runId, "saml-response", Map.of("ScenarioActionId", action.action().actionId()),
                        entryId.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        new EvidenceRef("transcript", entryId), contexts.contextFor(runId));
            } else if (dispatched.state() == com.samlscope.runner.outbox.OutboundDispatcher.State.UNKNOWN_DELIVERY) {
                executionService.resume(runId, testCase, contexts.contextFor(runId),
                        new CaseEvent.InboundUnavailable("direct-probe-delivery-unknown"));
            }
            continue;
        }
        var state = action.status() == OutboxStatus.PENDING ? State.READY : State.AWAITING_RESPONSE;
        var startUrl = state == State.READY
                ? publicBase.resolve("/p/" + run.planId() + "/probe/" + action.action().actionId()
                        + "?run=" + url(runId))
                : null;
        var browserScenario = (BrowserFrontChannelScenario) testCase;
        var observationExpected = Boolean.TRUE.equals(
                current.state().data().get("browser_observation"));
        return new Status(run.planId(), state, action.action().actionId(), startUrl,
                browserScenario.requiresFreshSession(current.state()), null,
                current.caseId(), browserScenario.instructionsEn(current.state()), observationExpected);
        }
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
        var binding = ((BrowserFrontChannelScenario) scenario(current.caseId(), requireRun(runId)).orElseThrow())
                .outboundBinding(execution.state());
        var redirect = new com.samlscope.saml.binding.SignedRedirectEncoder.Encoded[1];
        var dispatch = dispatcher.dispatchFrontChannel(actionId, action -> {
            var encodedRequest = Base64.getEncoder().encodeToString(action.payload());
            var body = "SAMLRequest=" + url(encodedRequest) + "&RelayState=" + url(relayState);
            var summary = new java.util.LinkedHashMap<String, Object>();
            summary.put("type", action.kind() == com.samlscope.core.caseexec.OutboundKind.LOGOUT_REQUEST
                    ? "LogoutRequest" : "AuthnRequest");
            summary.put("active_probe", true);
            summary.put("action_id", action.actionId());
            summary.put("scenario_case_id", current.caseId());
            var fixtureId = execution.state().data().get("fixture_id");
            if (fixtureId != null) summary.put("fixture_id", fixtureId);
            if (binding == BrowserFrontChannelScenario.Binding.SIGNED_REDIRECT) {
                redirect[0] = new com.samlscope.saml.binding.SignedRedirectEncoder().encode(
                        action.target(), action.payload(), relayState, redirectCredentials.apply(runId));
                return transcript.record(new TranscriptInput(
                        runId, Direction.OUTBOUND, clock.instant(), action.actionId(), "GET",
                        redirect[0].destination().toString(), null, Map.of(), new byte[0], null,
                        redirect[0].rawQuery(), redirect[0].decodedXml(), Map.copyOf(summary))).id();
            }
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
                dispatch.transcriptEntryId(), redirect[0] == null ? null : redirect[0].destination());
    }

    public Status accept(
            String runId,
            String actionId,
            byte[] decodedSaml,
            EvidenceRef evidence) {
        return accept(runId, actionId, decodedSaml, evidence, com.samlscope.core.caseexec.OutboundKind.AUTHN_REQUEST);
    }

    public Status acceptLogout(String runId, String actionId, byte[] decodedSaml, EvidenceRef evidence) {
        return accept(runId, actionId, decodedSaml, evidence, com.samlscope.core.caseexec.OutboundKind.LOGOUT_REQUEST);
    }

    private Status accept(String runId, String actionId, byte[] decodedSaml, EvidenceRef evidence,
            com.samlscope.core.caseexec.OutboundKind expectedKind) {
        requireRun(runId);
        var outbox = repository.findOutbox(actionId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown active-probe action"));
        var run = requireRun(runId);
        if (!outbox.runId().equals(runId) || scenario(outbox.caseId(), run).isEmpty()) {
            throw new IllegalArgumentException("Active-probe correlation belongs to another execution");
        }
        if (outbox.action().kind() != expectedKind) {
            throw new IllegalArgumentException("Active-probe response arrived on another protocol endpoint");
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

    /**
     * Records what the authenticated browser saw after delivering a probe, so session-dependent
     * HTTP feedback is observed without forging a log message. Unknown actions are ignored.
     */
    public Status reportBrowserResponse(String runId, String actionId, int httpStatus, String url, String body) {
        requireRun(runId);
        var outbox = repository.findOutbox(actionId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown active-probe action"));
        if (outbox.status() == OutboxStatus.PENDING || outbox.status() == OutboxStatus.BLOCKED_ON_CREDENTIAL) {
            throw new IllegalStateException("Browser observation arrived before front-channel dispatch");
        }
        var entry = recordBrowserObservation(runId, actionId, httpStatus, url, body,
                outbox.action().target().toString());
        if (outbox.status() == OutboxStatus.UNKNOWN_DELIVERY) {
            dispatcher.confirmInboundDelivery(actionId, entry.id());
        }
        var current = repository.find(runId, outbox.caseId())
                .orElseThrow(() -> new IllegalStateException("Active-probe execution is missing"));
        if (current.status() == CaseExecutionStatus.FINISHED) return status(runId);
        var waitingAction = current.waitCondition() == null
                ? null : current.waitCondition().inboundMatcher().criteria().get("ScenarioActionId");
        if (!actionId.equals(waitingAction)) return status(runId);
        var testCase = scenario(outbox.caseId(), requireRun(runId)).orElseThrow();
        executionService.resume(runId, testCase, contexts.contextFor(runId),
                new CaseEvent.BrowserObservation(httpStatus, url, body));
        return status(runId);
    }

    /** Records an observed browser landing as evidence for transcript-driven SLO binding rules. */
    public com.samlscope.core.transcript.TranscriptEntry recordBrowserObservation(
            String runId, String correlationId, int httpStatus, String url, String body, String fallbackUrl) {
        requireRun(runId);
        var bodyBytes = (body == null ? "" : body).getBytes(StandardCharsets.UTF_8);
        var saml = com.samlscope.saml.normal.SamlEmbeddedMessage.find(body)
                .map(bytes -> (byte[]) bytes).orElse(new byte[0]);
        var summary = new java.util.LinkedHashMap<String, Object>();
        summary.put("type", "BrowserResponseObservation");
        summary.put("http_status", httpStatus);
        summary.put("failure_indicated",
                com.samlscope.runner.cases.SloProbeObservation.failureIndicated(httpStatus, body));
        summary.put("url", url == null ? "" : url);
        return transcript.record(new TranscriptInput(
                runId, Direction.INBOUND, clock.instant(),
                correlationId == null || correlationId.isBlank() ? "browser-observation" : correlationId,
                "BROWSER",
                url == null || url.isBlank() ? (fallbackUrl == null ? "" : fallbackUrl) : url,
                httpStatus, Map.of(), bodyBytes, "text/html", null, saml, Map.copyOf(summary)));
    }

    /**
     * Concludes the target-initiated logout campaign when the target issued no request.
     * Campaign cases then record "not observed" instead of waiting forever.
     */
    public int concludeTargetInitiatedCampaign(String runId) {
        requireRun(runId);
        var concluded = 0;
        for (var execution : repository.list(runId)) {
            if (execution.status() == CaseExecutionStatus.FINISHED) continue;
            var testCase = scenarioCases.find(execution.caseId()).orElse(null);
            if (!(testCase instanceof com.samlscope.runner.RecordedEvidenceReevaluation)) continue;
            if (!(testCase instanceof com.samlscope.runner.EvidenceCampaignCase campaign)
                    || !"target-initiated-logout".equals(campaign.evidenceCampaignId())) continue;
            try {
                executionService.resume(runId, testCase, contexts.contextFor(runId),
                        new CaseEvent.Aborted("target-initiated-not-issued"));
                concluded++;
            } catch (RuntimeException notResumable) {
                // A case waiting on another evidence form keeps its own completion path.
            }
        }
        return concluded;
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
            String instructionsEn,
            boolean browserObservationExpected) {
        public Status {
            if (planId == null || planId.isBlank()) throw new IllegalArgumentException("planId is required");
        }
    }

    public record PreparedProbe(
            URI destination,
            String samlRequest,
            String relayState,
            String transcriptEntryId, URI redirectDestination) {
        public PreparedProbe(URI destination, String samlRequest, String relayState, String transcriptEntryId) {
            this(destination, samlRequest, relayState, transcriptEntryId, null);
        }
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
