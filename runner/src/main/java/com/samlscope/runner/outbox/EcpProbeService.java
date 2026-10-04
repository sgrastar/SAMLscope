package com.samlscope.runner.outbox;

import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import com.samlscope.core.caseexec.ActionIds;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboundKind;

/** Non-evaluative ECP fixture. It creates a durable send intent without inventing a case verdict. */
public final class EcpProbeService {
    public static final String FIXTURE_ID = "fixture-ecp-http-basic";
    public static final String CHANNEL_BINDING_MATCH_SIGNED = "fixture-ecp-channel-binding-match-signed";
    public static final String CHANNEL_BINDING_MATCH_UNSIGNED = "fixture-ecp-channel-binding-match-unsigned";
    public static final String CHANNEL_BINDING_MISMATCH = "fixture-ecp-channel-binding-mismatch";
    public static final String CHANNEL_BINDING_REQUEST_ONLY = "fixture-ecp-channel-binding-request-only";
    public static final String CHANNEL_BINDING_HEADER_ONLY = "fixture-ecp-channel-binding-header-only";
    public static final String SAML_EC_SESSION_KEY = "fixture-ecp-saml-ec-session-key";
    private static final List<String> REQUIRED_FIXTURE_IDS = List.of(
            FIXTURE_ID,
            CHANNEL_BINDING_MATCH_SIGNED,
            CHANNEL_BINDING_MATCH_UNSIGNED,
            CHANNEL_BINDING_MISMATCH,
            CHANNEL_BINDING_REQUEST_ONLY,
            CHANNEL_BINDING_HEADER_ONLY,
            SAML_EC_SESSION_KEY);
    private static final String PHASE = "send-baseline";
    private final CaseExecutionRepository repository;
    private final InMemoryEphemeralCredentialProvider credentials;
    private final OutboundDispatcher dispatcher;
    private final Clock clock;

    public EcpProbeService(
            CaseExecutionRepository repository,
            InMemoryEphemeralCredentialProvider credentials,
            OutboundDispatcher dispatcher,
            Clock clock) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.credentials = Objects.requireNonNull(credentials, "credentials");
        this.dispatcher = Objects.requireNonNull(dispatcher, "dispatcher");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public Result execute(String runId, URI endpoint, byte[] envelope, byte[] ephemeralCredential) {
        return execute(runId, FIXTURE_ID, endpoint, envelope, ephemeralCredential);
    }

    public Result execute(
            String runId, String fixtureId, URI endpoint, byte[] envelope, byte[] ephemeralCredential) {
        if (fixtureId == null || !fixtureId.matches("fixture-ecp-[a-z0-9-]+")) {
            throw new IllegalArgumentException("Invalid ECP fixture ID");
        }
        Objects.requireNonNull(endpoint, "endpoint");
        if (envelope == null || envelope.length == 0) throw new IllegalArgumentException("envelope must not be empty");
        if (ephemeralCredential == null || ephemeralCredential.length == 0) {
            throw new IllegalArgumentException("credential must not be empty");
        }
        var actionId = ActionIds.derive(runId, fixtureId, PHASE, 0);
        var action = new OutboundAction(actionId, OutboundKind.ECP_SOAP, envelope, endpoint, true);
        var existing = repository.find(runId, fixtureId);
        if (existing.isEmpty()) {
            var execution = new CaseExecution(
                    runId, fixtureId, 0, CaseExecutionStatus.RUNNING,
                    new CaseState(PHASE, Map.of("fixture", fixtureId)),
                    null, null, clock.instant());
            repository.apply(-1, execution, List.of(action));
        }
        var outbox = repository.findOutbox(actionId)
                .orElseThrow(() -> new IllegalStateException("ECP probe outbox intent was not persisted"));
        if (outbox.status() == com.samlscope.core.caseexec.OutboxStatus.PENDING
                || outbox.status() == com.samlscope.core.caseexec.OutboxStatus.BLOCKED_ON_CREDENTIAL) {
            credentials.put(runId, actionId, ephemeralCredential);
        }
        try {
            var result = dispatcher.dispatch(actionId);
            var stored = repository.findOutbox(actionId).orElseThrow();
            return new Result(actionId, result.state(), stored.status(), stored.transcriptEntryId(), result.incidents());
        } finally {
            credentials.discard(runId, actionId);
        }
    }

    /** A metadata collection action cannot silently reuse an intent from a different epoch. */
    public Result executeMetadata(
            String runId, String fixtureId, URI endpoint, byte[] envelope, byte[] ephemeralCredential) {
        validateMetadata(runId, fixtureId, endpoint, envelope);
        return execute(runId, fixtureId, endpoint, envelope, ephemeralCredential);
    }

    /** Preflights a complete metadata group before any of its members is dispatched. */
    public void validateMetadata(String runId, String fixtureId, URI endpoint, byte[] envelope) {
        if (!com.samlscope.saml.ecp.MetadataApplicationEcpProbeFactory.FIXTURES.contains(fixtureId)) {
            throw new IllegalArgumentException("Unknown metadata ECP fixture");
        }
        String id = ActionIds.derive(runId, fixtureId, PHASE, 0);
        var existing = repository.findOutbox(id);
        if (existing.isPresent()) {
            var action = existing.orElseThrow().action();
            if (action.kind() != OutboundKind.ECP_SOAP || !action.requiresEphemeralCredential()
                    || !endpoint.equals(action.target()) || !java.util.Arrays.equals(envelope, action.payload())) {
                throw new IllegalArgumentException("Metadata ECP intent does not match the original epoch");
            }
        }
    }

    public static List<String> requiredFixtureIds() {
        return REQUIRED_FIXTURE_IDS;
    }

    /** Exact non-evaluative inventory; unknown fixture IDs still fail closed in case projection. */
    public static boolean isKnownNonEvaluativeFixture(String id) {
        return REQUIRED_FIXTURE_IDS.contains(id)
                || com.samlscope.saml.ecp.MetadataApplicationEcpProbeFactory.FIXTURES.contains(id);
    }

    public static String actionId(String runId, String fixtureId) {
        if (!REQUIRED_FIXTURE_IDS.contains(fixtureId)) {
            throw new IllegalArgumentException("Unknown required ECP fixture ID");
        }
        return ActionIds.derive(runId, fixtureId, PHASE, 0);
    }

    public static boolean allRequiredFixturesSent(CaseExecutionRepository repository, String runId) {
        Objects.requireNonNull(repository, "repository");
        Objects.requireNonNull(runId, "runId");
        return REQUIRED_FIXTURE_IDS.stream()
                .map(fixtureId -> actionId(runId, fixtureId))
                .map(repository::findOutbox)
                .allMatch(entry -> entry
                        .map(value -> value.status() == com.samlscope.core.caseexec.OutboxStatus.SENT)
                        .orElse(false));
    }

    public record Result(
            String actionId,
            OutboundDispatcher.State dispatchState,
            com.samlscope.core.caseexec.OutboxStatus outboxStatus,
            String responseTranscriptId,
            List<com.samlscope.core.evaluation.SuiteIncident> incidents) {
        public Result { incidents = List.copyOf(incidents); }
    }
}
