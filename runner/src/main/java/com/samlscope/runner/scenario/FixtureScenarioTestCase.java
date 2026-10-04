package com.samlscope.runner.scenario;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import com.samlscope.core.caseexec.ActionIds;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.InboundMatcher;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;

/**
 * Executes multiple fixtures in a deterministic order through the persistent outbox. The engine
 * owns sequencing and uncertainty; fixtures own only message construction and observation.
 */
public final class FixtureScenarioTestCase implements TestCase {
    private static final int MAX_FIXTURE_RETRIES = 3;
    private final String id;
    private final TargetRole role;
    private final List<ScenarioFixture> fixtures;
    private final Predicate<CaseContext> preconditions;
    private final Vocabulary vocabulary;
    private final String scenarioFingerprint;

    public FixtureScenarioTestCase(
            String id,
            TargetRole role,
            List<ScenarioFixture> fixtures,
            Predicate<CaseContext> preconditions,
            Vocabulary vocabulary) {
        this.id = text(id, "id");
        this.role = Objects.requireNonNull(role, "role");
        this.fixtures = List.copyOf(fixtures == null ? List.of() : fixtures);
        if (this.fixtures.isEmpty()) throw new IllegalArgumentException("fixtures must not be empty");
        var ids = new LinkedHashSet<String>();
        for (var fixture : this.fixtures) {
            Objects.requireNonNull(fixture, "fixture");
            if (!fixture.id().matches("[a-z][a-z0-9-]{0,63}")) {
                throw new IllegalArgumentException("Unsafe fixture ID: " + fixture.id());
            }
            if (!ids.add(fixture.id())) throw new IllegalArgumentException("Duplicate fixture ID: " + fixture.id());
            if (fixture.timeout().isZero() || fixture.timeout().isNegative()) {
                throw new IllegalArgumentException("Fixture timeout must be positive: " + fixture.id());
            }
        }
        this.preconditions = Objects.requireNonNull(preconditions, "preconditions");
        this.vocabulary = Objects.requireNonNull(vocabulary, "vocabulary");
        this.scenarioFingerprint = fingerprint(this.id, this.role, this.fixtures);
    }

    @Override public String id() { return id; }
    @Override public TargetRole role() { return role; }

    @Override
    public CaseStep start(CaseContext context) {
        Objects.requireNonNull(context, "context");
        if (!preconditions.test(context)) {
            return new CaseStep.Finish(CaseOutcome.notVerified(
                    vocabulary.preconditionReason(), vocabulary.preconditionMessageKey()));
        }
        return awaitFixture(context, 0, 0, List.of(), List.of(), List.of(), List.of());
    }

    @Override
    public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        Objects.requireNonNull(context, "context");
        if (event instanceof CaseEvent.RetryInbound) {
            if (!matchesScenario(state)) {
                return new CaseStep.Finish(notVerified(
                        state, "scenario_definition_changed", "scenario.definition-changed", Map.of()));
            }
            var attempt = optionalInteger(state, "fixture_attempt", 0) + 1;
            if (attempt > MAX_FIXTURE_RETRIES) {
                throw new IllegalStateException("The current fixture has reached its retry limit");
            }
            return awaitFixture(
                    context, fixtureIndex(state), attempt,
                    strings(state, "violations"), optionalStrings(state, "violating_action_ids"),
                    strings(state, "unverifiable"), strings(state, "evidence"));
        }
        if (event instanceof CaseEvent.TimedOut timedOut) {
            return new CaseStep.Finish(notVerified(
                    state, vocabulary.timeoutReason(), vocabulary.timeoutMessageKey(),
                    Map.of("waited_seconds", timedOut.waited().toSeconds())));
        }
        if (event instanceof CaseEvent.Aborted) {
            return new CaseStep.Finish(notVerified(
                    state, vocabulary.abortedReason(), vocabulary.abortedMessageKey(), Map.of()));
        }
        if (event instanceof CaseEvent.InboundUnavailable unavailable) {
            if (!matchesScenario(state)) {
                return new CaseStep.Finish(notVerified(
                        state, "scenario_definition_changed", "scenario.definition-changed", Map.of()));
            }
            var index = fixtureIndex(state);
            var violations = strings(state, "violations");
            var violatingActionIds = optionalStrings(state, "violating_action_ids");
            var unverifiable = strings(state, "unverifiable");
            var evidence = strings(state, "evidence");
            var fixture = fixtures.get(index);
            var observation = fixture.observeUnavailable(unavailable.reason());
            if (observation == null) throw new IllegalStateException("Fixture returned no unavailable observation");
            if (observation == FixtureObservation.CONTROL_FAILED) {
                return new CaseStep.Finish(new CaseOutcome(
                        Outcome.NOT_VERIFIED, "control_failed", "control_failed",
                        vocabulary.controlFailedMessageKey(), refs(evidence),
                        Map.of("failed_control", fixture.id(), "unavailable_reason", unavailable.reason())));
            }
            if (observation == FixtureObservation.VIOLATED) {
                violations.add(fixture.id());
                violatingActionIds.add(ActionIds.derive(context.runId(), id, state.phase(), 0));
            }
            if (observation == FixtureObservation.NOT_VERIFIED) unverifiable.add(fixture.id());
            if (index + 1 < fixtures.size()) {
                return awaitFixture(
                        context, index + 1, 0, violations, violatingActionIds, unverifiable, evidence);
            }
            return finishScenario(violations, violatingActionIds, unverifiable, evidence,
                    Map.of("unavailable_reason", unavailable.reason()));
        }
        if (event instanceof CaseEvent.BrowserObservation browser) {
            if (!matchesScenario(state)) {
                return new CaseStep.Finish(notVerified(
                        state, "scenario_definition_changed", "scenario.definition-changed", Map.of()));
            }
            var index = fixtureIndex(state);
            var fixture = fixtures.get(index);
            var observation = browser.evidence() == null
                    ? FixtureObservation.NOT_VERIFIED
                    : fixture.observeBrowser(
                            string(state, "expected_response_correlation"),
                            browser.httpStatus(), browser.url(), browser.body());
            if (observation == null) throw new IllegalStateException("Fixture returned no browser observation");
            var violations = strings(state, "violations");
            var violatingActionIds = optionalStrings(state, "violating_action_ids");
            var unverifiable = strings(state, "unverifiable");
            var evidence = strings(state, "evidence");
            if (browser.evidence() != null) evidence.add(browser.evidence().reference());
            if (observation == FixtureObservation.CONTROL_FAILED) {
                return new CaseStep.Finish(new CaseOutcome(
                        Outcome.NOT_VERIFIED, "control_failed", "control_failed",
                        vocabulary.controlFailedMessageKey(), refs(evidence),
                        Map.of("failed_control", fixture.id(), "browser_http_status", browser.httpStatus())));
            }
            if (observation == FixtureObservation.VIOLATED) {
                violations.add(fixture.id());
                violatingActionIds.add(ActionIds.derive(context.runId(), id, state.phase(), 0));
            }
            if (observation == FixtureObservation.NOT_VERIFIED) unverifiable.add(fixture.id());
            if (index + 1 < fixtures.size()) {
                return awaitFixture(
                        context, index + 1, 0, violations, violatingActionIds, unverifiable, evidence);
            }
            return finishScenario(violations, violatingActionIds, unverifiable, evidence,
                    Map.of("browser_http_status", browser.httpStatus()));
        }
        if (!(event instanceof CaseEvent.InboundMessage inbound)) {
            throw new IllegalArgumentException("Fixture scenario requires an inbound message");
        }
        if (!matchesScenario(state)) {
            return new CaseStep.Finish(notVerified(
                    state, "scenario_definition_changed", "scenario.definition-changed", Map.of()));
        }
        if (!"transcript".equals(inbound.evidence().kind())) {
            return new CaseStep.Finish(notVerified(
                    state, "scenario_transcript_missing", "scenario.transcript-missing", Map.of()));
        }
        var index = fixtureIndex(state);
        var fixture = fixtures.get(index);
        var observation = fixture.observe(
                string(state, "expected_response_correlation"), inbound.decodedSaml());
        if (observation == null) throw new IllegalStateException("Fixture returned no observation");
        var violations = strings(state, "violations");
        var violatingActionIds = optionalStrings(state, "violating_action_ids");
        var unverifiable = strings(state, "unverifiable");
        var evidence = strings(state, "evidence");
        evidence.add(inbound.evidence().reference());
        if (observation == FixtureObservation.CONTROL_FAILED) {
            return new CaseStep.Finish(new CaseOutcome(
                    Outcome.NOT_VERIFIED, "control_failed", "control_failed",
                    vocabulary.controlFailedMessageKey(), refs(evidence),
                    Map.of("failed_control", fixture.id())));
        }
        if (observation == FixtureObservation.VIOLATED) {
            violations.add(fixture.id());
            violatingActionIds.add(ActionIds.derive(context.runId(), id, state.phase(), 0));
        }
        if (observation == FixtureObservation.NOT_VERIFIED) unverifiable.add(fixture.id());
        if (index + 1 < fixtures.size()) {
            return awaitFixture(
                    context, index + 1, 0, violations, violatingActionIds, unverifiable, evidence);
        }
        return finishScenario(violations, violatingActionIds, unverifiable, evidence, Map.of());
    }

    private CaseStep finishScenario(
            List<String> violations,
            List<String> violatingActionIds,
            List<String> unverifiable,
            List<String> evidence,
            Map<String, Object> additionalDetails) {
        if (!violations.isEmpty()) {
            var details = new java.util.LinkedHashMap<String, Object>();
            details.put("violating_fixtures", List.copyOf(violations));
            details.put("violating_action_ids", List.copyOf(violatingActionIds));
            details.put("unverifiable_fixtures", List.copyOf(unverifiable));
            details.putAll(additionalDetails);
            return new CaseStep.Finish(new CaseOutcome(
                    Outcome.VIOLATED, null, vocabulary.violatedReasonCode(),
                    vocabulary.violatedMessageKey(), refs(evidence), Map.copyOf(details)));
        }
        if (!unverifiable.isEmpty()) {
            var details = new java.util.LinkedHashMap<String, Object>();
            details.put("unverifiable_fixtures", List.copyOf(unverifiable));
            details.putAll(additionalDetails);
            return new CaseStep.Finish(new CaseOutcome(
                    Outcome.NOT_VERIFIED, vocabulary.inconclusiveReason(),
                    vocabulary.inconclusiveReasonCode(), vocabulary.inconclusiveMessageKey(),
                    refs(evidence), Map.copyOf(details)));
        }
        return new CaseStep.Finish(new CaseOutcome(
                Outcome.SATISFIED, null, vocabulary.satisfiedReasonCode(),
                vocabulary.satisfiedMessageKey(), refs(evidence),
                Map.of("completed_fixtures", fixtures.size())));
    }

    private boolean matchesScenario(CaseState state) {
        return id.equals(state.data().get("scenario_case_id"))
                && scenarioFingerprint.equals(state.data().get("scenario_fingerprint"));
    }

    private int fixtureIndex(CaseState state) {
        var index = integer(state, "fixture_index");
        if (index < 0 || index >= fixtures.size()) throw new IllegalStateException("Invalid fixture index");
        if (!fixtures.get(index).id().equals(string(state, "fixture_id"))) {
            throw new IllegalStateException("Persisted fixture does not match the scenario definition");
        }
        return index;
    }

    private CaseStep awaitFixture(
            CaseContext context,
            int index,
            int attempt,
            List<String> violations,
            List<String> violatingActionIds,
            List<String> unverifiable,
            List<String> evidence) {
        var fixture = fixtures.get(index);
        var phase = "await-fixture-" + fixture.id()
                + (attempt == 0 ? "" : "-retry-" + attempt);
        var actionId = ActionIds.derive(context.runId(), id, phase, 0);
        var prepared = fixture.prepare(context, actionId);
        if (!actionId.equals(prepared.action().actionId())) {
            throw new IllegalArgumentException("Fixture actionId is not the deterministic scenario actionId");
        }
        var next = new CaseState(phase, Map.of(
                "scenario_case_id", id,
                "scenario_fingerprint", scenarioFingerprint,
                "fixture_index", index,
                "fixture_id", fixture.id(),
                "fixture_attempt", attempt,
                "expected_response_correlation", prepared.expectedResponseCorrelation(),
                "violations", List.copyOf(violations),
                "violating_action_ids", List.copyOf(violatingActionIds),
                "unverifiable", List.copyOf(unverifiable),
                "evidence", List.copyOf(evidence)));
        return new CaseStep.AwaitInbound(
                next,
                List.of(prepared.action()),
                new InboundMatcher(fixture.inboundType(), Map.of("ScenarioActionId", actionId)),
                fixture.timeout());
    }

    private static List<EvidenceRef> refs(List<String> evidence) {
        return evidence.stream().map(value -> new EvidenceRef("transcript", value)).toList();
    }

    private static CaseOutcome notVerified(
            CaseState state, String reason, String messageKey, Map<String, Object> additionalDetails) {
        var evidence = strings(state, "evidence");
        var details = new java.util.LinkedHashMap<String, Object>();
        var fixture = state.data().get("fixture_id");
        if (fixture instanceof String value && !value.isBlank()) details.put("fixture_id", value);
        details.put("completed_fixtures", evidence.size());
        details.putAll(additionalDetails);
        return new CaseOutcome(
                Outcome.NOT_VERIFIED, reason, reason, messageKey, refs(evidence), Map.copyOf(details));
    }

    private static int integer(CaseState state, String key) {
        var value = state.data().get(key);
        if (!(value instanceof Number number)) throw new IllegalStateException("Missing numeric state: " + key);
        return number.intValue();
    }

    private static int optionalInteger(CaseState state, String key, int fallback) {
        var value = state.data().get(key);
        if (value == null) return fallback;
        if (!(value instanceof Number number)) throw new IllegalStateException("Invalid numeric state: " + key);
        return number.intValue();
    }

    private static String string(CaseState state, String key) {
        var value = state.data().get(key);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalStateException("Missing text state: " + key);
        }
        return text;
    }

    @SuppressWarnings("unchecked")
    private static ArrayList<String> strings(CaseState state, String key) {
        var value = state.data().get(key);
        if (!(value instanceof List<?> list) || list.stream().anyMatch(item -> !(item instanceof String))) {
            throw new IllegalStateException("Missing string-list state: " + key);
        }
        return new ArrayList<>((List<String>) list);
    }

    @SuppressWarnings("unchecked")
    private static ArrayList<String> optionalStrings(CaseState state, String key) {
        var value = state.data().get(key);
        if (value == null) return new ArrayList<>();
        if (!(value instanceof List<?> list) || list.stream().anyMatch(item -> !(item instanceof String))) {
            throw new IllegalStateException("Invalid string-list state: " + key);
        }
        return new ArrayList<>((List<String>) list);
    }

    private static String text(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
        return value;
    }

    private static String fingerprint(
            String caseId, TargetRole role, List<ScenarioFixture> fixtures) {
        var material = new StringBuilder(caseId).append('\u001f').append(role.name());
        for (var fixture : fixtures) {
            material.append('\u001f').append(fixture.id())
                    .append('\u001f').append(fixture.inboundType())
                    .append('\u001f').append(fixture.timeout())
                    .append('\u001f').append(fixture.definitionKey());
        }
        try {
            return "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(material.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    public record Vocabulary(
            String preconditionReason,
            String preconditionMessageKey,
            String timeoutReason,
            String timeoutMessageKey,
            String abortedReason,
            String abortedMessageKey,
            String controlFailedMessageKey,
            String violatedReasonCode,
            String violatedMessageKey,
            String inconclusiveReason,
            String inconclusiveReasonCode,
            String inconclusiveMessageKey,
            String satisfiedReasonCode,
            String satisfiedMessageKey) {
        public Vocabulary {
            text(preconditionReason, "preconditionReason");
            text(preconditionMessageKey, "preconditionMessageKey");
            text(timeoutReason, "timeoutReason");
            text(timeoutMessageKey, "timeoutMessageKey");
            text(abortedReason, "abortedReason");
            text(abortedMessageKey, "abortedMessageKey");
            text(controlFailedMessageKey, "controlFailedMessageKey");
            text(violatedReasonCode, "violatedReasonCode");
            text(violatedMessageKey, "violatedMessageKey");
            text(inconclusiveReason, "inconclusiveReason");
            text(inconclusiveReasonCode, "inconclusiveReasonCode");
            text(inconclusiveMessageKey, "inconclusiveMessageKey");
            text(satisfiedReasonCode, "satisfiedReasonCode");
            text(satisfiedMessageKey, "satisfiedMessageKey");
        }
    }
}
