package com.samlscope.runner;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Explicit, single-use intents for messages the target initiates (unsolicited SSO Responses
 * and target-initiated LogoutRequests). The Suite never accepts such a message without a
 * prepared intent, and each intent is consumed at most once. Intents are process-local by
 * design: a restart invalidates them, so the operator must prepare the check again.
 */
public final class TargetInitiatedIntents {
    public enum Kind { UNSOLICITED_SSO, TARGET_LOGOUT }

    public record Intent(String runId, String planId, Kind kind, Instant expiresAt) {
        public Intent { Objects.requireNonNull(runId); Objects.requireNonNull(planId); Objects.requireNonNull(kind); Objects.requireNonNull(expiresAt); }
    }

    private final Map<String, Intent> byRun = new ConcurrentHashMap<>();

    public Intent prepare(String runId, String planId, Kind kind, Duration ttl, Clock clock) {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(planId, "planId");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(clock, "clock");
        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("Intent TTL must be positive");
        }
        var intent = new Intent(runId, planId, kind, clock.instant().plus(ttl));
        byRun.put(runId, intent);
        return intent;
    }

    /** Single-use for a known Run; returns false when no matching unexpired intent exists. */
    public boolean consumeForRun(String runId, Kind kind, Clock clock) {
        var current = byRun.get(runId);
        if (current == null || current.kind() != kind || expired(current, clock)) return false;
        return byRun.remove(runId, current);
    }

    /** Resolves the only Run of a plan awaiting this kind; ambiguous or missing waits return empty. */
    public Optional<Intent> resolvePlan(String planId, Kind kind, Clock clock) {
        var matches = byRun.values().stream()
                .filter(value -> value.planId().equals(planId) && value.kind() == kind)
                .filter(value -> !expired(value, clock)).toList();
        if (matches.size() != 1) return Optional.empty();
        var intent = matches.getFirst();
        return byRun.remove(intent.runId(), intent) ? Optional.of(intent) : Optional.empty();
    }

    /** Peek at the only Run of a plan awaiting this kind without consuming the intent. */
    public Optional<Intent> peekPlan(String planId, Kind kind, Clock clock) {
        var matches = byRun.values().stream()
                .filter(value -> value.planId().equals(planId) && value.kind() == kind)
                .filter(value -> !expired(value, clock)).toList();
        return matches.size() == 1 ? Optional.of(matches.getFirst()) : Optional.empty();
    }

    public Optional<Intent> find(String runId, Clock clock) {
        var current = byRun.get(runId);
        return current == null || expired(current, clock) ? Optional.empty() : Optional.of(current);
    }

    public void clear(String runId) { byRun.remove(runId); }

    public int activeCount(Clock clock) {
        return (int) byRun.values().stream().filter(value -> !expired(value, clock)).count();
    }

    private static boolean expired(Intent intent, Clock clock) {
        return !clock.instant().isBefore(intent.expiresAt());
    }
}
