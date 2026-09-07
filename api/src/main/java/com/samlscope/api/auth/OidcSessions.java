package com.samlscope.api.auth;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/** Bounded process-local sessions. Restart logs users out; identity ownership stays in SQLite. */
public final class OidcSessions {
    public static final Duration SESSION_LIFETIME = Duration.ofHours(8);
    private static final Duration LOGIN_LIFETIME = Duration.ofMinutes(5);
    private static final SecureRandom RANDOM = new SecureRandom();
    private final Clock clock;
    private final Map<String, Pending> pending = new HashMap<>();
    private final Map<String, Session> sessions = new HashMap<>();
    public OidcSessions(Clock clock) { this.clock = clock; }

    public synchronized Login start(String oldBinding) {
        cleanup();
        if (oldBinding != null) pending.values().removeIf(p -> p.bindingHash().equals(hash(oldBinding)));
        if (pending.size() >= 2048) throw new CapacityExceeded();
        var login = new Login(token(), token(), token(), token());
        pending.put(hash(login.state()), new Pending(hash(login.binding()), login.nonce(), login.verifier(),
                clock.instant().plus(LOGIN_LIFETIME)));
        return login;
    }

    public synchronized Pending consume(String state, String binding) {
        cleanup();
        if (!validToken(state) || !validToken(binding)) throw denied();
        var key = hash(state);
        var value = pending.get(key);
        if (value == null || !same(value.bindingHash(), hash(binding))) throw denied();
        pending.remove(key);
        return value;
    }

    public synchronized String signIn(OidcIdentity identity, String oldToken) {
        cleanup();
        if (oldToken != null) sessions.remove(hash(oldToken));
        if (sessions.size() >= 10_000) throw new CapacityExceeded();
        var raw = token();
        sessions.put(hash(raw), new Session(identity, token(), clock.instant().plus(SESSION_LIFETIME)));
        return raw;
    }
    public synchronized Optional<Session> find(String raw) {
        cleanup();
        return validToken(raw) ? Optional.ofNullable(sessions.get(hash(raw))) : Optional.empty();
    }
    public synchronized void logout(String raw) {
        if (raw != null) sessions.remove(hash(raw));
    }
    public void requireCsrf(Session session, String provided) {
        if (provided == null || !same(session.csrfToken(), provided)) throw denied();
    }
    private void cleanup() {
        var now = clock.instant();
        pending.values().removeIf(p -> !p.expiresAt().isAfter(now));
        sessions.values().removeIf(s -> !s.expiresAt().isAfter(now));
    }
    private static boolean validToken(String raw) { return raw != null && raw.matches("[A-Za-z0-9_-]{43}"); }
    private static String token() {
        var bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    private static String hash(String raw) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    private static boolean same(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
    private static SecurityException denied() { return new SecurityException("Invalid or expired login session"); }
    public record Login(String state, String binding, String nonce, String verifier) {
        @Override public String toString() { return "Login[<redacted>]"; }
    }
    public record Pending(String bindingHash, String nonce, String verifier, Instant expiresAt) {
        @Override public String toString() { return "Pending[<redacted>]"; }
    }
    public record Session(OidcIdentity identity, String csrfToken, Instant expiresAt) {
        @Override public String toString() { return "Session[<redacted>]"; }
    }
    public static final class CapacityExceeded extends RuntimeException {
        public CapacityExceeded() { super("Login service is busy; try again later"); }
    }
}
