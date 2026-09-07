package com.samlscope.api.auth;

import java.time.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class OidcSessionsTest {
    @Test void bindsLoginToBrowserAndConsumesItOnlyOnce() {
        var sessions = new OidcSessions(Clock.systemUTC());
        var login = sessions.start(null);
        assertThrows(SecurityException.class, () -> sessions.consume(login.state(), "a".repeat(43)));
        assertThrows(SecurityException.class, () -> sessions.consume("a".repeat(43), login.binding()));
        assertEquals(login.nonce(), sessions.consume(login.state(), login.binding()).nonce());
        assertThrows(SecurityException.class, () -> sessions.consume(login.state(), login.binding()));
    }
    @Test void expiresLoginAndSessionOnServerAndRotatesSessionOnLogin() {
        var clock = new MutableClock();
        var sessions = new OidcSessions(clock);
        var login = sessions.start(null);
        clock.now = clock.now.plusSeconds(300);
        assertThrows(SecurityException.class, () -> sessions.consume(login.state(), login.binding()));
        var user = new OidcIdentity("https://issuer.example", "alice", "Alice");
        var old = sessions.signIn(user, null);
        var current = sessions.signIn(user, old);
        assertTrue(sessions.find(old).isEmpty());
        var session = sessions.find(current).orElseThrow();
        assertThrows(SecurityException.class, () -> sessions.requireCsrf(session, "wrong"));
        sessions.requireCsrf(session, session.csrfToken());
        clock.now = clock.now.plus(OidcSessions.SESSION_LIFETIME);
        assertTrue(sessions.find(current).isEmpty());
        var token = sessions.signIn(user, null);
        sessions.logout(token);
        assertTrue(sessions.find(token).isEmpty());
    }
    private static final class MutableClock extends Clock {
        Instant now = Instant.now();
        public ZoneId getZone() { return ZoneOffset.UTC; }
        public Clock withZone(ZoneId zone) { return this; }
        public Instant instant() { return now; }
    }
}
