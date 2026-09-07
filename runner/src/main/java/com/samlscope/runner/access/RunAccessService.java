package com.samlscope.runner.access;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.Objects;
import com.samlscope.core.access.RunAccessGrant;
import com.samlscope.core.access.RunAccessGrantRepository;
import com.samlscope.core.run.RunRepository;

/** Issues, exchanges, rotates, authorizes, and revokes per-Run management credentials. */
public final class RunAccessService implements ManagementSessionExecutor {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int TOKEN_BYTES = 32;
    private final URI publicBase;
    private final RunRepository runs;
    private final RunAccessGrantRepository grants;
    private final Clock clock;

    public RunAccessService(URI publicBase, RunRepository runs, RunAccessGrantRepository grants, Clock clock) {
        this.publicBase = Objects.requireNonNull(publicBase, "publicBase");
        this.runs = Objects.requireNonNull(runs, "runs");
        this.grants = Objects.requireNonNull(grants, "grants");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Reissuing invalidates the old access URL and every existing management session immediately. */
    public IssuedAccess issue(String runId) {
        requireRun(runId);
        var prepared = prepareIssue(runId);
        grants.save(prepared.grant());
        return prepared.access();
    }

    /** Prepares a credential for atomic persistence with a new Run. */
    public PreparedAccess prepareIssue(String runId) {
        var raw = token();
        return new PreparedAccess(
                new IssuedAccess(runId, publicBase.resolve("/manage/" + runId + "#t=" + raw)),
                new RunAccessGrant(runId, hash(raw), null, null, clock.instant(), false));
    }

    @Override
    public ManagementSession exchange(String runId, String accessToken) {
        validToken(accessToken);
        var grant = grants.find(runId).orElseThrow(RunAccessService::denied);
        if (grant.revoked() || !constantTimeEquals(grant.accessTokenHash(), hash(accessToken))) throw denied();
        var session = token();
        var csrf = token();
        grants.save(new RunAccessGrant(
                runId, grant.accessTokenHash(), hash(session), hash(csrf), clock.instant(), false));
        return new ManagementSession(runId, session, csrf);
    }

    public void authorize(String runId, String sessionToken) {
        if (!runId.equals(authorizeSession(sessionToken))) throw denied();
    }

    /** Resolves a valid session without exposing or persisting the raw credential. */
    public String authorizeSession(String sessionToken) {
        validToken(sessionToken);
        var sessionHash = hash(sessionToken);
        var grant = grants.findBySessionTokenHash(sessionHash).orElseThrow(RunAccessService::denied);
        if (grant.revoked() || grant.sessionTokenHash() == null
                || !constantTimeEquals(grant.sessionTokenHash(), sessionHash)) throw denied();
        return grant.runId();
    }

    public void authorizeMutation(String runId, String sessionToken, String csrfToken) {
        authorize(runId, sessionToken);
        validToken(csrfToken);
        var grant = grants.find(runId).orElseThrow(RunAccessService::denied);
        if (!constantTimeEquals(grant.csrfTokenHash(), hash(csrfToken))
                && !constantTimeEquals(resumedCsrf(sessionToken), csrfToken)) throw denied();
    }

    /** Same-session CSRF recovery; no rotation, renewed lifetime, or raw credential persistence. */
    public ManagementSession resume(String runId, String sessionToken) {
        authorize(runId, sessionToken);
        return new ManagementSession(runId, sessionToken, resumedCsrf(sessionToken));
    }

    private static String resumedCsrf(String sessionToken) {
        try {
            var mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(
                    sessionToken.getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    mac.doFinal("SAMLscope management CSRF v1".getBytes(StandardCharsets.US_ASCII)));
        } catch (java.security.GeneralSecurityException impossible) {
            throw new IllegalStateException("HMAC-SHA256 is unavailable", impossible);
        }
    }

    public void revoke(String runId) {
        var grant = grants.find(runId).orElseThrow(RunAccessService::denied);
        grants.save(new RunAccessGrant(runId, grant.accessTokenHash(), null, null, clock.instant(), true));
    }

    private void requireRun(String runId) {
        if (runs.find(runId).isEmpty()) throw new IllegalArgumentException("Unknown Run");
    }

    private static String token() {
        var bytes = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String hash(String value) {
        try {
            var digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return "sha256:" + java.util.HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static boolean constantTimeEquals(String left, String right) {
        return MessageDigest.isEqual(
                left.getBytes(StandardCharsets.US_ASCII), right.getBytes(StandardCharsets.US_ASCII));
    }

    private static void validToken(String value) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{43}")) throw denied();
    }

    private static SecurityException denied() {
        return new SecurityException("Invalid or revoked Run management credential");
    }

    public record IssuedAccess(String runId, URI managementUrl) {}
    public record PreparedAccess(IssuedAccess access, RunAccessGrant grant) {}
    public record ManagementSession(String runId, String sessionToken, String csrfToken) {}
}
