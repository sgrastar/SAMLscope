package com.samlscope.runner.access;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunAccessGrantRepository;
import com.samlscope.store.SqliteRunRepository;

class RunAccessServiceTest {
    @TempDir java.nio.file.Path directory;

    @Test
    void rawTokensNeverPersistAndRotationAndCsrfFailClosed() throws Exception {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plans = new SqlitePlanRepository(database, json);
        var runs = new SqliteRunRepository(database, json);
        var plan = plan();
        var run = new TestRun("run_0123456789ABCDEFGHJKMNPQRS", plan.id(), RunStatus.CREATED,
                Reachability.UNKNOWN, Map.of(), Instant.EPOCH, Instant.EPOCH);
        plans.save(plan);
        runs.save(run);
        var service = new RunAccessService(URI.create("https://app.example"), runs,
                new SqliteRunAccessGrantRepository(database), Clock.fixed(Instant.EPOCH, ZoneOffset.UTC));

        var issued = service.issue(run.id());
        var accessToken = issued.managementUrl().getFragment().substring(2);
        assertTrue(issued.managementUrl().toString().contains("#t="));
        assertFalse(new String(Files.readAllBytes(directory.resolve("samlscope.db")), StandardCharsets.ISO_8859_1)
                .contains(accessToken));

        var first = service.exchange(run.id(), accessToken);
        assertTrue(service.authorizeSession(first.sessionToken()).equals(run.id()));
        service.authorize(run.id(), first.sessionToken());
        service.authorizeMutation(run.id(), first.sessionToken(), first.csrfToken());
        var resumed = service.resume(run.id(), first.sessionToken());
        assertEquals(resumed.csrfToken(), service.resume(run.id(), first.sessionToken()).csrfToken());
        assertNotEquals(first.sessionToken(), resumed.csrfToken());
        service.authorizeMutation(run.id(), first.sessionToken(), resumed.csrfToken());
        // Resuming in another tab does not invalidate the original tab's CSRF token.
        service.authorizeMutation(run.id(), first.sessionToken(), first.csrfToken());
        assertThrows(SecurityException.class, () -> service.resume(run.id(), null));
        assertThrows(SecurityException.class, () -> service.resume("run_other", first.sessionToken()));
        assertThrows(SecurityException.class, () ->
                service.authorizeMutation(run.id(), first.sessionToken(), "x".repeat(43)));

        var second = service.exchange(run.id(), accessToken);
        assertNotEquals(first.sessionToken(), second.sessionToken());
        assertThrows(SecurityException.class, () -> service.authorizeSession(first.sessionToken()));
        assertThrows(SecurityException.class, () -> service.authorize(run.id(), first.sessionToken()));
        assertThrows(SecurityException.class, () -> service.resume(run.id(), first.sessionToken()));
        assertThrows(SecurityException.class, () ->
                service.authorizeMutation(run.id(), second.sessionToken(), resumed.csrfToken()));
        service.revoke(run.id());
        assertThrows(SecurityException.class, () -> service.exchange(run.id(), accessToken));
        assertThrows(SecurityException.class, () -> service.authorize(run.id(), second.sessionToken()));
        assertThrows(SecurityException.class, () -> service.resume(run.id(), second.sessionToken()));
    }

    private TestPlan plan() {
        return new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Access", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Instant.EPOCH, Instant.EPOCH);
    }
}
