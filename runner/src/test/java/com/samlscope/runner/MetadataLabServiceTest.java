package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunRepository;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;

class MetadataLabServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-31T00:00:00Z");

    @Test
    void automaticPollingAdvancesOnlyAfterTheSelectedFixtureWasFetched() {
        var fixture = fixture();
        var service = fixture.service();

        var armed = service.startAutomaticPolling(
                "run", List.of("control", "expired", "bad-signature"), 17);
        assertEquals(MetadataLabService.IngestionMode.AUTOMATIC_POLLING, armed.ingestionMode());
        assertEquals("control", armed.selectedVariant());
        assertEquals(0, armed.campaignIndex());
        assertEquals(17, armed.pollingDelaySeconds());
        assertEquals(null, queryOrNull(armed.metadataUrl(), "poll"),
                "the Target-configured metadata URL must remain stable and secret-free");
        var token = query(armed.automaticStartUrl(), "poll");
        assertEquals(token, query(armed.automaticStartUrl(), "poll"));
        service.recordLiveFetch("run", "plan", "control", null);
        assertThrows(IllegalArgumentException.class,
                () -> service.requireAutomaticCompletedFlow("run", "plan", token, 0),
                "a fetch before the signed browser attempt must not be correlated");
        var firstFlow = service.requireAutomaticStartFlow("run", "plan", token, 0);
        assertEquals("control", firstFlow.variant().id());
        assertEquals(17, firstFlow.pollingDelaySeconds());
        assertThrows(IllegalArgumentException.class,
                () -> service.requireAutomaticCompletedFlow("run", "plan", token, 0));

        var ignored = service.recordLiveFetch("run", "plan", "expired", token);
        assertEquals("control", ignored.selectedVariant());
        assertEquals(0, ignored.campaignIndex());

        var untrusted = service.recordLiveFetch("run", "plan", "control", "wrong-token");
        assertEquals(0, untrusted.campaignIndex());

        var fetched = service.recordLiveFetch("run", "plan", "control", null);
        assertEquals("control", fetched.selectedVariant());
        assertEquals(0, fetched.campaignIndex());
        var duplicateFetch = service.recordLiveFetch("run", "plan", "control", null);
        assertEquals("control", duplicateFetch.selectedVariant());
        assertEquals(0, duplicateFetch.campaignIndex(),
                "duplicate target fetches during one key reload must not skip fixtures");
        assertTrue(duplicateFetch.automaticContinueUrl().toString()
                .contains("/continue/metadata-polling/0"));
        assertEquals("control", service.requireAutomaticCompletedFlow(
                "run", "plan", token, 0).variant().id());
        var second = service.state("run");
        assertEquals("expired", second.selectedVariant());
        assertEquals(1, second.campaignIndex());
        assertEquals("expired", service.requireAutomaticStartFlow(
                "run", "plan", token, 1).variant().id());
        assertThrows(IllegalArgumentException.class,
                () -> service.requireAutomaticStartFlow("run", "plan", token, 0));

        var complete = service.recordLiveFetch("run", "plan", "bad-signature", token);
        assertEquals(1, complete.campaignIndex(), "out-of-order fetches must not skip a fixture");
        service.recordLiveFetch("run", "plan", "expired", token);
        service.requireAutomaticCompletedFlow("run", "plan", token, 1);
        assertEquals(2, service.state("run").campaignIndex());
        service.requireAutomaticStartFlow("run", "plan", token, 2);
        complete = service.recordLiveFetch("run", "plan", "bad-signature", token);
        assertEquals(2, complete.campaignIndex());
        service.requireAutomaticCompletedFlow("run", "plan", token, 2);
        complete = service.state("run");
        assertEquals(3, complete.campaignIndex());
        assertEquals(true, complete.campaignComplete());
        assertEquals(null, complete.automaticStartUrl());
        assertEquals(null, complete.automaticContinueUrl());
    }

    @Test
    void operatorContinuationAdvancesOnlyAFetchedFixtureAndDoesNotInventEvidence() {
        var service = fixture().service();
        var armed = service.startAutomaticPolling("run", List.of("control", "expired"), 0);
        var token = query(armed.automaticStartUrl(), "poll");

        assertThrows(IllegalArgumentException.class,
                () -> service.continueAfterObservedTargetResult("run", "plan", token, 0));
        service.requireAutomaticStartFlow("run", "plan", token, 0);
        var completed = service.continueAfterObservedTargetResult("run", "plan", token, 0);

        assertEquals("control", completed.variant().id());
        assertEquals("expired", service.state("run").selectedVariant());
        assertEquals(1, service.state("run").campaignIndex());
        assertEquals(1, service.state("run").operatorContinuationActions());
        assertEquals(null, service.state("run").automaticContinueUrl());
    }

    @Test
    void manualSelectionDisarmsAutomaticPollingAndCampaignInputIsStrict() {
        var service = fixture().service();
        service.startAutomaticPolling("run", List.of("control", "expired"));

        var manual = service.select("run", "no-key-info");
        assertEquals(MetadataLabService.IngestionMode.MANUAL_REFRESH, manual.ingestionMode());
        assertEquals("no-key-info", manual.selectedVariant());
        assertEquals(List.of(), manual.campaignVariants());
        assertThrows(IllegalArgumentException.class,
                () -> service.startAutomaticPolling("run", List.of("control", "control")));
        assertThrows(IllegalArgumentException.class,
                () -> service.startAutomaticPolling("run", List.of("unknown-fixture")));
        assertThrows(IllegalArgumentException.class,
                () -> service.startAutomaticPolling("run", List.of("control"), -1));
        assertThrows(IllegalArgumentException.class,
                () -> service.startAutomaticPolling("run", List.of("control"), 901));
    }

    @Test
    void preloadedAggregateRequiresItsFetchAndRunScopedTokenBeforeBrowserFlows() {
        var service = fixture().service();
        var armed = service.startPreloadedCampaign("run");

        assertEquals(MetadataLabService.IngestionMode.PRELOADED_AGGREGATE, armed.ingestionMode());
        assertEquals(com.samlscope.saml.metadata.MetadataService.preloadedCampaignVariants().size(),
                armed.preloadedVariants().size());
        assertTrue(armed.preloadedMetadataUrl().toString().contains("/metadata/preloaded"));
        assertTrue(armed.preloadedDownloadUrl().toString().contains("/metadata/preloaded/download"));
        assertTrue(armed.preloadedStartUrl().toString().contains("/start/metadata-preloaded/0"));
        var token = query(armed.preloadedMetadataUrl(), "preload");

        assertThrows(IllegalArgumentException.class,
                () -> service.authorizePreloadedFetch("run", "plan", "wrong-token"));
        assertEquals(armed.preloadedVariants(), service.authorizePreloadedFetch("run", "plan", token));
        var exported = service.authorizePreloadedDownload("run", "plan", token);
        assertEquals(armed.preloadedVariants(), exported);
        assertEquals(false, service.state("run").preloadedFetched(),
                "an operator download must not be recorded as a Target metadata fetch");
        assertEquals(exported.getFirst(), service.requirePreloadedFlow(
                "run", "plan", token, 0).variant().id());
        assertThrows(IllegalArgumentException.class,
                () -> service.recordPreloadedFetch("run", "plan", "wrong-token"));

        var fetched = service.recordPreloadedFetch("run", "plan", token);
        assertEquals(armed.preloadedVariants(), fetched);
        assertTrue(service.state("run").preloadedFetched());
        var first = service.requirePreloadedFlow("run", "plan", token, 0);
        assertEquals(fetched.getFirst(), first.variant().id());
        assertTrue(first.hasNext());
        assertThrows(IllegalArgumentException.class,
                () -> service.requirePreloadedFlow("run", "another-plan", token, 0));
        assertThrows(IllegalArgumentException.class,
                () -> service.requirePreloadedFlow("run", "plan", token, fetched.size()));
    }

    private static Fixture fixture() {
        var plans = new MemoryPlans(plan());
        var runs = new MemoryRuns(run());
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        return new Fixture(new MetadataLabService(
                URI.create("https://suite.example"), plans, runs,
                new RunService(plans, runs, new RunEventBus(), clock), clock));
    }

    private static String query(URI uri, String name) {
        var value = queryOrNull(uri, name);
        if (value != null) return value;
        throw new IllegalArgumentException("Missing query parameter " + name);
    }

    private static String queryOrNull(URI uri, String name) {
        for (var part : uri.getRawQuery().split("&")) {
            var pieces = part.split("=", 2);
            if (name.equals(pieces[0])) return java.net.URLDecoder.decode(
                    pieces[1], java.nio.charset.StandardCharsets.UTF_8);
        }
        return null;
    }

    private static TestPlan plan() {
        return new TestPlan(
                "plan", "Target", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.HTTP_URL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
    }

    private static TestRun run() {
        return new TestRun("run", "plan", RunStatus.COMPLETED, Reachability.CONFIRMED, Map.of(), NOW, NOW);
    }

    private record Fixture(MetadataLabService service) {}

    private static final class MemoryPlans implements PlanRepository {
        private TestPlan plan;
        private MemoryPlans(TestPlan plan) { this.plan = plan; }
        @Override public List<TestPlan> list() { return List.of(plan); }
        @Override public Optional<TestPlan> find(String id) {
            return plan.id().equals(id) ? Optional.of(plan) : Optional.empty();
        }
        @Override public void save(TestPlan value) { plan = value; }
        @Override public boolean delete(String id) { return false; }
    }

    private static final class MemoryRuns implements RunRepository {
        private TestRun run;
        private MemoryRuns(TestRun run) { this.run = run; }
        @Override public List<TestRun> listForPlan(String planId) { return List.of(run); }
        @Override public Optional<TestRun> find(String id) {
            return run.id().equals(id) ? Optional.of(run) : Optional.empty();
        }
        @Override public void save(TestRun value) { run = value; }
    }
}
