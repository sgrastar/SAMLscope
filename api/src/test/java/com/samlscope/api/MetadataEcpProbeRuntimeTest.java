package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.OutboxStatus;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.*;
import com.samlscope.runner.OutboundPolicy;
import com.samlscope.runner.outbox.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.ecp.EcpProbeEnvelopeFactory;
import com.samlscope.saml.ecp.MetadataApplicationEcpProbeFactory;
import com.samlscope.saml.metadata.*;
import com.samlscope.saml.normal.*;
import com.samlscope.store.*;
import java.net.URI;
import java.time.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MetadataEcpProbeRuntimeTest {
    private static final String PLAN = "plan_0123456789ABCDEFGHJKMNPQRS";
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-10-03T10:00:00Z");
    @TempDir java.nio.file.Path directory;
    private SqlitePlanRepository plans;
    private SqliteRunRepository runs;
    private SqliteCaseExecutionRepository cases;
    private MetadataCache cache;
    private InMemoryEphemeralCredentialProvider credentials;
    private final List<com.samlscope.core.caseexec.OutboundAction> sends = new ArrayList<>();
    private EcpProbeRuntime runtime;
    private int fixtureNumber;

    @BeforeEach void setup() {
        setupDatabase(directory);
        configure(FunctionalProfile.METADATA_IDP, TargetKind.IDP, RunStatus.COMPLETED,
                "multiple-signing-keys-first", "AUTOMATIC_POLLING");
        target(true);
    }
    private void setupDatabase(java.nio.file.Path location) {
        var json = new JsonCodec(); var db = new SqliteDatabase(location);
        plans = new SqlitePlanRepository(db, json); runs = new SqliteRunRepository(db, json);
        cases = new SqliteCaseExecutionRepository(db, json); cache = new MetadataCache(location);
        credentials = new InMemoryEphemeralCredentialProvider();
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        var saml = new SamlProtocolService(URI.create("https://peer.example"), new FilePlanKeyStore(location, clock),
                new XmlSigner(), new OpenSamlReader(), clock);
        OutboundSender sender = (run, action, secret) -> {
            assertEquals(RUN, run); assertArrayEquals("tester:memory-only".getBytes(StandardCharsets.UTF_8), secret);
            sends.add(action); return new OutboundSender.SendResult(false, Map.of("http_status", 200), "tx-" + sends.size());
        };
        var dispatcher = new OutboundDispatcher(cases, sender, credentials, new OutboundPolicy(true), clock);
        runtime = new EcpProbeRuntime(URI.create("https://peer.example"), plans, runs, cache,
                new TargetMetadataParser(), saml, new EcpProbeEnvelopeFactory(),
                new EcpProbeService(cases, credentials, dispatcher, clock));
    }
    private void configure(FunctionalProfile profile, TargetKind role, RunStatus status, String variant, String mode) {
        var plan = new TestPlan(PLAN, "Metadata ECP", profile,
                new TestPlan.Target(role, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.HTTP_URL, Map.of(), TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), NOW, NOW);
        if (plans.find(PLAN).map(existing -> !existing.sameExecutionConfiguration(plan)).orElse(false)) {
            // A different profile/role is a separate fixture database; never bypass Plan immutability.
            setupDatabase(directory.resolve("scenario-" + ++fixtureNumber)); target(true);
        }
        plans.save(plan); runs.save(new TestRun(RUN, PLAN, status, Reachability.CONFIRMED,
                Map.of("metadata_lab", Map.of("selected_variant", variant, "selected_at", NOW.toString(),
                        "ingestion_mode", mode, "campaign_variants", List.of(variant),
                        "campaign_index", 1)), NOW, NOW));
    }
    private void target(boolean soap) {
        String xml = "<md:EntityDescriptor xmlns:md='" + MetadataService.MD + "' entityID='https://idp.example/entity'>"
                + "<md:IDPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>"
                + "<md:SingleSignOnService Binding='" + MetadataService.REDIRECT + "' Location='https://idp.example/sso'/>"
                + (soap ? "<md:SingleSignOnService Binding='" + MetadataService.SOAP + "' Location='https://idp.example/ecp'/>" : "")
                + "</md:IDPSSODescriptor></md:EntityDescriptor>";
        cache.put(RUN, xml.getBytes(StandardCharsets.UTF_8));
    }
    private List<EcpProbeService.Result> execute() { return runtime.execute(RUN, "tester", "memory-only"); }

    @Test void twoEpochsUseSixDeterministicIntentsWithoutPersistingCredentialsOrReplacingTheRun() {
        var rollover = execute(); assertEquals(3, rollover.size());
        var repeated = execute(); assertEquals(rollover, repeated); assertEquals(3, sends.size());
        configure(FunctionalProfile.METADATA_IDP, TargetKind.IDP, RunStatus.COMPLETED, "no-valid-until", "AUTOMATIC_POLLING");
        var b = execute(); assertEquals(3, b.size()); assertEquals(6, sends.size());
        assertEquals(Set.copyOf(MetadataApplicationEcpProbeFactory.FIXTURES), cases.list(RUN).stream()
                .map(com.samlscope.core.caseexec.CaseExecution::caseId).collect(java.util.stream.Collectors.toSet()));
        assertEquals(RunStatus.COMPLETED, runs.find(RUN).orElseThrow().status());
        for (var result : java.util.stream.Stream.concat(rollover.stream(), b.stream()).toList()) {
            assertEquals(OutboxStatus.SENT, result.outboxStatus());
            assertTrue(credentials.credentialFor(RUN, result.actionId()).isEmpty());
            String payload = new String(cases.findOutbox(result.actionId()).orElseThrow().action().payload(), StandardCharsets.UTF_8);
            assertFalse(payload.contains("memory-only")); assertFalse(payload.contains("Authorization"));
            assertFalse(payload.contains("Cookie"));
            var request = (org.w3c.dom.Element) SecureXml.parse(payload.getBytes(StandardCharsets.UTF_8))
                    .getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol", "AuthnRequest").item(0);
            assertEquals("_" + result.actionId(), request.getAttribute("ID"));
            assertEquals(MetadataService.PAOS, request.getAttribute("ProtocolBinding"));
            assertTrue(request.getAttribute("AssertionConsumerServiceURL").endsWith("run=" + RUN));
        }
        assertFalse(EcpProbeService.allRequiredFixturesSent(cases, RUN));
    }
    @Test void theActualMetadataLabCompletedEpochRemainsPollingAcrossBothEcpGroups() {
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        var lab = new com.samlscope.runner.MetadataLabService(URI.create("https://peer.example"), plans, runs,
                new com.samlscope.runner.RunService(plans, runs, new com.samlscope.runner.RunEventBus(), clock), clock);
        for (var variant : List.of("multiple-signing-keys-first", "no-valid-until")) {
            var started = lab.startAutomaticPolling(RUN, List.of(variant), 0);
            assertFalse(started.campaignComplete());
            assertThrows(IllegalArgumentException.class, this::execute);
            var context = (Map<?,?>)runs.find(RUN).orElseThrow().context().get("metadata_lab");
            String token = (String)context.get("campaign_token");
            lab.requireAutomaticStartFlow(RUN, PLAN, token, 0);
            lab.recordLiveFetch(RUN, PLAN, variant, token);
            lab.requireAutomaticCompletedFlow(RUN, PLAN, token, 0);
            assertTrue(lab.state(RUN).campaignComplete());
            assertEquals(com.samlscope.runner.MetadataLabService.IngestionMode.AUTOMATIC_POLLING,
                    lab.state(RUN).ingestionMode());
            assertEquals(3, execute().size());
            assertEquals(variant, lab.state(RUN).selectedVariant());
        }
        assertEquals(6, sends.size());
    }
    @Test void theExistingEcpProfileStillExecutesExactlyItsSevenRequiredFixtures() {
        configure(FunctionalProfile.ECP_IDP, TargetKind.IDP, RunStatus.COMPLETED, "control", "MANUAL_REFRESH");
        assertEquals(7, execute().size()); assertEquals(7, sends.size());
        assertTrue(EcpProbeService.allRequiredFixturesSent(cases, RUN));
        assertEquals(7, EcpProbeService.requiredFixtureIds().size());
    }
    @Test void absentSoapEndpointProducesNoNewIntentOrSend() {
        target(false); assertThrows(IllegalArgumentException.class, this::execute);
        assertTrue(sends.isEmpty()); assertTrue(cases.list(RUN).isEmpty());
    }
    @Test void anUnsupportedEpochOrAutomaticTransitionProducesNoSend() {
        for (var input : List.of(new String[]{"control", "MANUAL_REFRESH"},
                new String[]{"multiple-signing-keys-first", "MANUAL_REFRESH"})) {
            configure(FunctionalProfile.METADATA_IDP, TargetKind.IDP, RunStatus.COMPLETED, input[0], input[1]);
            assertThrows(IllegalArgumentException.class, this::execute);
        }
        assertTrue(sends.isEmpty()); assertTrue(cases.list(RUN).isEmpty());
    }
    @Test void inProgressMultiMemberAndForeignPollingEpochsProduceNoIntentOrSend() {
        var existing = runs.find(RUN).orElseThrow();
        for (var changed : List.of(Map.<String,Object>of("campaign_index", 0),
                Map.<String,Object>of("campaign_index", 1.5),
                Map.<String,Object>of("campaign_index", "1"),
                Map.<String,Object>of("campaign_variants", List.of("control", "multiple-signing-keys-first")),
                Map.<String,Object>of("campaign_variants", List.of("no-valid-until")),
                Map.<String,Object>of("campaign_variants", List.of()))) {
            var lab = new LinkedHashMap<String,Object>();
            lab.put("selected_variant", "multiple-signing-keys-first"); lab.put("ingestion_mode", "AUTOMATIC_POLLING");
            lab.put("selected_at", NOW.toString()); lab.put("campaign_variants", List.of("multiple-signing-keys-first"));
            lab.put("campaign_index", 1); lab.putAll(changed);
            runs.save(new TestRun(RUN, PLAN, existing.status(), existing.targetToSuiteReachability(),
                    Map.of("metadata_lab", Map.copyOf(lab)), NOW, NOW));
            assertThrows(IllegalArgumentException.class, this::execute);
        }
        assertTrue(sends.isEmpty()); assertTrue(cases.list(RUN).isEmpty());
    }
    @Test void foreignProfilesOrRolesAndIncompleteBaselineProduceNoSend() {
        for (var input : List.of(new Object[]{FunctionalProfile.BROWSER_SSO_IDP, TargetKind.IDP, RunStatus.COMPLETED},
                new Object[]{FunctionalProfile.METADATA_IDP, TargetKind.TOKEN_TRANSLATION_PROXY, RunStatus.COMPLETED},
                new Object[]{FunctionalProfile.METADATA_IDP, TargetKind.IDP, RunStatus.CREATED})) {
            configure((FunctionalProfile)input[0], (TargetKind)input[1], (RunStatus)input[2],
                    "multiple-signing-keys-first", "AUTOMATIC_POLLING");
            assertThrows(IllegalArgumentException.class, this::execute);
        }
        assertTrue(sends.isEmpty()); assertTrue(cases.list(RUN).isEmpty());
    }
    @Test void missingOrForeignSelectionClockProducesNoSend() {
        var existing = runs.find(RUN).orElseThrow();
        for (var context : List.of(Map.<String, Object>of(), Map.<String, Object>of("metadata_lab", Map.of(
                "selected_variant", "multiple-signing-keys-first", "ingestion_mode", "AUTOMATIC_POLLING",
                "selected_at", NOW.minusSeconds(1).toString(), "campaign_variants", List.of("multiple-signing-keys-first"), "campaign_index", 1)))) {
            runs.save(new TestRun(RUN, PLAN, existing.status(), existing.targetToSuiteReachability(), context, NOW, NOW));
            assertThrows(IllegalArgumentException.class, this::execute);
        }
        assertTrue(sends.isEmpty()); assertTrue(cases.list(RUN).isEmpty());
    }
    @Test void aConflictingLaterMemberBlocksTheWholeGroupBeforeAnyNewIntentOrSend() {
        var second = MetadataApplicationEcpProbeFactory.R_SECOND;
        String id = com.samlscope.core.caseexec.ActionIds.derive(RUN, second,
                MetadataApplicationEcpProbeFactory.PHASE, 0);
        cases.apply(-1, new com.samlscope.core.caseexec.CaseExecution(RUN, second, 0,
                com.samlscope.core.caseexec.CaseExecutionStatus.RUNNING,
                new com.samlscope.core.caseexec.CaseState("send-baseline", Map.of("fixture", second)),
                null, null, NOW), List.of(new com.samlscope.core.caseexec.OutboundAction(id,
                        com.samlscope.core.caseexec.OutboundKind.ECP_SOAP,
                        "<foreign/>".getBytes(StandardCharsets.UTF_8), URI.create("https://idp.example/ecp"), true)));
        assertThrows(IllegalArgumentException.class, this::execute);
        assertTrue(sends.isEmpty()); assertEquals(1, cases.list(RUN).size());
        assertTrue(cases.findOutbox(com.samlscope.core.caseexec.ActionIds.derive(RUN,
                MetadataApplicationEcpProbeFactory.R_FIRST, MetadataApplicationEcpProbeFactory.PHASE, 0)).isEmpty());
    }
}
