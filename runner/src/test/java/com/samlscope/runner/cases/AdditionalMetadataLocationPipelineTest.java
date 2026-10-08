package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.sun.net.httpserver.HttpServer;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.casedef.CaseDefinitionCatalog.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import com.samlscope.runner.outbox.*;
import com.samlscope.store.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class AdditionalMetadataLocationPipelineTest {
    static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS", ENTITY = "https://target.example/entity";
    static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    @TempDir Path folder;
    HttpServer server;
    String base;
    AtomicInteger gets;
    @BeforeEach void server() throws Exception {
        gets = new AtomicInteger(); server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        for (String name : List.of("one", "two")) server.createContext("/" + name, e -> {
            gets.incrementAndGet(); var body = ("<x:document xmlns:x='urn:test:" + name + "'/>").getBytes(StandardCharsets.UTF_8);
            assertNull(e.getRequestHeaders().getFirst("Authorization")); assertNull(e.getRequestHeaders().getFirst("Cookie"));
            assertEquals("GET", e.getRequestMethod());
            e.getResponseHeaders().set("Content-Type", "application/xml"); e.getResponseHeaders().set("Set-Cookie", "sentinel-never-persist");
            e.sendResponseHeaders(200, body.length); e.getResponseBody().write(body); e.close();
        });
        server.createContext("/redirect", e -> { gets.incrementAndGet(); e.getResponseHeaders().set("Location", base + "/one"); e.sendResponseHeaders(302, -1); e.close(); });
        server.createContext("/html", e -> { gets.incrementAndGet(); var body = "<html><input value='secret-html-sentinel'/></html>".getBytes(StandardCharsets.UTF_8);
            e.getResponseHeaders().set("Content-Type", "text/html"); e.sendResponseHeaders(200, body.length); e.getResponseBody().write(body); e.close(); });
        server.start();
    }
    @AfterEach void stop() { server.stop(0); }

    @Test void productionControlsAndActualGetsFinishBothRolesThroughOrdinaryReadyEvaluation() {
        for (var role : TargetRole.values()) {
            var h = harness(role, location("one", "urn:test:one") + location("two", "urn:test:two"));
            h.start(); assertEquals(2, h.executions.listOutbox(RUN).size()); assertFalse(h.testCase.evidenceStatus(h.context).ready());
            assertEquals(2, h.collector.collect(RUN).sent().size());
            assertTrue(h.testCase.evidenceStatus(h.context).ready());
            var before = h.executions.find(RUN, h.testCase.id()).orElseThrow(); assertEquals(0, before.revision());
            var result = h.automation.evaluateReady(RUN); assertEquals(1, result.completed().size());
            var finished = h.executions.find(RUN, h.testCase.id()).orElseThrow();
            assertEquals(CaseExecutionStatus.FINISHED, finished.status()); assertEquals(1, finished.revision());
            assertEquals(Outcome.SATISFIED, finished.outcome().outcome());
            assertEquals(Boolean.FALSE, finished.outcome().details().get("suite_calibration_is_target_evidence"));
            assertEquals(2, finished.outcome().evidence().stream().filter(e -> "transcript".equals(e.kind())).count());
            assertEquals(4, finished.outcome().evidence().stream().filter(e -> "suite-calibration".equals(e.kind())).count());
            assertTrue(h.testCase.resolvedFromExternalEvidence(finished));
            h.collector.collect(RUN); assertTrue(h.automation.evaluateReady(RUN).completed().isEmpty());
        }
        assertEquals(4, gets.get());
    }

    @Test void oneActualPublisherMismatchViolatesWithoutTreatingTheCalibrationAsTargetOutput() {
        var h = harness(TargetRole.IDP, location("one", "urn:test:wrong") + location("two", "urn:test:two"));
        h.start(); h.collector.collect(RUN); h.automation.evaluateReady(RUN);
        var outcome = h.executions.find(RUN, h.testCase.id()).orElseThrow().outcome();
        assertEquals(Outcome.VIOLATED, outcome.outcome()); assertEquals(List.of(0), outcome.details().get("mismatched_location_indices"));
    }

    @Test void duplicateLocationsReuseOneOriginalAndStillCheckBothDeclarations() {
        var h = harness(TargetRole.IDP, location("one", "urn:test:one") + location("one", "urn:test:wrong"));
        h.start(); assertEquals(1, h.executions.listOutbox(RUN).size()); h.collector.collect(RUN); h.automation.evaluateReady(RUN);
        var outcome = h.executions.find(RUN, h.testCase.id()).orElseThrow().outcome();
        assertEquals(Outcome.VIOLATED, outcome.outcome()); assertEquals(List.of(1), outcome.details().get("mismatched_location_indices"));
        assertEquals(1, gets.get()); assertEquals(1, outcome.evidence().stream().filter(e -> "transcript".equals(e.kind())).count());
    }

    @Test void productionRecorderListenerCompletesTheFirstOutcomeWithoutASecondOperatorAction() throws Exception {
        var h = harness(TargetRole.IDP, location("one", "urn:test:one") + location("one", "urn:test:one"));
        h.start(); var finished = new java.util.concurrent.CountDownLatch(1);
        h.productionRecorder.onRecorded(ignored -> {
            h.collector.collect(RUN); h.automation.evaluateReady(RUN);
            if (h.executions.find(RUN, h.testCase.id()).orElseThrow().status() == CaseExecutionStatus.FINISHED) finished.countDown();
        });
        try {
            h.collector.collect(RUN);
            assertTrue(finished.await(5, java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(Outcome.SATISFIED, h.executions.find(RUN, h.testCase.id()).orElseThrow().outcome().outcome());
            assertEquals(1, h.executions.find(RUN, h.testCase.id()).orElseThrow().revision());
            assertEquals(1, gets.get());
            assertEquals(2, h.recorder.list(RUN).stream().filter(e -> AdditionalMetadataLocationControlProducer.TYPE.equals(e.samlSummary().get("type"))).count());
        } finally { h.productionRecorder.close(); }
    }

    @Test void retrievalAloneCannotPassAndMissingControlOrMutatedControlStaysUnverified() throws Exception {
        var h = harness(TargetRole.IDP, location("one", "urn:test:one")); h.start();
        for (var entry : h.executions.listOutbox(RUN)) h.dispatcher.dispatch(entry.action().actionId());
        assertFalse(h.testCase.evidenceStatus(h.context).ready()); assertTrue(h.automation.evaluateReady(RUN).completed().isEmpty());
        h.collector.collect(RUN); assertTrue(h.testCase.evidenceStatus(h.context).ready());
        var control = h.recorder.list(RUN).stream().filter(e -> AdditionalMetadataLocationControlProducer.TYPE.equals(e.samlSummary().get("type"))).findFirst().orElseThrow();
        var path = h.path.resolve(control.bodyRef()); var altered = Files.readAllBytes(path); altered[0] = 'x'; Files.write(path, altered);
        assertFalse(h.testCase.evidenceStatus(h.context).ready()); assertTrue(h.automation.evaluateReady(RUN).completed().isEmpty());
    }

    @Test void absentSetupRedirectAndNonXmlRemainUnverifiedWithoutExtraLoginOrFetch() throws Exception {
        for (String input : List.of("", location("redirect", "urn:test:one"), location("html", "urn:test:one"))) {
            var h = harness(TargetRole.IDP, input); h.start(); h.collector.collect(RUN);
            assertFalse(h.testCase.evidenceStatus(h.context).ready()); assertTrue(h.automation.evaluateReady(RUN).completed().isEmpty());
            assertEquals(CaseExecutionStatus.WAITING_CONFIG, h.executions.find(RUN, h.testCase.id()).orElseThrow().status());
            for (var row : h.recorder.list(RUN)) if (row.bodyRef() != null)
                assertFalse(Files.readString(h.path.resolve(row.bodyRef())).contains("secret-html-sentinel"));
        }
        assertEquals(2, gets.get(), "Redirect was not followed and absent AML was not invented");
    }

    @Test void configurationFailureAndManualAttestationKeepTheirApprovedSemantics() {
        var h = harness(TargetRole.IDP, ""); h.start();
        var current = h.executions.find(RUN, h.testCase.id()).orElseThrow();
        var manual = assertInstanceOf(CaseStep.AwaitAttestation.class,
                h.testCase.resume(h.context, current.state(), new CaseEvent.ConfigConfirmed()));
        var declared = assertInstanceOf(CaseStep.Finish.class,
                h.testCase.resume(h.context, manual.next(), new CaseEvent.Attested("evidence_satisfies", "operator evidence")));
        assertEquals(Outcome.SATISFIED, declared.outcome().outcome()); assertEquals(Boolean.TRUE, declared.outcome().details().get("attested"));
        for (var issue : CaseEvent.ConfigurationIssue.values()) {
            var failure = assertInstanceOf(CaseStep.Finish.class,
                    h.testCase.resume(h.context, current.state(), new CaseEvent.ConfigUnavailable(issue, "unavailable")));
            assertEquals(Outcome.NOT_VERIFIED, failure.outcome().outcome());
        }
    }

    @Test void hostedPolicyBlocksPrivateFetchAndWrongProfileCannotProduceAnAction() {
        var h = harness(TargetRole.IDP, location("one", "urn:test:one")); h.start();
        var blocked = new MetadataFetchAutomationService(h.executions, h.registry,
                new OutboundDispatcher(h.executions, new HttpOutboundSender(java.net.http.HttpClient.newHttpClient(), h.recorder, h.context.clock()),
                        (run, action) -> Optional.empty(), new OutboundPolicy(false), h.context.clock()), run -> h.context);
        assertEquals(1, blocked.collect(RUN).policyBlocked().size()); assertEquals(0, gets.get());
        var bad = new AdditionalMetadataLocationEvidence(definition(TargetRole.IDP), h.recorder,
                ignored -> snapshot(location("one", "urn:test:one")), h.executions,
                ignored -> new AdditionalMetadataLocationEvidence.Scope(RUN, "BROWSER_SSO_IDP", ENTITY));
        assertThrows(IllegalArgumentException.class, () -> bad.actions(h.context));
    }

    @Test void credentialQueriesCreateNoOutboxNoRequestAndNoAutomaticVerdict() {
        for (String key : List.of("access_token", "REFRESH-TOKEN", "client%5Fsecret", "API%2DKEY")) {
            var h = harness(TargetRole.IDP, location("one?" + key + "=opaque", "urn:test:one"));
            h.start(); h.collector.collect(RUN);
            assertTrue(h.executions.listOutbox(RUN).isEmpty()); assertTrue(h.recorder.list(RUN).isEmpty());
            assertFalse(h.testCase.evidenceStatus(h.context).ready());
            assertTrue(h.automation.evaluateReady(RUN).completed().isEmpty());
            assertEquals(CaseExecutionStatus.WAITING_CONFIG, h.executions.find(RUN, h.testCase.id()).orElseThrow().status());
        }
        assertEquals(0, gets.get());
        var ordinary = harness(TargetRole.IDP, location("one?realm=example", "urn:test:one"));
        ordinary.start(); ordinary.collector.collect(RUN); ordinary.automation.evaluateReady(RUN);
        assertEquals(Outcome.SATISFIED, ordinary.executions.find(RUN, ordinary.testCase.id()).orElseThrow().outcome().outcome());
        assertEquals(1, gets.get());
    }

    @Test void originalBodyTamperAndUnknownDeliveryCannotBeReplacedBySummarySuccess() throws Exception {
        var h = harness(TargetRole.IDP, location("one", "urn:test:one")); h.start(); h.collector.collect(RUN);
        var response = h.recorder.list(RUN).stream().filter(e -> MetadataFetchOutboundSender.RESPONSE.equals(e.samlSummary().get("type"))).findFirst().orElseThrow();
        var path = h.path.resolve(response.bodyRef()); var bytes = Files.readAllBytes(path); bytes[0] = 'x'; Files.write(path, bytes);
        assertFalse(h.testCase.evidenceStatus(h.context).ready());
        var action = h.executions.listOutbox(RUN).getFirst();
        var unknown = harness(TargetRole.IDP, location("one", "urn:test:one")); unknown.start();
        var pending = unknown.executions.listOutbox(RUN).getFirst();
        assertTrue(unknown.executions.transitionOutbox(pending.action().actionId(), OutboxStatus.PENDING, OutboxStatus.SENDING, Map.of(), null, NOW));
        assertTrue(unknown.executions.transitionOutbox(pending.action().actionId(), OutboxStatus.SENDING, OutboxStatus.UNKNOWN_DELIVERY,
                Map.of("passed", true), response.id(), NOW));
        assertFalse(unknown.testCase.evidenceStatus(unknown.context).ready());
    }

    Harness harness(TargetRole role, String content) {
        try { return new Harness(role, content, Files.createTempDirectory(folder, role.name())); }
        catch (java.io.IOException failure) { throw new RuntimeException(failure); }
    }
    String location(String path, String namespace) { return "<md:AdditionalMetadataLocation namespace='" + namespace + "'>" + base + "/" + path + "</md:AdditionalMetadataLocation>"; }
    static byte[] snapshot(String locations) { return ("<md:EntityDescriptor xmlns:md='" + AdditionalMetadataLocationEvidence.MD + "' entityID='" + ENTITY + "'>" + locations + "</md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8); }
    static CaseDefinition definition(TargetRole role) {
        String id = "IIP-MD05-a8-" + role.name().toLowerCase(Locale.ROOT) + "-01";
        var variants = List.of(AdditionalMetadataLocationEvidence.DIFFERENT, AdditionalMetadataLocationEvidence.MATCH);
        return new CaseDefinition(id, "IIP-MD05.a8", role, ExecutionMode.CONFIG, Milestone.M2, variants,
                Map.of(variants.get(0), VariantScope.OWNER_CONDITION, variants.get(1), VariantScope.OWNER_CONDITION),
                variants.stream().map(v -> new VariantInstruction(v, VariantScope.OWNER_CONDITION, VariantTreatment.VERDICT, v)).toList(),
                List.of(new VariantGroup("default-all-of", GroupKind.ALL_OF, variants, "Approved group")),
                List.of(new Control(id.toLowerCase(Locale.ROOT) + "-positive", ControlKind.POSITIVE,
                            role == TargetRole.IDP ? "idp-core-no-ecp" : "sp-core-minimal", "Approved positive", "control_failed"),
                        new Control(id.toLowerCase(Locale.ROOT) + "-negative", ControlKind.NEGATIVE,
                            "mut-iip-md05-a8-" + role.name().toLowerCase(Locale.ROOT), "Approved negative", "control_failed")),
                "Approved counterexample", List.of("Referenced location must be retrieved"), new Requirements(List.of(), "none"), false,
                ConfigurationFailureSemantics.TEST_PRECONDITION, role == TargetRole.IDP
                    ? "sha256:64b57fc4a00042b2826b202abb00c6a62e4bcf36ea9b090d2d695fe30bce3973"
                    : "sha256:08cb7fcc85208ad73bcb574dac2a30f0095488ceb60f7854fa901110ccfe2f05");
    }

    class Harness {
        final Path path; final FileTranscriptRecorder recorder; final TranscriptAutomationRecorder productionRecorder;
        final SqliteCaseExecutionRepository executions;
        final CaseContext context; final CaseExecutionService transitions; final TestCaseRegistry registry;
        final AdditionalMetadataLocationConfigurationTestCase testCase; final OutboundDispatcher dispatcher;
        final MetadataFetchAutomationService collector; final ProtocolEvidenceAutomationService automation;
        Harness(TargetRole role, String locations, Path path) {
            this.path = path; var db = new SqliteDatabase(path); var json = new JsonCodec();
            var plan = new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Example", role == TargetRole.IDP ? FunctionalProfile.METADATA_IDP : FunctionalProfile.METADATA_SP,
                    new TestPlan.Target(role == TargetRole.IDP ? TargetKind.IDP : TargetKind.SP, ENTITY,
                            new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://target.example/metadata")), MetadataDeliveryKind.MANUAL,
                    Map.of(), TestPlan.Parameters.defaults(), new TestPlan.Interaction(false, true), NOW, NOW);
            new SqlitePlanRepository(db, json).save(plan); new SqliteRunRepository(db, json).save(new TestRun(RUN, plan.id(), RunStatus.COMPLETED, Reachability.CONFIRMED, Map.of(), NOW, NOW));
            recorder = new FileTranscriptRecorder(db, json, path); executions = new SqliteCaseExecutionRepository(db, json);
            productionRecorder = new TranscriptAutomationRecorder(recorder, recorder);
            context = new DefaultCaseContext(RUN, role, Clock.fixed(NOW, ZoneOffset.UTC), plan.parameters(), plan.interaction(), Reachability.CONFIRMED, productionRecorder, true);
            var definition = definition(role); var catalog = new CaseDefinitionCatalog(List.of(definition));
            registry = ApprovedConfigCaseRegistry.withAdditionalMetadataLocations(ApprovedConfigCaseRegistry.create(catalog, Milestone.M2),
                    catalog, productionRecorder, ignored -> snapshot(locations), executions,
                    ignored -> new AdditionalMetadataLocationEvidence.Scope(RUN, plan.profile().name(), ENTITY));
            testCase = (AdditionalMetadataLocationConfigurationTestCase) registry.require(definition.id());
            transitions = new CaseExecutionService(executions);
            dispatcher = new OutboundDispatcher(executions, new HttpOutboundSender(java.net.http.HttpClient.newHttpClient(), productionRecorder, context.clock()),
                    (run, action) -> Optional.empty(), new OutboundPolicy(true), context.clock());
            collector = new MetadataFetchAutomationService(executions, registry, dispatcher, ignored -> context);
            automation = new ProtocolEvidenceAutomationService(executions, registry, transitions, ignored -> context);
        }
        void start() { transitions.start(RUN, testCase, context); }
    }
}
