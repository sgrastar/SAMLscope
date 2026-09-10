package com.samlscope.peer.sp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Base64;
import java.util.zip.Deflater;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.RunStatus;
import com.samlscope.runner.RunEventBus;
import com.samlscope.runner.RunService;
import com.samlscope.runner.ActiveProbeCorrelation;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.OpenSamlReader;
import com.samlscope.saml.normal.SamlProtocolService;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.raw.XmlDoctypeDetector;
import com.samlscope.store.FileTranscriptRecorder;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.MetadataCache;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

class SpPeerRoundTripTest {
    @TempDir java.nio.file.Path directory;

    @Test
    void completesOneNormalBrowserRoundTripWithoutProducingAVerdict() {
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var clock = Clock.fixed(now, ZoneOffset.UTC);
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plans = new SqlitePlanRepository(database, json);
        var runs = new SqliteRunRepository(database, json);
        var cache = new MetadataCache(directory);
        var plan = plan("plan_0123456789ABCDEFGHJKMNPQRS", FunctionalProfile.BROWSER_SSO_IDP, TargetKind.IDP,
                "https://idp.example/entity", now);
        plans.save(plan);
        var runService = new RunService(plans, runs, new RunEventBus(), clock);
        var run = runService.create(plan.id());
        var signer = new XmlSigner();
        var saml = new SamlProtocolService(URI.create("https://peer.example"),
                new FilePlanKeyStore(directory, clock), signer, new OpenSamlReader(), clock);
        var recorder = new FileTranscriptRecorder(database, json, directory);
        var routedAction = new java.util.concurrent.atomic.AtomicReference<String>();
        var peer = new SpPeerService(plans, runs, runService, cache, new TargetMetadataParser(),
                saml, recorder, clock, (routedRun, actionId, decodedSaml, evidence) -> {
                    assertEquals(run.id(), routedRun);
                    assertTrue(decodedSaml.length > 0);
                    assertEquals("transcript", evidence.kind());
                    routedAction.set(actionId);
                });

        assertThrows(MetadataCache.MetadataUnavailable.class, () -> peer.start(plan.id(), run.id()));
        assertEquals(RunStatus.CREATED, runs.find(run.id()).orElseThrow().status());
        assertTrue(recorder.list(run.id()).isEmpty());
        cache.put(plan.id(), idpMetadata());
        cache.putIfAbsent(run.id(), idpMetadata());
        var redirect = peer.start(plan.id(), run.id());
        var request = saml.decodeRedirect(redirect.getRawQuery(), "SAMLRequest");
        var responsePlan = plan("plan_1123456789ABCDEFGHJKMNPQRS", FunctionalProfile.BROWSER_SSO_SP, TargetKind.SP,
                "https://peer.example/p/" + plan.id(), now);
        var response = saml.buildResponse(responsePlan, request,
                URI.create("https://peer.example/p/" + plan.id() + "/sp/acs/0"), "smoke-user");
        var body = "SAMLResponse=" + URLEncoder.encode(response.base64(), StandardCharsets.UTF_8)
                + "&RelayState=" + URLEncoder.encode(run.id(), StandardCharsets.UTF_8);

        peer.consume(plan.id(), body.getBytes(StandardCharsets.UTF_8), Map.of(),
                "https://peer.example/p/" + plan.id() + "/sp/acs/0");

        var completed = runs.find(run.id()).orElseThrow();
        assertEquals(RunStatus.COMPLETED, completed.status());
        assertEquals("completed", completed.context().get("m0RoundTrip"));
        assertEquals(2, recorder.list(run.id()).size());
        assertEquals(true, recorder.list(run.id()).stream()
                .filter(entry -> entry.direction() == com.samlscope.core.transcript.Direction.INBOUND)
                .findFirst().orElseThrow().samlSummary().get("normalFlowAccepted"));
        assertTrue(completed.context().keySet().stream().noneMatch(key -> key.toLowerCase().contains("verdict")));

        var normalRequestId = request.parsed().document().getDocumentElement().getAttribute("ID");
        var probeBody = "SAMLResponse=" + URLEncoder.encode(response.base64(), StandardCharsets.UTF_8);
        peer.consume(plan.id(), probeBody.getBytes(StandardCharsets.UTF_8), Map.of(),
                "https://peer.example/p/" + plan.id() + "/sp/acs/0?mdv=no-key-info&run=" + run.id());
        assertEquals(3, recorder.list(run.id()).size());
        assertEquals(false, recorder.list(run.id()).stream()
                .filter(entry -> entry.url().contains("mdv=no-key-info"))
                .findFirst().orElseThrow().samlSummary().get("metadataProbeAccepted"));
        var probeContext = new java.util.LinkedHashMap<String, Object>(
                runs.find(run.id()).orElseThrow().context());
        probeContext.put("metadata_polling_requests", Map.of("no-key-info", normalRequestId));
        var beforeCorrelatedProbe = runs.find(run.id()).orElseThrow();
        runService.update(
                beforeCorrelatedProbe, beforeCorrelatedProbe.status(),
                beforeCorrelatedProbe.targetToSuiteReachability(), probeContext);
        peer.consume(plan.id(), probeBody.getBytes(StandardCharsets.UTF_8), Map.of(),
                "https://peer.example/p/" + plan.id() + "/sp/acs/0?mdv=no-key-info&run=" + run.id());
        assertTrue(recorder.list(run.id()).stream()
                .filter(entry -> entry.url().contains("mdv=no-key-info"))
                .anyMatch(entry -> Boolean.TRUE.equals(
                        entry.samlSummary().get("metadataProbeAccepted"))));
        assertEquals(RunStatus.COMPLETED, runs.find(run.id()).orElseThrow().status());
        assertEquals("completed", runs.find(run.id()).orElseThrow().context().get("m0RoundTrip"),
                "probe traffic must not rewrite the normal round-trip state");

        var actionId = "action_00000000000000000000000000000000";
        var activeRequestXml = new String(request.xml(), StandardCharsets.UTF_8)
                .replace(normalRequestId, "_" + actionId).getBytes(StandardCharsets.UTF_8);
        var activeRequest = saml.parse(new SamlProtocolService.RawDecodedMessage(activeRequestXml, run.id()));
        var activeResponse = saml.buildResponse(responsePlan, activeRequest,
                URI.create("https://peer.example/p/" + plan.id() + "/sp/acs/0"), "smoke-user");
        var activeBody = "SAMLResponse=" + URLEncoder.encode(activeResponse.base64(), StandardCharsets.UTF_8)
                + "&RelayState=" + URLEncoder.encode(
                        ActiveProbeCorrelation.encode(run.id(), actionId), StandardCharsets.UTF_8);
        var active = peer.consumeDetailed(
                plan.id(), activeBody.getBytes(StandardCharsets.UTF_8), Map.of(),
                "https://peer.example/p/" + plan.id() + "/sp/acs/0");
        assertTrue(active.activeProbe());
        assertEquals(run.id(), active.activeProbeRunId());
        assertEquals(actionId, routedAction.get());
        assertEquals(true, active.summary().get("activeProbeAccepted"));
        assertEquals(true, recorder.list(run.id()).stream()
                .filter(entry -> ("_" + actionId).equals(entry.correlationId()))
                .findFirst().orElseThrow().samlSummary().get("activeProbeAccepted"));
        assertEquals(RunStatus.COMPLETED, runs.find(run.id()).orElseThrow().status(),
                "active probes must not rewrite the baseline round-trip state");

        var malformedAction = "action_11111111111111111111111111111111";
        var malformedXml = "<samlp:Response".getBytes(StandardCharsets.UTF_8);
        var malformedBody = "SAMLResponse=" + URLEncoder.encode(
                Base64.getEncoder().encodeToString(malformedXml), StandardCharsets.UTF_8)
                + "&RelayState=" + URLEncoder.encode(
                        ActiveProbeCorrelation.encode(run.id(), malformedAction), StandardCharsets.UTF_8);
        var malformed = peer.consumeDetailed(
                plan.id(), malformedBody.getBytes(StandardCharsets.UTF_8), Map.of(),
                "https://peer.example/p/" + plan.id() + "/sp/acs/0");

        assertTrue(malformed.activeProbe());
        assertEquals(malformedAction, routedAction.get());
        var malformedEntry = recorder.list(run.id()).stream()
                .filter(entry -> malformedAction.equals(entry.correlationId()))
                .findFirst().orElseThrow();
        assertEquals("error", malformedEntry.samlSummary().get("parseStatus"));
        assertEquals("malformed-saml-response", malformedEntry.samlSummary().get("errorCategory"));
    }

    @Test
    void recordsRedirectBoundResponsesFromTheRawQuery() {
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var clock = Clock.fixed(now, ZoneOffset.UTC);
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plans = new SqlitePlanRepository(database, json);
        var runs = new SqliteRunRepository(database, json);
        var cache = new MetadataCache(directory);
        var plan = plan("plan_0123456789ABCDEFGHJKMNPQRS", FunctionalProfile.BROWSER_SSO_IDP, TargetKind.IDP,
                "https://idp.example/entity", now);
        plans.save(plan);
        cache.put(plan.id(), idpMetadata());
        var runService = new RunService(plans, runs, new RunEventBus(), clock);
        var run = runService.create(plan.id());
        cache.putIfAbsent(run.id(), idpMetadata());
        var saml = new SamlProtocolService(URI.create("https://peer.example"),
                new FilePlanKeyStore(directory, clock), new XmlSigner(), new OpenSamlReader(), clock);
        var recorder = new FileTranscriptRecorder(database, json, directory);
        var peer = new SpPeerService(plans, runs, runService, cache, new TargetMetadataParser(),
                saml, recorder, clock);
        var redirect = peer.start(plan.id(), run.id());
        var request = saml.decodeRedirect(redirect.getRawQuery(), "SAMLRequest");
        var responsePlan = plan("plan_1123456789ABCDEFGHJKMNPQRS", FunctionalProfile.BROWSER_SSO_SP, TargetKind.SP,
                "https://peer.example/p/" + plan.id(), now);
        var response = saml.buildResponse(responsePlan, request,
                URI.create("https://peer.example/p/" + plan.id() + "/sp/acs/3"), "smoke-user");
        var rawQuery = "SAMLResponse=" + URLEncoder.encode(
                Base64.getEncoder().encodeToString(deflate(response.xml())), StandardCharsets.UTF_8)
                + "&RelayState=" + URLEncoder.encode(run.id(), StandardCharsets.UTF_8);

        peer.consumeRedirectDetailed(
                plan.id(), rawQuery, Map.of(),
                "https://peer.example/p/" + plan.id() + "/sp/acs/3?" + rawQuery);

        var inbound = recorder.list(run.id()).stream()
                .filter(value -> value.direction() == com.samlscope.core.transcript.Direction.INBOUND)
                .findFirst().orElseThrow();
        assertEquals("GET", inbound.method());
        assertEquals(rawQuery, inbound.rawQuery());
        assertEquals(true, inbound.samlSummary().get("normalFlowAccepted"));
    }

    @Test
    void recordsTargetResponseBeforeDtdRejection() {
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var clock = Clock.fixed(now, ZoneOffset.UTC);
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plans = new SqlitePlanRepository(database, json);
        var runs = new SqliteRunRepository(database, json);
        var plan = plan("plan_0123456789ABCDEFGHJKMNPQRS", FunctionalProfile.BROWSER_SSO_IDP, TargetKind.IDP,
                "https://idp.example/entity", now);
        plans.save(plan);
        var runService = new RunService(plans, runs, new RunEventBus(), clock);
        var run = runService.create(plan.id());
        var saml = new SamlProtocolService(URI.create("https://peer.example"),
                new FilePlanKeyStore(directory, clock), new XmlSigner(), new OpenSamlReader(), clock);
        var recorder = new FileTranscriptRecorder(database, json, directory);
        var peer = new SpPeerService(
                plans, runs, runService, new MetadataCache(directory), new TargetMetadataParser(),
                saml, recorder, clock);
        var xml = "<!DOCTYPE Response [<!ELEMENT Response EMPTY>]><Response/>"
                .getBytes(StandardCharsets.UTF_8);
        var body = "SAMLResponse=" + URLEncoder.encode(
                Base64.getEncoder().encodeToString(xml), StandardCharsets.UTF_8)
                + "&RelayState=" + URLEncoder.encode(run.id(), StandardCharsets.UTF_8);

        assertThrows(SamlException.class, () -> peer.consume(
                plan.id(), body.getBytes(StandardCharsets.UTF_8), Map.of(), "https://peer.example/acs"));

        var entry = recorder.list(run.id()).getFirst();
        assertTrue(XmlDoctypeDetector.containsDoctype(recorder.readDecodedSaml(entry)));
        assertEquals("not-yet-parsed", entry.samlSummary().get("parseStatus"));
    }

    private byte[] deflate(byte[] xml) {
        var deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        try {
            deflater.setInput(xml);
            deflater.finish();
            var buffer = new byte[xml.length + 128];
            return java.util.Arrays.copyOf(buffer, deflater.deflate(buffer));
        } finally {
            deflater.end();
        }
    }

    private TestPlan plan(String id, FunctionalProfile profile, TargetKind kind, String entityId, Instant now) {
        return new TestPlan(id, "Round trip", profile,
                new TestPlan.Target(kind, entityId,
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://target.example/metadata")),
                MetadataDeliveryKind.HTTP_URL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), now, now);
    }

    private byte[] idpMetadata() {
        return """
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                    entityID="https://idp.example/entity">
                  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:SingleSignOnService
                        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                        Location="https://idp.example/sso"/>
                  </md:IDPSSODescriptor>
                </md:EntityDescriptor>
                """.getBytes(StandardCharsets.UTF_8);
    }
}
