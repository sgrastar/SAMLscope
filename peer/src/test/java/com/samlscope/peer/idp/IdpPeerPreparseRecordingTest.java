package com.samlscope.peer.idp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.runner.RunEventBus;
import com.samlscope.runner.RunService;
import com.samlscope.core.run.RunStatus;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.OpenSamlReader;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SamlProtocolService;
import com.samlscope.saml.raw.XmlDoctypeDetector;
import com.samlscope.store.FileTranscriptRecorder;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.MetadataCache;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

class IdpPeerPreparseRecordingTest {
    @TempDir java.nio.file.Path directory;

    @Test
    void recordsTargetRequestBeforeDtdRejection() {
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var clock = Clock.fixed(now, ZoneOffset.UTC);
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plans = new SqlitePlanRepository(database, json);
        var runs = new SqliteRunRepository(database, json);
        var plan = new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "SP target", FunctionalProfile.BROWSER_SSO_SP,
                new TestPlan.Target(TargetKind.SP, "https://sp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://sp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), now, now);
        plans.save(plan);
        var runService = new RunService(plans, runs, new RunEventBus(), clock);
        var run = runService.create(plan.id());
        var saml = new SamlProtocolService(URI.create("https://peer.example"),
                new FilePlanKeyStore(directory, clock), new XmlSigner(), new OpenSamlReader(), clock);
        var recorder = new FileTranscriptRecorder(database, json, directory);
        var peer = new IdpPeerService(
                plans, runs, runService, new MetadataCache(directory), new TargetMetadataParser(),
                saml, recorder, clock);
        var xml = "<!DOCTYPE AuthnRequest [<!ELEMENT AuthnRequest EMPTY>]><AuthnRequest/>"
                .getBytes(StandardCharsets.UTF_8);
        var body = "SAMLRequest=" + URLEncoder.encode(
                Base64.getEncoder().encodeToString(xml), StandardCharsets.UTF_8);

        assertThrows(SamlException.class, () -> peer.consume(
                plan.id(), "POST", null, body.getBytes(StandardCharsets.UTF_8),
                Map.of(), "https://peer.example/idp/sso"));

        var entry = recorder.list(run.id()).getFirst();
        assertTrue(XmlDoctypeDetector.containsDoctype(recorder.readDecodedSaml(entry)));
        assertEquals("not-yet-parsed", entry.samlSummary().get("parseStatus"));
    }

    @Test
    void acceptsCorrelatedMetadataProbeForACompletedRunWithoutRewritingItsState() {
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var clock = Clock.fixed(now, ZoneOffset.UTC);
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plans = new SqlitePlanRepository(database, json);
        var runs = new SqliteRunRepository(database, json);
        var plan = new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "SP target", FunctionalProfile.BROWSER_SSO_SP,
                new TestPlan.Target(TargetKind.SP, "https://sp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://sp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), now, now);
        plans.save(plan);
        var runService = new RunService(plans, runs, new RunEventBus(), clock);
        var run = runService.create(plan.id());
        runService.update(run, RunStatus.COMPLETED, run.targetToSuiteReachability(),
                Map.of("m0RoundTrip", "completed"));
        var cache = new MetadataCache(directory);
        cache.put(plan.id(), ("""
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                    entityID="https://sp.example/entity">
                  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:AssertionConsumerService
                        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        Location="https://sp.example/acs" index="0" isDefault="true"/>
                  </md:SPSSODescriptor>
                </md:EntityDescriptor>
                """).getBytes(StandardCharsets.UTF_8));
        cache.putIfAbsent(run.id(), ("""
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                    entityID="https://sp.example/entity">
                  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:AssertionConsumerService
                        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        Location="https://sp.example/acs" index="0" isDefault="true"/>
                  </md:SPSSODescriptor>
                </md:EntityDescriptor>
                """).getBytes(StandardCharsets.UTF_8));
        var saml = new SamlProtocolService(URI.create("https://peer.example"),
                new FilePlanKeyStore(directory, clock), new XmlSigner(), new OpenSamlReader(), clock);
        var recorder = new FileTranscriptRecorder(database, json, directory);
        var peer = new IdpPeerService(
                plans, runs, runService, cache, new TargetMetadataParser(), saml, recorder, clock);
        var destination = URI.create("https://peer.example/p/" + plan.id()
                + "/idp/sso?mdv=no-key-info&run=" + run.id());
        var request = saml.buildAuthnRequest(plan, destination, run.id());
        var targetRequest = new String(request.xml(), StandardCharsets.UTF_8).replace(
                "https://peer.example/p/" + plan.id() + "/sp/acs/0", "https://sp.example/acs")
                .getBytes(StandardCharsets.UTF_8);
        var body = "SAMLRequest=" + URLEncoder.encode(
                Base64.getEncoder().encodeToString(targetRequest), StandardCharsets.UTF_8);

        var response = peer.consume(
                plan.id(), "POST", destination.getRawQuery(), body.getBytes(StandardCharsets.UTF_8),
                Map.of(), destination.toString());

        assertEquals(URI.create("https://sp.example/acs"), response.destination());
        assertEquals(RunStatus.COMPLETED, runs.find(run.id()).orElseThrow().status());
        assertEquals("completed", runs.find(run.id()).orElseThrow().context().get("m0RoundTrip"));
        assertEquals(2, recorder.list(run.id()).size());
    }
}
