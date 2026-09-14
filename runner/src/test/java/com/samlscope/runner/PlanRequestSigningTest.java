package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;
import com.samlscope.store.*;

class PlanRequestSigningTest {
    @TempDir java.nio.file.Path directory;
    private static final Instant NOW = Instant.parse("2026-09-07T00:00:00Z");
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";

    private TestPlan plan(TestPlan.RequestSigningMode mode) {
        return new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Signing test", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), new TestPlan.Parameters(180, 300, "", mode),
                TestPlan.Interaction.defaults(), NOW, NOW);
    }

    @Test void signsNormalRequestsAndPreservesBrokenSignaturesInThePersistedOutbox() {
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        var db = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plans = new SqlitePlanRepository(db, json);
        var runs = new SqliteRunRepository(db, json);
        var plan = plan(TestPlan.RequestSigningMode.REQUIRED);
        plans.save(plan);
        runs.save(new TestRun(RUN, plan.id(), RunStatus.RUNNING, Reachability.UNKNOWN, Map.of(), NOW, NOW));
        var keys = new FilePlanKeyStore(directory, clock);
        var signing = new PlanRequestSigning(plans, runs, keys);
        var xml = new SamlNameIdPolicyRequestFactory().build("_request", URI.create("https://idp.example/sso"),
                "https://suite.example/sp", URI.create("https://suite.example/acs"), NOW,
                new SamlNameIdPolicyRequestFactory.Policy(true, SamlNameIdPolicyRequestFactory.PERSISTENT, "qualifier", true));
        var action = new OutboundAction("action", OutboundKind.AUTHN_REQUEST, xml, URI.create("https://idp.example/sso"), false);
        var signed = signing.apply(RUN, action);
        var root = SecureXml.parse(signed.payload()).getDocumentElement();
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root, keys.getOrCreate(plan.id()).certificate()));
        assertEquals("qualifier", ((org.w3c.dom.Element) root.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:protocol", "NameIDPolicy").item(0)).getAttribute("SPNameQualifier"));
        assertEquals(action.actionId(), signed.actionId());
        for (var fixture : SamlSignedRequestFactory.Fixture.values()) {
            var payload = new SamlSignedRequestFactory().build(fixture, "_signed", action.target(),
                    "https://suite.example/sp", URI.create("https://suite.example/acs"), NOW, keys.getOrCreate(plan.id()));
            var deliberate = new OutboundAction("action", OutboundKind.AUTHN_REQUEST, payload, action.target(), false);
            assertArrayEquals(payload, signing.apply(RUN, deliberate).payload(), fixture.name());
        }
        var repository = new SqliteCaseExecutionRepository(db, json);
        var context = new DefaultCaseContext(RUN, TargetRole.IDP, clock, plan.parameters(), plan.interaction(),
                Reachability.UNKNOWN, new FileTranscriptRecorder(db, json, directory), true);
        TestCase test = new TestCase() {
            public String id() { return "signing-case"; }
            public TargetRole role() { return TargetRole.IDP; }
            public CaseStep start(CaseContext c) {
                return new CaseStep.Continue(CaseState.initial(), List.of(new OutboundAction(
                        ActionIds.derive(RUN, id(), CaseState.initial().phase(), 0), action.kind(), xml, action.target(), false)));
            }
            public CaseStep resume(CaseContext c, CaseState s, CaseEvent e) { throw new UnsupportedOperationException(); }
        };
        new CaseExecutionService(repository, signing).start(RUN, test, context);
        var persisted = repository.findOutbox(ActionIds.derive(RUN, test.id(), CaseState.initial().phase(), 0)).orElseThrow();
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(
                SecureXml.parse(persisted.action().payload()).getDocumentElement(), keys.getOrCreate(plan.id()).certificate()));
    }

    @Test void requiredSigningPreservesTheCharacterMatrixOnTheActualOutboxPath() {
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        var db = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plans = new SqlitePlanRepository(db, json);
        var runs = new SqliteRunRepository(db, json);
        var plan = plan(TestPlan.RequestSigningMode.REQUIRED);
        plans.save(plan);
        runs.save(new TestRun(RUN, plan.id(), RunStatus.RUNNING, Reachability.UNKNOWN, Map.of(), NOW, NOW));
        var keys = new FilePlanKeyStore(directory, clock);
        var signing = new PlanRequestSigning(plans, runs, keys);
        for (var probe : SamlErrorProbeRequestFactory.stringProbes()) {
            var original = new SamlErrorProbeRequestFactory().build(probe, "_request",
                    URI.create("https://idp.example/sso"), "https://suite.example/sp",
                    URI.create("https://suite.example/acs"), NOW);
            var action = new OutboundAction("action", OutboundKind.AUTHN_REQUEST, original,
                    URI.create("https://idp.example/sso"), false);
            var signed = signing.apply(RUN, action);
            var root = SecureXml.parse(signed.payload()).getDocumentElement();
            assertEquals(SamlErrorProbeRequestFactory.parsedStringValue(probe), root.getAttribute("ProviderName"), probe.name());
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root, keys.getOrCreate(plan.id()).certificate()), probe.name());
            assertEquals(action.actionId(), signed.actionId());
            if (probe.name().contains("_LITERAL_")) {
                char expected=probe.name().contains("TAB") ? '\t' : '\n';
                assertTrue(new String(signed.payload(),java.nio.charset.StandardCharsets.UTF_8).contains("a"+expected+"b"));
            }
            var repository=new SqliteCaseExecutionRepository(db,json);
            var context=new DefaultCaseContext(RUN,TargetRole.IDP,clock,plan.parameters(),plan.interaction(),
                    Reachability.UNKNOWN,new FileTranscriptRecorder(db,json,directory),true);
            TestCase fixture=new TestCase() {
                public String id(){return "wire-"+probe.name();}
                public TargetRole role(){return TargetRole.IDP;}
                public CaseStep start(CaseContext c){return new CaseStep.Continue(CaseState.initial(),List.of(
                        new OutboundAction(ActionIds.derive(RUN,id(),CaseState.initial().phase(),0),action.kind(),original,action.target(),false)));}
                public CaseStep resume(CaseContext c,CaseState state,CaseEvent event){throw new UnsupportedOperationException();}
            };
            new CaseExecutionService(repository,signing).start(RUN,fixture,context);
            var saved=repository.findOutbox(ActionIds.derive(RUN,fixture.id(),CaseState.initial().phase(),0)).orElseThrow().action().payload();
            var storedRoot=SecureXml.parse(saved).getDocumentElement();
            assertEquals(SamlErrorProbeRequestFactory.parsedStringValue(probe),storedRoot.getAttribute("ProviderName"));
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(storedRoot,keys.getOrCreate(plan.id()).certificate()));
            if (probe.name().contains("_LITERAL_")) assertTrue(new String(saved,java.nio.charset.StandardCharsets.UTF_8)
                    .contains(probe.name().contains("TAB") ? "a\tb" : "a\nb"));
        }
    }

    @Test void modeIsImmutableAndLegacyPlansRemainOptional() {
        var json = new JsonCodec();
        var db = new SqliteDatabase(directory);
        var plans = new SqlitePlanRepository(db, json);
        var optional = plan(TestPlan.RequestSigningMode.OPTIONAL);
        var legacy = json.read(json.write(optional).replace(",\"requestSigningMode\":\"OPTIONAL\"", ""), TestPlan.class);
        assertEquals(TestPlan.RequestSigningMode.OPTIONAL, legacy.parameters().requestSigningMode());
        plans.save(legacy);
        assertThrows(IllegalArgumentException.class, () -> plans.save(plan(TestPlan.RequestSigningMode.REQUIRED)));
        assertEquals(TestPlan.RequestSigningMode.OPTIONAL, plans.find(legacy.id()).orElseThrow().parameters().requestSigningMode());
        plans.save(optional);
    }

    @Test void signedLogoutFixturesPersistWithoutRepairOrUnsafeRetryPermission() {
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        var db = new SqliteDatabase(directory); var json = new JsonCodec();
        var plans = new SqlitePlanRepository(db, json); var runs = new SqliteRunRepository(db, json);
        var plan = plan(TestPlan.RequestSigningMode.REQUIRED); plans.save(plan);
        runs.save(new TestRun(RUN, plan.id(), RunStatus.RUNNING, Reachability.UNKNOWN, Map.of(), NOW, NOW));
        var keys = new FilePlanKeyStore(directory, clock);
        var repository = new SqliteCaseExecutionRepository(db, json);
        var service = new CaseExecutionService(repository, new PlanRequestSigning(plans, runs, keys));
        var context = new DefaultCaseContext(RUN, TargetRole.IDP, clock, plan.parameters(), plan.interaction(),
                Reachability.UNKNOWN, new FileTranscriptRecorder(db, json, directory), true);
        var identifier = SecureXml.parse("<saml:NameID xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>user</saml:NameID>"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)).getDocumentElement();
        var factory = new SamlLogoutRequestFactory();
        for (var mutation : List.of("valid", "signature-value", "signed-destination")) {
            var caseId = "logout-" + mutation;
            var actionId = ActionIds.derive(RUN, caseId, CaseState.initial().phase(), 0);
            var target = URI.create("https://idp.example/slo");
            var signed = factory.sign(factory.build("_"+actionId, target, "https://suite.example/sp", identifier,
                    List.of("session"), NOW, null, true), keys.getOrCreate(plan.id()));
            var root = SecureXml.parse(signed).getDocumentElement();
            if (mutation.equals("signature-value")) root.getElementsByTagNameNS(
                    "http://www.w3.org/2000/09/xmldsig#", "SignatureValue").item(0).setTextContent("AAAA");
            if (mutation.equals("signed-destination")) root.setAttribute("Destination", "https://other.example/slo");
            var payload = mutation.equals("valid") ? signed : SecureXml.serialize(root.getOwnerDocument());
            TestCase fixture = new TestCase() {
                public String id() { return caseId; }
                public TargetRole role() { return TargetRole.IDP; }
                public CaseStep start(CaseContext c) { return new CaseStep.Continue(CaseState.initial(), List.of(
                        new OutboundAction(actionId, OutboundKind.LOGOUT_REQUEST, payload, target, false))); }
                public CaseStep resume(CaseContext c, CaseState s, CaseEvent e) { throw new UnsupportedOperationException(); }
            };
            service.start(RUN, fixture, context);
            var saved = repository.findOutbox(actionId).orElseThrow().action();
            assertArrayEquals(payload, saved.payload());
            assertEquals(OutboundKind.LOGOUT_REQUEST, saved.kind());
            assertEquals(OutboundKind.Retry.UNSAFE, saved.kind().retry());
            assertEquals(mutation.equals("valid"), new XmlSignatureVerifier().hasValidEnvelopedSignature(
                    SecureXml.parse(saved.payload()).getDocumentElement(), keys.getOrCreate(plan.id()).certificate()));
        }
    }
}
