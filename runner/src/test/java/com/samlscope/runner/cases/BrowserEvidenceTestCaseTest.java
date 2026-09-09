package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.normal.SecureXml;

class BrowserEvidenceTestCaseTest {
    private static final Instant NOW = Instant.parse("2026-08-29T13:00:00Z");
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";

    @Test
    void browserCompletionNeverAsksTheOperatorToGradeTheTarget() {
        var evidence = new AttestedOutcomeTestCase(
                "IIP-G01-a-idp-01", TargetRole.IDP, "browser.evidence", "Review browser evidence.",
                Duration.ofHours(1), List.of(
                        AttestationOption.of("satisfied", Outcome.SATISFIED, "satisfied"),
                        AttestationOption.notVerified("unclear", "unclear", "evidence_unavailable")));
        var testCase = new BrowserEvidenceTestCase(
                evidence, URI.create("https://suite.example"), "Execute both controls.", Duration.ofHours(1));

        var browser = assertInstanceOf(CaseStep.AwaitBrowser.class, testCase.start(context()));
        assertEquals(URI.create("https://suite.example/browser/" + RUN_ID + "/IIP-G01-a-idp-01"),
                browser.startUrl());
        assertThrows(IllegalArgumentException.class, () -> testCase.resume(
                context(), browser.next(), new CaseEvent.Attested("satisfied", "too early")));

        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), browser.next(), new CaseEvent.BrowserReturned("operator-completed-approved-steps")));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertEquals(false, finish.outcome().details().get("operator_verdict_requested"));
    }

    @Test
    void ordinaryTranscriptFinishesSupportedBrowserCaseWithoutHumanCompletion() {
        var fallback = browserCase("IIP-SSO03-a-idp-01");
        var xml = """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                </samlp:Response>
                """.getBytes(StandardCharsets.UTF_8);
        var entry = new TranscriptEntry(
                "entry-1", RUN_ID, com.samlscope.core.transcript.Direction.INBOUND, NOW, "_response",
                "POST", "https://suite.example/acs", 200, Map.of(), null, 0,
                "decoded-ref", xml.length, "application/x-www-form-urlencoded", null,
                Map.of("type", "Response", "normalFlowAccepted", true));
        var testCase = new AutoBrowserEvidenceTestCase(fallback, ignored -> xml);

        var finish = assertInstanceOf(CaseStep.Finish.class,
                testCase.start(context(new FixedTranscript(List.of(entry)))));
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
    }

    @Test
    void inconclusiveOrdinaryTranscriptWaitsForMoreProtocolEvidence() {
        var fallback = browserCase("IIP-SSO03-a-idp-01");
        var testCase = new AutoBrowserEvidenceTestCase(fallback, ignored -> new byte[0]);

        assertInstanceOf(CaseStep.AwaitBrowser.class,
                testCase.start(context(new FixedTranscript(List.of()))));
    }

    @Test
    void waitingCaseFinishesWhenTheSuiteSignalsConclusiveTranscriptEvidence() {
        var fallback = browserCase("IIP-SSO03-a-idp-01");
        var xml = """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                </samlp:Response>
                """.getBytes(StandardCharsets.UTF_8);
        var testCase = new AutoBrowserEvidenceTestCase(fallback, ignored -> xml);
        var waiting = assertInstanceOf(CaseStep.AwaitBrowser.class,
                testCase.start(context(new FixedTranscript(List.of()))));
        var entry = new TranscriptEntry(
                "entry-ready", RUN_ID, com.samlscope.core.transcript.Direction.INBOUND, NOW, "_response",
                "POST", "https://suite.example/acs", 200, Map.of(), null, 0,
                "decoded-ref", xml.length, "application/x-www-form-urlencoded", null,
                Map.of("type", "Response", "normalFlowAccepted", true));

        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(new FixedTranscript(List.of(entry))), waiting.next(),
                new CaseEvent.TranscriptReady()));

        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
    }

    @Test
    void inspectsAnEncryptedAssertionThroughTheRunScopedKeyWithoutPersistingPlaintext() {
        var fallback = browserCase("IIP-SSO05-a2-idp-01");
        var response = """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
                  <saml:EncryptedAssertion><EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion>
                </samlp:Response>
                """.getBytes(StandardCharsets.UTF_8);
        var assertion = """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
                  <saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">opaque-123</saml:NameID></saml:Subject>
                </saml:Assertion>
                """.getBytes(StandardCharsets.UTF_8);
        var entry = new TranscriptEntry(
                "entry-encrypted", RUN_ID, com.samlscope.core.transcript.Direction.INBOUND, NOW, "_response",
                "POST", "https://suite.example/acs", 200, Map.of(), null, 0,
                "decoded-ref", response.length, "application/x-www-form-urlencoded", null,
                Map.of("type", "Response", "normalFlowAccepted", true));
        var key = new PrivateKey() {
            @Override public String getAlgorithm() { return "test"; }
            @Override public String getFormat() { return "test"; }
            @Override public byte[] getEncoded() { return new byte[0]; }
        };
        var testCase = new AutoBrowserEvidenceTestCase(
                fallback, ignored -> response, ignored -> java.util.Optional.of(key),
                ignored -> java.util.Optional.empty(),
                (wrapper, ignored) -> SecureXml.parse(assertion).getDocumentElement());

        var finish = assertInstanceOf(CaseStep.Finish.class,
                testCase.start(context(new FixedTranscript(List.of(entry)))));

        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
    }

    @Test
    void envelopeRulesInspectTheEncryptedOriginalWithoutReplacingIt() {
        var fallback = browserCase("IIP-SSO01-h1-idp-01");
        var response = """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
                  <saml:EncryptedAssertion><EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion>
                </samlp:Response>
                """.getBytes(StandardCharsets.UTF_8);
        var entry = new TranscriptEntry(
                "entry-encrypted-envelope", RUN_ID, com.samlscope.core.transcript.Direction.INBOUND,
                NOW, "_response", "POST", "https://suite.example/acs", 200, Map.of(), null, 0,
                "decoded-ref", response.length, "application/x-www-form-urlencoded", null,
                Map.of("type", "Response", "normalFlowAccepted", true));
        var key = new PrivateKey() {
            @Override public String getAlgorithm() { return "test"; }
            @Override public String getFormat() { return "test"; }
            @Override public byte[] getEncoded() { return new byte[0]; }
        };
        var testCase = new AutoBrowserEvidenceTestCase(
                fallback, ignored -> response, ignored -> java.util.Optional.of(key),
                ignored -> java.util.Optional.empty(),
                (wrapper, ignored) -> { throw new AssertionError("envelope must not be replaced"); });

        var finish = assertInstanceOf(CaseStep.Finish.class,
                testCase.start(context(new FixedTranscript(List.of(entry)))));

        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
    }

    @Test
    void durableButNotYetParsedInboundResponseCannotCompleteTheCase() {
        var fallback = browserCase("IIP-SSO03-a-idp-01");
        var xml = """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                </samlp:Response>
                """.getBytes(StandardCharsets.UTF_8);
        var unparsed = new TranscriptEntry(
                "entry-unparsed", RUN_ID, com.samlscope.core.transcript.Direction.INBOUND, NOW, RUN_ID,
                "POST", "https://suite.example/acs", 200, Map.of(), null, 0,
                "decoded-ref", xml.length, "application/x-www-form-urlencoded", null,
                Map.of("type", "SAMLResponse", "parseStatus", "not-yet-parsed"));
        var testCase = new AutoBrowserEvidenceTestCase(fallback, ignored -> xml);

        assertInstanceOf(CaseStep.AwaitBrowser.class,
                testCase.start(context(new FixedTranscript(List.of(unparsed)))));
    }

    @Test
    void parsedButRejectedResponseCannotCompleteTheCase() {
        var fallback = browserCase("IIP-SSO03-a-idp-01");
        var xml = """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                </samlp:Response>
                """.getBytes(StandardCharsets.UTF_8);
        var rejected = new TranscriptEntry(
                "entry-rejected", RUN_ID, com.samlscope.core.transcript.Direction.INBOUND, NOW, "_wrong",
                "POST", "https://suite.example/acs", 200, Map.of(), null, 0,
                "decoded-ref", xml.length, "application/x-www-form-urlencoded", null,
                Map.of("type", "Response", "normalFlowAccepted", false));
        var testCase = new AutoBrowserEvidenceTestCase(fallback, ignored -> xml);

        assertInstanceOf(CaseStep.AwaitBrowser.class,
                testCase.start(context(new FixedTranscript(List.of(rejected)))));
    }

    @Test
    void explicitlyAllowedNameIdOracleReusesCorrelatedActiveScenarioEvidence() {
        var action = "action_00000000000000000000000000000000";
        var requestId = "_" + action;
        var request = ("""
                <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="%s" Version="2.0">
                  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>
                </samlp:AuthnRequest>
                """).formatted(requestId).getBytes(StandardCharsets.UTF_8);
        var response = ("""
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    Version="2.0" InResponseTo="%s">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                  <saml:Assertion><saml:Subject><saml:NameID
                    Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">opaque</saml:NameID>
                  </saml:Subject></saml:Assertion>
                </samlp:Response>
                """).formatted(requestId).getBytes(StandardCharsets.UTF_8);
        var outbound = new TranscriptEntry(
                "entry-active-request", RUN_ID, com.samlscope.core.transcript.Direction.OUTBOUND, NOW, action,
                "POST", "https://idp.example/sso", 200, Map.of(), null, 0,
                "request-ref", request.length, "application/xml", null,
                Map.of("type", "AuthnRequest", "active_probe", true));
        var inbound = new TranscriptEntry(
                "entry-active-response", RUN_ID, com.samlscope.core.transcript.Direction.INBOUND, NOW, requestId,
                "POST", "https://suite.example/acs", 200, Map.of(), null, 0,
                "response-ref", response.length, "application/x-www-form-urlencoded", null,
                Map.of("type", "Response", "activeProbeAccepted", true));
        var content = Map.of("entry-active-request", request, "entry-active-response", response);
        var testCase = new AutoBrowserEvidenceTestCase(
                browserCase("IIP-SSO05-a-idp-01"), entry -> content.get(entry.id()));

        var finish = assertInstanceOf(CaseStep.Finish.class,
                testCase.start(context(new FixedTranscript(List.of(outbound, inbound)))));

        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
        assertEquals(2, finish.outcome().evidence().size());
    }

    @Test
    void unsolicitedMetadataCampaignResponseCanCompleteOnlyTheApprovedInitiationOracle() {
        var spInitiated = """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    Version="2.0" InResponseTo="_request">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                  <saml:Assertion/>
                </samlp:Response>
                """.getBytes(StandardCharsets.UTF_8);
        var unsolicited = """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                  <saml:Assertion/>
                </samlp:Response>
                """.getBytes(StandardCharsets.UTF_8);
        var normalEntry = new TranscriptEntry(
                "normal", RUN_ID, com.samlscope.core.transcript.Direction.INBOUND, NOW, "_request",
                "POST", "https://suite.example/acs", 200, Map.of(), null, 0,
                "normal-ref", spInitiated.length, "application/x-www-form-urlencoded", null,
                Map.of("type", "Response", "normalFlowAccepted", true));
        var metadataEntry = new TranscriptEntry(
                "metadata", RUN_ID, com.samlscope.core.transcript.Direction.INBOUND, NOW, RUN_ID,
                "POST", "https://suite.example/acs?mdv=control&run=" + RUN_ID, 200, Map.of(), null, 0,
                "metadata-ref", unsolicited.length, "application/x-www-form-urlencoded", null,
                Map.of("type", "Response", "metadataProbeAccepted", true));
        var content = Map.of("normal", spInitiated, "metadata", unsolicited);
        var allowed = new AutoBrowserEvidenceTestCase(
                browserCase("IIP-SSO01-g-idp-01"), entry -> content.get(entry.id()));
        var unrelated = new AutoBrowserEvidenceTestCase(
                browserCase("IIP-SSO03-a-idp-01"), entry -> content.get(entry.id()));

        assertEquals(Outcome.SATISFIED, assertInstanceOf(
                CaseStep.Finish.class,
                allowed.start(context(new FixedTranscript(List.of(normalEntry, metadataEntry)))))
                .outcome().outcome());
        assertInstanceOf(CaseStep.AwaitBrowser.class,
                unrelated.start(context(new FixedTranscript(List.of(metadataEntry)))));
    }

    @Test
    void activeScenarioEvidenceCannotLeakIntoAnUnrelatedNormalFlowOracle() {
        var response = """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    Version="2.0" InResponseTo="_action_00000000000000000000000000000000">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                </samlp:Response>
                """.getBytes(StandardCharsets.UTF_8);
        var inbound = new TranscriptEntry(
                "entry-active-response", RUN_ID, com.samlscope.core.transcript.Direction.INBOUND, NOW,
                "_action_00000000000000000000000000000000", "POST", "https://suite.example/acs",
                200, Map.of(), null, 0, "response-ref", response.length,
                "application/x-www-form-urlencoded", null,
                Map.of("type", "Response", "activeProbeAccepted", true));
        var testCase = new AutoBrowserEvidenceTestCase(
                browserCase("IIP-SSO01-x-idp-01"), ignored -> response);

        assertInstanceOf(CaseStep.AwaitBrowser.class,
                testCase.start(context(new FixedTranscript(List.of(inbound)))));
    }

    @Test
    void userLogoutActionCompletesSloBrowserCaseFromTargetTranscript() {
        var xml = """
                <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_logout" Version="2.0" IssueInstant="2026-08-29T13:00:00Z"
                    InResponseTo="_suite-request">
                  <saml:Issuer>https://idp.example/entity</saml:Issuer>
                  <samlp:Status><samlp:StatusCode
                    Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                </samlp:LogoutResponse>
                """.getBytes(StandardCharsets.UTF_8);
        var entry = new TranscriptEntry(
                "entry-logout", RUN_ID, com.samlscope.core.transcript.Direction.INBOUND, NOW,
                "_suite-request", "POST", "https://suite.example/sp/slo", 200, Map.of(), null, 0,
                "logout-ref", xml.length, "application/xml", null, Map.of("type", "LogoutResponse"));
        var testCase = new LogoutBrowserEvidenceTestCase(
                browserCase("IIP-IDP17-g-idp-01"), ignored -> xml,
                ignored -> java.util.Optional.of("https://idp.example/entity"), ignored -> List.of());

        var finish = assertInstanceOf(CaseStep.Finish.class,
                testCase.start(context(new FixedTranscript(List.of(entry)))));

        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
    }

    @Test
    void sloBrowserCaseWaitsForTheUserActionWhenNoTargetMessageExists() {
        var testCase = new LogoutBrowserEvidenceTestCase(
                browserCase("IIP-IDP17-g-idp-01"), ignored -> new byte[0],
                ignored -> java.util.Optional.of("https://idp.example/entity"), ignored -> List.of());

        assertInstanceOf(CaseStep.AwaitBrowser.class,
                testCase.start(context(new FixedTranscript(List.of()))));
    }

    private BrowserEvidenceTestCase browserCase(String id) {
        var evidence = new AttestedOutcomeTestCase(
                id, TargetRole.IDP, "browser.evidence", "Review browser evidence.",
                Duration.ofHours(1), List.of(
                        AttestationOption.of("satisfied", Outcome.SATISFIED, "satisfied"),
                        AttestationOption.notVerified("unclear", "unclear", "evidence_unavailable")));
        return new BrowserEvidenceTestCase(
                evidence, URI.create("https://suite.example"), "Execute the approved controls.", Duration.ofHours(1));
    }

    private DefaultCaseContext context() {
        return context(new NoopTranscript());
    }

    private DefaultCaseContext context(TranscriptRecorder recorder) {
        var plan = new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "Browser", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(
                        TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                new TestPlan.Interaction(true, true), NOW, NOW);
        return new DefaultCaseContext(
                RUN_ID, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC), plan.parameters(), plan.interaction(),
                Reachability.CONFIRMED, recorder, true);
    }

    private static final class NoopTranscript implements TranscriptRecorder {
        @Override public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
        @Override public TranscriptEntry updateSamlAnalysis(
                String entryId, String correlationId, Map<String, Object> summary) {
            throw new UnsupportedOperationException();
        }
        @Override public List<TranscriptEntry> list(String runId) { return List.of(); }
    }

    private static final class FixedTranscript implements TranscriptRecorder {
        private final List<TranscriptEntry> entries;

        private FixedTranscript(List<TranscriptEntry> entries) { this.entries = List.copyOf(entries); }
        @Override public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
        @Override public TranscriptEntry updateSamlAnalysis(
                String entryId, String correlationId, Map<String, Object> summary) {
            throw new UnsupportedOperationException();
        }
        @Override public List<TranscriptEntry> list(String runId) { return entries; }
    }
}
