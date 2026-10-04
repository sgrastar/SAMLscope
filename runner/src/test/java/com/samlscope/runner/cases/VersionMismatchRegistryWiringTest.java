package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.casedef.CaseDefinitionCatalog.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.runner.TestCaseRegistry;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;

class VersionMismatchRegistryWiringTest {
    @TempDir Path directory;
    private static final String RUN = "run_00000000000000000000000001";
    private static final String PLAN = "plan_00000000000000000000000001";
    private static final URI SSO = URI.create("https://target.example/sso");
    private static final URI ACS = URI.create("https://suite.example/acs");
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-03T19:00:00Z"), ZoneOffset.UTC);
    private static final IdpErrorProbeConfiguration CONFIG = new IdpErrorProbeConfiguration(
            SSO, "https://suite.example/sp", ACS, Duration.ofMinutes(2), true, true, false);
    private static final TranscriptContentReader CONTENT = entry -> {
        throw new AssertionError("No fabricated transcript original");
    };

    @Test void runtimeRegistryBindsOriginalMetadataWithoutEditingTheProtectedRuntime() throws Exception {
        var key = new FilePlanKeyStore(directory.resolve("keys"), CLOCK).getOrCreate(PLAN);
        var original = create(key, TargetRole.IDP);
        var pending = assertInstanceOf(IdpVersionMismatchScenarioTestCase.class,
                original.require(IdpVersionMismatchScenarioTestCase.CASE_ID));
        assertEquals(Outcome.NOT_VERIFIED,
                assertInstanceOf(CaseStep.Finish.class, pending.start(context())).outcome().outcome());

        var bound = bind(original, key);
        assertTrue(bound.ids().containsAll(original.ids()));
        assertSame(original.require(IdpVersionScenarioTestCase.CASE_ID),
                bound.require(IdpVersionScenarioTestCase.CASE_ID));
        var scenario = assertInstanceOf(IdpVersionMismatchScenarioTestCase.class,
                bound.require(IdpVersionMismatchScenarioTestCase.CASE_ID));
        var awaiting = assertInstanceOf(CaseStep.AwaitInbound.class, scenario.start(context()));
        assertEquals("baseline-success", awaiting.next().data().get("fixture_id"));
        assertEquals(1, awaiting.actions().size());
        var action = awaiting.actions().getFirst();
        assertEquals(OutboundKind.AUTHN_REQUEST, action.kind());
        assertEquals(OutboundAction.RequestSigning.REQUIRE, action.requestSigning());
        assertEquals(SSO, action.target());
        var xml = SecureXml.parse(action.payload()).getDocumentElement();
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(xml, key.certificate()));
        assertEquals("_" + action.actionId(), xml.getAttribute("ID"));
        assertEquals(action.actionId(), assertInstanceOf(CaseStep.AwaitInbound.class,
                scenario.start(context())).actions().getFirst().actionId());
    }

    @Test void anotherRoleCannotBeUpgradedToAnIdpVersionOracle() throws Exception {
        var key = new FilePlanKeyStore(directory.resolve("keys"), CLOCK).getOrCreate(PLAN);
        var original = create(key, TargetRole.SP);
        var other = original.require(IdpVersionMismatchScenarioTestCase.CASE_ID);
        assertFalse(other instanceof IdpVersionMismatchScenarioTestCase);
        assertSame(other, bind(original, key).require(other.id()));
    }

    @Test void missingAdvertisedSuiteSigningKeyNeverStartsAProbe() {
        var scenario = assertInstanceOf(IdpVersionMismatchScenarioTestCase.class,
                ApprovedBrowserCaseRegistry.create(definitions(TargetRole.IDP), URI.create("https://suite.example"),
                        CONTENT, run -> Optional.empty(), run -> Optional.of("https://target.example/idp"),
                        run -> List.of(), run -> CONFIG, run -> Optional.empty())
                    .require(IdpVersionMismatchScenarioTestCase.CASE_ID));
        var bound = scenario.withNativeEvidence(directory.resolve("version-mismatch-evidence"),
                CONTENT, run -> new byte[0]);
        assertEquals(Outcome.NOT_VERIFIED,
                assertInstanceOf(CaseStep.Finish.class, bound.start(context())).outcome().outcome());
    }

    private TestCaseRegistry create(PlanCredentials key, TargetRole epRole) {
        return ApprovedBrowserCaseRegistry.create(definitions(epRole), URI.create("https://suite.example"),
                CONTENT, run -> Optional.of(key.privateKey()), run -> Optional.of("https://target.example/idp"),
                run -> List.of(key.certificate()), run -> CONFIG, run -> Optional.of(key));
    }

    private TestCaseRegistry bind(TestCaseRegistry registry, PlanCredentials key) throws Exception {
        byte[] metadata = ("<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' entityID='https://target.example/idp'>"
                + "<md:IDPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>"
                + "<md:KeyDescriptor use='signing'><ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>"
                + "<ds:X509Data><ds:X509Certificate>" + Base64.getEncoder().encodeToString(key.certificate().getEncoded())
                + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
                + "</md:IDPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
        return ApprovedBrowserCaseRegistry.withNativeEcSignature(registry, CONTENT, run -> metadata,
                directory.resolve("ec-signature-preparations"));
    }

    private static CaseDefinitionCatalog definitions(TargetRole epRole) {
        return new CaseDefinitionCatalog(List.of(
                definition(IdpVersionMismatchScenarioTestCase.CASE_ID, "IIP-SSO01.ep", epRole),
                definition(IdpVersionScenarioTestCase.CASE_ID, "IIP-SSO01.em", TargetRole.IDP)));
    }

    private static CaseDefinition definition(String id, String obligation, TargetRole role) {
        return new CaseDefinition(id, obligation, role, ExecutionMode.BROWSER, Milestone.M1,
                List.of(), Map.of(), List.of(), List.of(), List.of(), "Approved version control",
                List.of(), new Requirements(List.of(), "none"), false,
                null, "sha256:" + "a".repeat(64));
    }

    private static DefaultCaseContext context() {
        return new DefaultCaseContext(RUN, TargetRole.IDP, CLOCK, TestPlan.Parameters.defaults(),
                new TestPlan.Interaction(true, false), Reachability.CONFIRMED, new TranscriptRecorder() {
                    public List<TranscriptEntry> list(String run) { return List.of(); }
                    public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("Read only"); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) {
                        throw new AssertionError("Read only");
                    }
                }, true);
    }
}
