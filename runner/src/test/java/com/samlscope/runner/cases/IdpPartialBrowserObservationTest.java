package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.normal.SecureXml;

class IdpPartialBrowserObservationTest {
    private static final String SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    private static IdpExecutableBrowserFixtureScenarioTestCase scenario(String id) {
        return new IdpExecutableBrowserFixtureScenarioTestCase(id, ignored -> new IdpErrorProbeConfiguration(
                URI.create("https://idp.example/sso"), "https://suite.example/sp", URI.create("https://suite.example/acs"),
                Duration.ofMinutes(2), true, true, true));
    }
    private static CaseContext context() { return context(null); }
    private static CaseContext context(com.samlscope.core.transcript.TranscriptRecorder recorder) {
        return new CaseContext() {
            public String runId() { return "run_0123456789ABCDEFGHJKMNPQRS"; }
            public TargetRole targetRole() { return TargetRole.IDP; }
            public Clock clock() { return Clock.fixed(Instant.parse("2026-09-14T00:00:00Z"), ZoneOffset.UTC); }
            public TestPlan.Parameters parameters() { return new TestPlan.Parameters(180, 300, ""); }
            public TestPlan.Interaction interaction() { return TestPlan.Interaction.defaults(); }
            public Reachability reachability() { return Reachability.CONFIRMED; }
            public com.samlscope.core.transcript.TranscriptRecorder transcript() { return recorder; }
            public boolean transcriptComplete() { return true; }
        };
    }
    private static CaseStep reply(TestCase test, CaseStep.AwaitInbound wait, boolean success, String assertion) {
        return reply(test, wait, success, assertion, context());
    }
    private static CaseStep reply(TestCase test, CaseStep.AwaitInbound wait, boolean success, String assertion, CaseContext context) {
        String xml = "<samlp:Response xmlns:samlp='" + PROTOCOL + "' xmlns:saml='" + SAML + "' InResponseTo='"
                + wait.next().data().get("expected_response_correlation") + "'><samlp:Status><samlp:StatusCode Value='"
                + "urn:oasis:names:tc:SAML:2.0:status:" + (success ? "Success" : "Responder")
                + "'/></samlp:Status>" + assertion + "</samlp:Response>";
        return test.resume(context, wait.next(), new CaseEvent.InboundMessage(xml.getBytes(StandardCharsets.UTF_8),
                new EvidenceRef("transcript", "tx-" + wait.next().phase())));
    }
    private static CaseStep.AwaitInbound controlled(TestCase test) {
        var start = assertInstanceOf(CaseStep.AwaitInbound.class, test.start(context()));
        return assertInstanceOf(CaseStep.AwaitInbound.class, reply(test, start, true, "<saml:Assertion/>"));
    }
    @Test void detectsDtdAcceptanceButDoesNotTreatAnUnobservedResponseDirectionAsVerified() {
        for (boolean acceptDtd : new boolean[]{true, false}) {
            var test = scenario("IIP-G03-b-idp-01");
            var dtd = controlled(test);
            assertTrue(new String(dtd.actions().getFirst().payload(), StandardCharsets.UTF_8).contains("<!DOCTYPE"));
            var external = assertInstanceOf(CaseStep.AwaitInbound.class,
                    reply(test, dtd, acceptDtd, acceptDtd ? "<saml:Assertion/>" : ""));
            var result = assertInstanceOf(CaseStep.Finish.class, reply(test, external, false, "")).outcome();
            assertEquals(acceptDtd ? Outcome.VIOLATED : Outcome.NOT_VERIFIED, result.outcome());
        }
    }
    @Test void detectsEveryCharacterCategoryMutantWithoutClaimingAllTypeVariantsAreVerified() {
        var probes = com.samlscope.saml.normal.SamlErrorProbeRequestFactory.stringProbes();
        assertEquals(20, probes.size());
        // Reject one category at a time while accepting every other request. This catches
        // accidentally generating a new fixture without connecting it to the oracle.
        for (int rejected = -1; rejected < probes.size(); rejected++) {
            var test = scenario("IIP-G02-a-idp-01");
            CaseStep step = controlled(test);
            for (int index = 0; index < probes.size(); index++) {
                var wait = assertInstanceOf(CaseStep.AwaitInbound.class, step);
                var root = SecureXml.parse(wait.actions().getFirst().payload()).getDocumentElement();
                var value = root.getAttribute("ProviderName");
                assertEquals(probes.get(index).name().endsWith("255") ? 255 : 256,
                        value.codePointCount(0, value.length()));
                boolean accepted = index != rejected;
                step = reply(test, wait, accepted, accepted ? "<saml:Assertion/>" : "");
            }
            for (var fixture : nameIdStringFixtures()) {
                var wait = assertInstanceOf(CaseStep.AwaitInbound.class, step);
                var root = SecureXml.parse(wait.actions().getFirst().payload()).getDocumentElement();
                var nameId = assertInstanceOf(org.w3c.dom.Element.class,
                        root.getElementsByTagNameNS(SAML, "NameID").item(0));
                assertEquals(fixture.placement() == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.PERSISTENT_NAMEID
                        ? "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                        : "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", nameId.getAttribute("Format"));
                assertEquals(256, nameId.getTextContent().codePointCount(0, nameId.getTextContent().length()));
                assertEquals(java.util.Optional.empty(),
                        com.samlscope.saml.normal.SamlSchemaValidation.stringFixtureValidationFailure(root));
                step = reply(test, wait, true, "<saml:Assertion/>");
            }
            for (int index = 0; index < 16; index++) {
                step = reply(test, assertInstanceOf(CaseStep.AwaitInbound.class, step), true, "<saml:Assertion/>");
            }
            for (int index = 0; index < userDefinedValueFixtures().size(); index++) {
                step = reply(test, assertInstanceOf(CaseStep.AwaitInbound.class, step), true, "<saml:Assertion/>");
            }
            var result = assertInstanceOf(CaseStep.Finish.class, step).outcome();
            assertEquals(rejected < 0 ? Outcome.SATISFIED : Outcome.VIOLATED, result.outcome());
            assertEquals(rejected < 0 ? 20 : 19, ((java.util.List<?>) result.details().get("confirmed_character_fixtures")).size());
            assertFalse(((java.util.List<?>) result.details().get("remaining_conditions")).contains("persistent-nameid"));
            assertFalse(((java.util.List<?>) result.details().get("remaining_conditions")).contains("transient-nameid"));
            assertEquals(2, ((java.util.List<?>) result.details().get("responded_nameid_string_fixtures")).size());
        }
    }
    @Test void runsEveryTypedExtensionInputAndJudgesErrorFreeProcessingWithoutDemandingPreservation() {
        var inputs = com.samlscope.saml.normal.SamlTypedStringFixtures.matrix().stream()
                .filter(f -> f.placement() == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.EXTENSION_STRING_ATTRIBUTE).toList();
        // Every individual missing/failed response must remove only its exchange observation.
        for (int missing = -1; missing < inputs.size(); missing++) {
            for (boolean errorResponse : new boolean[]{false, true}) {
                var test = scenario("IIP-G02-a-idp-01");
                CaseStep step = controlled(test);
                for (int index = 0; index < 20; index++)
                    step = reply(test, assertInstanceOf(CaseStep.AwaitInbound.class, step), true, "<saml:Assertion/>");
                for (var fixture : nameIdStringFixtures()) {
                    var wait = assertInstanceOf(CaseStep.AwaitInbound.class, step);
                    var root = SecureXml.parse(wait.actions().getFirst().payload()).getDocumentElement();
                    var nameIds = root.getElementsByTagNameNS(SAML, "NameID");
                    assertEquals(1, nameIds.getLength());
                    var nameId = (org.w3c.dom.Element) nameIds.item(0);
                    assertEquals(256, nameId.getTextContent().codePointCount(0, nameId.getTextContent().length()));
                    assertEquals(fixture.placement() == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.PERSISTENT_NAMEID
                            ? "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                            : "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", nameId.getAttribute("Format"));
                    assertEquals(java.util.Optional.empty(),
                            com.samlscope.saml.normal.SamlSchemaValidation.stringFixtureValidationFailure(root));
                    step = reply(test, wait, true, "<saml:Assertion/>");
                }
                for (int index = 0; index < inputs.size(); index++) {
                    var wait = assertInstanceOf(CaseStep.AwaitInbound.class, step);
                    var xml = SecureXml.parse(wait.actions().getFirst().payload()).getDocumentElement();
                    assertFalse(xml.hasAttribute("ProviderName"));
                    assertEquals(java.util.Optional.empty(), com.samlscope.saml.normal.SamlSchemaValidation.stringFixtureValidationFailure(xml));
                    var extension = xml.getElementsByTagNameNS(com.samlscope.saml.normal.SamlTypedStringFixtures.NAMESPACE, "ExtensionString");
                    assertEquals(1, extension.getLength());
                    assertEquals(inputs.get(index).value(), ((org.w3c.dom.Element)extension.item(0)).getAttribute("value"));
                    boolean selected = index == missing;
                    boolean accepted = !selected || !errorResponse;
                    step = reply(test, wait, accepted, accepted ? "<saml:Assertion/>" : "");
                }
                for (int index = 0; index < userDefinedValueFixtures().size(); index++)
                    step = reply(test, assertInstanceOf(CaseStep.AwaitInbound.class, step), true, "<saml:Assertion/>");
                var result = assertInstanceOf(CaseStep.Finish.class, step).outcome();
                assertEquals(missing >= 0 && errorResponse ? Outcome.VIOLATED : Outcome.SATISFIED, result.outcome(),
                        "missing=" + missing + " errorResponse=" + errorResponse + " details=" + result.details());
                var observed = (java.util.List<?>) result.details().get("responded_extension_string_fixtures");
                boolean failedInput = missing >= 0 && errorResponse;
                assertEquals(failedInput ? 15 : 16, observed.size());
                if (failedInput) assertFalse(observed.contains(inputs.get(missing).id().replace(':', '-')));
                assertEquals(failedInput, ((java.util.List<?>) result.details().get("remaining_conditions"))
                        .contains("user-defined-extension-string-attribute"));
                assertEquals(failedInput
                                ? java.util.List.of("persistent-nameid", "transient-nameid", "user-defined-advice-string",
                                        "user-defined-attribute-value-string")
                                : java.util.List.of("persistent-nameid", "transient-nameid", "user-defined-extension-string-attribute",
                                        "user-defined-advice-string", "user-defined-attribute-value-string"),
                        result.details().get("confirmed_type_conditions"));
            }
        }
    }

    @Test void sendsSchemaValidAdviceAndCustomAttributeValueAtBothBoundaryLengths() {
        var fixtures = userDefinedValueFixtures();
        assertEquals(4, fixtures.size());
        for (int missing = -1; missing < fixtures.size(); missing++) {
            var test = scenario("IIP-G02-a-idp-01");
            CaseStep step = controlled(test);
            for (int index = 0; index < 20; index++)
                step = reply(test, assertInstanceOf(CaseStep.AwaitInbound.class, step), true, "<saml:Assertion/>");
            for (var ignored : nameIdStringFixtures())
                step = reply(test, assertInstanceOf(CaseStep.AwaitInbound.class, step), true, "<saml:Assertion/>");
            for (int index = 0; index < 16; index++)
                step = reply(test, assertInstanceOf(CaseStep.AwaitInbound.class, step), true, "<saml:Assertion/>");
            for (int index = 0; index < fixtures.size(); index++) {
                var wait = assertInstanceOf(CaseStep.AwaitInbound.class, step);
                var request = SecureXml.parse(wait.actions().getFirst().payload()).getDocumentElement();
                assertEquals(java.util.Optional.empty(), com.samlscope.saml.normal.SamlSchemaValidation
                        .stringFixtureValidationFailure(request));
                assertFalse(request.hasAttribute("ProviderName"));
                var assertions = request.getElementsByTagNameNS(SAML, "Assertion");
                assertEquals(1, assertions.getLength());
                var assertion = (org.w3c.dom.Element) assertions.item(0);
                var fixture = fixtures.get(index);
                if (fixture.placement() == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.ADVICE_STRING) {
                    var values = request.getElementsByTagNameNS(
                            com.samlscope.saml.normal.SamlTypedStringFixtures.NAMESPACE, "AdviceString");
                    assertEquals(1, values.getLength());
                    assertEquals(fixture.value(), values.item(0).getTextContent());
                } else {
                    var values = assertion.getElementsByTagNameNS(SAML, "AttributeValue");
                    assertEquals(1, values.getLength());
                    var value = (org.w3c.dom.Element) values.item(0);
                    assertEquals(fixture.value(), value.getTextContent());
                    assertEquals("MyStringType", value.getAttributeNS(
                            javax.xml.XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI, "type").split(":", 2)[1]);
                }
                var reject = index == missing;
                step = reply(test, wait, !reject, reject ? "" : "<saml:Assertion/>");
            }
            var outcome = assertInstanceOf(CaseStep.Finish.class, step).outcome();
            assertEquals(missing < 0 ? Outcome.SATISFIED : Outcome.NOT_VERIFIED, outcome.outcome());
            assertEquals(missing < 0 ? 4 : 3,
                    ((java.util.List<?>) outcome.details().get("responded_user_defined_value_fixtures")).size());
            if (missing >= 0) {
                var condition = fixtures.get(missing).placement()
                        == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.ADVICE_STRING
                        ? "user-defined-advice-string" : "user-defined-attribute-value-string";
                assertTrue(((java.util.List<?>) outcome.details().get("remaining_conditions")).contains(condition));
            }
        }
    }

    @Test void unknownOrMissingStatusAtEveryStringInputCannotBecomeAStringViolation() {
        int standard = com.samlscope.saml.normal.SamlErrorProbeRequestFactory.stringProbes().size();
        int nameIds = nameIdStringFixtures().size();
        int inputs = standard + nameIds + 16 + userDefinedValueFixtures().size();
        for (int unknown = 0; unknown < inputs; unknown++) {
            for (var code : new String[]{"urn:example:unknown-status", ""}) {
                var test = scenario("IIP-G02-a-idp-01");
                CaseStep step = controlled(test);
                for (int index = 0; index < standard; index++) {
                    var wait = assertInstanceOf(CaseStep.AwaitInbound.class, step);
                    if (index != unknown) {
                        step = reply(test, wait, true, "<saml:Assertion/>");
                        continue;
                    }
                    var xml = "<samlp:Response xmlns:samlp='" + PROTOCOL + "' xmlns:saml='" + SAML
                            + "' InResponseTo='" + wait.next().data().get("expected_response_correlation")
                            + "'><samlp:Status><samlp:StatusCode Value='" + code
                            + "'/></samlp:Status><saml:Assertion/></samlp:Response>";
                    step = test.resume(context(), wait.next(), new CaseEvent.InboundMessage(
                            xml.getBytes(StandardCharsets.UTF_8),new EvidenceRef("transcript","unknown-status")));
                }
                for (int index = 0; index < nameIds; index++) {
                    var wait = assertInstanceOf(CaseStep.AwaitInbound.class, step,
                            "expected next fixture after standard=" + standard + " nameIds=" + nameIds
                                    + " unknown=" + unknown + " status=" + code + " step=" + step);
                    if (standard + index != unknown) {
                        step = reply(test, wait, true, "<saml:Assertion/>");
                        continue;
                    }
                    var xml = "<samlp:Response xmlns:samlp='" + PROTOCOL + "' xmlns:saml='" + SAML
                            + "' InResponseTo='" + wait.next().data().get("expected_response_correlation")
                            + "'><samlp:Status><samlp:StatusCode Value='" + code
                            + "'/></samlp:Status><saml:Assertion/></samlp:Response>";
                    step = test.resume(context(), wait.next(), new CaseEvent.InboundMessage(
                            xml.getBytes(StandardCharsets.UTF_8), new EvidenceRef("transcript", "unknown-nameid-status")));
                }
                for (int index = 0; index < 16; index++) {
                    var wait = assertInstanceOf(CaseStep.AwaitInbound.class, step);
                    if (standard + nameIds + index != unknown) {
                        step = reply(test, wait, true, "<saml:Assertion/>");
                        continue;
                    }
                    var xml = "<samlp:Response xmlns:samlp='" + PROTOCOL + "' xmlns:saml='" + SAML
                            + "' InResponseTo='" + wait.next().data().get("expected_response_correlation")
                            + "'><samlp:Status><samlp:StatusCode Value='" + code
                            + "'/></samlp:Status><saml:Assertion/></samlp:Response>";
                    step = test.resume(context(), wait.next(), new CaseEvent.InboundMessage(
                            xml.getBytes(StandardCharsets.UTF_8), new EvidenceRef("transcript", "unknown-extension-status")));
                }
                for (int index = 0; index < userDefinedValueFixtures().size(); index++) {
                    var wait = assertInstanceOf(CaseStep.AwaitInbound.class, step);
                    if (standard + nameIds + 16 + index != unknown) {
                        step = reply(test, wait, true, "<saml:Assertion/>");
                        continue;
                    }
                    var xml = "<samlp:Response xmlns:samlp='" + PROTOCOL + "' xmlns:saml='" + SAML
                            + "' InResponseTo='" + wait.next().data().get("expected_response_correlation")
                            + "'><samlp:Status><samlp:StatusCode Value='" + code
                            + "'/></samlp:Status><saml:Assertion/></samlp:Response>";
                    step = test.resume(context(), wait.next(), new CaseEvent.InboundMessage(
                            xml.getBytes(StandardCharsets.UTF_8), new EvidenceRef("transcript", "unknown-user-defined-type-status")));
                }
                var result = assertInstanceOf(CaseStep.Finish.class,step).outcome();
                assertEquals(Outcome.NOT_VERIFIED,result.outcome());
                assertEquals(1,((java.util.List<?>)result.details().get("unverifiable_fixtures")).size());
                assertTrue(result.details().containsKey("confirmed_type_conditions"));
                boolean whitespaceUnknown = unknown < standard &&
                        (com.samlscope.saml.normal.SamlErrorProbeRequestFactory.stringProbes().get(unknown).name().contains("_TAB_")
                        || com.samlscope.saml.normal.SamlErrorProbeRequestFactory.stringProbes().get(unknown).name().contains("_LF_"));
                assertEquals(whitespaceUnknown, ((java.util.List<?>)result.details().get("remaining_conditions"))
                        .contains("literal-tab-and-lf-on-wire"));
            }
        }
    }

    @Test void anUnknownPrincipalErrorForLongNameIdIsNotMisattributedToStringLength() {
        var test = scenario("IIP-G02-a-idp-01");
        CaseStep step = controlled(test);
        for (int index = 0; index < 20; index++)
            step = reply(test, assertInstanceOf(CaseStep.AwaitInbound.class, step), true, "<saml:Assertion/>");
        var persistent = assertInstanceOf(CaseStep.AwaitInbound.class, step);
        step = reply(test, persistent, false, "");
        step = reply(test, assertInstanceOf(CaseStep.AwaitInbound.class, step), true, "<saml:Assertion/>");
        for (int index = 0; index < 16 + userDefinedValueFixtures().size(); index++)
            step = reply(test, assertInstanceOf(CaseStep.AwaitInbound.class, step), true, "<saml:Assertion/>");
        var outcome = assertInstanceOf(CaseStep.Finish.class, step).outcome();
        assertEquals(Outcome.NOT_VERIFIED, outcome.outcome());
        assertEquals(java.util.List.of("persistent-nameid-ascii-256"), outcome.details().get("unverifiable_fixtures"));
        assertFalse(outcome.details().containsKey("violating_fixtures"));
    }

    private static java.util.List<com.samlscope.saml.normal.SamlTypedStringFixtures.Fixture> userDefinedValueFixtures() {
        return com.samlscope.saml.normal.SamlTypedStringFixtures.matrix().stream()
                .filter(f -> (f.placement() == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.ADVICE_STRING
                        || f.placement() == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.ATTRIBUTE_VALUE_STRING)
                        && (f.characters() == com.samlscope.saml.normal.SamlErrorProbeRequestFactory.Probe.STRING_ASCII_255
                        || f.characters() == com.samlscope.saml.normal.SamlErrorProbeRequestFactory.Probe.STRING_ASCII_256))
                .toList();
    }

    @Test void detectsAMismatchingSubjectEvenWhenAnotherAssertionMatches() {
        var test = scenario("IIP-SSO07-b-idp-01");
        var wait = controlled(test);
        var request = SecureXml.parse(wait.actions().getFirst().payload());
        String expected = request.getElementsByTagNameNS(SAML, "NameID").item(0).getTextContent();
        for (String subject : new String[]{"unrelated", expected.toUpperCase(java.util.Locale.ROOT), " " + expected}) {
            var result = assertInstanceOf(CaseStep.Finish.class, reply(test, wait, true,
                    assertion(expected, FORMAT) + assertion(subject, FORMAT))).outcome();
            assertEquals(Outcome.VIOLATED, result.outcome());
        }
        assertEquals(Outcome.NOT_VERIFIED, assertInstanceOf(CaseStep.Finish.class,
                reply(test, wait, true, assertion(expected, FORMAT))).outcome().outcome());
        assertEquals(Outcome.NOT_VERIFIED, assertInstanceOf(CaseStep.Finish.class,
                reply(test, wait, false, "")).outcome().outcome());
        assertEquals(Outcome.NOT_VERIFIED, assertInstanceOf(CaseStep.Finish.class,
                reply(test, wait, true, "<saml:EncryptedAssertion/>")).outcome().outcome());
    }
    @Test void controlsAndUnknownDeliveryCannotBecomeTargetFailures() {
        for (String id : new String[]{"IIP-G02-a-idp-01", "IIP-G03-b-idp-01", "IIP-SSO07-b-idp-01"}) {
            var test = scenario(id);
            var initial = assertInstanceOf(CaseStep.AwaitInbound.class, test.start(context()));
            assertEquals("control_failed", assertInstanceOf(CaseStep.Finish.class,
                    reply(test, initial, false, "")).outcome().reasonCode());
            var wait = controlled(test);
            var result = assertInstanceOf(CaseStep.Finish.class,
                    test.resume(context(), wait.next(), new CaseEvent.TimedOut(Duration.ofMinutes(2))));
            assertEquals(Outcome.NOT_VERIFIED, result.outcome().outcome());
        }
    }
    @Test void extensionElementMatrixRequiresEveryCorrelatedSuccessAndRejectsTerminalOnlyEvidence() {
        for (int unavailable = -1; unavailable < 4; unavailable++) {
            var test = scenario("IIP-EXT01-b-idp-01");
            CaseStep step = test.start(context());
            for (int index = 0; index < 4; index++) {
                var wait = assertInstanceOf(CaseStep.AwaitInbound.class, step);
                if (index == unavailable) {
                    step = test.resume(context(), wait.next(), new CaseEvent.BrowserObservation(
                            400, "https://idp.example/error", "local error",
                            new EvidenceRef("transcript", "terminal-" + index)));
                } else {
                    step = reply(test, wait, true, "<saml:Assertion/>");
                }
            }
            var outcome = assertInstanceOf(CaseStep.Finish.class, step).outcome();
            assertEquals(unavailable < 0 ? Outcome.SATISFIED : Outcome.NOT_VERIFIED, outcome.outcome());
            if (unavailable >= 0) assertEquals(
                    java.util.List.of(new String[]{"baseline-success", "unknown-extension",
                            "unknown-advice-extension", "unknown-metadata-extension"}[unavailable]),
                    outcome.details().get("unverifiable_fixtures"));
        }
    }

    @Test void extensionElementAndAttributeErrorsOrUnknownDeliveryRemainNotVerified() {
        for (String id : java.util.List.of("IIP-EXT01-b-idp-01", "IIP-EXT01-c-idp-01")) {
            var test = scenario(id);
            var baseline = assertInstanceOf(CaseStep.AwaitInbound.class, test.start(context()));
            assertEquals("control_failed", assertInstanceOf(CaseStep.Finish.class,
                    reply(test, baseline, false, "")).outcome().reasonCode());

            test = scenario(id);
            baseline = assertInstanceOf(CaseStep.AwaitInbound.class, test.start(context()));
            var next = assertInstanceOf(CaseStep.AwaitInbound.class,
                    reply(test, baseline, true, "<saml:Assertion/>"));
            var timedOut = assertInstanceOf(CaseStep.Finish.class,
                    test.resume(context(), next.next(), new CaseEvent.TimedOut(Duration.ofMinutes(2)))).outcome();
            assertEquals(Outcome.NOT_VERIFIED, timedOut.outcome());

            test = scenario(id);
            CaseStep step = test.start(context());
            var total = id.contains("-b-") ? 4 : 3;
            for (int index = 0; index < total; index++) {
                var wait = assertInstanceOf(CaseStep.AwaitInbound.class, step);
                step = reply(test, wait, index != 1, index == 1 ? "" : "<saml:Assertion/>");
            }
            assertEquals(Outcome.NOT_VERIFIED,
                    assertInstanceOf(CaseStep.Finish.class, step).outcome().outcome());
        }
    }

    @Test void supplementalMetadataObservationsCompleteOnlyWithBothProtocolElements() {
        var entries = new java.util.ArrayList<com.samlscope.core.transcript.TranscriptEntry>();
        var variants = new java.util.ArrayList<String>();
        variants.add("control");
        java.util.Arrays.stream(com.samlscope.saml.metadata.MetadataService.Variant.values())
                .map(com.samlscope.saml.metadata.MetadataService.Variant::id)
                .filter(v -> v.startsWith("foreign-attribute-")).forEach(variants::add);
        String run = context().runId();
        for (String variant : variants) {
            for (boolean fetch : new boolean[]{true, false}) {
                int index = entries.size();
                entries.add(new com.samlscope.core.transcript.TranscriptEntry(
                        "metadata-" + index, run, com.samlscope.core.transcript.Direction.INBOUND,
                        context().clock().instant().plusSeconds(index), "corr", "GET",
                        fetch ? "https://suite.example/metadata/live" :
                                "https://suite.example/sp/acs/0?run=" + run + "&mdv=" + variant,
                        200, java.util.Map.of(), null, 0, fetch ? null : "decoded", fetch ? 0 : 10,
                        null, null, fetch ? java.util.Map.of("type", "MetadataFetch", "variant", variant) :
                                java.util.Map.of("type", "SAMLResponse", "metadataProbeAccepted", true,
                                        "statusCode", "urn:oasis:names:tc:SAML:2.0:status:Success")));
            }
        }
        var recorder = new com.samlscope.core.transcript.TranscriptRecorder() {
            public com.samlscope.core.transcript.TranscriptEntry record(com.samlscope.core.transcript.TranscriptInput input) {
                throw new AssertionError("Snapshot must not write a transcript");
            }
            public com.samlscope.core.transcript.TranscriptEntry updateSamlAnalysis(String entryId, String correlationId,
                    java.util.Map<String,Object> summary) { throw new AssertionError("Snapshot must not mutate evidence"); }
            public java.util.List<com.samlscope.core.transcript.TranscriptEntry> list(String runId) { return entries; }
        };
        for (boolean complete : new boolean[]{true, false}) {
            if (!complete) entries.removeLast();
            var test = scenario("IIP-EXT01-c-idp-01");
            var ctx = context(recorder);
            CaseStep step = test.start(ctx);
            for (int index = 0; index < 3; index++) {
                step = reply(test, assertInstanceOf(CaseStep.AwaitInbound.class, step),
                        true, "<saml:Assertion/>", ctx);
            }
            var result = assertInstanceOf(CaseStep.Finish.class, step).outcome();
            assertEquals(complete ? Outcome.SATISFIED : Outcome.NOT_VERIFIED, result.outcome());
            assertEquals(complete, result.details().get("metadata_attribute_matrix_complete"));
            for (var entry : entries) {
                assertTrue(result.evidence().contains(new EvidenceRef("transcript", "transcript:" + entry.id())));
            }
            assertEquals(entries.size() + 3, result.evidence().size());
            assertEquals(java.util.List.of("SubjectConfirmationData", "Attribute"), result.details().get("completed_protocol_elements"));
            assertEquals(java.util.List.of(), result.details().get("remaining_protocol_elements"));
            if (complete) {
                var replay = scenario("IIP-EXT01-c-idp-01");
                CaseStep replayStep = replay.start(context());
                for (int index = 0; index < 3; index++) {
                    replayStep = reply(replay, assertInstanceOf(CaseStep.AwaitInbound.class, replayStep),
                            true, "<saml:Assertion/>");
                }
                var previous = assertInstanceOf(CaseStep.Finish.class, replayStep).outcome();
                assertEquals(Outcome.NOT_VERIFIED, previous.outcome());
                assertTrue(replay.supportsRecordedEvidenceReevaluation(previous));
                var reevaluated = replay.reevaluateRecordedEvidence(ctx, previous).orElseThrow();
                assertEquals(Outcome.SATISFIED, reevaluated.outcome());
                assertEquals(true, reevaluated.details().get("metadata_attribute_matrix_complete"));
                assertEquals(entries.size() + 3, reevaluated.evidence().size());
            }
        }
    }
    @Test void encryptedSubjectMatrixUsesTargetKeysAndDetectsMismatchesWithPlainOrEncryptedReplies() throws Exception {
        var generator = java.security.KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        var target = generator.generateKeyPair(); var suite = generator.generateKeyPair();
        var matrix = com.samlscope.saml.crypto.SamlEncryptionFixtureFactory.matrix();
        for (boolean encryptedReply : new boolean[]{false, true}) for (int bad = -1; bad < matrix.size(); bad++) {
            var test = new IdpExecutableBrowserFixtureScenarioTestCase("IIP-SSO07-b-idp-01", ignored ->
                    new IdpErrorProbeConfiguration(URI.create("https://idp.example/sso"), "https://suite.example/sp",
                            URI.create("https://suite.example/acs"), Duration.ofMinutes(2), true, true, true,
                            java.util.List.of(target.getPublic())), ignored -> java.util.Optional.of(suite.getPrivate()));
            var plain = controlled(test);
            var plainRequest = SecureXml.parse(plain.actions().getFirst().payload());
            var plainId = (org.w3c.dom.Element) plainRequest.getElementsByTagNameNS(SAML, "NameID").item(0);
            CaseStep step = reply(test, plain, true, assertion(plainId.getTextContent(), plainId.getAttribute("Format")));
            for (int i=0; i<matrix.size(); i++) {
                var wait = assertInstanceOf(CaseStep.AwaitInbound.class, step);
                var request = SecureXml.parse(wait.actions().getFirst().payload());
                assertTrue(com.samlscope.saml.normal.SamlSchemaValidation.isValid(request.getDocumentElement(),
                        com.samlscope.saml.normal.SamlSchemaValidation.SchemaKind.PROTOCOL));
                assertEquals(0, request.getElementsByTagNameNS(SAML, "NameID").getLength());
                var encrypted = (org.w3c.dom.Element)request.getElementsByTagNameNS(SAML,"EncryptedID").item(0);
                var nameId = new com.samlscope.saml.crypto.SamlXmlDecrypter().decrypt(encrypted,target.getPrivate());
                assertEquals("NameID",nameId.getLocalName());
                String value = i==bad ? "different-principal" : nameId.getTextContent();
                String returned = assertion(value,nameId.getAttribute("Format"));
                if (encryptedReply) {
                    var document=SecureXml.parse(("<saml:NameID xmlns:saml='"+SAML+"' Format='"+nameId.getAttribute("Format")+"'>"+value+"</saml:NameID>").getBytes(StandardCharsets.UTF_8));
                    var wrapper=new com.samlscope.saml.crypto.SamlEncryptionFixtureFactory().encrypt(
                            com.samlscope.saml.crypto.SamlEncryptionFixtureFactory.Wrapper.EncryptedID,
                            document.getDocumentElement(),suite.getPublic(),matrix.get(i));
                    returned="<saml:Assertion><saml:Subject>"+new String(SecureXml.serialize(wrapper.getOwnerDocument()),StandardCharsets.UTF_8).replaceFirst("<[?]xml[^>]*[?]>", "")
                            +"</saml:Subject></saml:Assertion>";
                }
                step=reply(test,wait,true,returned);
            }
            var result=assertInstanceOf(CaseStep.Finish.class,step).outcome();
            assertEquals(bad<0 ? Outcome.NOT_VERIFIED : Outcome.VIOLATED,result.outcome(),
                    "mismatch="+bad+" encryptedReply="+encryptedReply);
        }
    }

    @Test void unreadableOrForeignAssertionsCannotCauseOrHideAnIdentifierViolation() throws Exception {
        var keys=java.security.KeyPairGenerator.getInstance("RSA");keys.initialize(2048);var pair=keys.generateKeyPair();
        var test=new IdpExecutableBrowserFixtureScenarioTestCase("IIP-SSO07-b-idp-01",ignored ->
                new IdpErrorProbeConfiguration(URI.create("https://idp.example/sso"),"https://suite.example/sp",
                        URI.create("https://suite.example/acs"),Duration.ofMinutes(2),true,true,true),
                ignored -> java.util.Optional.of(pair.getPrivate()));
        var wait=controlled(test);
        var foreignAssertion=SecureXml.parse(("<foreign:Assertion xmlns:foreign='urn:foreign' xmlns:saml='"+SAML+"'><saml:Subject><saml:NameID Format='"+FORMAT+"'>different</saml:NameID></saml:Subject></foreign:Assertion>").getBytes(StandardCharsets.UTF_8));
        var factory=new com.samlscope.saml.crypto.SamlEncryptionFixtureFactory();
        var algorithm=com.samlscope.saml.crypto.SamlEncryptionFixtureFactory.matrix().getFirst();
        var foreign=factory.encrypt(com.samlscope.saml.crypto.SamlEncryptionFixtureFactory.Wrapper.EncryptedAssertion,
                foreignAssertion.getDocumentElement(),pair.getPublic(),algorithm);
        String foreignXml=new String(SecureXml.serialize(foreign.getOwnerDocument()),StandardCharsets.UTF_8).replaceFirst("<[?]xml[^>]*[?]>", "");
        var foreignName=SecureXml.parse(("<foreign:NameID xmlns:foreign='urn:foreign' Format='"+FORMAT+"'>different</foreign:NameID>").getBytes(StandardCharsets.UTF_8));
        var encryptedName=factory.encrypt(com.samlscope.saml.crypto.SamlEncryptionFixtureFactory.Wrapper.EncryptedID,
                foreignName.getDocumentElement(),pair.getPublic(),algorithm);
        String nameXml="<saml:Assertion><saml:Subject>"+new String(SecureXml.serialize(encryptedName.getOwnerDocument()),StandardCharsets.UTF_8).replaceFirst("<[?]xml[^>]*[?]>", "")+"</saml:Subject></saml:Assertion>";
        for(String unreadable:java.util.List.of("<saml:EncryptedAssertion/>",foreignXml,nameXml)) {
            assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,reply(test,wait,true,unreadable)).outcome().outcome());
            for(String xml:java.util.List.of(unreadable+assertion("different",FORMAT),assertion("different",FORMAT)+unreadable))
                assertEquals(Outcome.VIOLATED,assertInstanceOf(CaseStep.Finish.class,reply(test,wait,true,xml)).outcome().outcome());
        }
        for(String ambiguous:java.util.List.of(
                "<saml:Assertion><saml:Subject><saml:NameID>different</saml:NameID><saml:NameID>other</saml:NameID></saml:Subject></saml:Assertion>",
                "<saml:Assertion><saml:Subject><saml:NameID>different</saml:NameID></saml:Subject><saml:Subject><saml:NameID>other</saml:NameID></saml:Subject></saml:Assertion>"))
            assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,reply(test,wait,true,ambiguous)).outcome().outcome());
    }

    private static String assertion(String value, String format) {
        return "<saml:Assertion><saml:Subject><saml:NameID Format='" + format + "'>" + value
                + "</saml:NameID></saml:Subject></saml:Assertion>";
    }

    private static java.util.List<com.samlscope.saml.normal.SamlTypedStringFixtures.Fixture> nameIdStringFixtures() {
        return com.samlscope.saml.normal.SamlTypedStringFixtures.matrix().stream()
                .filter(f -> (f.placement() == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.PERSISTENT_NAMEID
                        || f.placement() == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.TRANSIENT_NAMEID)
                        && f.characters() == com.samlscope.saml.normal.SamlErrorProbeRequestFactory.Probe.STRING_ASCII_256)
                .toList();
    }
}
