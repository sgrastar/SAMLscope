package com.samlscope.runner.cases;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboundKind;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.scenario.FixtureObservation;
import com.samlscope.runner.scenario.FixtureScenarioTestCase;
import com.samlscope.runner.scenario.ScenarioFixture;
import com.samlscope.saml.normal.SamlErrorProbeRequestFactory;
import com.samlscope.saml.normal.SamlErrorProbeRequestFactory.Probe;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;

/**
 * Replaces instruction-only browser completion with real, correlated protocol fixtures. These
 * cases intentionally remain NOT_VERIFIED when the approved obligation contains variants that a
 * remote IdP cannot expose through SAML traffic alone; executing a partial fixture must never be
 * promoted into a false conformance claim.
 */
public final class IdpExecutableBrowserFixtureScenarioTestCase
        implements TestCase, BrowserFrontChannelScenario, BrowserPrompt {
    public static final List<String> CASE_IDS = List.of(
            "IIP-EXT01-b-idp-01", "IIP-EXT01-c-idp-01", "IIP-G01-a-idp-01",
            "IIP-G02-a-idp-01", "IIP-G03-b-idp-01",
            "IIP-MD05-f5-idp-01", "IIP-MD05-fg-idp-01", "IIP-SSO01-eb-idp-01",
            "IIP-SSO01-i2-idp-01", "IIP-SSO04-a-idp-01", "IIP-SSO05-a3-idp-01",
            "IIP-SSO07-b-idp-01");

    private final String id;
    private final java.util.function.Function<String, IdpErrorProbeConfiguration> configurations;
    private final SamlErrorProbeRequestFactory requests;
    private final SamlDecryptionKeyProvider decryptionKeys;

    public IdpExecutableBrowserFixtureScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations) {
        this(id, configurations, new SamlErrorProbeRequestFactory(), ignored -> java.util.Optional.empty());
    }

    public IdpExecutableBrowserFixtureScenarioTestCase(String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlDecryptionKeyProvider decryptionKeys) {
        this(id, configurations, new SamlErrorProbeRequestFactory(), decryptionKeys);
    }

    IdpExecutableBrowserFixtureScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlErrorProbeRequestFactory requests) {
        this(id, configurations, requests, ignored -> java.util.Optional.empty());
    }

    private IdpExecutableBrowserFixtureScenarioTestCase(String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlErrorProbeRequestFactory requests, SamlDecryptionKeyProvider decryptionKeys) {
        if (!CASE_IDS.contains(id)) throw new IllegalArgumentException("Unsupported executable browser case: " + id);
        this.id = id;
        this.configurations = java.util.Objects.requireNonNull(configurations, "configurations");
        this.requests = java.util.Objects.requireNonNull(requests, "requests");
        this.decryptionKeys = java.util.Objects.requireNonNull(decryptionKeys, "decryptionKeys");
    }

    private FixtureScenarioTestCase scenario(String runId) {
        var configuration = java.util.Objects.requireNonNull(configurations.apply(runId));
        var fixtures = new java.util.ArrayList<ScenarioFixture>(probes().stream()
                .map(probe -> (ScenarioFixture) new PartialFixture(
                        probe.name().toLowerCase(java.util.Locale.ROOT).replace('_', '-'),
                        probe, configuration, requests, "IIP-G01-a-idp-01".equals(id), id,
                        decryptionKeys.keyFor(runId).orElse(null), null, null))
                .toList());
        if ("IIP-SSO07-b-idp-01".equals(id) && !configuration.encryptionKeys().isEmpty()) {
            for (var encryption : com.samlscope.saml.crypto.SamlEncryptionFixtureFactory.matrix()) {
                fixtures.add(new PartialFixture("enc-subject-" + encryption.id(), Probe.UNRECOGNIZED_SUBJECT,
                        configuration, requests, false, id, decryptionKeys.keyFor(runId).orElse(null), encryption, null));
            }
        }
        if ("IIP-G02-a-idp-01".equals(id)) {
            for (var typed : extensionStringFixtures()) {
                fixtures.add(new PartialFixture(typed.id().replace(':', '-'), typed.characters(),
                        configuration, requests, false, id, null, null, typed));
            }
        }
        return new FixtureScenarioTestCase(
                id, TargetRole.IDP, fixtures,
                ignored -> configuration.userAgentAvailable()
                        && configuration.acceptableResponseLocationKnown(),
                new FixtureScenarioTestCase.Vocabulary(
                        "browser_fixture_preconditions_unmet", "idp.browser-fixture.preconditions-unmet",
                        "delivery_or_response_unknown", "idp.browser-fixture.delivery-unknown",
                        "scenario_aborted", "idp.browser-fixture.aborted",
                        "case.idp.browser-fixture.control-failed",
                        "browser_fixture_observed_violation", "case.idp.browser-fixture.violated",
                        "additional_variants_not_externally_observable", "browser_fixture_partial",
                        "case.idp.browser-fixture.partial",
                        "browser_fixture_satisfied", "case.idp.browser-fixture.satisfied"));
    }

    private static List<com.samlscope.saml.normal.SamlTypedStringFixtures.Fixture> extensionStringFixtures() {
        return com.samlscope.saml.normal.SamlTypedStringFixtures.matrix().stream()
                .filter(f -> f.placement() == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.EXTENSION_STRING_ATTRIBUTE)
                .toList();
    }

    private List<Probe> probes() {
        return switch (id) {
            case "IIP-EXT01-b-idp-01" -> List.of(Probe.UNKNOWN_EXTENSION);
            case "IIP-EXT01-c-idp-01" -> List.of(Probe.UNKNOWN_ANY_ATTRIBUTE);
            case "IIP-G01-a-idp-01" -> List.of(Probe.BASELINE_SUCCESS);
            case "IIP-G02-a-idp-01" -> java.util.stream.Stream.concat(
                    java.util.stream.Stream.of(Probe.BASELINE_SUCCESS),
                    SamlErrorProbeRequestFactory.stringProbes().stream()).toList();
            case "IIP-G03-b-idp-01" -> List.of(
                    Probe.BASELINE_SUCCESS, Probe.DTD_AUTHN_REQUEST, Probe.DTD_EXTERNAL_ENTITY_AUTHN_REQUEST);
            case "IIP-SSO01-eb-idp-01" -> List.of(
                    Probe.BASELINE_SUCCESS, Probe.ISSUER_TRAILING_WHITESPACE);
            case "IIP-SSO05-a3-idp-01" -> List.of(Probe.PERSISTENT_NAMEID_POLICY);
            case "IIP-SSO07-b-idp-01" -> List.of(Probe.BASELINE_SUCCESS, Probe.UNRECOGNIZED_SUBJECT);
            default -> List.of(Probe.BASELINE_SUCCESS);
        };
    }

    @Override public String id() { return id; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public CaseStep start(CaseContext context) { return scenario(context.runId()).start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        var step = withExtensionCoverage(context, withStringCoverage(scenario(context.runId()).resume(context, state, event)));
        if ("IIP-SSO07-b-idp-01".equals(id) && step instanceof CaseStep.Finish finish
                && configurations.apply(context.runId()).encryptionKeys().isEmpty()) {
            var outcome = finish.outcome();
            var details = new java.util.LinkedHashMap<String,Object>(outcome.details());
            details.put("missing_inputs", List.of("target-encryption-key"));
            return new CaseStep.Finish(new com.samlscope.core.evaluation.CaseOutcome(outcome.outcome(),
                    outcome.notVerifiedReason(), outcome.reasonCode(), outcome.reasonMessageKey(), outcome.evidence(), details));
        }
        return step;
    }

    @Override public List<com.samlscope.runner.EvidenceCampaignCase> supplementalEvidenceCampaigns() {
        return "IIP-EXT01-c-idp-01".equals(id) ? List.of(metadataAttributes()) : List.of();
    }

    private MetadataFixtureObservationTestCase metadataAttributes() {
        var fixtures = java.util.Arrays.stream(com.samlscope.saml.metadata.MetadataService.Variant.values())
                .filter(value -> value.id().startsWith("foreign-attribute-"))
                .map(value -> new MetadataFixtureObservationTestCase.Fixture(value.id(),
                        MetadataFixtureObservationTestCase.Behavior.ACCEPT, "consume a foreign attribute without software failure"))
                .toList();
        return new MetadataFixtureObservationTestCase(id, TargetRole.IDP, fixtures,
                com.samlscope.core.caseexec.ConfigurationFailureSemantics.TEST_PRECONDITION);
    }

    private CaseStep withExtensionCoverage(CaseContext context, CaseStep step) {
        if (!"IIP-EXT01-c-idp-01".equals(id) || !(step instanceof CaseStep.Finish finish)) return step;
        var details = new java.util.LinkedHashMap<String, Object>(finish.outcome().details());
        var evidence = new java.util.LinkedHashSet<>(finish.outcome().evidence());
        if (context.transcript() != null) {
            var observed = metadataAttributes().recordedObservation(context);
            details.put("metadata_attribute_observations", observed.details());
            details.put("metadata_attribute_matrix_complete",
                    observed.outcome() == com.samlscope.core.evaluation.Outcome.SATISFIED);
            evidence.addAll(observed.evidence());
        }
        details.put("remaining_protocol_elements", List.of("SubjectConfirmationData", "Attribute"));
        var outcome = finish.outcome();
        return new CaseStep.Finish(new com.samlscope.core.evaluation.CaseOutcome(outcome.outcome(),
                outcome.notVerifiedReason(), outcome.reasonCode(), outcome.reasonMessageKey(), List.copyOf(evidence), details));
    }

    private CaseStep withStringCoverage(CaseStep step) {
        if (!"IIP-G02-a-idp-01".equals(id) || !(step instanceof CaseStep.Finish finish)) return step;
        var outcome = finish.outcome();
        if (!List.of("browser_fixture_satisfied", "browser_fixture_partial", "browser_fixture_observed_violation")
                .contains(outcome.reasonCode())) return step;
        var details = new java.util.LinkedHashMap<String, Object>(outcome.details());
        var unknown = outcome.details().get("unverifiable_fixtures") instanceof List<?> values ? values : List.of();
        var violated = outcome.details().get("violating_fixtures") instanceof List<?> values ? values : List.of();
        details.put("confirmed_character_fixtures", SamlErrorProbeRequestFactory.stringProbes().stream()
                .map(probe -> probe.name().toLowerCase(java.util.Locale.ROOT).replace('_', '-'))
                .filter(value -> !unknown.contains(value) && !violated.contains(value)).toList());
        var acceptedExtensions = extensionStringFixtures().stream()
                .map(f -> f.id().replace(':', '-'))
                .filter(value -> !unknown.contains(value) && !violated.contains(value)).toList();
        details.put("responded_extension_string_fixtures", acceptedExtensions);
        var remaining = new java.util.ArrayList<>(List.of("persistent-nameid", "transient-nameid",
                "user-defined-advice-string", "user-defined-attribute-value-string",
                "user-defined-extension-string-attribute", "literal-tab-and-lf-on-wire"));
        // G02.a accepts a completed, error-free flow even if the extension is ignored.
        // Preservation/readback belongs to G02.b/c; do not impose it on this obligation.
        if (acceptedExtensions.size() == extensionStringFixtures().size()) {
            details.put("confirmed_type_conditions", List.of("user-defined-extension-string-attribute"));
            remaining.remove("user-defined-extension-string-attribute");
        }
        boolean literalObserved = SamlErrorProbeRequestFactory.stringProbes().stream()
                .filter(probe -> probe.name().contains("_LITERAL_"))
                .flatMap(probe -> java.util.stream.Stream.of(probe.name(), probe.name().replace("_LITERAL_", "_REFERENCE_")))
                .map(name -> name.toLowerCase(java.util.Locale.ROOT).replace('_', '-'))
                .allMatch(name -> !unknown.contains(name) && !violated.contains(name));
        if (literalObserved) remaining.remove("literal-tab-and-lf-on-wire");
        details.put("remaining_conditions", List.copyOf(remaining));
        if (outcome.outcome() == com.samlscope.core.evaluation.Outcome.SATISFIED) {
            return new CaseStep.Finish(new com.samlscope.core.evaluation.CaseOutcome(
                    com.samlscope.core.evaluation.Outcome.NOT_VERIFIED, "additional_type_variants_unverified",
                    "browser_fixture_partial", "case.idp.browser-fixture.partial", outcome.evidence(), details));
        }
        return new CaseStep.Finish(new com.samlscope.core.evaluation.CaseOutcome(outcome.outcome(),
                outcome.notVerifiedReason(), outcome.reasonCode(), outcome.reasonMessageKey(), outcome.evidence(), details));
    }
    @Override public String browserInstructionsEn() {
        return "Run the correlated SAML fixtures for this case. SAMLscope records observable protocol behavior "
                + "and conservatively leaves variants that are not externally provable as not verified; do not enter a verdict.";
    }
    @Override public String instructionsEn(CaseState state) { return browserInstructionsEn(); }

    private record PartialFixture(
            String id,
            Probe probe,
            IdpErrorProbeConfiguration configuration,
            SamlErrorProbeRequestFactory requests,
            boolean useAttestedClockTolerance,
            String caseId,
            java.security.PrivateKey decryptionKey,
            com.samlscope.saml.crypto.SamlEncryptionFixtureFactory.Algorithms encryption,
            com.samlscope.saml.normal.SamlTypedStringFixtures.Fixture typedString) implements ScenarioFixture {
        @Override public Prepared prepare(CaseContext context, String actionId) {
            var requestId = "_" + actionId;
            var issueInstant = context.clock().instant();
            if (useAttestedClockTolerance) {
                issueInstant = issueInstant.minusSeconds(
                        Math.max(0, context.parameters().clockSkewToleranceSeconds() - 1L));
            }
            var payload = requests.build(
                    probe, requestId, configuration.ssoEndpoint(), configuration.suiteIssuer(),
                    configuration.registeredAcs(), issueInstant);
            if (typedString != null) {
                var document = SecureXml.parse(payload);
                var root = document.getDocumentElement();
                // Keep the baseline ProviderName unchanged: this fixture varies only the extension.
                root.removeAttribute("ProviderName");
                var extension = document.importNode(typedString.create(), true);
                var issuer = direct(root, "urn:oasis:names:tc:SAML:2.0:assertion", "Issuer");
                root.insertBefore(extension, issuer.getNextSibling());
                payload = SecureXml.serialize(document);
            }
            if (encryption != null) {
                var document = SecureXml.parse(payload);
                var subject = direct(document.getDocumentElement(), "urn:oasis:names:tc:SAML:2.0:assertion", "Subject");
                var nameId = direct(subject, "urn:oasis:names:tc:SAML:2.0:assertion", "NameID");
                var encrypted = new com.samlscope.saml.crypto.SamlEncryptionFixtureFactory().encrypt(
                        com.samlscope.saml.crypto.SamlEncryptionFixtureFactory.Wrapper.EncryptedID,
                        nameId, configuration.encryptionKeys().getFirst(), encryption);
                subject.replaceChild(document.importNode(encrypted, true), nameId);
                payload = SecureXml.serialize(document);
            }
            return new Prepared(new OutboundAction(
                    actionId, OutboundKind.AUTHN_REQUEST, payload, configuration.ssoEndpoint(), false), requestId);
        }

        @Override public FixtureObservation observe(String requestId, byte[] responseXml) {
            try {
                var root = SecureXml.parse(responseXml).getDocumentElement();
                if (!"urn:oasis:names:tc:SAML:2.0:protocol".equals(root.getNamespaceURI())
                        || !"Response".equals(root.getLocalName())
                        || !requestId.equals(root.getAttribute("InResponseTo"))) {
                    return FixtureObservation.NOT_VERIFIED;
                }
                if (List.of("IIP-G02-a-idp-01", "IIP-G03-b-idp-01", "IIP-SSO07-b-idp-01").contains(caseId)) {
                    var status = direct(root, "urn:oasis:names:tc:SAML:2.0:protocol", "Status");
                    var code = status == null ? null : direct(status, "urn:oasis:names:tc:SAML:2.0:protocol", "StatusCode");
                    if (code == null || code.getAttribute("Value").isBlank()) return FixtureObservation.NOT_VERIFIED;
                    var success = "urn:oasis:names:tc:SAML:2.0:status:Success".equals(code.getAttribute("Value"));
                    var assertion = direct(root, "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
                    var encrypted = direct(root, "urn:oasis:names:tc:SAML:2.0:assertion", "EncryptedAssertion");
                    if (probe == Probe.BASELINE_SUCCESS) {
                        return success && (assertion != null || encrypted != null)
                                ? FixtureObservation.SATISFIED : FixtureObservation.CONTROL_FAILED;
                    }
                    if ("IIP-G03-b-idp-01".equals(caseId) && success && (assertion != null || encrypted != null)) {
                        return FixtureObservation.VIOLATED;
                    }
                    if ("IIP-G02-a-idp-01".equals(caseId)) {
                        if (!success) {
                            // Only a recognized SAML error is evidence of rejection. An unknown
                            // status is malformed/ambiguous evidence, not this string violation.
                            return List.of("urn:oasis:names:tc:SAML:2.0:status:Requester",
                                    "urn:oasis:names:tc:SAML:2.0:status:Responder",
                                    "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch")
                                    .contains(code.getAttribute("Value"))
                                    ? FixtureObservation.VIOLATED : FixtureObservation.NOT_VERIFIED;
                        }
                        return assertion != null || encrypted != null
                                ? FixtureObservation.SATISFIED : FixtureObservation.NOT_VERIFIED;
                    }
                    if ("IIP-SSO07-b-idp-01".equals(caseId) && success) {
                        var expected = SecureXml.parse(requests.build(Probe.UNRECOGNIZED_SUBJECT,
                                requestId, configuration.ssoEndpoint(), configuration.suiteIssuer(),
                                configuration.registeredAcs(), java.time.Instant.EPOCH)).getDocumentElement();
                        var requestedSubject = direct(expected, "urn:oasis:names:tc:SAML:2.0:assertion", "Subject");
                        var requestedId = direct(requestedSubject, "urn:oasis:names:tc:SAML:2.0:assertion", "NameID");
                        for (var child = root.getFirstChild(); child != null; child = child.getNextSibling()) {
                            if (!(child instanceof org.w3c.dom.Element value)
                                    || !"urn:oasis:names:tc:SAML:2.0:assertion".equals(value.getNamespaceURI())) continue;
                            try {
                                if ("EncryptedAssertion".equals(value.getLocalName())) {
                                    if (decryptionKey == null) continue;
                                    value = new com.samlscope.saml.crypto.SamlXmlDecrypter().decrypt(value, decryptionKey);
                                }
                                if (!"urn:oasis:names:tc:SAML:2.0:assertion".equals(value.getNamespaceURI())
                                        || !"Assertion".equals(value.getLocalName())) continue;
                                var subjects = directElements(value, "Subject");
                                if (subjects.size() != 1) continue;
                                var subject = subjects.getFirst();
                                var ids = directElements(subject, "NameID");
                                var encryptedIds = directElements(subject, "EncryptedID");
                                if (ids.size() + encryptedIds.size() + directElements(subject, "BaseID").size() != 1) continue;
                                var returnedId = ids.isEmpty() ? null : ids.getFirst();
                                if (returnedId == null && encryptedIds.size() == 1 && decryptionKey != null) {
                                    returnedId = new com.samlscope.saml.crypto.SamlXmlDecrypter().decrypt(encryptedIds.getFirst(), decryptionKey);
                                }
                                if (returnedId != null && "urn:oasis:names:tc:SAML:2.0:assertion".equals(returnedId.getNamespaceURI())
                                        && "NameID".equals(returnedId.getLocalName())
                                        && (!requestedId.getTextContent().equals(returnedId.getTextContent())
                                        || !requestedId.getAttribute("Format").equals(returnedId.getAttribute("Format")))) {
                                    return FixtureObservation.VIOLATED;
                                }
                            } catch (SamlException unreadableAssertion) {
                                // An unreadable assertion cannot hide a separately observable
                                // mismatch in another assertion. It also cannot prove a mismatch.
                                continue;
                            }
                        }
                    }
                }
                // An observed violation is conclusive, but acceptance of a subset does not prove
                // the other approved variants. No response or a missing key is never a violation.
                return FixtureObservation.NOT_VERIFIED;
            } catch (SamlException malformed) {
                return FixtureObservation.NOT_VERIFIED;
            }
        }

        private static List<org.w3c.dom.Element> directElements(org.w3c.dom.Element parent, String local) {
            var result = new java.util.ArrayList<org.w3c.dom.Element>();
            for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
                if (child instanceof org.w3c.dom.Element element
                        && "urn:oasis:names:tc:SAML:2.0:assertion".equals(element.getNamespaceURI())
                        && local.equals(element.getLocalName())) result.add(element);
            }
            return List.copyOf(result);
        }

        private static org.w3c.dom.Element direct(org.w3c.dom.Element parent, String namespace, String local) {
            for (var node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
                if (node instanceof org.w3c.dom.Element element && namespace.equals(element.getNamespaceURI())
                        && local.equals(element.getLocalName())) return element;
            }
            return null;
        }

        @Override public Duration timeout() { return configuration.responseTimeout(); }
        @Override public String definitionKey() {
            return String.join("|", id, probe.name(), configuration.ssoEndpoint().toString(),
                    configuration.registeredAcs().toString(), Boolean.toString(useAttestedClockTolerance),
                    caseId, encryption == null ? "plain" : encryption.id() + ":" + java.util.Base64.getEncoder()
                            .encodeToString(configuration.encryptionKeys().getFirst().getEncoded()), typedString == null ? "no-typed-string" : typedString.id(), "partial-observation-v7");
        }
    }
}
