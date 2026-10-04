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
        implements TestCase, BrowserFrontChannelScenario, BrowserPrompt, ProtocolEvidenceCase,
        com.samlscope.runner.RecordedEvidenceReevaluation {
    public static final List<String> CASE_IDS = List.of(
            "IIP-EXT01-b-idp-01", "IIP-EXT01-c-idp-01", "IIP-G01-a-idp-01",
            "IIP-G02-a-idp-01", "IIP-G03-b-idp-01",
            "IIP-MD05-f5-idp-01", "IIP-MD05-fg-idp-01", "IIP-SSO01-eb-idp-01",
            "IIP-SSO01-i2-idp-01", "IIP-SSO04-a-idp-01", "IIP-SSO05-a3-idp-01",
            "IIP-SSO07-b-idp-01");
    public static final String G03_CASE = "IIP-G03-b-idp-01";

    private final String id;
    private final java.util.function.Function<String, IdpErrorProbeConfiguration> configurations;
    private final SamlErrorProbeRequestFactory requests;
    private final SamlDecryptionKeyProvider decryptionKeys;
    private final java.util.function.Function<CaseContext, java.util.Optional<com.samlscope.core.evaluation.CaseOutcome>> nativeDtdEvidence;
    private final java.util.function.Function<CaseContext, java.util.Optional<com.samlscope.core.evaluation.CaseOutcome>> nativePairwiseEvidence;

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
        this(id, configurations, requests, decryptionKeys, ignored -> java.util.Optional.empty());
    }

    private IdpExecutableBrowserFixtureScenarioTestCase(String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlErrorProbeRequestFactory requests, SamlDecryptionKeyProvider decryptionKeys,
            java.util.function.Function<CaseContext, java.util.Optional<com.samlscope.core.evaluation.CaseOutcome>> nativeDtdEvidence) {
        this(id, configurations, requests, decryptionKeys, nativeDtdEvidence, ignored -> java.util.Optional.empty());
    }

    private IdpExecutableBrowserFixtureScenarioTestCase(String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlErrorProbeRequestFactory requests, SamlDecryptionKeyProvider decryptionKeys,
            java.util.function.Function<CaseContext, java.util.Optional<com.samlscope.core.evaluation.CaseOutcome>> nativeDtdEvidence,
            java.util.function.Function<CaseContext, java.util.Optional<com.samlscope.core.evaluation.CaseOutcome>> nativePairwiseEvidence) {
        if (!CASE_IDS.contains(id)) throw new IllegalArgumentException("Unsupported executable browser case: " + id);
        this.id = id;
        this.configurations = java.util.Objects.requireNonNull(configurations, "configurations");
        this.requests = java.util.Objects.requireNonNull(requests, "requests");
        this.decryptionKeys = java.util.Objects.requireNonNull(decryptionKeys, "decryptionKeys");
        this.nativeDtdEvidence = java.util.Objects.requireNonNull(nativeDtdEvidence, "nativeDtdEvidence");
        this.nativePairwiseEvidence = java.util.Objects.requireNonNull(nativePairwiseEvidence, "nativePairwiseEvidence");
    }

    public IdpExecutableBrowserFixtureScenarioTestCase withNativeDtdEvidence(
            java.nio.file.Path directory, com.samlscope.core.transcript.TranscriptContentReader content,
            java.util.function.Function<String, byte[]> metadata) {
        if (!G03_CASE.equals(id)) throw new IllegalStateException("Native DTD evidence is only for G03.b");
        return new IdpExecutableBrowserFixtureScenarioTestCase(id, configurations, requests,
                decryptionKeys, new NativeDtdRejectionEvidence(directory, content, metadata), nativePairwiseEvidence);
    }

    public RequestedSubjectMatchTestCase withRequestedSubjectMatchEvidence(
            java.nio.file.Path directory, com.samlscope.core.transcript.TranscriptContentReader content,
            java.util.function.Function<String, byte[]> metadata) {
        if (!RequestedSubjectMatchTestCase.CASE.equals(id))
            throw new IllegalStateException("Requested-subject evidence is only for SSO07.b");
        return new RequestedSubjectMatchTestCase(this,
                new ShibbolethRequestedSubjectMatchEvidence(directory, content, metadata, decryptionKeys));
    }

    public IdpExecutableBrowserFixtureScenarioTestCase withPersistentPairwiseEvidence(
            java.nio.file.Path directory, com.samlscope.core.transcript.TranscriptContentReader content,
            java.util.function.Function<String, byte[]> metadata) {
        if (!PersistentPairwiseNameIdEvidence.CASE.equals(id))
            throw new IllegalStateException("Pairwise evidence is only for SSO05.a3");
        var proof = new PersistentPairwiseNameIdEvidence(directory, content, metadata, decryptionKeys);
        var simpleSamlPhp = new SimpleSamlPhpPersistentPairwiseEvidence(directory, content, metadata);
        var keycloak = new KeycloakPersistentPairwiseEvidence(directory, content, metadata, decryptionKeys);
        return new IdpExecutableBrowserFixtureScenarioTestCase(id, configurations, requests,
                decryptionKeys, nativeDtdEvidence, context -> {
                    boolean keycloakOwned = keycloak.exists(context.runId());
                    boolean legacyOwned = java.nio.file.Files.exists(directory.resolve(context.runId()),
                            java.nio.file.LinkOption.NOFOLLOW_LINKS);
                    if (keycloakOwned && legacyOwned)
                        return java.util.Optional.of(com.samlscope.core.evaluation.CaseOutcome.notVerified(
                                "ambiguous_native_pairwise_product", "idp.persistent-pairwise.unproven"));
                    if (keycloakOwned) return keycloak.evaluate(context);
                    var shibboleth = proof.evaluate(context);
                    var observed = shibboleth.isPresent() ? shibboleth : simpleSamlPhp.evaluate(context);
                    return observed.isPresent() || !legacyOwned ? observed
                            : java.util.Optional.of(com.samlscope.core.evaluation.CaseOutcome.notVerified(
                                    "native_pairwise_originals_unproven", "idp.persistent-pairwise.unproven"));
                });
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
            for (var typed : nameIdStringFixtures()) {
                fixtures.add(new PartialFixture(typed.id().replace(':', '-'), Probe.BASELINE_SUCCESS,
                        configuration, requests, false, id, null, null, typed));
            }
            for (var typed : extensionStringFixtures()) {
                fixtures.add(new PartialFixture(typed.id().replace(':', '-'), typed.characters(),
                        configuration, requests, false, id, null, null, typed));
            }
            for (var typed : userDefinedValueFixtures()) {
                fixtures.add(new PartialFixture(typed.id().replace(':', '-'), Probe.BASELINE_SUCCESS,
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

    private static List<com.samlscope.saml.normal.SamlTypedStringFixtures.Fixture> nameIdStringFixtures() {
        return com.samlscope.saml.normal.SamlTypedStringFixtures.matrix().stream()
                .filter(f -> (f.placement() == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.PERSISTENT_NAMEID
                        || f.placement() == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.TRANSIENT_NAMEID)
                        && f.characters() == Probe.STRING_ASCII_256)
                .toList();
    }

    private static List<com.samlscope.saml.normal.SamlTypedStringFixtures.Fixture> userDefinedValueFixtures() {
        return com.samlscope.saml.normal.SamlTypedStringFixtures.matrix().stream()
                .filter(f -> (f.placement() == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.ADVICE_STRING
                        || f.placement() == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.ATTRIBUTE_VALUE_STRING)
                        && (f.characters() == Probe.STRING_ASCII_255 || f.characters() == Probe.STRING_ASCII_256))
                .toList();
    }

    private List<Probe> probes() {
        return switch (id) {
            case "IIP-EXT01-b-idp-01" -> List.of(
                    Probe.BASELINE_SUCCESS,
                    Probe.UNKNOWN_EXTENSION,
                    Probe.UNKNOWN_ADVICE_EXTENSION,
                    Probe.UNKNOWN_METADATA_EXTENSION);
            case "IIP-EXT01-c-idp-01" -> List.of(
                    Probe.BASELINE_SUCCESS,
                    Probe.UNKNOWN_ANY_ATTRIBUTE,
                    Probe.UNKNOWN_ATTRIBUTE_ANY_ATTRIBUTE);
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
    @Override public CaseStep start(CaseContext context) {
        var observed = recordedPersistentPairwise(context);
        return observed.<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> scenario(context.runId()).start(context));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (PersistentPairwiseNameIdEvidence.CASE.equals(id)) {
            var observed = recordedPersistentPairwise(context);
            if (observed.isPresent()) return new CaseStep.Finish(observed.orElseThrow());
        }
        if (G03_CASE.equals(id) && event instanceof CaseEvent.TranscriptReady) {
            var observed = nativeDtdEvidence.apply(context);
            if (observed.isPresent() && observed.orElseThrow().outcome() == com.samlscope.core.evaluation.Outcome.SATISFIED)
                return new CaseStep.Finish(observed.orElseThrow());
        }
        var step = withExtensionCoverage(context, withStringCoverage(scenario(context.runId()).resume(context, state, event)));
        if (PersistentPairwiseNameIdEvidence.CASE.equals(id) && step instanceof CaseStep.Finish) {
            var observed = nativePairwiseEvidence.apply(context);
            if (observed.isPresent()) return new CaseStep.Finish(observed.orElseThrow());
        }
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

    java.util.Optional<com.samlscope.core.evaluation.CaseOutcome> recordedPersistentPairwise(CaseContext context) {
        return PersistentPairwiseNameIdEvidence.CASE.equals(id)
                ? nativePairwiseEvidence.apply(context) : java.util.Optional.empty();
    }

    @Override public boolean supportsRecordedEvidenceReevaluation(com.samlscope.core.evaluation.CaseOutcome previous) {
        if (previous == null || previous.outcome() != com.samlscope.core.evaluation.Outcome.NOT_VERIFIED) return false;
        if (G03_CASE.equals(id)) return true;
        if (PersistentPairwiseNameIdEvidence.CASE.equals(id))
            return java.util.Set.of("browser_fixture_partial", "idp.persistent-pairwise.unproven")
                    .contains(String.valueOf(previous.reasonCode()));
        return "IIP-EXT01-c-idp-01".equals(id)
                && "browser_fixture_partial".equals(previous.reasonCode())
                && List.of("SubjectConfirmationData", "Attribute").equals(
                        previous.details().get("completed_protocol_elements"))
                && (!(previous.details().get("unverifiable_fixtures") instanceof List<?> values)
                        || values.isEmpty());
    }

    @Override public java.util.Optional<com.samlscope.core.evaluation.CaseOutcome> reevaluateRecordedEvidence(
            CaseContext context, com.samlscope.core.evaluation.CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous)) return java.util.Optional.empty();
        if (PersistentPairwiseNameIdEvidence.CASE.equals(id)) {
            if (!context.transcriptComplete()) return java.util.Optional.empty();
            return nativePairwiseEvidence.apply(context)
                    .flatMap(next -> com.samlscope.runner.RecordedEvidenceReevaluation.conclusiveUpdate(previous, next));
        }
        if ("IIP-EXT01-c-idp-01".equals(id)) {
            var metadata = metadataAttributes().recordedObservation(context);
            if (metadata.outcome() != com.samlscope.core.evaluation.Outcome.SATISFIED) {
                return java.util.Optional.empty();
            }
            var evidence = new java.util.LinkedHashSet<>(previous.evidence());
            evidence.addAll(metadata.evidence());
            var details = new java.util.LinkedHashMap<String, Object>(previous.details());
            details.put("metadata_attribute_observations", metadata.details());
            details.put("metadata_attribute_matrix_complete", true);
            details.remove("remaining_metadata_matrix");
            var next = new com.samlscope.core.evaluation.CaseOutcome(
                    com.samlscope.core.evaluation.Outcome.SATISFIED, null,
                    "browser_fixture_satisfied", "case.idp.browser-fixture.satisfied",
                    List.copyOf(evidence), details);
            return com.samlscope.runner.RecordedEvidenceReevaluation.conclusiveUpdate(previous, next);
        }
        return nativeDtdEvidence.apply(context)
                .flatMap(next -> com.samlscope.runner.RecordedEvidenceReevaluation.conclusiveUpdate(previous, next));
    }

    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        if (PersistentPairwiseNameIdEvidence.CASE.equals(id)) {
            var ready = nativePairwiseEvidence.apply(context).map(value ->
                    java.util.Set.of(com.samlscope.core.evaluation.Outcome.SATISFIED,
                            com.samlscope.core.evaluation.Outcome.SATISFIED_WITH_NOTE,
                            com.samlscope.core.evaluation.Outcome.VIOLATED).contains(value.outcome())).orElse(false);
            var required = List.of("same-principal-primary-peer", "same-principal-secondary-peer",
                    "native-generator-and-audit", "configuration-restoration");
            return new EvidenceStatus(ready, required, ready ? required : List.of(), Map.of());
        }
        if (!G03_CASE.equals(id)) return new EvidenceStatus(false, List.of(), List.of(), Map.of());
        var ready = nativeDtdEvidence.apply(context).stream()
                .anyMatch(value -> value.outcome() == com.samlscope.core.evaluation.Outcome.SATISFIED);
        var required = List.of("baseline-success", "dtd-authn-request", "dtd-external-entity-authn-request");
        return new EvidenceStatus(ready, required, ready ? required : List.of(), Map.of());
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
        details.put("completed_protocol_elements", List.of("SubjectConfirmationData", "Attribute"));
        details.put("remaining_protocol_elements", List.of());
        var outcome = finish.outcome();
        if (outcome.outcome() == com.samlscope.core.evaluation.Outcome.SATISFIED
                && !Boolean.TRUE.equals(details.get("metadata_attribute_matrix_complete"))) {
            details.put("remaining_metadata_matrix", metadataAttributes().evidenceActionKeys().stream()
                    .filter(value -> !"control".equals(value)).toList());
            return new CaseStep.Finish(new com.samlscope.core.evaluation.CaseOutcome(
                    com.samlscope.core.evaluation.Outcome.NOT_VERIFIED,
                    "metadata_attribute_matrix_incomplete", "browser_fixture_partial",
                    "case.idp.browser-fixture.partial", List.copyOf(evidence), details));
        }
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
        var acceptedUserDefinedValues = userDefinedValueFixtures().stream()
                .map(f -> f.id().replace(':', '-'))
                .filter(value -> !unknown.contains(value) && !violated.contains(value)).toList();
        details.put("responded_user_defined_value_fixtures", acceptedUserDefinedValues);
        var remaining = new java.util.ArrayList<>(List.of("persistent-nameid", "transient-nameid",
                "user-defined-advice-string", "user-defined-attribute-value-string",
                "user-defined-extension-string-attribute", "literal-tab-and-lf-on-wire"));
        var confirmedTypes = new java.util.ArrayList<String>();
        var acceptedNameIds = nameIdStringFixtures().stream()
                .map(f -> f.id().replace(':', '-'))
                .filter(value -> !unknown.contains(value) && !violated.contains(value)).toList();
        details.put("responded_nameid_string_fixtures", acceptedNameIds);
        for (var placement : List.of(
                com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.PERSISTENT_NAMEID,
                com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.TRANSIENT_NAMEID)) {
            var type = placement.name().toLowerCase(java.util.Locale.ROOT).replace('_', '-');
            var expected = nameIdStringFixtures().stream().filter(f -> f.placement() == placement).count();
            var accepted = nameIdStringFixtures().stream().filter(f -> f.placement() == placement)
                    .map(f -> f.id().replace(':', '-')).filter(acceptedNameIds::contains).count();
            if (expected > 0 && accepted == expected) {
                confirmedTypes.add(type);
                remaining.remove(type);
            }
        }
        // G02.a accepts a completed, error-free flow even if the extension is ignored.
        // Preservation/readback belongs to G02.b/c; do not impose it on this obligation.
        if (acceptedExtensions.size() == extensionStringFixtures().size()) {
            confirmedTypes.add("user-defined-extension-string-attribute");
            remaining.remove("user-defined-extension-string-attribute");
        }
        for (var placement : List.of(
                com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.ADVICE_STRING,
                com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.ATTRIBUTE_VALUE_STRING)) {
            var expected = userDefinedValueFixtures().stream().filter(f -> f.placement() == placement).count();
            var accepted = userDefinedValueFixtures().stream().filter(f -> f.placement() == placement)
                    .map(f -> f.id().replace(':', '-')).filter(acceptedUserDefinedValues::contains).count();
            if (expected == 0 || accepted != expected) continue;
            var condition = placement == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.ADVICE_STRING
                    ? "user-defined-advice-string" : "user-defined-attribute-value-string";
            confirmedTypes.add(condition);
            remaining.remove(condition);
        }
        if (!confirmedTypes.isEmpty()) details.put("confirmed_type_conditions", List.copyOf(confirmedTypes));
        boolean literalObserved = SamlErrorProbeRequestFactory.stringProbes().stream()
                .filter(probe -> probe.name().contains("_LITERAL_"))
                .flatMap(probe -> java.util.stream.Stream.of(probe.name(), probe.name().replace("_LITERAL_", "_REFERENCE_")))
                .map(name -> name.toLowerCase(java.util.Locale.ROOT).replace('_', '-'))
                .allMatch(name -> !unknown.contains(name) && !violated.contains(name));
        if (literalObserved) remaining.remove("literal-tab-and-lf-on-wire");
        details.put("remaining_conditions", List.copyOf(remaining));
        if (outcome.outcome() == com.samlscope.core.evaluation.Outcome.SATISFIED && !remaining.isEmpty()) {
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
                // A typed fragment is the only request content changed by this fixture.
                root.removeAttribute("ProviderName");
                var fragment = document.importNode(typedString.create(), true);
                var issuer = direct(root, "urn:oasis:names:tc:SAML:2.0:assertion", "Issuer");
                switch (typedString.placement()) {
                    case EXTENSION_STRING_ATTRIBUTE -> root.insertBefore(fragment, issuer.getNextSibling());
                    case PERSISTENT_NAMEID, TRANSIENT_NAMEID -> {
                        var subject = document.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Subject");
                        subject.appendChild(fragment);
                        root.appendChild(subject);
                    }
                    case ADVICE_STRING, ATTRIBUTE_VALUE_STRING -> {
                        var extension = document.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "samlp:Extensions");
                        var assertion = document.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Assertion");
                        assertion.setAttribute("Version", "2.0");
                        assertion.setAttribute("ID", "_fixture" + requestId);
                        assertion.setAttribute("IssueInstant", issueInstant.toString());
                        var assertionIssuer = document.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Issuer");
                        assertionIssuer.setTextContent(configuration.suiteIssuer());
                        assertion.appendChild(assertionIssuer);
                        if (typedString.placement()
                                == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.ADVICE_STRING) {
                            assertion.appendChild(fragment);
                        } else {
                            var statement = document.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:AttributeStatement");
                            var attribute = document.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Attribute");
                            attribute.setAttribute("Name", "urn:samlscope:fixture:string");
                            attribute.appendChild(fragment);
                            statement.appendChild(attribute);
                            assertion.appendChild(statement);
                        }
                        extension.appendChild(assertion);
                        root.insertBefore(extension, issuer.getNextSibling());
                    }
                }
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
                if (List.of("IIP-EXT01-b-idp-01", "IIP-EXT01-c-idp-01").contains(caseId)) {
                    var status = direct(root, "urn:oasis:names:tc:SAML:2.0:protocol", "Status");
                    var code = status == null ? null
                            : direct(status, "urn:oasis:names:tc:SAML:2.0:protocol", "StatusCode");
                    var success = code != null
                            && "urn:oasis:names:tc:SAML:2.0:status:Success".equals(code.getAttribute("Value"));
                    var assertion = direct(root, "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
                    var encrypted = direct(root, "urn:oasis:names:tc:SAML:2.0:assertion", "EncryptedAssertion");
                    if (probe == Probe.BASELINE_SUCCESS) {
                        return success && (assertion != null || encrypted != null)
                                ? FixtureObservation.SATISFIED : FixtureObservation.CONTROL_FAILED;
                    }
                    // The requirement permits the content to be ignored. Only a correlated
                    // successful SAML flow proves that this schema-valid input caused no software
                    // failure. Errors, HTTP terminal pages, and silence remain inconclusive.
                    return success && (assertion != null || encrypted != null)
                            ? FixtureObservation.SATISFIED : FixtureObservation.NOT_VERIFIED;
                }
                if (List.of("IIP-G02-a-idp-01", "IIP-G03-b-idp-01", "IIP-SSO07-b-idp-01").contains(caseId)) {
                    var status = direct(root, "urn:oasis:names:tc:SAML:2.0:protocol", "Status");
                    var code = status == null ? null : direct(status, "urn:oasis:names:tc:SAML:2.0:protocol", "StatusCode");
                    if (code == null || code.getAttribute("Value").isBlank()) return FixtureObservation.NOT_VERIFIED;
                    var success = "urn:oasis:names:tc:SAML:2.0:status:Success".equals(code.getAttribute("Value"));
                    var assertion = direct(root, "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
                    var encrypted = direct(root, "urn:oasis:names:tc:SAML:2.0:assertion", "EncryptedAssertion");
                    if (probe == Probe.BASELINE_SUCCESS && typedString == null) {
                        return success && (assertion != null || encrypted != null)
                                ? FixtureObservation.SATISFIED : FixtureObservation.CONTROL_FAILED;
                    }
                    if ("IIP-G03-b-idp-01".equals(caseId) && success && (assertion != null || encrypted != null)) {
                        return FixtureObservation.VIOLATED;
                    }
                    if ("IIP-G02-a-idp-01".equals(caseId)) {
                        if (!success) {
                            if (typedString != null && (typedString.placement()
                                    == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.ADVICE_STRING
                                    || typedString.placement()
                                    == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.ATTRIBUTE_VALUE_STRING)) {
                                // A rejected assertion nested in Extensions can reflect unrelated
                                // extension or assertion policy. Only success proves acceptance.
                                return FixtureObservation.NOT_VERIFIED;
                            }
                            // A long requested subject can be unknown for unrelated identity or
                            // policy reasons. Without a provisioned matching principal, that is
                            // not evidence that the string length caused the error.
                            if (typedString != null && (typedString.placement()
                                    == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.PERSISTENT_NAMEID
                                    || typedString.placement()
                                    == com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.TRANSIENT_NAMEID)) {
                                return FixtureObservation.NOT_VERIFIED;
                            }
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
                            .encodeToString(configuration.encryptionKeys().getFirst().getEncoded()), typedString == null ? "no-typed-string" : typedString.id(), "partial-observation-v8");
        }
    }
}
