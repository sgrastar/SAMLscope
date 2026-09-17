package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import com.samlscope.core.casedef.CaseDefinitionCatalogMapper;
import com.samlscope.core.evaluation.CoverageCatalogMapper;
import com.samlscope.core.evaluation.PredicateCatalogMapper;
import com.samlscope.runner.result.EvaluationArtifactDigests;
import com.samlscope.runner.CaseImplementationAudit;
import com.samlscope.runner.cases.ApprovedAttestedCaseRegistry;
import com.samlscope.runner.cases.ApprovedConfigCaseRegistry;
import com.samlscope.runner.cases.ApprovedBrowserCaseRegistry;
import com.samlscope.runner.cases.BrowserEvidenceTestCase;
import com.samlscope.runner.cases.AttestationPrompt;
import com.samlscope.runner.cases.M2AutomatedCaseRegistry;
import com.samlscope.runner.cases.M3AutomatedCaseRegistry;
import com.samlscope.runner.cases.AttestedOutcomeTestCase;
import com.samlscope.runner.cases.ProtocolEvidenceCase;
import com.samlscope.runner.cases.InformationalChoiceTestCase;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.cases.IdpErrorProbeConfiguration;
import com.samlscope.runner.cases.IdpExecutableBrowserFixtureScenarioTestCase;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.casedef.CaseDefinitionCatalog.ExecutionMode;
import com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone;

class CatalogDocumentsTest {
    @Test
    void embedsAndStrictlyMapsTheSignedG1AndG2Catalogs() throws Exception {
        var documents = CatalogDocuments.load();
        var coverage = CoverageCatalogMapper.fromDocument(documents.parsed("tests/coverage.yaml"));
        var predicates = PredicateCatalogMapper.fromDocument(documents.parsed("tests/predicates.yaml"));
        var cases = CaseDefinitionCatalogMapper.fromDocument(documents.parsed("tests/cases.yaml"));
        var digests = EvaluationArtifactDigests.fromDocuments(
                documents.bytes("tests/coverage.yaml"), documents.testDefinitions(),
                documents.bytes("tests/specs.yaml"));

        assertEquals(544, coverage.obligations().size());
        assertEquals(26, predicates.definitions().size());
        assertEquals(732, cases.cases().size());
        var attested = ApprovedAttestedCaseRegistry.create(cases);
        assertEquals(47, attested.ids().size());
        CaseImplementationAudit.requireExact(cases, attested, Milestone.M1, ExecutionMode.ATTESTED);
        var firstAttestation = (AttestedOutcomeTestCase) attested.require("IIP-G02-c-idp-01");
        assertEquals(java.util.List.of("satisfied", "violated", "unable_to_verify"),
                firstAttestation.options().stream().map(value -> value.value()).toList());
        assertTrue(firstAttestation.promptEn().contains("SPProvidedID"));
        assertTrue(firstAttestation.promptEn().contains("Counterexample to avoid"));
        var config = ApprovedConfigCaseRegistry.create(cases);
        assertEquals(65, config.ids().size());
        CaseImplementationAudit.requireExact(cases, config, Milestone.M1, ExecutionMode.CONFIG);
        var browser = ApprovedBrowserCaseRegistry.create(cases, java.net.URI.create("https://suite.example"));
        assertEquals(151, browser.ids().size());
        CaseImplementationAudit.requireExact(cases, browser, Milestone.M1, ExecutionMode.BROWSER);
        var unavailable = org.junit.jupiter.api.Assertions.assertInstanceOf(
                com.samlscope.runner.cases.UnavailableBrowserOracleTestCase.class,
                browser.require("IIP-ALG01-a-idp-01"));
        var finished = org.junit.jupiter.api.Assertions.assertInstanceOf(
                com.samlscope.core.caseexec.CaseStep.Finish.class, unavailable.start(null));
        assertEquals(com.samlscope.core.evaluation.Outcome.NOT_VERIFIED, finished.outcome().outcome());
        assertEquals("browser.oracle-unavailable", finished.outcome().reasonCode());
        var publisherBase = ApprovedBrowserCaseRegistry.create(cases, java.net.URI.create("https://suite.example"), Milestone.M2);
        var publisherRegistry = ApprovedBrowserCaseRegistry.withPublishedMetadata(publisherBase,
                ignored -> new byte[0], ignored -> java.util.Optional.empty());
        assertEquals(publisherBase.ids(), publisherRegistry.ids());
        org.junit.jupiter.api.Assertions.assertInstanceOf(com.samlscope.runner.cases.PublishedUiUrlTestCase.class,
                publisherRegistry.require("IIP-MD05-fi-idp-01"));
        assertEquals(12, ApprovedAttestedCaseRegistry.create(cases, Milestone.M2).ids().size());
        assertEquals(214, ApprovedConfigCaseRegistry.create(cases, Milestone.M2).ids().size());
        assertEquals(20, ApprovedBrowserCaseRegistry.create(
                cases, java.net.URI.create("https://suite.example"), Milestone.M2).ids().size());
        var m2Automated = M2AutomatedCaseRegistry.create(runId -> null);
        assertEquals(18, m2Automated.ids().size());
        CaseImplementationAudit.requireExact(cases, m2Automated, Milestone.M2, ExecutionMode.AUTOMATED);
        assertEquals(11, ApprovedAttestedCaseRegistry.create(cases, Milestone.M3).ids().size());
        assertEquals(9, ApprovedConfigCaseRegistry.create(cases, Milestone.M3).ids().size());
        assertEquals(83, ApprovedBrowserCaseRegistry.create(
                cases, java.net.URI.create("https://suite.example"), Milestone.M3).ids().size());
        var m3Automated = M3AutomatedCaseRegistry.create(
                runId -> null, entry -> new byte[0], runId -> java.util.List.of(),
                runId -> java.util.Optional.empty());
        assertEquals(35, m3Automated.ids().size());
        CaseImplementationAudit.requireExact(cases, m3Automated, Milestone.M3, ExecutionMode.AUTOMATED);
        assertFalse(digests.compositeDigest().isBlank());
        assertArrayEquals(Files.readAllBytes(repositoryRoot().resolve("tests/coverage.yaml")),
                documents.bytes("tests/coverage.yaml"));
    }

    @Test
    void metadataKeysAndDefaultAcsHaveConnectedEvidenceCampaigns() {
        var cases = CaseDefinitionCatalogMapper.fromDocument(CatalogDocuments.load().parsed("tests/cases.yaml"));
        var config = ApprovedConfigCaseRegistry.create(cases, Milestone.M2);
        for (var id : java.util.List.of("IIP-MD05-ad-idp-01", "IIP-MD06-a5-idp-01",
                "IIP-MD06-a7-idp-01", "IIP-MD06-a9-idp-01", "IIP-MD07-a-idp-01")) {
            var implementation = org.junit.jupiter.api.Assertions.assertInstanceOf(
                    com.samlscope.runner.cases.MetadataFixtureObservationTestCase.class, config.require(id));
            assertEquals("control", implementation.evidenceActionKeys().getFirst());
            for (var variant : implementation.evidenceActionKeys()) {
                com.samlscope.saml.metadata.MetadataService.Variant.parse(variant);
            }
        }
        var browser = ApprovedBrowserCaseRegistry.create(cases, java.net.URI.create("https://suite.example"));
        var defaults = org.junit.jupiter.api.Assertions.assertInstanceOf(
                com.samlscope.runner.cases.MetadataFixtureObservationTestCase.class,
                browser.require("IIP-IDP12-c-idp-01"));
        assertEquals(java.util.List.of("control", "default-acs-first", "default-acs-second", "default-acs-implicit",
                "default-acs-first-omitted", "default-acs-all-false", "default-acs-multiple-true"),
                defaults.evidenceActionKeys());
        assertTrue(com.samlscope.saml.metadata.MetadataService.preloadedCampaignVariants().stream()
                .noneMatch(com.samlscope.saml.metadata.MetadataService.Variant::defaultAcsProbe),
                "Changing the default requires refreshing the same entity, not separate preloaded identities");
    }

    @Test
    void browserAutomationCannotSilentlyRegressBackToQuestionnaires() {
        var cases = CaseDefinitionCatalogMapper.fromDocument(
                CatalogDocuments.load().parsed("tests/cases.yaml"));
        var configuration = new IdpErrorProbeConfiguration(
                java.net.URI.create("https://idp.example/sso"), "https://suite.example/sp",
                java.net.URI.create("https://suite.example/sp/acs/0"),
                java.time.Duration.ofMinutes(5), true, true, true);
        var m1 = ApprovedBrowserCaseRegistry.create(
                cases, java.net.URI.create("https://suite.example"), ignored -> new byte[0],
                ignored -> java.util.Optional.empty(), ignored -> java.util.Optional.of("https://idp.example"),
                ignored -> java.util.List.of(), ignored -> configuration,
                ignored -> java.util.Optional.empty());
        var automatedM1Idp = m1.forRole(TargetRole.IDP).stream().filter(value ->
                value instanceof ProtocolEvidenceCase
                        || (value instanceof BrowserFrontChannelScenario
                            && !(value instanceof IdpExecutableBrowserFixtureScenarioTestCase))).count();
        assertEquals(67, automatedM1Idp,
                "Update this explicit automatic-oracle inventory when adding or removing an oracle");
        var ec = org.junit.jupiter.api.Assertions.assertInstanceOf(
                com.samlscope.runner.cases.EcSignatureSupportTestCase.class,
                m1.require("IIP-ALG03-a-idp-01"));
        assertEquals(java.util.List.of("control", "ecdsa-sha256", "ecdsa-sha256-invalid-signature"),
                ec.evidenceActionKeys());
        assertTrue(m1.forRole(TargetRole.IDP).stream().noneMatch(AttestationPrompt.class::isInstance),
                "A browser action must never be followed by an operator-supplied verdict");

        var m3 = ApprovedBrowserCaseRegistry.create(
                cases, java.net.URI.create("https://suite.example"), Milestone.M3,
                ignored -> new byte[0], ignored -> java.util.Optional.empty(),
                ignored -> java.util.Optional.of("https://idp.example"), ignored -> java.util.List.of());
        var automatedM3Idp = m3.forRole(TargetRole.IDP).stream()
                .filter(ProtocolEvidenceCase.class::isInstance).count();
        assertEquals(17, automatedM3Idp,
                "Update this explicit no-questionnaire inventory when adding or removing an SLO oracle");
        assertTrue(m3.forRole(TargetRole.IDP).stream().noneMatch(AttestationPrompt.class::isInstance),
                "An SLO browser action must never be followed by an operator-supplied verdict");
    }

    @Test
    void idpFullAutomaticOracleBudgetStaysAboveHalf() {
        var cases = CaseDefinitionCatalogMapper.fromDocument(
                CatalogDocuments.load().parsed("tests/cases.yaml"));
        var publicBase = java.net.URI.create("https://suite.example");
        var configuration = new IdpErrorProbeConfiguration(
                java.net.URI.create("https://idp.example/sso"), "https://suite.example/sp",
                java.net.URI.create("https://suite.example/sp/acs/0"),
                java.time.Duration.ofMinutes(5), true, true, true);
        com.samlscope.core.transcript.TranscriptContentReader content = ignored -> new byte[0];

        var m1Browser = ApprovedBrowserCaseRegistry.create(
                cases, publicBase, content,
                ignored -> java.util.Optional.empty(), ignored -> java.util.Optional.of("https://idp.example"),
                ignored -> java.util.List.of(), ignored -> configuration,
                ignored -> java.util.Optional.empty());
        var m3Browser = ApprovedBrowserCaseRegistry.create(
                cases, publicBase, Milestone.M3, content,
                ignored -> java.util.Optional.empty(), ignored -> java.util.Optional.of("https://idp.example"),
                ignored -> java.util.List.of(), ignored -> configuration,
                ignored -> java.util.Optional.empty());
        var m2Browser = ApprovedBrowserCaseRegistry.create(
                cases, publicBase, Milestone.M2, content,
                ignored -> java.util.Optional.empty(), ignored -> java.util.Optional.of("https://idp.example"),
                ignored -> java.util.List.of(), ignored -> configuration,
                ignored -> java.util.Optional.empty());
        var m1Attested = ApprovedAttestedCaseRegistry.create(
                cases, Milestone.M1, publicBase, ignored -> configuration, content,
                ignored -> java.util.Optional.of("https://idp.example"), ignored -> java.util.List.of());
        var m3Attested = ApprovedAttestedCaseRegistry.create(
                cases, Milestone.M3, publicBase, null, content,
                ignored -> java.util.Optional.of("https://idp.example"), ignored -> java.util.List.of());
        var m2Config = ApprovedConfigCaseRegistry.create(
                cases, Milestone.M2, ignored -> """
                        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                          entityID="https://idp.example"/>
                        """.getBytes(java.nio.charset.StandardCharsets.UTF_8), content, ignored -> java.util.Optional.empty());
        var m1Config = ApprovedConfigCaseRegistry.create(
                cases, Milestone.M1, ignored -> """
                        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                          entityID="https://idp.example"/>
                        """.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                content, ignored -> java.util.Optional.empty());

        var automated = cases.cases().stream()
                .filter(value -> value.role() == TargetRole.IDP)
                .filter(value -> value.mode() == ExecutionMode.AUTOMATED).count();
        var conclusiveBrowser = java.util.stream.Stream.concat(
                        m1Browser.forRole(TargetRole.IDP).stream(),
                        m3Browser.forRole(TargetRole.IDP).stream())
                .filter(value -> value instanceof ProtocolEvidenceCase
                        || (value instanceof BrowserFrontChannelScenario
                            && !(value instanceof IdpExecutableBrowserFixtureScenarioTestCase))
                        || value instanceof InformationalChoiceTestCase)
                .count();
        assertTrue(IdpExecutableBrowserFixtureScenarioTestCase.CASE_IDS.stream()
                .allMatch(caseId -> m1Browser.find(caseId)
                        .or(() -> m2Browser.find(caseId))
                        .or(() -> m3Browser.find(caseId))
                        .orElseThrow() instanceof IdpExecutableBrowserFixtureScenarioTestCase),
                "Every former instruction-only browser case must have a runnable front-channel fixture");
        var conclusiveAttested = java.util.stream.Stream.concat(
                        m1Attested.forRole(TargetRole.IDP).stream(),
                        m3Attested.forRole(TargetRole.IDP).stream())
                .filter(value -> !(value instanceof AttestationPrompt)).count();
        var conclusiveConfig = java.util.stream.Stream.concat(
                        m1Config.forRole(TargetRole.IDP).stream(),
                        m2Config.forRole(TargetRole.IDP).stream())
                .filter(value -> !value.getClass().getSimpleName().equals("ConfigurationGateTestCase"))
                .count();
        var totalIdpFull = cases.cases().stream()
                .filter(value -> value.role() == TargetRole.IDP).count();
        var conclusive = automated + conclusiveBrowser + conclusiveAttested + conclusiveConfig;
        var browserActions = java.util.stream.Stream.of(m1Browser, m2Browser, m3Browser)
                .flatMap(registry -> registry.forRole(TargetRole.IDP).stream()).count();
        var questionnaireFree = automated + browserActions + conclusiveAttested + conclusiveConfig;

        assertEquals(413, totalIdpFull);
        assertEquals(244, conclusive,
                "Update this explicit IDP Full automatic-oracle inventory when an oracle changes: automated="
                        + automated + ", browser=" + conclusiveBrowser + ", attested="
                        + conclusiveAttested + ", config=" + conclusiveConfig);
        assertTrue(conclusive * 2 > totalIdpFull,
                "At least half of IDP Full must conclude without an operator-supplied verdict");
        assertEquals(288, questionnaireFree,
                "Update this explicit IDP Full no-questionnaire inventory when an interaction changes");
    }

    private Path repositoryRoot() {
        for (var value : java.util.List.of(Path.of("."), Path.of(".."))) {
            var root = value.toAbsolutePath().normalize();
            if (Files.isRegularFile(root.resolve("tests/coverage.yaml"))) return root;
        }
        throw new IllegalStateException("Cannot locate repository root");
    }
}
