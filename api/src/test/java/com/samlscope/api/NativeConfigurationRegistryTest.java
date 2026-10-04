package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone;
import com.samlscope.core.casedef.CaseDefinitionCatalogMapper;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.cases.*;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Validate composition from approved cases, not a hand-written replacement catalog. */
class NativeConfigurationRegistryTest {
    private final TranscriptContentReader content = entry -> { throw new AssertionError("No original available"); };
    @TempDir java.nio.file.Path directory;

    @Test void nativeSchemaAdmissionIsComposedByTheExistingM2EvidenceHook() {
        var definitions = CaseDefinitionCatalogMapper.fromDocument(CatalogDocuments.load().parsed("tests/cases.yaml"));
        var id = MetadataSchemaAdmissionConfigurationTestCase.ID;
        assertEquals(Milestone.M2, definitions.require(id).milestone());
        var original = ApprovedConfigCaseRegistry.create(definitions, Milestone.M2,
                r -> new byte[0], content, r -> Optional.empty());
        var fixture = assertInstanceOf(MetadataFixtureObservationTestCase.class, original.require(id));
        var composed = ApprovedConfigCaseRegistry.withMetadataRejection(original, content, r -> new byte[0],
                java.nio.file.Path.of("build/test-native-evidence/metadata-rejection-evidence"));
        var observed = assertInstanceOf(MetadataSchemaAdmissionConfigurationTestCase.class, composed.require(id));
        assertEquals("metadata-native-schema-admission", observed.evidenceCampaignId());
        assertTrue(observed.evidenceActionKeys().contains("schema-sso-endpoint-without-foreign"));
        assertTrue(observed.evidenceActionKeys().containsAll(fixture.evidenceActionKeys()));
        assertEquals(fixture.instructionEn(), observed.instructionEn());
    }

    @Test void nativeEntityIdObserverIsComposedInTheActualM2ConfigurationRegistry() {
        var definitions = CaseDefinitionCatalogMapper.fromDocument(CatalogDocuments.load().parsed("tests/cases.yaml"));
        var id = "IIP-MD05-a1-idp-01";
        assertEquals(Milestone.M2, definitions.require(id).milestone());
        var registry = ApprovedConfigCaseRegistry.create(definitions, Milestone.M2,
                run -> new byte[0], content, run -> Optional.empty());
        var observed = assertInstanceOf(MetadataEntityIdentityConfigurationTestCase.class, registry.require(id));
        assertTrue(observed.instructionEn().contains("duplicate-entity-ids"));
        assertTrue(observed.evidenceActionKeys().contains("control"));
        assertTrue(observed.evidenceActionKeys().contains("duplicate-entity-ids"));
        // A composition without native evidence dependencies keeps the approved original gate.
        assertInstanceOf(MetadataFixtureObservationTestCase.class,
                ApprovedConfigCaseRegistry.create(definitions, Milestone.M2).require(id));
    }

    @Test void ordinaryBearerObserversAreComposedInTheActualM1ConfigurationRegistry() {
        var definitions = CaseDefinitionCatalogMapper.fromDocument(CatalogDocuments.load().parsed("tests/cases.yaml"));
        var registry = ApprovedConfigCaseRegistry.create(definitions, Milestone.M1,
                run -> new byte[0], content, run -> Optional.empty());
        for (var id : java.util.List.of("IIP-SSO01-fr-idp-01", "IIP-SSO01-gd-idp-01")) {
            assertInstanceOf(SubjectConfirmationConfigurationTestCase.class, registry.require(id));
            assertInstanceOf(ConfigurationGateTestCase.class,
                    ApprovedConfigCaseRegistry.create(definitions, Milestone.M1).require(id));
        }
    }

    @Test void attributeIndexNativeObserverUsesTheExistingM1PreparationHook() {
        var definitions = CaseDefinitionCatalogMapper.fromDocument(CatalogDocuments.load().parsed("tests/cases.yaml"));
        String id = "IIP-IDP04-b-idp-01";
        assertEquals(Milestone.M1, definitions.require(id).milestone());
        var original = ApprovedConfigCaseRegistry.create(definitions, Milestone.M1,
                run -> new byte[0], content, run -> Optional.empty());
        assertInstanceOf(ConfigurationGateTestCase.class, original.require(id));
        var composed = ApprovedConfigCaseRegistry.withAttributePolicyPreparation(original, content,
                run -> new byte[0], (run, variant) -> Optional.empty(),
                java.nio.file.Path.of("build/test-native-evidence/attribute-policy-preparations"));
        var observed = assertInstanceOf(AttributePolicyConfigurationTestCase.class, composed.require(id));
        assertEquals(java.util.List.of("control", "attribute-policy-indexed"), observed.evidenceActionKeys());
        assertEquals("metadata-fixture-refresh", observed.evidenceCampaignId());
    }

    @Test void transientAllowCreateUsesTheApprovedM1BrowserCaseAndNativeComposition() {
        var definitions=CaseDefinitionCatalogMapper.fromDocument(CatalogDocuments.load().parsed("tests/cases.yaml"));
        var base=java.net.URI.create("https://suite.example");
        var config=new IdpErrorProbeConfiguration(java.net.URI.create("https://idp.example/sso"),
                base+"/sp",java.net.URI.create(base+"/acs"),java.time.Duration.ofMinutes(1),true,true,true);
        var registry=ApprovedBrowserCaseRegistry.create(definitions,base,content,r->Optional.empty(),
                r->Optional.empty(),r->java.util.List.of(),r->config);
        assertEquals(Milestone.M1,definitions.require(TransientAllowCreateScenarioTestCase.CASE).milestone());
        assertInstanceOf(TransientAllowCreateScenarioTestCase.class,registry.require(TransientAllowCreateScenarioTestCase.CASE));
        var composed=ApprovedBrowserCaseRegistry.withNativeEcSignature(registry,content,r->new byte[0],
                java.nio.file.Path.of("build/test-native-evidence/ec-signature-evidence"));
        assertInstanceOf(QueuedProtocolEvidenceCase.class,composed.require(TransientAllowCreateScenarioTestCase.CASE));
    }

    @Test void actualNativeBrowserHookShadowsIncompleteOtherProductEvidenceWithoutSending()throws Exception {
        var definitions=CaseDefinitionCatalogMapper.fromDocument(CatalogDocuments.load().parsed("tests/cases.yaml"));
        var base=java.net.URI.create("https://suite.example");
        String run="run_00000000000000000000000000";
        var registry=ApprovedBrowserCaseRegistry.create(definitions,base,content,r->Optional.empty(),
                r->Optional.empty(),r->java.util.List.of(),r->{throw new AssertionError("Owned native evidence must not prepare browser actions");});
        var composed=ApprovedBrowserCaseRegistry.withNativeEcSignature(registry,content,r->new byte[0],
                directory.resolve("ec-signature-evidence"));
        var nativeDirectory=java.nio.file.Files.createDirectory(directory.resolve("transient-allow-create-evidence"));
        var context=new com.samlscope.runner.DefaultCaseContext(run,com.samlscope.core.plan.TargetRole.IDP,
                java.time.Clock.systemUTC(),com.samlscope.core.plan.TestPlan.Parameters.defaults(),
                com.samlscope.core.plan.TestPlan.Interaction.defaults(),com.samlscope.core.run.Reachability.CONFIRMED,
                new com.samlscope.core.transcript.TranscriptRecorder(){
                    public java.util.List<com.samlscope.core.transcript.TranscriptEntry> list(String id){return java.util.List.of();}
                    public com.samlscope.core.transcript.TranscriptEntry record(com.samlscope.core.transcript.TranscriptInput input){throw new AssertionError("No direct send or recording");}
                    public com.samlscope.core.transcript.TranscriptEntry updateSamlAnalysis(String id,String c,java.util.Map<String,Object>s){throw new AssertionError("Originals remain unchanged");}
                },true);
        for(String product:java.util.List.of("keycloak","shibboleth")) {
            var marker=nativeDirectory.resolve(run+"."+product+"-transient-allow-create.json");
            java.nio.file.Files.writeString(marker,"{}");
            var test=composed.require(TransientAllowCreateScenarioTestCase.CASE);
            assertEquals(com.samlscope.core.evaluation.Outcome.NOT_VERIFIED,
                    assertInstanceOf(com.samlscope.core.caseexec.CaseStep.Finish.class,test.start(context)).outcome().outcome());
            assertEquals(com.samlscope.core.evaluation.Outcome.NOT_VERIFIED,
                    assertInstanceOf(QueuedProtocolEvidenceCase.class,test).queuedEvidenceOutcome(context).outcome());
            java.nio.file.Files.delete(marker);
        }
    }

    @Test void requestedSubjectObserverIsComposedFromTheApprovedM1BrowserCase() {
        var definitions = CaseDefinitionCatalogMapper.fromDocument(CatalogDocuments.load().parsed("tests/cases.yaml"));
        var base = java.net.URI.create("https://suite.example");
        var config = new IdpErrorProbeConfiguration(java.net.URI.create("https://idp.example/sso"), base + "/sp",
                java.net.URI.create(base + "/acs"), java.time.Duration.ofMinutes(1), true, true, true);
        var registry = ApprovedBrowserCaseRegistry.create(definitions, base, content, r -> Optional.empty(),
                r -> Optional.empty(), r -> java.util.List.of(), r -> config);
        assertEquals(Milestone.M1, definitions.require(RequestedSubjectMatchTestCase.CASE).milestone());
        assertInstanceOf(IdpExecutableBrowserFixtureScenarioTestCase.class, registry.require(RequestedSubjectMatchTestCase.CASE));
        var composed = ApprovedBrowserCaseRegistry.withNativeEcSignature(registry, content, r -> new byte[0],
                java.nio.file.Path.of("build/test-native-evidence/ec-signature-evidence"));
        assertInstanceOf(RequestedSubjectMatchTestCase.class, composed.require(RequestedSubjectMatchTestCase.CASE));
    }
    @Test void mechanismReachabilityUsesTheActualSevenArgumentM1AttestedRegistrySeam() {
        var definitions=CaseDefinitionCatalogMapper.fromDocument(CatalogDocuments.load().parsed("tests/cases.yaml"));
        var base=java.net.URI.create("https://suite.example");
        var config=new IdpErrorProbeConfiguration(java.net.URI.create("https://idp.example/sso"),
                base+"/sp",java.net.URI.create(base+"/acs"),java.time.Duration.ofMinutes(1),true,true,true);
        var registry=ApprovedAttestedCaseRegistry.create(definitions,Milestone.M1,base,r->config,
                content,r->Optional.empty(),r->java.util.List.of());
        var id=IdpForceAuthnScenarioTestCase.MECHANISM_ACCESS_CASE;
        assertEquals(Milestone.M1,definitions.require(id).milestone());
        var mechanism=assertInstanceOf(ForceAuthnMechanismEvidenceTestCase.class,registry.require(id));
        assertEquals(com.samlscope.runner.RunCampaignQuery.ActionKind.NONE,mechanism.evidenceActionKind());
        assertTrue(mechanism.evidenceActionKeys().isEmpty());
        assertFalse(com.samlscope.runner.BrowserFrontChannelScenario.class.isInstance(mechanism),
                "The production registry must not queue external logins for an internal-evidence case");
    }

}
