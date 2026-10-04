package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.samlscope.core.casedef.CaseDefinitionCatalog.CaseDefinition;
import com.samlscope.core.casedef.CaseDefinitionCatalog.ExecutionMode;
import com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone;
import com.samlscope.core.casedef.CaseDefinitionCatalog.Requirements;
import com.samlscope.core.caseexec.ConfigurationFailureSemantics;
import com.samlscope.core.plan.TargetRole;

class MetadataConfigCaseFactoryTest {
    @Test
    void duplicateAndExtensionObligationsUseProtocolEvidenceInsteadOfVerdictForms() {
        for (var obligation : List.of(
                "IIP-MD03.a", "IIP-MD03.b", "IIP-MD03.c",
                "IIP-MD05.a1", "IIP-MD05.a2", "IIP-MD05.a3", "IIP-MD05.as", "IIP-MD05.av", "IIP-MD05.cd",
                "IIP-MD12.a", "IIP-MD12.b", "IIP-MD12.c", "IIP-MD12.d")) {
            assertInstanceOf(MetadataFixtureObservationTestCase.class,
                    MetadataConfigCaseFactory.create(definition(obligation)).orElseThrow());
        }
    }

    @Test
    void defaultAcsMetadataCaseUsesTheFourApprovedCounterexamples() {
        var testCase = assertInstanceOf(MetadataFixtureObservationTestCase.class,
                MetadataConfigCaseFactory.create(definition("IIP-MD05.av")).orElseThrow());
        assertEquals(List.of("control", "default-acs-first", "default-acs-first-omitted",
                        "default-acs-all-false", "default-acs-duplicate-index"),
                testCase.evidenceActionKeys());
    }

    @Test
    void mdiopRepresentationCaseIncludesEveryCertificateAndKeyRepresentationFamily() {
        var testCase = assertInstanceOf(MetadataFixtureObservationTestCase.class,
                MetadataConfigCaseFactory.create(definition("IIP-MD05.c")).orElseThrow());
        assertEquals(List.of("control", "entity-root", "entities-root-one", "keyvalue-only", "keyvalue-and-x509",
                "certificate-expired", "certificate-not-yet-valid", "certificate-empty-subject", "certificate-unknown-ca",
                "certificate-critical-extension", "certificate-noncritical-extension", "certificate-no-digital-signature",
                "certificate-unrelated-eku", "key-use-omitted", "multiple-signing-keys-first", "multiple-signing-keys",
                "multiple-omitted-keys-first", "multiple-omitted-keys-second", "multiple-encryption-keys"),
                testCase.evidenceActionKeys());
    }

    @Test
    void unrelatedConfigurationCasesStillUseTheApprovedFallback() {
        assertTrue(MetadataConfigCaseFactory.create(definition("IIP-IDP09.a")).isEmpty());
    }

    private CaseDefinition definition(String obligation) {
        return new CaseDefinition(
                obligation + "-idp-01", obligation, TargetRole.IDP, ExecutionMode.CONFIG, Milestone.M2,
                List.of(), Map.of(), List.of(), List.of(), List.of(), "counterexample",
                List.of(), new Requirements(List.of(), "none"), false,
                ConfigurationFailureSemantics.TEST_PRECONDITION,
                "sha256:" + "0".repeat(64));
    }
}
