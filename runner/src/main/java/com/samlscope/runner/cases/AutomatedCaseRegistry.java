package com.samlscope.runner.cases;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.Set;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.runner.TestCaseRegistry;

/** Composition root for the complete approved M1 AUTOMATED case set. */
public final class AutomatedCaseRegistry {
    private static final Set<String> DURING_RUN_CASES = Set.of(IdpErrorResponseTestCase.CASE_ID);
    private AutomatedCaseRegistry() {}

    public static TestCaseRegistry create(AutomatedCaseDependencies dependencies) {
        var cases = new ArrayList<TestCase>();
        var content = dependencies.transcriptContent();
        add(cases, List.of("IIP-G03-a-idp-01", "IIP-G03-a-sp-01"),
                id -> new DtdFreeTranscriptTestCase(id, content));
        add(cases, List.of("IIP-SSO01-af-sp-01", "IIP-SSO01-ao-idp-01"),
                id -> new SamlIdentifierTranscriptTestCase(id, content));
        add(cases, List.of(
                        "IIP-SSO01-ah-idp-01", "IIP-SSO01-ah-sp-01",
                        "IIP-SSO01-da-idp-01", "IIP-SSO01-di-idp-01"),
                id -> new SamlExtensionNamespaceTranscriptTestCase(id, content));
        add(cases, List.of("IIP-SSO01-cc-idp-01", "IIP-SSO01-cc-sp-01"),
                id -> new SamlIdentifierDeclarationTranscriptTestCase(id, content));
        add(cases, List.of("IIP-SSO01-cg-sp-01", "IIP-SSO01-dv-idp-01"),
                id -> new SamlSchemaConformanceTranscriptTestCase(id, content));
        cases.add(new SamlAssertionSchemaTranscriptTestCase(content, dependencies.decryptionKeys()));
        add(cases, List.of(
                        "IIP-SSO01-ch-idp-01", "IIP-SSO01-ci-idp-01", "IIP-SSO01-cj-idp-01",
                        "IIP-SSO01-ck-idp-01", "IIP-SSO01-cl-idp-01", "IIP-SSO01-cm-idp-01",
                        "IIP-SSO01-dd-idp-01", "IIP-SSO01-dh-idp-01"),
                id -> new SamlCoreStructureTranscriptTestCase(id, content));
        add(cases, List.of("IIP-SSO01-cn-idp-01", "IIP-SSO01-db-idp-01", "IIP-SSO01-dc-idp-01"),
                id -> new SamlTimeRelationshipTranscriptTestCase(id, content));
        add(cases, List.of("IIP-SSO01-cy-idp-01", "IIP-SSO01-cy-sp-01"),
                id -> new SamlQualifierOmissionTranscriptTestCase(id, content));
        cases.add(new SamlSubjectPrincipalTranscriptTestCase(content, dependencies.principalIdentities()));
        add(cases, List.of("IIP-SSO01-dj-idp-01", "IIP-SSO01-dk-idp-01",
                        "IIP-SSO01-dl-idp-01", "IIP-SSO01-du-idp-01"),
                id -> new SamlAttributeValueTranscriptTestCase(id, content, dependencies.attributeFixture(id)));
        add(cases, List.of("IIP-SSO01-dm-idp-01", "IIP-SSO01-dn-idp-01"),
                id -> new SamlEncryptedDataTypeTranscriptTestCase(id, content));
        cases.add(new SamlDecryptedTypeTranscriptTestCase(content, dependencies.decryptionKeys()));
        cases.add(new SamlEncryptedIdentifierUniquenessTranscriptTestCase("IIP-SSO01-dp-idp-01", content));
        cases.add(new SamlEncryptedKeyRecipientTranscriptTestCase(
                "IIP-SSO01-dq-idp-01", content, dependencies.peerEntityId()));
        cases.add(new SamlAddressTranscriptTestCase("IIP-SSO01-ds-idp-01", content));
        add(cases, List.of("IIP-SSO01-dz-idp-01", "IIP-SSO01-dz-sp-01"),
                id -> new SamlStringValueTranscriptTestCase(id, content));
        add(cases, List.of(
                        "IIP-SSO01-ef-idp-01", "IIP-SSO01-ef-sp-01",
                        "IIP-SSO01-eg-idp-01", "IIP-SSO01-eg-sp-01",
                        "IIP-SSO01-ei-idp-01", "IIP-SSO01-ei-sp-01"),
                id -> new SamlLexicalTranscriptTestCase(id, content));
        add(cases, List.of("IIP-SSO01-ej-idp-01", "IIP-SSO01-eq-idp-01", "IIP-SSO01-fg-sp-01"),
                id -> new SamlVersionTranscriptTestCase(id, content));
        cases.add(new SamlRequesterVersionTranscriptTestCase(content, dependencies.caseExecutions()));
        for (var suffix : List.of("er", "eu", "ev", "ew", "ex", "fs")) {
            add(cases, List.of(
                            "IIP-SSO01-" + suffix + "-idp-01",
                            "IIP-SSO01-" + suffix + "-sp-01"),
                    id -> new SamlSignatureTranscriptTestCase(id, content));
        }
        add(cases, List.of("IIP-SSO01-fl-sp-01", "IIP-SSO01-fn-sp-01"),
                id -> new SamlAllowCreateTranscriptTestCase(id, content));
        cases.add(new SamlCbcEncryptedAssertionSignatureTranscriptTestCase(
                "IIP-SSO01-fv-idp-01", content, dependencies.targetSigningCertificates()));
        add(cases, List.of("IIP-SSO07-a-idp-01", "IIP-SSO07-a-sp-01"),
                id -> new SamlOptionalFieldObservationTranscriptTestCase(
                        id, content, dependencies.optionalSelector(id)));
        cases.add(new IdpErrorResponseTestCase(dependencies.idpErrorProbe()));
        return new TestCaseRegistry(cases);
    }

    public static boolean runsDuringRun(String caseId) {
        return DURING_RUN_CASES.contains(caseId);
    }

    private static void add(
            List<TestCase> target, List<String> ids, Function<String, ? extends TestCase> factory) {
        ids.stream().map(factory).forEach(target::add);
    }
}
