package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.Outcome;

class SamlSubjectPrincipalCaseTest {
    @Test
    void anOpaqueEncryptedAssertionDoesNotProveAbsenceOfSubjectPrincipals() {
        var encrypted = "<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'><saml:EncryptedAssertion/></samlp:Response>";
        var outcome = rule(identifier -> PrincipalIdentityResolver.Resolution.resolved("principal-1"))
                .evaluate("run", List.of(message(encrypted)));
        assertEquals(Outcome.NOT_VERIFIED, outcome.outcome());
        assertEquals("saml.subject-principal.undetermined", outcome.reasonCode());
    }

    @Test
    void differentFormatsForTheSameKnownPrincipalAreNotAStringComparisonViolation() {
        var outcome = rule(identifier -> {
            if (identifier.kind().startsWith("Attribute:role")) return PrincipalIdentityResolver.Resolution.notSubjectIdentifying();
            if (identifier.value().contains("alice")) return PrincipalIdentityResolver.Resolution.resolved("principal-1");
            return PrincipalIdentityResolver.Resolution.unknown();
        }).evaluate("run", List.of(message(subjectFixture("alice-persistent", "alice-transient", "alice@example", "admin"))));

        assertEquals(Outcome.SATISFIED, outcome.outcome());
    }

    @Test
    void identifiersResolvedToDifferentPrincipalsViolateTheObligation() {
        var outcome = rule(identifier -> {
            if (identifier.kind().startsWith("Attribute:role")) return PrincipalIdentityResolver.Resolution.notSubjectIdentifying();
            return PrincipalIdentityResolver.Resolution.resolved(
                    identifier.value().contains("bob") ? "principal-2" : "principal-1");
        }).evaluate("run", List.of(message(subjectFixture("alice", "bob", "alice", "admin"))));

        assertEquals(Outcome.VIOLATED, outcome.outcome());
    }

    @Test
    void unresolvedSemanticIdentityIsNotMisreportedFromUnequalStrings() {
        var outcome = rule(identifier -> PrincipalIdentityResolver.Resolution.unknown())
                .evaluate("run", List.of(message(subjectFixture("opaque-a", "opaque-b", "opaque-c", "admin"))));

        assertEquals(Outcome.NOT_VERIFIED, outcome.outcome());
    }

    @Test
    void requiresExactlyOneIdentifierDirectlyUnderSubject() {
        var noIdentifier = """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                  <saml:Subject><saml:SubjectConfirmation/></saml:Subject>
                </saml:Assertion>
                """;
        var twoIdentifiers = """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                  <saml:Subject><saml:NameID>a</saml:NameID><saml:BaseID>b</saml:BaseID></saml:Subject>
                </saml:Assertion>
                """;
        var resolved = rule(identifier -> PrincipalIdentityResolver.Resolution.resolved("principal-1"));

        assertEquals(Outcome.VIOLATED, resolved.evaluate("run", List.of(message(noIdentifier))).outcome());
        assertEquals(Outcome.VIOLATED, resolved.evaluate("run", List.of(message(twoIdentifiers))).outcome());
    }

    private SamlSubjectPrincipalCase rule(
            java.util.function.Function<PrincipalIdentityResolver.Identifier, PrincipalIdentityResolver.Resolution> mapping) {
        return new SamlSubjectPrincipalCase((runId, identifier) -> mapping.apply(identifier));
    }

    private String subjectFixture(String direct, String confirmation, String subjectAttribute, String role) {
        return """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                  <saml:Subject>
                    <saml:NameID Format="urn:persistent">%s</saml:NameID>
                    <saml:SubjectConfirmation><saml:NameID Format="urn:transient">%s</saml:NameID></saml:SubjectConfirmation>
                  </saml:Subject>
                  <saml:AttributeStatement>
                    <saml:Attribute Name="subject-id"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                    <saml:Attribute Name="role"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                  </saml:AttributeStatement>
                </saml:Assertion>
                """.formatted(direct, confirmation, subjectAttribute, role);
    }

    private TargetTranscriptMessages.Message message(String xml) {
        return new TargetTranscriptMessages.Message("fixture", xml.getBytes(StandardCharsets.UTF_8));
    }
}
