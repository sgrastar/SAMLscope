package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import com.samlscope.core.evaluation.Outcome;

class PublishedUiUrlTestCaseTest {
    private static final String TARGET = "https://target.example/idp";
    private static String entity(String id, String content) {
        return "<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' "
                + "xmlns:mdui='urn:oasis:names:tc:SAML:metadata:ui' entityID='" + id + "'>"
                + "<md:IDPSSODescriptor><md:Extensions><mdui:UIInfo>" + content
                + "</mdui:UIInfo></md:Extensions></md:IDPSSODescriptor></md:EntityDescriptor>";
    }
    private static com.samlscope.core.evaluation.CaseOutcome evaluate(String xml) {
        return PublishedUiUrlTestCase.evaluate(xml.getBytes(StandardCharsets.UTF_8), TARGET);
    }
    @Test void observesEveryPublishedUrlWithoutFetchingIt() {
        var xml = entity(TARGET, "<mdui:Logo>https://target.example/logo.png</mdui:Logo>"
                + "<mdui:InformationURL>HTTPS://target.example/info</mdui:InformationURL>"
                + "<mdui:PrivacyStatementURL>https://target.example/privacy</mdui:PrivacyStatementURL>");
        var result = evaluate(xml);
        assertEquals(Outcome.SATISFIED, result.outcome());
        assertEquals(3, result.details().get("observed_urls"));
        assertEquals("target-metadata", result.evidence().getFirst().kind());
        assertTrue(result.evidence().getFirst().reference().matches("sha256:[0-9a-f]{64}"));
    }
    @ParameterizedTest @ValueSource(strings={"Logo", "InformationURL", "PrivacyStatementURL"})
    void eachNonHttpsElementIsDetectedEvenAlongsideHttps(String element) {
        for (String scheme : new String[]{"http://target.example/x", "data:image/png;base64,AA==", "javascript:alert(1)", "file:///tmp/x"}) {
            var result = evaluate(entity(TARGET, "<mdui:Logo>https://target.example/logo.png</mdui:Logo>"
                    + "<mdui:" + element + ">" + scheme + "</mdui:" + element + ">"));
            assertEquals(Outcome.VIOLATED, result.outcome(), element + ":" + scheme);
            // Evaluator applies RECOMMENDED; the case never constructs a FAIL verdict.
            assertEquals(java.util.List.of(element), result.details().get("non_https_elements"));
        }
    }
    @Test void cannotBorrowAnotherEntityOrRoleEvidence() {
        String unrelated = entity("https://other.example/idp", "<mdui:Logo>http://other.example/x</mdui:Logo>");
        String own = entity(TARGET, "<mdui:Logo>https://target.example/x</mdui:Logo>");
        assertEquals(Outcome.SATISFIED, evaluate("<md:EntitiesDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata'>"
                + unrelated + own + "</md:EntitiesDescriptor>").outcome());
        assertEquals(Outcome.NOT_VERIFIED, evaluate(unrelated).outcome());
        assertEquals(Outcome.NOT_VERIFIED, evaluate(own.replace("IDPSSODescriptor", "SPSSODescriptor")).outcome());
        assertEquals(Outcome.NOT_VERIFIED, evaluate("<md:EntitiesDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata'>"
                + own + own + "</md:EntitiesDescriptor>").outcome());
    }
    @Test void absenceIsNotARequirementToPublishAndInvalidInputIsNotProductFailure() {
        assertEquals(Outcome.SATISFIED_WITH_NOTE, evaluate(entity(TARGET, "")).outcome());
        assertEquals(Outcome.NOT_VERIFIED, evaluate("<broken").outcome());
        assertEquals(Outcome.NOT_VERIFIED, PublishedUiUrlTestCase.evaluate(null, TARGET).outcome());
        assertEquals(Outcome.NOT_VERIFIED, evaluate(entity(TARGET, "<mdui:Logo>https://bad url</mdui:Logo>")).outcome());
    }
}
