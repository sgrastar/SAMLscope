package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import com.samlscope.store.JsonCodec;
import com.samlscope.core.evaluation.Outcome;
import java.util.List;
import java.nio.charset.StandardCharsets;

class SimpleSamlPhpPrincipalIdentityResolverTest {
    static final String RUN="run_00000000000000000000000000",SP="https://sp.example/metadata",TARGET="https://idp.example/metadata";
    static SimpleSamlPhpPrincipalIdentityResolver resolver()throws Exception {
        var rows=new JsonCodec().mapper().readTree("""
            [{"principal":"alice","attributes":{"uid":["alice-uid"],"eduPersonAffiliation":["member"]},
              "nameId":{"value":"1111111111111111111111111111111111111111","format":"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent","nameQualifier":null,"spNameQualifier":"https://sp.example/metadata"}},
             {"principal":"bob","attributes":{"uid":["bob-uid"],"eduPersonAffiliation":["member"]},
              "nameId":{"value":"2222222222222222222222222222222222222222","format":"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent","nameQualifier":null,"spNameQualifier":"https://sp.example/metadata"}}]
            """);return new SimpleSamlPhpPrincipalIdentityResolver(RUN,TARGET,SP,rows);
    }
    static byte[] assertion(String confirmation,String uid){return ("<s:Assertion xmlns:s='urn:oasis:names:tc:SAML:2.0:assertion'><s:Subject>"
        +"<s:NameID Format='"+SimpleSamlPhpPrincipalIdentityResolver.PERSISTENT+"' SPNameQualifier='"+SP+"'>1111111111111111111111111111111111111111</s:NameID>"
        +confirmation+"</s:Subject><s:AttributeStatement><s:Attribute Name='uid'><s:AttributeValue>"+uid+"</s:AttributeValue></s:Attribute>"
        +"<s:Attribute Name='eduPersonAffiliation'><s:AttributeValue>member</s:AttributeValue></s:Attribute></s:AttributeStatement></s:Assertion>").getBytes(StandardCharsets.UTF_8);}
    @Test void opaqueAndDifferentFormatIdentifiersResolveOneActualPrincipal()throws Exception {
        var xml=assertion("<s:SubjectConfirmation><s:NameID Format='"+SimpleSamlPhpPrincipalIdentityResolver.UNSPECIFIED+"'>alice-uid</s:NameID></s:SubjectConfirmation>","alice-uid");
        assertEquals(Outcome.SATISFIED,new SamlSubjectPrincipalCase(resolver()).evaluate(RUN,List.of(new TargetTranscriptMessages.Message("tx",xml))).outcome());
    }
    @Test void differentPrincipalInConfirmationIsSemanticViolation()throws Exception {
        var xml=assertion("<s:SubjectConfirmation><s:NameID Format='"+SimpleSamlPhpPrincipalIdentityResolver.PERSISTENT+"' SPNameQualifier='"+SP+"'>2222222222222222222222222222222222222222</s:NameID></s:SubjectConfirmation>","alice-uid");
        assertEquals(Outcome.VIOLATED,new SamlSubjectPrincipalCase(resolver()).evaluate(RUN,List.of(new TargetTranscriptMessages.Message("tx",xml))).outcome());
    }
    @Test void unknownAndForeignRunIdentifiersRemainUnverified()throws Exception {
        var semantic=new SamlSubjectPrincipalCase(resolver());
        assertEquals(Outcome.NOT_VERIFIED,semantic.evaluate(RUN,List.of(new TargetTranscriptMessages.Message("tx",assertion("","unknown")))).outcome());
        assertEquals(Outcome.NOT_VERIFIED,semantic.evaluate("run_foreign",List.of(new TargetTranscriptMessages.Message("tx",assertion("","alice-uid")))).outcome());
    }
    @Test void principalAliasUidOrUnexpectedAttributeCannotCreateNativeResolver()throws Exception {
        var json=new JsonCodec().mapper();var rows=json.readTree("""
            [{"principal":"alice","attributes":{"uid":["alias"],"eduPersonAffiliation":["member"]},"nameId":{"value":"1111111111111111111111111111111111111111","format":"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent","nameQualifier":null,"spNameQualifier":"https://sp.example/metadata"}},
             {"principal":"bob","attributes":{"uid":["alias"],"eduPersonAffiliation":["member"]},"nameId":{"value":"2222222222222222222222222222222222222222","format":"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent","nameQualifier":null,"spNameQualifier":"https://sp.example/metadata"}}]
            """);
        assertThrows(IllegalArgumentException.class,()->new SimpleSamlPhpPrincipalIdentityResolver(RUN,TARGET,SP,rows));
    }
}
