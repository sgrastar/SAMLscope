package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.evaluation.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;

class MetadataIntersectionEvidenceTest {
    @TempDir java.nio.file.Path directory;
    private static final String S="urn:oasis:names:tc:SAML:2.0:assertion",MD="urn:oasis:names:tc:SAML:2.0:metadata",DS="http://www.w3.org/2000/09/xmldsig#",X="http://www.w3.org/2001/04/xmlenc#",X11="http://www.w3.org/2009/xmlenc11#";
    private List<MetadataIntersectionEvidence.Sample> matrix() {
        return MetadataIntersectionEvidence.REQUIRED.stream().map(v->new MetadataIntersectionEvidence.Sample("campaign",v,List.<String>of(),List.of(MetadataAlgorithmSelection.S256,MetadataAlgorithmSelection.S384),List.of(new EvidenceRef("transcript",v)))).toList();
    }
    @Test void requiresEveryVariantInOneCampaignAndNoEvidenceIssues() {
        var complete=matrix();assertEquals(Outcome.SATISFIED,MetadataIntersectionEvidence.evaluate(complete,List.of()).outcome());
        for(var missing:complete) {
            assertEquals(Outcome.NOT_VERIFIED,MetadataIntersectionEvidence.evaluate(complete.stream().filter(s->s!=missing).toList(),List.of()).outcome());
            var split=complete.stream().map(s->s==missing?new MetadataIntersectionEvidence.Sample("other",s.variant(),s.mismatches(),s.signatureAlgorithms(),s.evidence()):s).toList();
            assertEquals(Outcome.NOT_VERIFIED,MetadataIntersectionEvidence.evaluate(split,List.of()).outcome());
        }
        assertEquals(Outcome.NOT_VERIFIED,MetadataIntersectionEvidence.evaluate(complete,List.of("corrupt-input")).outcome());
    }
    @Test void keysizeMutantFailsOnlyWithCompleteCapabilityControls() {
        var mutant=matrix().stream().map(s->new MetadataIntersectionEvidence.Sample(s.campaign(),s.variant(),s.variant().equals("algorithm-signing-256-keysize-excluded")?List.of("signing-keysize-intersection"):List.of(),s.signatureAlgorithms(),s.evidence())).toList();
        assertEquals(Outcome.VIOLATED,MetadataIntersectionEvidence.evaluate(mutant,List.of()).outcome());
        var incapable=mutant.stream().map(s->new MetadataIntersectionEvidence.Sample(s.campaign(),s.variant(),s.mismatches(),List.of(MetadataAlgorithmSelection.S256),s.evidence())).toList();
        assertEquals(Outcome.NOT_VERIFIED,MetadataIntersectionEvidence.evaluate(incapable,List.of()).outcome());
    }
    private PlanCredentials key(String alias) { return new FilePlanKeyStore(directory,Clock.systemUTC()).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS",alias); }
    private MetadataAlgorithmEvidence.Exchange exchange(String variant,PlanCredentials key,String ads,SamlEncryptionFixtureFactory.Algorithms algorithms,String signature) throws Exception {
        var metadata=SecureXml.parse(("<md:EntityDescriptor xmlns:md='"+MD+"' xmlns:ds='"+DS+"' xmlns:xenc11='"+X11+"' xmlns:alg='urn:oasis:names:tc:SAML:metadata:algsupport'><md:SPSSODescriptor>"+(variant.endsWith("keysize-excluded")?"<md:Extensions><alg:SigningMethod Algorithm='"+MetadataAlgorithmSelection.S256+"' MaxKeySize='1'/><alg:SigningMethod Algorithm='"+MetadataAlgorithmSelection.S384+"'/></md:Extensions>":"")+"<md:KeyDescriptor use='encryption'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+Base64.getEncoder().encodeToString(key.certificate().getEncoded())+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"+ads+"</md:KeyDescriptor></md:SPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8)).getDocumentElement();
        var plain=SecureXml.parse(("<s:Assertion xmlns:s='"+S+"'><s:Issuer>https://idp.example</s:Issuer></s:Assertion>").getBytes(StandardCharsets.UTF_8)).getDocumentElement();
        var encrypted=new SamlEncryptionFixtureFactory().encrypt(SamlEncryptionFixtureFactory.Wrapper.EncryptedAssertion,plain,key.certificate().getPublicKey(),algorithms);
        var response=SecureXml.parse(("<p:Response xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:s='"+S+"'><s:Issuer>https://idp.example</s:Issuer></p:Response>").getBytes(StandardCharsets.UTF_8)).getDocumentElement();
        response.appendChild(response.getOwnerDocument().importNode(encrypted,true));
        var hash=HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(key.certificate().getPublicKey().getEncoded()));
        return new MetadataAlgorithmEvidence.Exchange("campaign",variant,metadata,response,List.of(new VerifiedSignatureAlgorithms.Observation("Response","_r",signature,MetadataAlgorithmSelection.D256,hash)),List.of(key.certificate()),List.of(new EvidenceRef("transcript","response")));
    }
    private SamlEncryptionFixtureFactory.Algorithms algorithms(boolean sha256) {
        return new SamlEncryptionFixtureFactory.Algorithms(SamlEncryptionFixtureFactory.Content.AES128_GCM,SamlEncryptionFixtureFactory.Transport.RSA_OAEP_11,sha256?SamlEncryptionFixtureFactory.Digest.SHA256:SamlEncryptionFixtureFactory.Digest.SHA1,sha256?SamlEncryptionFixtureFactory.Mgf.SHA256:SamlEncryptionFixtureFactory.Mgf.SHA1);
    }
    @Test void decryptsMatchingKeyButRejectsWrongKeyAndRelabeledInput() throws Exception {
        var key=key("fixture");
        var e=exchange("algorithm-encryption-aes128-gcm",key,"<md:EncryptionMethod Algorithm='"+X11+"aes128-gcm'/>",algorithms(true),MetadataAlgorithmSelection.S256);
        assertEquals(List.of(),MetadataIntersectionEvidence.inspect(e,key).mismatches());
        assertThrows(Exception.class,()->MetadataIntersectionEvidence.inspect(e,key("wrong")));
        var relabeled=new MetadataAlgorithmEvidence.Exchange(e.campaign(),"algorithm-encryption-aes256-gcm",e.metadata(),e.response(),e.signatures(),e.signingKeys(),e.evidence());
        assertThrows(Exception.class,()->MetadataIntersectionEvidence.inspect(relabeled,key));
        var data=(org.w3c.dom.Element)e.response().getElementsByTagNameNS(X,"CipherValue").item(0);data.setTextContent("invalid");
        assertThrows(Exception.class,()->MetadataIntersectionEvidence.inspect(e,key));
    }
    @Test void decryptableWrongOaepParametersRemainDetectable() throws Exception {
        var key=key("fixture");var ads="<md:EncryptionMethod Algorithm='"+X11+"aes128-gcm'/><md:EncryptionMethod Algorithm='"+X11+"rsa-oaep'><ds:DigestMethod Algorithm='"+X+"sha256'/><xenc11:MGF Algorithm='"+X11+"mgf1sha256'/></md:EncryptionMethod>";
        assertEquals(List.of(),MetadataIntersectionEvidence.inspect(exchange("algorithm-oaep-11-sha256",key,ads,algorithms(true),MetadataAlgorithmSelection.S256),key).mismatches());
        assertEquals(Set.of("oaep-digest-intersection","oaep-mgf-intersection"),new HashSet<>(MetadataIntersectionEvidence.inspect(exchange("algorithm-oaep-11-sha256",key,ads,algorithms(false),MetadataAlgorithmSelection.S256),key).mismatches()));
    }
    @Test void signingKeysizeControlUsesVerifiedKeyNotAnUntrustedSize() throws Exception {
        var key=key("fixture");
        assertEquals(List.of(),MetadataIntersectionEvidence.inspect(exchange("algorithm-signing-256-keysize-excluded",key,"",algorithms(true),MetadataAlgorithmSelection.S384),key).mismatches());
        assertEquals(List.of("signing-keysize-intersection"),MetadataIntersectionEvidence.inspect(exchange("algorithm-signing-256-keysize-excluded",key,"",algorithms(true),MetadataAlgorithmSelection.S256),key).mismatches());
    }
}
