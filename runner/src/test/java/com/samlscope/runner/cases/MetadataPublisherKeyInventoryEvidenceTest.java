package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import static com.samlscope.runner.cases.MetadataPublisherKeyInventoryEvidence.*;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

class MetadataPublisherKeyInventoryEvidenceTest {
    @TempDir Path data;
    private static final String ENTITY="http://localhost:18380/idp";
    private String certificate(String alias) throws Exception {
        var store=new FilePlanKeyStore(data.resolve("keys"), Clock.fixed(Instant.parse("2026-10-03T00:00:00Z"),ZoneOffset.UTC));
        return Base64.getEncoder().encodeToString(store.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS",alias).certificate().getEncoded());
    }
    private Element role(String descriptors,String extra) throws Exception {
        return MetadataPublisherKeyInventoryEvidence.role(("<md:EntityDescriptor xmlns:md='"+MD+"' xmlns:ds='"+DS+"' entityID='"+ENTITY+"'>"
                +"<md:IDPSSODescriptor protocolSupportEnumeration='"+P+"' "+extra+">"+descriptors+"</md:IDPSSODescriptor></md:EntityDescriptor>").getBytes(),ENTITY);
    }
    private String kd(String use,String cert) {return "<md:KeyDescriptor"+(use.isEmpty()?"":" use='"+use+"'")+"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+cert+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>";}
    private NativeMetadataPublisherInventoryAdapter.Inventory inventory(String cert,String purpose)throws Exception{
        return new NativeMetadataPublisherInventoryAdapter.Inventory(List.of(new NativeMetadataPublisherInventoryAdapter.RoleKey(certificateSpki(cert),purpose,"native-loaded-role-key")),List.of(),Set.of(P),null,List.of());
    }
    @Test void actualCurrentKeyOmissionDetectedForEachPurpose()throws Exception {
        String cert=certificate("current");
        for(String purpose:List.of("signing","encryption","transport-authentication")) {
            var inv=inventory(cert,purpose); String use=purpose.equals("transport-authentication")?"signing":purpose;
            assertTrue(compare(role(kd(use,cert),""),inv,C3).isEmpty());
            assertEquals(List.of("key:"+purpose+":"+certificateSpki(cert)),compare(role("",""),inv,C3));
        }
    }
    @Test void encryptionDescriptorDoesNotSupplySigningOrMutualAuthentication()throws Exception {
        String cert=certificate("current"); var r=role(kd("encryption",cert),"");
        assertTrue(compare(r,inventory(cert,"encryption"),C3).isEmpty());
        assertFalse(compare(r,inventory(cert,"signing"),C3).isEmpty());
        assertFalse(compare(r,inventory(cert,"transport-authentication"),C3).isEmpty());
    }
    @Test void omittedUseIsValidForBothPurposes()throws Exception {
        String cert=certificate("current"); var r=role(kd("",cert),"");
        assertTrue(compare(r,inventory(cert,"signing"),C3).isEmpty());assertTrue(compare(r,inventory(cert,"encryption"),C3).isEmpty());
    }
    @Test void multipleCurrentSamePurposeOmissionCannotHideBehindOnePresentKey()throws Exception {
        String a=certificate("a"),b=certificate("b"); var keys=new ArrayList<NativeMetadataPublisherInventoryAdapter.RoleKey>();
        keys.addAll(inventory(a,"signing").keys());keys.addAll(inventory(b,"signing").keys());
        var inv=new NativeMetadataPublisherInventoryAdapter.Inventory(keys,List.of(),Set.of(P),null,List.of());
        assertTrue(compare(role(kd("signing",a)+kd("signing",b),""),inv,C3).isEmpty());
        assertEquals(List.of("key:signing:"+certificateSpki(b)),compare(role(kd("signing",a),""),inv,C3));
    }
    @Test void nestedForeignRoleAndDocumentSignerCannotSupplyOwnRoleKey()throws Exception {
        String cert=certificate("other");String xml="<md:EntityDescriptor xmlns:md='"+MD+"' xmlns:ds='"+DS+"' entityID='"+ENTITY+"'><ds:Signature><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+cert+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:SPSSODescriptor protocolSupportEnumeration='"+P+"'>"+kd("signing",cert)+"</md:SPSSODescriptor><md:IDPSSODescriptor protocolSupportEnumeration='"+P+"'/></md:EntityDescriptor>";
        assertFalse(compare(MetadataPublisherKeyInventoryEvidence.role(xml.getBytes(),ENTITY),inventory(cert,"signing"),C3).isEmpty());
    }
    @Test void keyInfoAmbiguityAndInvalidPurposeFailClosed()throws Exception {
        String a=certificate("a"),b=certificate("b");
        String ambiguous="<md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+a+"</ds:X509Certificate><ds:X509Certificate>"+b+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>";
        assertThrows(IllegalArgumentException.class,()->roleKeys(role(ambiguous,"")));
        assertThrows(IllegalArgumentException.class,()->roleKeys(role(kd("TLS",a),"")));
    }
    @Test void standalonePolicyAndResponseEndpointAreComparedSeparatelyFromKeyInventory()throws Exception {
        String cert=certificate("a");var e=new NativeMetadataPublisherInventoryAdapter.Endpoint("SingleLogoutService","urn:test:POST","http://target/slo","http://target/response");
        var inv=new NativeMetadataPublisherInventoryAdapter.Inventory(inventory(cert,"signing").keys(),List.of(e),Set.of(P),true,List.of());
        var good=role(kd("signing",cert)+"<md:SingleLogoutService Binding='urn:test:POST' Location='http://target/slo' ResponseLocation='http://target/response'/>","WantAuthnRequestsSigned='true'");
        assertTrue(compare(good,inv,C1).isEmpty());
        var bad=role(kd("signing",cert)+"<md:SingleLogoutService Binding='urn:test:POST' Location='http://target/slo' ResponseLocation='http://old/response'/>","WantAuthnRequestsSigned='false'");
        assertEquals(2,compare(bad,inv,C1).size());assertTrue(compare(bad,inv,C3).isEmpty());
    }
    @Test void certificatePublicKeyMatchesDerSpkiWithoutUsingCertificateValidityDates()throws Exception {
        String cert=certificate("a");var parsed=(java.security.cert.X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getDecoder().decode(cert)));
        String pem="-----BEGIN PUBLIC KEY-----\n"+Base64.getMimeEncoder(64,new byte[]{'\n'}).encodeToString(parsed.getPublicKey().getEncoded())+"\n-----END PUBLIC KEY-----\n";
        assertEquals(certificateSpki(cert),publicPemSpki(pem));assertThrows(IllegalArgumentException.class,()->publicPemSpki("-----BEGIN PRIVATE KEY-----\naaaa\n-----END PRIVATE KEY-----"));
    }
    @Test void privacyGuardRejectsNestedCredentialsHeadersAndPrivateMaterial()throws Exception {
        var mapper=new JsonCodec().mapper();
        for(String key:List.of("client_secret","Cookie","Authorization","password","attributes.privateKey","registrationAccessToken")) {
            assertTrue(sensitive(mapper.createObjectNode().set("nested",mapper.createObjectNode().put(key,"never-record"))));
        }
        assertTrue(sensitive(mapper.createObjectNode().put("material","-----BEGIN RSA PRIVATE KEY-----\nnever-record")));
        assertFalse(sensitive(mapper.createObjectNode().put("privateCredentialPresent",true).put("nativePrivateCredentialPublicSpkiPem","-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----")));
    }
    @Test void ownedPartialDirectoryAndSymlinkCannotEscapeToLegacyFallback()throws Exception {
        String run="run_0123456789ABCDEFGHJKMNPQRS";var reader=new MetadataPublisherKeyInventoryEvidence(data,e->null,r->null);
        assertFalse(reader.exists(run));Files.createDirectory(data.resolve(run));assertTrue(reader.exists(run));Files.delete(data.resolve(run));
        Files.createSymbolicLink(data.resolve(run),data.resolve("missing"));assertTrue(reader.exists(run));assertFalse(reader.exists("../outside"));
        assertTrue(supports(C1));assertTrue(supports(C3));assertFalse(supports("IIP-MD05-c5-idp-01"));
    }    @Test void sharedNativeControlOriginalStillBindsBothExactApprovedCaseControls()throws Exception {
        var mapper=new JsonCodec().mapper();var n=mapper.createObjectNode();
        n.putArray("positiveControlIds").add("iip-md05-c1-idp-01-positive").add("iip-md05-c3-idp-01-positive");
        n.putArray("negativeControlIds").add("iip-md05-c1-idp-01-negative").add("iip-md05-c3-idp-01-negative");
        validateControlIds(n);
        for(String mutation:List.of("missing","duplicate","swapped","foreign-case","extra")) {
            var v=n.deepCopy();var a=(com.fasterxml.jackson.databind.node.ArrayNode)v.path("negativeControlIds");
            switch(mutation) {
                case "missing"->a.remove(1);case "duplicate"->a.set(1,a.get(0));case "swapped"->{var first=a.get(0);a.set(0,a.get(1));a.set(1,first);}
                case "foreign-case"->a.set(1,mapper.getNodeFactory().textNode("iip-md05-c5-idp-01-negative"));default->a.add("iip-md05-c1-idp-01-negative");
            }
            assertThrows(IllegalArgumentException.class,()->validateControlIds(v),mutation);
        }
    }

}
