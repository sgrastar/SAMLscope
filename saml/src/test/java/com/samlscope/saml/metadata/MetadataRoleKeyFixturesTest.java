package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;

class MetadataRoleKeyFixturesTest {
    @TempDir java.nio.file.Path directory;
    private static List<Element> children(Element root,String namespace,String local) {
        var values=new ArrayList<Element>();
        for(var n=root.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element e&&namespace.equals(e.getNamespaceURI())&&local.equals(e.getLocalName()))values.add(e);
        return values;
    }
    private static String certificate(Element descriptor) {
        return descriptor.getElementsByTagNameNS(MetadataService.DS,"X509Certificate").item(0).getTextContent();
    }
    @Test void fourEpochsPreserveBothRolesSwapSigningKeysAndUseDistinctEncryptionKeys() throws Exception {
        var clock=Clock.fixed(Instant.parse("2026-10-02T00:00:00Z"),ZoneOffset.UTC);var store=new FilePlanKeyStore(directory,clock);var plan=SamlTestFixtures.idpPlan();
        var service=new MetadataService(URI.create("https://peer.example"),store,new XmlSigner(),clock);
        String first=null,second=null;
        for(var variant:List.of(MetadataService.Variant.ROLE_KEYS_SP_FIRST_EXPLICIT_A,MetadataService.Variant.ROLE_KEYS_IDP_FIRST_EXPLICIT_B,
                MetadataService.Variant.ROLE_KEYS_SP_FIRST_OMITTED_A,MetadataService.Variant.ROLE_KEYS_IDP_FIRST_OMITTED_B)) {
            var root=SecureXml.parse(service.generatePolling(plan,variant,"run_probe")).getDocumentElement();
            var sp=children(root,MetadataService.MD,"SPSSODescriptor");var idp=children(root,MetadataService.MD,"IDPSSODescriptor");assertEquals(1,sp.size());assertEquals(1,idp.size());
            var spKeys=children(sp.getFirst(),MetadataService.MD,"KeyDescriptor");var idpKeys=children(idp.getFirst(),MetadataService.MD,"KeyDescriptor");
            boolean explicit=variant.id().contains("explicit"), flipped=variant.id().contains("idp-first");
            assertEquals(explicit?2:1,spKeys.size());assertEquals(explicit?2:1,idpKeys.size());
            String signer=certificate(spKeys.getFirst()),peer=certificate(idpKeys.getFirst());assertNotEquals(signer,peer);
            if(!flipped){if(first==null){first=signer;second=peer;}else{assertEquals(first,signer);assertEquals(second,peer);}}
            else{assertEquals(second,signer);assertEquals(first,peer);}
            var requestKey=service.credentialsForPollingVariant(plan,variant);var receiverKey=service.decryptionCredentialsForPollingVariant(plan,variant);
            assertEquals(Base64.getEncoder().encodeToString(requestKey.certificate().getEncoded()),signer);
            if(explicit){assertEquals("signing",spKeys.getFirst().getAttribute("use"));assertEquals("encryption",spKeys.get(1).getAttribute("use"));assertNotEquals(signer,certificate(spKeys.get(1)));assertNotEquals(peer,certificate(spKeys.get(1)));assertEquals(Base64.getEncoder().encodeToString(receiverKey.certificate().getEncoded()),certificate(spKeys.get(1)));}
            else{assertFalse(spKeys.getFirst().hasAttribute("use"));assertFalse(idpKeys.getFirst().hasAttribute("use"));assertEquals(signer,Base64.getEncoder().encodeToString(receiverKey.certificate().getEncoded()));}
            var roles=new ArrayList<String>();for(var n=root.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element e&&MetadataService.MD.equals(e.getNamespaceURI())&&e.getLocalName().endsWith("SSODescriptor"))roles.add(e.getLocalName());
            assertEquals(flipped?List.of("IDPSSODescriptor","SPSSODescriptor"):List.of("SPSSODescriptor","IDPSSODescriptor"),roles);
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root,service.credentialsForPollingVariant(plan,MetadataService.Variant.THREE_SIGNING_KEYS_FIRST).certificate()));
            byte[] request=new SamlSignedRequestFactory().build(SamlSignedRequestFactory.Fixture.VALID,"_request",URI.create("https://target.example/sso"),root.getAttribute("entityID"),URI.create("https://peer.example/acs"),clock.instant(),requestKey);
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(SecureXml.parse(request).getDocumentElement(),requestKey.certificate()));
            assertFalse(new XmlSignatureVerifier().hasValidEnvelopedSignature(SecureXml.parse(request).getDocumentElement(),(java.security.cert.X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getDecoder().decode(peer)))));
        }
    }
    @Test void unselectedVariantLeavesEveryByteAndRoleIntact() {
        var document=SecureXml.parse("<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' entityID='same'><md:SPSSODescriptor/><md:IDPSSODescriptor/></md:EntityDescriptor>".getBytes());var before=SecureXml.serialize(document);
        assertSame(document.getDocumentElement(),MetadataRoleKeyFixtures.apply(document,document.getDocumentElement(),null,null,null,MetadataService.Variant.CONTROL));assertArrayEquals(before,SecureXml.serialize(document));
    }
}
