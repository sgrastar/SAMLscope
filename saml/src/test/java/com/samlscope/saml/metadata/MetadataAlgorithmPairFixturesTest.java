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
import com.samlscope.saml.normal.SecureXml;

class MetadataAlgorithmPairFixturesTest {
    @TempDir java.nio.file.Path directory;
    private static final String ALG="urn:oasis:names:tc:SAML:metadata:algsupport",MORE="http://www.w3.org/2001/04/xmldsig-more#";
    @Test void individualDigestAndSigningOrdersDoNotChangeTheOtherType() {
        var clock=Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"),ZoneOffset.UTC);
        var plan=SamlTestFixtures.idpPlan();
        var service=new MetadataService(URI.create("https://peer.example"),new FilePlanKeyStore(directory,clock),new XmlSigner(),clock);
        for(var variant:List.of(MetadataService.Variant.ALGORITHM_ENTITY_DIGEST_ORDER_256_512,
                MetadataService.Variant.ALGORITHM_ENTITY_DIGEST_ORDER_512_256,
                MetadataService.Variant.ALGORITHM_ENTITY_SIGNING_ORDER_256_512,
                MetadataService.Variant.ALGORITHM_ENTITY_SIGNING_ORDER_512_256)) {
            var doc=SecureXml.parse(service.generatePolling(plan,variant,"run_probe"));
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(doc.getDocumentElement(),service.credentialsForPollingVariant(plan,variant).certificate()));
            var digest=variant.id().contains("-digest-");var reversed=variant.id().endsWith("512-256");
            var selected=doc.getElementsByTagNameNS(ALG,digest?"DigestMethod":"SigningMethod");
            assertEquals(2,selected.getLength());assertEquals(0,doc.getElementsByTagNameNS(ALG,digest?"SigningMethod":"DigestMethod").getLength());
            var bits=reversed?List.of(512,256):List.of(256,512);
            for(int index=0;index<2;index++)assertEquals(digest?"http://www.w3.org/2001/04/xmlenc#sha"+bits.get(index):MORE+"rsa-sha"+bits.get(index),
                ((Element)selected.item(index)).getAttribute("Algorithm"));
        }
    }
    @Test void explicitSha512FixturesBindActualAlgorithmsWithoutRelabelingSha384() {
        var clock=Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"),ZoneOffset.UTC);
        var store=new FilePlanKeyStore(directory,clock);var plan=SamlTestFixtures.idpPlan();
        var service=new MetadataService(URI.create("https://peer.example"),store,new XmlSigner(),clock);
        for(var variant:List.of(MetadataService.Variant.ALGORITHM_ENTITY_SHA512,
                MetadataService.Variant.ALGORITHM_SIGNING_256_512_KEYSIZE_EXCLUDED,
                MetadataService.Variant.ALGORITHM_SIGNING_512_256_KEYSIZE_EXCLUDED,
                MetadataService.Variant.ALGORITHM_ENTITY_SHA384)) {
            var raw=service.generatePolling(plan,variant,"run_probe");var doc=SecureXml.parse(raw);
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(doc.getDocumentElement(),
                    service.credentialsForPollingVariant(plan,variant).certificate()));
            var methods=doc.getElementsByTagNameNS(ALG,"SigningMethod");
            if(variant==MetadataService.Variant.ALGORITHM_ENTITY_SHA512 || variant==MetadataService.Variant.ALGORITHM_ENTITY_SHA384) {
                var bits=variant==MetadataService.Variant.ALGORITHM_ENTITY_SHA512?512:384;
                assertEquals(1,methods.getLength());
                assertEquals(MORE+"rsa-sha"+bits,((Element)methods.item(0)).getAttribute("Algorithm"));
                var digest=(Element)doc.getElementsByTagNameNS(ALG,"DigestMethod").item(0);
                assertEquals(bits==512?"http://www.w3.org/2001/04/xmlenc#sha512":MORE+"sha384",digest.getAttribute("Algorithm"));
            } else {
                var first256=variant==MetadataService.Variant.ALGORITHM_SIGNING_256_512_KEYSIZE_EXCLUDED;
                assertEquals(2,methods.getLength());
                assertEquals(MORE+"rsa-sha"+(first256?256:512),((Element)methods.item(0)).getAttribute("Algorithm"));
                assertEquals("1",((Element)methods.item(0)).getAttribute("MaxKeySize"));
                assertEquals(MORE+"rsa-sha"+(first256?512:256),((Element)methods.item(1)).getAttribute("Algorithm"));
                assertFalse(((Element)methods.item(1)).hasAttribute("MaxKeySize"));
            }
            var endpoints=doc.getElementsByTagNameNS(MetadataService.MD,"AssertionConsumerService");
            for(int index=0;index<endpoints.getLength();index++)
                assertTrue(((Element)endpoints.item(index)).getAttribute("Location").contains("mdv="+variant.id()+"&run=run_probe"));
        }
    }
}
