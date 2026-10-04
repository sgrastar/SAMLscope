package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.time.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;

class MetadataLiveValidityFixturesTest {
    @TempDir java.nio.file.Path directory;
    @Test void eachLiveInputHasTheRequiredEarliestLevelAndItsWholeDocumentSignature() {
        Instant now=Instant.parse("2026-10-02T00:00:00Z");
        var clock=Clock.fixed(now,ZoneOffset.UTC);var store=new FilePlanKeyStore(directory,clock);
        var plan=SamlTestFixtures.idpPlan();var service=new MetadataService(URI.create("https://peer.example"),store,new XmlSigner(),clock);
        for (var variant:java.util.List.of(MetadataService.Variant.LIVE_VALIDITY_ROOT,
                MetadataService.Variant.LIVE_VALIDITY_PARENT,MetadataService.Variant.LIVE_VALIDITY_CHILD)) {
            var root=SecureXml.parse(service.generatePolling(plan,variant,"run_probe")).getDocumentElement();
            String expected=now.plusSeconds(plan.parameters().metadataRefreshWaitSeconds()).toString();
            if(variant==MetadataService.Variant.LIVE_VALIDITY_ROOT) {
                assertEquals("EntityDescriptor",root.getLocalName());assertEquals(expected,root.getAttribute("validUntil"));
            } else {
                assertEquals("EntitiesDescriptor",root.getLocalName());
                var inner=(Element)root.getElementsByTagNameNS(MetadataService.MD,"EntitiesDescriptor").item(0);
                var entity=(Element)root.getElementsByTagNameNS(MetadataService.MD,"EntityDescriptor").item(0);
                Element early=variant==MetadataService.Variant.LIVE_VALIDITY_PARENT?root:inner;
                Element later=variant==MetadataService.Variant.LIVE_VALIDITY_PARENT?inner:root;
                assertEquals(expected,early.getAttribute("validUntil"));
                assertTrue(Instant.parse(later.getAttribute("validUntil")).isAfter(Instant.parse(expected)));
                assertTrue(Instant.parse(entity.getAttribute("validUntil")).isAfter(Instant.parse(expected)));
            }
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root,service.credentialsForPollingVariant(plan,variant).certificate()));
        }
    }
    @Test void helperLeavesExistingInputUntouched() {
        var document=SecureXml.parse("<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' entityID='same' validUntil='2027-01-01T00:00:00Z'/>".getBytes());
        var before=SecureXml.serialize(document);var root=document.getDocumentElement();
        assertSame(root,MetadataLiveValidityFixtures.apply(document,root,MetadataService.Variant.EXPIRED,Instant.EPOCH,0));
        assertArrayEquals(before,SecureXml.serialize(document));
    }
    @Test void liveFixtureRefusesAnUnusableTestLifetime() {
        var document=SecureXml.newDocument();var root=document.createElementNS(MetadataService.MD,"md:EntityDescriptor");document.appendChild(root);
        assertThrows(IllegalArgumentException.class,()->MetadataLiveValidityFixtures.apply(document,root,MetadataService.Variant.LIVE_VALIDITY_ROOT,Instant.EPOCH,0));
    }
}
