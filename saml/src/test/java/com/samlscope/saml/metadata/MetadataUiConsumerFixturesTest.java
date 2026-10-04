package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.time.Clock;
import javax.xml.XMLConstants;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.xml.sax.SAXException;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;

class MetadataUiConsumerFixturesTest {
    @TempDir java.nio.file.Path directory;

    @Test void displayCandidatesHaveDistinctTextAndAnExplicitAbsenceControl() {
        var service = service();
        for (boolean polling : new boolean[]{false, true}) {
            var all = generate(service, MetadataService.Variant.UI_CONSUMER_DISPLAY_ALL, polling);
            var name = generate(service, MetadataService.Variant.UI_CONSUMER_DISPLAY_SERVICE, polling);
            var entity = generate(service, MetadataService.Variant.UI_CONSUMER_DISPLAY_ENTITY, polling);
            assertEquals(all.getAttribute("entityID"), entity.getAttribute("entityID"));
            assertEquals(MetadataUiConsumerFixtures.DISPLAY_NAME,
                    all.getElementsByTagNameNS(MetadataUiConsumerFixtures.UI, "DisplayName").item(0).getTextContent());
            assertEquals(MetadataUiConsumerFixtures.SERVICE_NAME,
                    name.getElementsByTagNameNS(MetadataService.MD, "ServiceName").item(0).getTextContent());
            assertNotEquals(MetadataUiConsumerFixtures.DISPLAY_NAME, MetadataUiConsumerFixtures.SERVICE_NAME);
            assertEquals(0, name.getElementsByTagNameNS(MetadataUiConsumerFixtures.UI, "DisplayName").getLength());
            assertEquals(0, entity.getElementsByTagNameNS(MetadataService.MD, "ServiceName").getLength());
            assertEquals(0, entity.getElementsByTagNameNS(MetadataUiConsumerFixtures.UI, "UIInfo").getLength());
            assertEquals(1, all.getElementsByTagNameNS(MetadataService.MD, "RequestedAttribute").getLength());
        }
    }

    @Test void logoControlChangesOnlyTheLocalizedCandidatesLanguage() {
        var service = service();
        for (boolean polling : new boolean[]{false, true}) {
            var localized = generate(service, MetadataService.Variant.UI_CONSUMER_LOGO_LOCALIZED, polling);
            var fallback = generate(service, MetadataService.Variant.UI_CONSUMER_LOGO_FALLBACK, polling);
            var first = localized.getElementsByTagNameNS(MetadataUiConsumerFixtures.UI, "Logo");
            var second = fallback.getElementsByTagNameNS(MetadataUiConsumerFixtures.UI, "Logo");
            assertEquals(2, first.getLength());
            assertEquals(2, second.getLength());
            for (int i = 0; i < 2; i++) {
                var logo = (Element) first.item(i);
                assertEquals(logo.getTextContent(), second.item(i).getTextContent());
                assertTrue(logo.getTextContent().startsWith("data:image/svg+xml;base64,"));
                assertEquals("SPSSODescriptor", logo.getParentNode().getParentNode().getParentNode().getLocalName());
            }
            assertFalse(((Element) first.item(0)).hasAttributeNS(XMLConstants.XML_NS_URI, "lang"));
            assertEquals("en", ((Element) first.item(1)).getAttributeNS(XMLConstants.XML_NS_URI, "lang"));
            assertEquals("ja", ((Element) second.item(1)).getAttributeNS(XMLConstants.XML_NS_URI, "lang"));
            assertNotEquals(first.item(0).getTextContent(), first.item(1).getTextContent());
        }
    }

    @Test void fullUiPlacesBothContainersUnderTheRoleAndPassesThePinnedOfficialSchema() throws Exception {
        var schema = metadataUiSchema();
        var service = service();
        for (boolean polling : new boolean[]{false, true}) {
            var entity = generate(service, MetadataService.Variant.FULL_UI_INFO, polling);
            var info = (Element) entity.getElementsByTagNameNS(MetadataUiConsumerFixtures.UI, "UIInfo").item(0);
            var hints = (Element) entity.getElementsByTagNameNS(MetadataUiConsumerFixtures.UI, "DiscoHints").item(0);
            assertEquals("Extensions", info.getParentNode().getLocalName());
            assertEquals(MetadataService.MD, info.getParentNode().getNamespaceURI());
            assertSame(info.getParentNode(), hints.getParentNode());
            assertEquals("SPSSODescriptor", hints.getParentNode().getParentNode().getLocalName());
            assertEquals(2, hints.getElementsByTagNameNS(MetadataUiConsumerFixtures.UI, "IPHint").getLength());
            assertEquals(2, info.getElementsByTagNameNS(MetadataUiConsumerFixtures.UI, "Description").getLength());
            assertEquals(1, info.getElementsByTagNameNS("urn:samlscope:test:ui-extension", "Probe").getLength());
            assertEquals(1, hints.getElementsByTagNameNS("urn:samlscope:test:geo-extension", "Probe").getLength());
            assertDoesNotThrow(() -> schema.newValidator().validate(new DOMSource(entity)));
        }
    }

    @Test void serializedFullUiMetadataKeepsItsSignatureValidInNormalAndPollingPaths() throws Exception {
        for (boolean polling : new boolean[]{false, true}) {
            var entity = generate(service(), MetadataService.Variant.FULL_UI_INFO, polling);
            var signature = (Element) entity.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
            var encoded = signature.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate").item(0).getTextContent();
            var certificate = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(new java.io.ByteArrayInputStream(java.util.Base64.getMimeDecoder().decode(encoded)));
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(entity, certificate));
        }
    }

    @Test void officialSchemaRejectsTheFormerDiscoHintsInsideUiInfoPlacement() throws Exception {
        var schema = metadataUiSchema();
        for (boolean polling : new boolean[]{false, true}) {
            var entity = generate(service(), MetadataService.Variant.FULL_UI_INFO, polling);
            var info = entity.getElementsByTagNameNS(MetadataUiConsumerFixtures.UI, "UIInfo").item(0);
            var hints = entity.getElementsByTagNameNS(MetadataUiConsumerFixtures.UI, "DiscoHints").item(0);
            info.appendChild(hints);
            assertThrows(SAXException.class, () -> schema.newValidator().validate(new DOMSource(entity)));
        }
    }

    @Test void unknownExtensionsAreAllowedOnlyOutsideTheMetadataUiNamespace() throws Exception {
        var schema = metadataUiSchema();
        for (var container : java.util.List.of("UIInfo", "DiscoHints")) {
            var entity = generate(service(), MetadataService.Variant.FULL_UI_INFO, false);
            var parent = entity.getElementsByTagNameNS(MetadataUiConsumerFixtures.UI, container).item(0);
            var unknown = entity.getOwnerDocument().createElementNS(MetadataUiConsumerFixtures.UI, "mdui:UndeclaredProbe");
            parent.appendChild(unknown);
            assertThrows(SAXException.class, () -> schema.newValidator().validate(new DOMSource(entity)), container);
        }
    }

    /** All schema imports resolve to the pinned OpenSAML resources; no network access. */
    private static Schema metadataUiSchema() throws Exception {
        var resources = java.util.Map.of(
                MetadataUiConsumerFixtures.UI, "schema/sstc-saml-metadata-ui-v1.0.xsd",
                MetadataService.MD, "schema/saml-schema-metadata-2.0.xsd",
                XMLConstants.XML_NS_URI, "schema/xml.xsd",
                "urn:oasis:names:tc:SAML:2.0:assertion", "schema/saml-schema-assertion-2.0.xsd",
                "http://www.w3.org/2000/09/xmldsig#", "schema/xmldsig-core-schema.xsd",
                "http://www.w3.org/2001/04/xmlenc#", "schema/xenc-schema.xsd");
        var implementation = (DOMImplementationLS) DOMImplementationRegistry.newInstance().getDOMImplementation("LS");
        var factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        factory.setResourceResolver((type, namespace, publicId, systemId, baseUri) -> {
            var resource = resources.get(namespace);
            if (resource == null) return null;
            var input = implementation.createLSInput();
            input.setPublicId(publicId);
            input.setSystemId("classpath:/" + resource);
            input.setByteStream(requiredSchema(resource));
            return input;
        });
        var resource = resources.get(MetadataUiConsumerFixtures.UI);
        return factory.newSchema(new StreamSource(requiredSchema(resource), "classpath:/" + resource));
    }

    private static java.io.InputStream requiredSchema(String path) {
        var stream = MetadataUiConsumerFixturesTest.class.getClassLoader().getResourceAsStream(path);
        if (stream == null) throw new IllegalStateException("Missing pinned schema: " + path);
        return stream;
    }

    private MetadataService service() {
        return new MetadataService(URI.create("https://suite.example"),
                new FilePlanKeyStore(directory, Clock.systemUTC()), new XmlSigner(), Clock.systemUTC());
    }

    private Element generate(MetadataService service, MetadataService.Variant variant, boolean polling) {
        // FULL_UI_INFO is a CONFIG fixture; the display/logo fixtures below are preloaded browser probes.
        if (variant != MetadataService.Variant.FULL_UI_INFO) {
            assertTrue(MetadataService.preloadedCampaignVariants().contains(variant));
        }
        var plan = SamlTestFixtures.idpPlan();
        return SecureXml.parse(polling ? service.generatePolling(plan, variant, "run_ui")
                : service.generate(plan, variant, "run_ui")).getDocumentElement();
    }
}
