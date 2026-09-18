package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.time.Clock;
import javax.xml.XMLConstants;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
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

    private MetadataService service() {
        return new MetadataService(URI.create("https://suite.example"),
                new FilePlanKeyStore(directory, Clock.systemUTC()), new XmlSigner(), Clock.systemUTC());
    }

    private Element generate(MetadataService service, MetadataService.Variant variant, boolean polling) {
        assertTrue(MetadataService.preloadedCampaignVariants().contains(variant));
        var plan = SamlTestFixtures.idpPlan();
        return SecureXml.parse(polling ? service.generatePolling(plan, variant, "run_ui")
                : service.generate(plan, variant, "run_ui")).getDocumentElement();
    }
}
