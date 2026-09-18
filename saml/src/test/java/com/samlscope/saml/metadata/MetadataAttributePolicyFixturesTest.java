package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.SecureXml;

class MetadataAttributePolicyFixturesTest {
    @TempDir java.nio.file.Path directory;

    @Test void metadataPolicyInputsDistinguishEveryApprovedCondition() {
        var service = new MetadataService(URI.create("https://suite.example"),
                new FilePlanKeyStore(directory, Clock.systemUTC()), new XmlSigner(), Clock.systemUTC());
        for (boolean polling : new boolean[]{false, true}) {
            var present = generate(service, MetadataService.Variant.ATTRIBUTE_POLICY_ENTITY_PRESENT, polling);
            var absent = generate(service, MetadataService.Variant.ATTRIBUTE_POLICY_ENTITY_ABSENT, polling);
            assertEquals(present.getAttribute("entityID"), absent.getAttribute("entityID"));
            assertEquals(0, absent.getElementsByTagNameNS(MetadataAttributePolicyFixtures.MDATTR, "EntityAttributes").getLength());
            var container = (Element) present.getElementsByTagNameNS(MetadataAttributePolicyFixtures.MDATTR, "EntityAttributes").item(0);
            assertEquals(present, container.getParentNode().getParentNode());
            var policy = (Element) container.getElementsByTagNameNS(MetadataService.SAML, "Attribute").item(0);
            assertEquals(MetadataAttributePolicyFixtures.POLICY_NAME, policy.getAttribute("Name"));
            assertEquals("release", policy.getTextContent());

            var required = generate(service, MetadataService.Variant.ATTRIBUTE_POLICY_REQUESTED_REQUIRED, polling);
            var optional = generate(service, MetadataService.Variant.ATTRIBUTE_POLICY_REQUESTED_OPTIONAL, polling);
            var noRequested = generate(service, MetadataService.Variant.ATTRIBUTE_POLICY_REQUESTED_ABSENT, polling);
            assertEquals(0, noRequested.getElementsByTagNameNS(MetadataService.MD, "RequestedAttribute").getLength());
            assertEquals("true", requested(required, 0).getAttribute("isRequired"));
            assertEquals("false", requested(optional, 0).getAttribute("isRequired"));
            assertEquals(requested(required, 0).getAttribute("Name"), requested(optional, 0).getAttribute("Name"));
            var indexed = generate(service, MetadataService.Variant.ATTRIBUTE_POLICY_INDEXED, polling);
            var services = indexed.getElementsByTagNameNS(MetadataService.MD, "AttributeConsumingService");
            assertEquals(2, services.getLength());
            for (int index = 0; index < 2; index++) {
                var consuming = (Element) services.item(index);
                assertEquals(Integer.toString(index), consuming.getAttribute("index"));
                assertEquals("SPSSODescriptor", consuming.getParentNode().getLocalName());
                assertEquals(1, consuming.getElementsByTagNameNS(MetadataService.MD, "ServiceName").getLength());
            }
            assertNotEquals(requested(indexed, 0).getAttribute("Name"), requested(indexed, 1).getAttribute("Name"));
        }
    }

    private Element generate(MetadataService service, MetadataService.Variant variant, boolean polling) {
        assertTrue(MetadataService.preloadedCampaignVariants().contains(variant));
        var plan = SamlTestFixtures.idpPlan();
        return SecureXml.parse(polling ? service.generatePolling(plan, variant, "run_attributes")
                : service.generate(plan, variant, "run_attributes")).getDocumentElement();
    }

    private Element requested(Element entity, int index) {
        return (Element) entity.getElementsByTagNameNS(MetadataService.MD, "RequestedAttribute").item(index);
    }
}
