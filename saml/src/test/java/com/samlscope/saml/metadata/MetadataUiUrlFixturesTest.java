package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.SecureXml;

class MetadataUiUrlFixturesTest {
    @TempDir java.nio.file.Path directory;
    @Test void everyUrlElementHasIndependentAllowedAndExcludedSchemeInputs() {
        var service = new MetadataService(URI.create("https://suite.example"),
                new FilePlanKeyStore(directory, Clock.systemUTC()), new XmlSigner(), Clock.systemUTC());
        var variants = Arrays.stream(MetadataService.Variant.values()).filter(v -> v.id().startsWith("ui-url-")).toList();
        assertEquals(15, variants.size());
        var names = Map.of("logo", "Logo", "information", "InformationURL", "privacy", "PrivacyStatementURL");
        for (boolean polling : new boolean[]{false, true}) for (var variant : variants) {
            assertTrue(MetadataService.preloadedCampaignVariants().contains(variant));
            var plan = SamlTestFixtures.idpPlan();
            var raw = polling ? service.generatePolling(plan, variant, "run_ui_url") : service.generate(plan, variant, "run_ui_url");
            var root = SecureXml.parse(raw).getDocumentElement();
            var tokens = variant.id().split("-");
            for (var name : names.values()) {
                var urls = root.getElementsByTagNameNS(MetadataUiConsumerFixtures.UI, name);
                assertEquals(name.equals(names.get(tokens[2])) ? 1 : 0, urls.getLength());
                if (urls.getLength() == 0) continue;
                var element = (Element) urls.item(0);
                assertEquals("SPSSODescriptor", element.getParentNode().getParentNode().getParentNode().getLocalName());
                var uri = URI.create(element.getTextContent());
                assertEquals(tokens[3], uri.getScheme());
                if (Set.of("http", "https").contains(tokens[3])) {
                    assertEquals("suite.example", uri.getHost());
                    assertEquals(MetadataUiFixtureAsset.PATH, uri.getPath());
                }
                if (tokens[3].equals("data")) {
                    var encoded = element.getTextContent().substring("data:image/svg+xml;base64,".length());
                    assertEquals(MetadataUiFixtureAsset.SVG, new String(Base64.getDecoder().decode(encoded), java.nio.charset.StandardCharsets.UTF_8));
                }
            }
        }
    }
}
