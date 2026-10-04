package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MetadataUiSafetyFixturesTest {
    @TempDir java.nio.file.Path directory;
    @Test void scriptCapableInputsStaySignedAndBoundToTheExistingUrlComparisonKey() throws Exception {
        var plan = SamlTestFixtures.idpPlan();
        var service = new MetadataService(URI.create("https://suite.example"),
                new FilePlanKeyStore(directory, Clock.systemUTC()), new XmlSigner(), Clock.systemUTC());
        var keys = service.credentialsForPollingVariant(plan, MetadataService.Variant.UI_URL_LOGO_HTTP);
        for (var variant : List.of(MetadataService.Variant.UI_SAFETY_LOGO_DATA,
                MetadataService.Variant.UI_SAFETY_INFORMATION_JAVASCRIPT,
                MetadataService.Variant.UI_SAFETY_PRIVACY_JAVASCRIPT)) {
            assertTrue(MetadataService.preloadedCampaignVariants().contains(variant));
            var root = SecureXml.parse(service.generatePolling(plan, variant, "run_safety")).getDocumentElement();
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root, keys.certificate()));
            assertArrayEquals(keys.certificate().getEncoded(),
                    service.credentialsForPollingVariant(plan, variant).certificate().getEncoded());
            var info = root.getElementsByTagNameNS(MetadataService.UI, "UIInfo").item(0);
            assertNotNull(info);
            String kind = variant == MetadataService.Variant.UI_SAFETY_LOGO_DATA ? "Logo"
                    : variant == MetadataService.Variant.UI_SAFETY_INFORMATION_JAVASCRIPT ? "InformationURL" : "PrivacyStatementURL";
            var payload = root.getElementsByTagNameNS(MetadataService.UI, kind).item(0).getTextContent();
            if (kind.equals("Logo")) {
                assertEquals(MetadataUiSafetyFixtures.SCRIPT_SVG, new String(Base64.getDecoder().decode(
                        payload.substring("data:image/svg+xml;base64,".length())), StandardCharsets.UTF_8));
            } else assertEquals(MetadataUiSafetyFixtures.JAVASCRIPT, payload);
            var acs = root.getElementsByTagNameNS(MetadataService.MD, "AssertionConsumerService").item(0);
            assertTrue(acs.getAttributes().getNamedItem("Location").getNodeValue().contains("mdv=" + variant.id()));
        }
    }
}
