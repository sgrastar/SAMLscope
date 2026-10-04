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

class MetadataEncryptionAlgorithmFixturesTest {
    @TempDir java.nio.file.Path directory;
    private static final String XENC = "http://www.w3.org/2001/04/xmlenc#";
    private static final String XENC11 = "http://www.w3.org/2009/xmlenc11#";

    @Test void pairedDataOrdersKeySizesAndSigningLimitsAreIndependentInputs() {
        for (boolean polling : List.of(false, true)) {
            var first = encryption(generate(MetadataService.Variant.ALGORITHM_ENCRYPTION_ORDER_128_256, polling));
            var reverse = encryption(generate(MetadataService.Variant.ALGORITHM_ENCRYPTION_ORDER_256_128, polling));
            assertEquals(List.of(XENC11 + "aes128-gcm", XENC11 + "aes256-gcm"), algorithms(first));
            assertEquals(List.of(XENC11 + "aes256-gcm", XENC11 + "aes128-gcm"), algorithms(reverse));
            for (var variant : List.of(MetadataService.Variant.ALGORITHM_ENCRYPTION_KEYSIZE_128,
                    MetadataService.Variant.ALGORITHM_ENCRYPTION_KEYSIZE_256)) {
                var method = encryption(generate(variant, polling)).getFirst();
                var size = (Element) method.getElementsByTagNameNS(XENC, "KeySize").item(0);
                var bits = variant == MetadataService.Variant.ALGORITHM_ENCRYPTION_KEYSIZE_128 ? "128" : "256";
                assertEquals(bits, size.getTextContent());
                assertEquals(XENC + "aes" + bits + "-cbc", method.getAttribute("Algorithm"));
            }
            for (var variant : List.of(MetadataService.Variant.ALGORITHM_SIGNING_256_KEYSIZE_EXCLUDED,
                    MetadataService.Variant.ALGORITHM_SIGNING_384_KEYSIZE_EXCLUDED)) {
                var root = generate(variant, polling);
                var methods = root.getElementsByTagNameNS(MetadataAlgorithmFixtures.ALG, "SigningMethod");
                assertEquals(2, methods.getLength());
                assertEquals("1", ((Element) methods.item(0)).getAttribute("MaxKeySize"));
                assertFalse(((Element) methods.item(1)).hasAttribute("MaxKeySize"));
                assertNotEquals(((Element) methods.item(0)).getAttribute("Algorithm"),
                        ((Element) methods.item(1)).getAttribute("Algorithm"));
                assertEquals("SPSSODescriptor", methods.item(0).getParentNode().getParentNode().getLocalName());
            }
        }
    }

    @Test void oaepDigestAndMgfMatrixPreservesExplicitVersusDefaultMgf() {
        for (boolean polling : List.of(false, true)) {
            for (var variant : List.of(MetadataService.Variant.ALGORITHM_OAEP_10_SHA1,
                    MetadataService.Variant.ALGORITHM_OAEP_10_SHA256, MetadataService.Variant.ALGORITHM_OAEP_11_SHA1,
                    MetadataService.Variant.ALGORITHM_OAEP_11_SHA256, MetadataService.Variant.ALGORITHM_OAEP_11_DEFAULT_MGF)) {
                var methods = encryption(generate(variant, polling));
                assertEquals(2, methods.size());
                assertEquals(XENC11 + "aes128-gcm", methods.getFirst().getAttribute("Algorithm"));
                var transport = methods.getLast();
                boolean old = variant.name().contains("OAEP_10");
                boolean sha1 = variant.name().endsWith("_SHA1");
                assertEquals(old ? XENC + "rsa-oaep-mgf1p" : XENC11 + "rsa-oaep", transport.getAttribute("Algorithm"));
                var digests = transport.getElementsByTagNameNS(MetadataService.DS, "DigestMethod");
                assertEquals(1, digests.getLength());
                assertEquals(sha1 ? MetadataService.DS + "sha1" : XENC + "sha256", ((Element) digests.item(0)).getAttribute("Algorithm"));
                var mgfs = transport.getElementsByTagNameNS(XENC11, "MGF");
                boolean explicit = !old && variant != MetadataService.Variant.ALGORITHM_OAEP_11_DEFAULT_MGF;
                assertEquals(explicit ? 1 : 0, mgfs.getLength());
                if (explicit) assertEquals(XENC11 + (sha1 ? "mgf1sha1" : "mgf1sha256"), ((Element) mgfs.item(0)).getAttribute("Algorithm"));
            }
        }
    }

    private Element generate(MetadataService.Variant variant, boolean polling) {
        assertTrue(MetadataService.preloadedCampaignVariants().contains(variant));
        var service = new MetadataService(URI.create("https://suite.example"),
                new FilePlanKeyStore(directory, Clock.systemUTC()), new XmlSigner(), Clock.systemUTC());
        var plan = SamlTestFixtures.idpPlan();
        return SecureXml.parse(polling ? service.generatePolling(plan, variant, "run_alg")
                : service.generate(plan, variant, "run_alg")).getDocumentElement();
    }

    private List<Element> encryption(Element root) {
        var roles = root.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor");
        var keys = ((Element) roles.item(0)).getElementsByTagNameNS(MetadataService.MD, "KeyDescriptor");
        var result = new ArrayList<Element>();
        for (int i = 0; i < keys.getLength(); i++) {
            var key = (Element) keys.item(i);
            var methods = key.getElementsByTagNameNS(MetadataService.MD, "EncryptionMethod");
            if (key.getAttribute("use").equals("signing")) assertEquals(0, methods.getLength());
            else for (int j = 0; j < methods.getLength(); j++) result.add((Element) methods.item(j));
        }
        return result;
    }

    private List<String> algorithms(List<Element> methods) {
        return methods.stream().map(e -> e.getAttribute("Algorithm")).toList();
    }
}
