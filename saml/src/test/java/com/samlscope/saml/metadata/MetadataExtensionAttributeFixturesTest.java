package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.time.*;
import java.util.*;
import javax.xml.namespace.QName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;
import org.w3c.dom.Element;

class MetadataExtensionAttributeFixturesTest {
    @TempDir java.nio.file.Path directory;

    @Test void coversEveryMetadataDeclarationWithAnOwnAttributeWildcard() {
        var clock = Clock.fixed(Instant.parse("2026-09-14T00:00:00Z"), ZoneOffset.UTC);
        var keys = new FilePlanKeyStore(directory, clock);
        var plan = SamlTestFixtures.idpPlan();
        var service = new MetadataService(URI.create("https://suite.example"), keys, new XmlSigner(), clock);
        assertEquals(Optional.empty(), SamlSchemaValidation.validationFailure(
                SecureXml.parse(service.generate(plan)).getDocumentElement(), SamlSchemaValidation.SchemaKind.METADATA));
        var expected = SamlExtensionAttributePoints.inventory().stream()
                .filter(point -> point.element().getNamespaceURI().equals(MetadataService.MD))
                .map(SamlExtensionAttributePoints.Point::element).collect(java.util.stream.Collectors.toSet());
        assertEquals(13, expected.size());
        var seen = new HashSet<QName>();
        for (var variant : MetadataService.Variant.values()) {
            if (!variant.id().startsWith("foreign-attribute-")) continue;
            var document = SecureXml.parse(service.generate(plan, variant, "run_attribute_matrix"));
            var root = document.getDocumentElement();
            assertEquals(Optional.empty(), SamlSchemaValidation.validationFailure(root, SamlSchemaValidation.SchemaKind.METADATA), variant.id());
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root, keys.getOrCreate(plan.id()).certificate()), variant.id());
            var all = document.getElementsByTagNameNS(MetadataService.MD, "*");
            int markers = 0;
            for (int i = 0; i < all.getLength(); i++) {
                var element = (Element) all.item(i);
                if (element.hasAttributeNS(MetadataExtensionAttributeFixtures.FOREIGN, "undefined")) {
                    assertTrue(seen.add(new QName(element.getNamespaceURI(), element.getLocalName())), variant.id());
                    markers++;
                }
            }
            assertEquals(1, markers, variant.id());
            assertTrue(document.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").getLength() > 0);
            assertTrue(document.getElementsByTagNameNS(MetadataService.MD, "IDPSSODescriptor").getLength() > 0);
        }
        assertEquals(expected, seen, "Schema changes must expose missing fixtures rather than silently shrinking the matrix");
        var assertion = SamlExtensionAttributePoints.inventory().stream()
                .filter(point -> point.element().getNamespaceURI().equals("urn:oasis:names:tc:SAML:2.0:assertion"))
                .map(point -> point.element().getLocalPart()).collect(java.util.stream.Collectors.toSet());
        assertEquals(Set.of("SubjectConfirmationData", "Attribute"), assertion);
        assertFalse(expected.contains(new QName(MetadataService.MD, "AssertionConsumerService")),
                "IndexedEndpointType inherits its wildcard; it does not directly declare one");
    }
}
